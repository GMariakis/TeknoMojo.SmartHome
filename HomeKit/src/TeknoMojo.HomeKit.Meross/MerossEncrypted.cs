using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace TeknoMojo.HomeKit.Meross;

/// <summary>
/// An encrypted local-HTTP session with an encrypt:1 Meross device.
///
/// Newer Meross firmware (e.g. MSS110 fw 7.3.46) drops PLAINTEXT control/config writes over local
/// HTTP, but accepts them once an ECDHE session is established. The handshake is a single plaintext
/// `Appliance.Encrypt.ECDHE` exchange on prime256v1; the derived shared secret is the AES-256-CBC
/// key (fixed IV, null padding) used to wrap every subsequent request/response body.
///
/// Ported from bytespider/Meross (develop branch): encryption.ts, message/configureECDH.ts,
/// transport/http.ts.
/// </summary>
public sealed class EcdheHttpSession : IDisposable
{
    private static readonly byte[] Iv = Encoding.ASCII.GetBytes("0000000000000000"); // 16 bytes of '0'
    private const string From = "/app/0";

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _url;
    private readonly string _key;
    private byte[]? _sharedKey;

    public EcdheHttpSession(string host, string key)
    {
        _url = $"http://{host}/config";
        _key = key;
    }

    public bool IsEstablished => _sharedKey is not null;

    /// <summary>Perform the ECDHE handshake and derive the AES session key.</summary>
    public async Task HandshakeAsync(CancellationToken ct = default)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] ourPublic = ExportUncompressedPoint(ecdh);

        var payload = new JsonObject
        {
            ["ecdhe"] = new JsonObject
            {
                ["step"] = 1,
                ["pubkey"] = Convert.ToBase64String(ourPublic),
            },
        };
        string requestJson = BuildSignedMessage("SET", "Appliance.Encrypt.ECDHE", payload);

        // The handshake itself is sent in the clear.
        using var content = new StringContent(requestJson, Encoding.UTF8, "application/json");
        using HttpResponseMessage resp = await _http.PostAsync(_url, content, ct);
        string raw = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode || raw.Length == 0)
            throw new MerossException($"ECDHE handshake failed (HTTP {(int)resp.StatusCode}, {raw.Length} bytes).");

        JsonNode root = JsonNode.Parse(raw) ?? throw new MerossException("ECDHE: unparseable response.");
        string? devPubB64 = root["payload"]?["ecdhe"]?["pubkey"]?.GetValue<string>();
        if (devPubB64 is null)
            throw new MerossException($"ECDHE: no device pubkey in response: {Truncate(raw)}");

        byte[] devPublic = Convert.FromBase64String(devPubB64);
        _sharedKey = DeriveSharedKey(ecdh, devPublic); // 32-byte raw X coordinate = AES-256 key
    }

    /// <summary>Send an encrypted request and return the decrypted response.</summary>
    public async Task<JsonNode> InvokeAsync(string method, string @namespace, JsonObject payload, CancellationToken ct = default)
    {
        if (_sharedKey is null) throw new InvalidOperationException("Call HandshakeAsync first.");

        string messageJson = BuildSignedMessage(method, @namespace, payload);
        byte[] cipher = AesCbc(Encoding.UTF8.GetBytes(messageJson), _sharedKey, encrypt: true);
        string body = Convert.ToBase64String(cipher);

        using var content = new StringContent(body, Encoding.UTF8, "text/plain");
        using HttpResponseMessage resp = await _http.PostAsync(_url, content, ct);
        string raw = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new MerossException($"Encrypted request failed (HTTP {(int)resp.StatusCode}).");
        if (raw.Length == 0)
            throw new MerossException("Encrypted request: empty reply (device rejected the message).");

        byte[] plain = AesCbc(Convert.FromBase64String(raw), _sharedKey, encrypt: false);
        string json = Encoding.UTF8.GetString(plain).TrimEnd('\0');
        JsonNode root = JsonNode.Parse(json) ?? throw new MerossException("Decrypted response was not JSON.");

        int? apiStatus = root["payload"]?["error"]?["code"]?.GetValue<int>();
        if (apiStatus is int code && code != 0)
            throw new MerossException($"Device error {code}: {root["payload"]!["error"]!["detail"]?.GetValue<string>()}", code);
        return root;
    }

    public Task<JsonNode> SystemAllAsync(CancellationToken ct = default) =>
        InvokeAsync("GET", "Appliance.System.All", new JsonObject(), ct);

    public Task<JsonNode> ToggleAsync(int channel, bool on, CancellationToken ct = default) =>
        InvokeAsync("SET", "Appliance.Control.ToggleX",
            new JsonObject { ["togglex"] = new JsonObject { ["channel"] = channel, ["onoff"] = on ? 1 : 0 } }, ct);

    // --- helpers ---

    private string BuildSignedMessage(string method, string @namespace, JsonObject payload)
    {
        string messageId = MerossClient.NewMessageId();
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string sign = MerossClient.ComputeSign(messageId, _key, timestamp);
        var envelope = new JsonObject
        {
            ["header"] = new JsonObject
            {
                ["from"] = From,
                ["messageId"] = messageId,
                ["method"] = method,
                ["namespace"] = @namespace,
                ["payloadVersion"] = 1,
                ["sign"] = sign,
                ["timestamp"] = timestamp,
                ["timestampMs"] = 0,
            },
            // Clone so the caller's payload node is never parented — the same payload may already
            // have been used to build a plaintext envelope before falling back to this path.
            ["payload"] = payload.DeepClone(),
        };
        return envelope.ToJsonString();
    }

    private static byte[] ExportUncompressedPoint(ECDiffieHellman ecdh)
    {
        ECParameters p = ecdh.ExportParameters(false);
        byte[] x = p.Q.X!, y = p.Q.Y!;
        var point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04; // uncompressed
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);
        return point;
    }

    private static byte[] DeriveSharedKey(ECDiffieHellman ours, byte[] peerUncompressedPoint)
    {
        // Accept 0x04||X||Y (65 bytes) or bare X||Y (64 bytes).
        int off = peerUncompressedPoint.Length == 65 ? 1 : 0;
        int coord = 32;
        var px = new byte[coord];
        var py = new byte[coord];
        Array.Copy(peerUncompressedPoint, off, px, 0, coord);
        Array.Copy(peerUncompressedPoint, off + coord, py, 0, coord);

        var peerParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = px, Y = py },
        };
        using ECDiffieHellman peer = ECDiffieHellman.Create(peerParams);
        // Node's ecdh.computeSecret() returns the raw shared X coordinate (32 bytes)...
        byte[] rawSecret = ours.DeriveRawSecretAgreement(peer.PublicKey);
        // ...but the AES-256 key is md5(rawSecret) as a lowercase-hex STRING, taken as ASCII bytes
        // (32 hex chars = 32 bytes). See device.ts: Buffer.from(md5(sharedKey,'hex'),'utf8').
        string hex = Convert.ToHexString(MD5.HashData(rawSecret)).ToLowerInvariant();
        return Encoding.ASCII.GetBytes(hex);
    }

    private static byte[] AesCbc(byte[] data, byte[] key, bool encrypt)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = Iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        if (encrypt)
        {
            int padded = (data.Length + 15) / 16 * 16;
            if (padded != data.Length)
            {
                var buf = new byte[padded];
                data.CopyTo(buf, 0); // remaining bytes already 0x00
                data = buf;
            }
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(data, 0, data.Length);
        }
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(data, 0, data.Length);
    }

    private static string Truncate(string s) => s.Length > 200 ? s[..200] + "..." : s;

    public void Dispose() => _http.Dispose();
}
