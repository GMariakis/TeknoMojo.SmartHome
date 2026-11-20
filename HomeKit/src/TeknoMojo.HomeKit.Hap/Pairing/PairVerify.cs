using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TeknoMojo.HomeKit.Core;
using TeknoMojo.HomeKit.Hap.Http;
using TeknoMojo.HomeKit.Hap.Session;
using TeknoMojo.HomeKit.Hap.Tlv;
using BCEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;
using BCX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace TeknoMojo.HomeKit.Hap.Pairing;

/// <summary>
/// HAP pair-verify: X25519 ephemeral exchange with mutual Ed25519 identity proofs
/// (HAP §5.7). On success, returns a <see cref="HapVerifiedSession"/> that wraps the TCP
/// connection with ChaCha20-Poly1305 record framing.
/// </summary>
public static class PairVerify
{
    private const string TlvContentType = "application/pairing+tlv8";

    public static async Task<HapVerifiedSession> RunAsync(
        HapAccessory accessory,
        HapPairing pairing,
        CancellationToken ct = default)
    {
        if (accessory is null) throw new ArgumentNullException(nameof(accessory));
        if (pairing is null) throw new ArgumentNullException(nameof(pairing));
        if (accessory.Port <= 0) throw new ArgumentException("HapAccessory.Port not resolved.", nameof(accessory));

        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(new IPEndPoint(accessory.Address, accessory.Port), ct);
            var net = tcp.GetStream();

            // --- Generate controller ephemeral X25519 keypair ---
            byte[] controllerEphSk = new byte[BCX25519.ScalarSize];
            RandomNumberGenerator.Fill(controllerEphSk);
            byte[] controllerEphPk = new byte[BCX25519.PointSize];
            BCX25519.ScalarMultBase(controllerEphSk, 0, controllerEphPk, 0);

            // --- M1 --> ---
            var m1 = Tlv8.Encode(
                Tlv8.Byte(HapTlvType.State, HapPairingState.M1),
                Tlv8.Bytes(HapTlvType.PublicKey, controllerEphPk));
            await HapHttp.WriteRequestAsync(net, "POST", "/pair-verify", TlvContentType, m1, ct);

            // --- M2 <-- ---
            var m2 = await ReadTlvAsync(net, ct);
            EnsureState(m2, HapPairingState.M2);
            byte[] accessoryEphPk = m2.Get(HapTlvType.PublicKey);
            byte[] encryptedSub = m2.Get(HapTlvType.EncryptedData);

            // Shared secret via X25519, then session key via HKDF.
            byte[] sharedSecret = new byte[BCX25519.PointSize];
            if (!BCX25519.CalculateAgreement(controllerEphSk, 0, accessoryEphPk, 0, sharedSecret, 0))
                throw new HapProtocolException("Pair-verify: X25519 agreement failed.");

            byte[] sessionKey = HapCrypto.HkdfSha512(sharedSecret,
                salt: "Pair-Verify-Encrypt-Salt", info: "Pair-Verify-Encrypt-Info", length: 32);

            // Decrypt M2 sub-TLV and verify accessory identity signature.
            byte[] m2Sub = DecryptPairing(sessionKey, "PV-Msg02", encryptedSub);
            var m2SubTlv = Tlv8.Decode(m2Sub);
            string accessoryId = Encoding.UTF8.GetString(m2SubTlv.Get(HapTlvType.Identifier));
            byte[] accessorySig = m2SubTlv.Get(HapTlvType.Signature);

            if (!string.Equals(accessoryId, pairing.AccessoryId, StringComparison.OrdinalIgnoreCase))
                throw new HapAuthenticationException(
                    $"Pair-verify: unexpected accessory id \"{accessoryId}\" (paired as \"{pairing.AccessoryId}\").");

            byte[] accessoryInfo = Concat(accessoryEphPk, Encoding.UTF8.GetBytes(accessoryId), controllerEphPk);
            if (!BCEd25519.Verify(accessorySig, 0, pairing.AccessoryLtpk, 0, accessoryInfo, 0, accessoryInfo.Length))
                throw new HapAuthenticationException("Pair-verify: accessory identity signature invalid.");

            // --- M3 --> (encrypted controller identity proof) ---
            byte[] controllerInfo = Concat(controllerEphPk, Encoding.UTF8.GetBytes(pairing.ControllerId), accessoryEphPk);
            byte[] controllerSig = new byte[BCEd25519.SignatureSize];
            BCEd25519.Sign(pairing.ControllerLtsk, 0, controllerInfo, 0, controllerInfo.Length, controllerSig, 0);

            byte[] subTlvPlain = Tlv8.Encode(
                Tlv8.String(HapTlvType.Identifier, pairing.ControllerId),
                Tlv8.Bytes(HapTlvType.Signature, controllerSig));
            byte[] subTlvEncrypted = EncryptPairing(sessionKey, "PV-Msg03", subTlvPlain);

            var m3 = Tlv8.Encode(
                Tlv8.Byte(HapTlvType.State, HapPairingState.M3),
                Tlv8.Bytes(HapTlvType.EncryptedData, subTlvEncrypted));
            await HapHttp.WriteRequestAsync(net, "POST", "/pair-verify", TlvContentType, m3, ct);

            // --- M4 <-- ---
            var m4 = await ReadTlvAsync(net, ct);
            EnsureState(m4, HapPairingState.M4);

            // Derive session keys and wrap the socket. Naming per HAP §5.7.5:
            //   read (accessory->controller): "Control-Read-Encryption-Key"
            //   write (controller->accessory): "Control-Write-Encryption-Key"
            byte[] readKey = HapCrypto.HkdfSha512(sharedSecret, "Control-Salt", "Control-Read-Encryption-Key", 32);
            byte[] writeKey = HapCrypto.HkdfSha512(sharedSecret, "Control-Salt", "Control-Write-Encryption-Key", 32);

            var secure = new HapSessionStream(net, readKey: readKey, writeKey: writeKey);
            var session = new HapVerifiedSession(tcp, secure);
            tcp = null!; // ownership transferred; the finally block below must not close it
            return session;
        }
        finally
        {
            tcp?.Dispose();
        }
    }

    // -------- helpers (mirror PairSetup; kept private-here to avoid over-exposing) --------

    private static async Task<List<TlvItem>> ReadTlvAsync(Stream s, CancellationToken ct)
    {
        var resp = await HapHttp.ReadResponseAsync(s, ct);
        if (resp.Status != 200) throw new HapProtocolException($"HAP pair-verify HTTP {resp.Status}");
        var tlv = Tlv8.Decode(resp.Body);
        if (tlv.TryGet(HapTlvType.Error, out var err) && err.Length == 1)
            throw new HapProtocolException($"HAP pair-verify error 0x{err[0]:X2} ({(HapTlvError)err[0]})");
        return tlv;
    }

    private static void EnsureState(List<TlvItem> tlv, byte expected)
    {
        byte? state = tlv.GetByteOrNull(HapTlvType.State);
        if (state != expected)
            throw new HapProtocolException($"HAP pair-verify: expected M{expected} got {(state.HasValue ? "M" + state : "no-state")}");
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = parts.Sum(p => p.Length);
        var buf = new byte[total];
        int pos = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, buf, pos, p.Length); pos += p.Length; }
        return buf;
    }

    private static byte[] EncryptPairing(byte[] key, string label, byte[] plaintext)
    {
        using var cha = new ChaCha20Poly1305(key);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        cha.Encrypt(HapCrypto.PairingNonce(label), plaintext, cipher, tag);
        var output = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, output, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, output, cipher.Length, tag.Length);
        return output;
    }

    private static byte[] DecryptPairing(byte[] key, string label, byte[] ciphertextAndTag)
    {
        if (ciphertextAndTag.Length < 16)
            throw new HapProtocolException("Encrypted pairing payload smaller than a tag.");
        int cipherLen = ciphertextAndTag.Length - 16;
        var cipher = ciphertextAndTag.AsSpan(0, cipherLen);
        var tag = ciphertextAndTag.AsSpan(cipherLen, 16);
        using var cha = new ChaCha20Poly1305(key);
        var plaintext = new byte[cipherLen];
        cha.Decrypt(HapCrypto.PairingNonce(label), cipher, tag, plaintext);
        return plaintext;
    }
}

/// <summary>
/// A pair-verified HAP session: an encrypted duplex stream to the accessory plus ownership of
/// the underlying TCP socket. Dispose closes both.
/// </summary>
public sealed class HapVerifiedSession : IDisposable
{
    private readonly TcpClient _tcp;
    internal Stream Stream { get; }

    internal HapVerifiedSession(TcpClient tcp, Stream secureStream)
    {
        _tcp = tcp;
        Stream = secureStream;
    }

    public void Dispose()
    {
        Stream.Dispose();
        _tcp.Dispose();
    }
}
