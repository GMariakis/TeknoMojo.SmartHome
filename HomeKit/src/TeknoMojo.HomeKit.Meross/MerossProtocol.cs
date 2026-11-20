using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TeknoMojo.HomeKit.Meross;

/// <summary>
/// Meross local LAN control protocol — envelope construction, MD5 signing, and a pluggable
/// transport. Everything here is transport-agnostic so an MQTT transport can be dropped in
/// later without touching the message layer (see plan Phase 6.4 / Appendix B).
/// </summary>
public interface IMerossTransport
{
    /// <summary>Send one fully-built envelope JSON and return the raw response JSON.</summary>
    Task<string> SendAsync(string envelopeJson, CancellationToken ct = default);
}

/// <summary>Well-known Meross namespaces used by this POC.</summary>
public static class MerossNamespace
{
    public const string SystemAll   = "Appliance.System.All";
    public const string ToggleX     = "Appliance.Control.ToggleX";
    public const string DndMode     = "Appliance.System.DNDMode";
    public const string ConfigKey   = "Appliance.Config.Key";
    public const string ConfigWifi  = "Appliance.Config.Wifi";
    public const string WifiList    = "Appliance.Config.WifiList";
}

/// <summary>Builds and signs Meross message envelopes and interprets responses.</summary>
public sealed class MerossClient
{
    private readonly IMerossTransport _transport;
    private readonly string _key;
    private readonly string _from;

    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true };

    /// <param name="key">
    /// Device signing key. Empty string is valid and expected when talking to a factory-reset
    /// device in AP mode — such a device does not validate the signature at all.
    /// </param>
    public MerossClient(IMerossTransport transport, string key = "", string from = "/app/0")
    {
        _transport = transport;
        _key = key ?? string.Empty;
        _from = from;
    }

    /// <summary>sign = md5(messageId + key + timestamp), hex, lowercase.</summary>
    public static string ComputeSign(string messageId, string key, long timestamp) =>
        Convert.ToHexString(
            MD5.HashData(Encoding.UTF8.GetBytes(messageId + key + timestamp)))
        .ToLowerInvariant();

    public static string NewMessageId() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    /// <summary>Build a signed envelope for the given method/namespace/payload.</summary>
    public string BuildEnvelope(string method, string @namespace, JsonObject payload, out string messageId) =>
        BuildEnvelope(_key, _from, method, @namespace, payload, out messageId);

    public string BuildEnvelope(string method, string @namespace, JsonObject payload) =>
        BuildEnvelope(method, @namespace, payload, out _);

    /// <summary>Transport-independent signed-envelope builder (used for the MQTT path).</summary>
    public static string BuildEnvelope(string key, string from, string method, string @namespace, JsonObject payload, out string messageId)
    {
        messageId = NewMessageId();
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string sign = ComputeSign(messageId, key, timestamp);

        var envelope = new JsonObject
        {
            ["header"] = new JsonObject
            {
                ["from"] = from,
                ["messageId"] = messageId,
                ["method"] = method,
                ["namespace"] = @namespace,
                ["payloadVersion"] = 1,
                ["sign"] = sign,
                ["timestamp"] = timestamp,
                ["timestampMs"] = 0,
            },
            // Clone so the caller's payload node is never parented — it may be reused across
            // attempts (e.g. MerossOutlet's plaintext-then-encrypted fallback builds two envelopes
            // from the same payload). A JsonNode can only have one parent.
            ["payload"] = payload.DeepClone(),
        };
        return envelope.ToJsonString();
    }

    /// <summary>Invoke a command and return the parsed response document.</summary>
    public async Task<JsonNode> InvokeAsync(string method, string @namespace, JsonObject? payload = null, CancellationToken ct = default)
    {
        string request = BuildEnvelope(method, @namespace, payload ?? new JsonObject());
        string response = await _transport.SendAsync(request, ct);

        JsonNode root = JsonNode.Parse(response)
            ?? throw new MerossException("Empty response from device.");

        // Meross reports errors as an ApiStatus payload with a non-zero code (e.g. 5001 = sign error).
        JsonNode? apiStatus = root["payload"]?["error"];
        if (apiStatus is not null)
        {
            int code = apiStatus["code"]?.GetValue<int>() ?? -1;
            string detail = apiStatus["detail"]?.GetValueKind() == JsonValueKind.String
                ? apiStatus["detail"]!.GetValue<string>() : apiStatus.ToJsonString();
            throw new MerossException($"Device returned error {code}: {detail}", code);
        }
        return root;
    }

    public Task<JsonNode> SystemAllAsync(CancellationToken ct = default) =>
        InvokeAsync("GET", MerossNamespace.SystemAll, ct: ct);

    public Task<JsonNode> ToggleAsync(int channel, bool on, CancellationToken ct = default) =>
        InvokeAsync("SET", MerossNamespace.ToggleX, new JsonObject
        {
            ["togglex"] = new JsonObject { ["channel"] = channel, ["onoff"] = on ? 1 : 0 },
        }, ct);

    public Task<JsonNode> SetKeyAsync(string key, string? mqttServerHost = null, int mqttServerPort = 8883, CancellationToken ct = default)
    {
        var cfgKey = new JsonObject { ["key"] = key };
        if (mqttServerHost is not null)
        {
            cfgKey["gateway"] = new JsonObject
            {
                ["host"] = mqttServerHost,
                ["port"] = mqttServerPort,
                ["secondHost"] = mqttServerHost,
                ["secondPort"] = mqttServerPort,
            };
        }
        return InvokeAsync("SET", MerossNamespace.ConfigKey, new JsonObject { ["key"] = cfgKey }, ct);
    }

    public Task<JsonNode> SetWifiAsync(string ssidBase64, string passwordBase64, CancellationToken ct = default) =>
        InvokeAsync("SET", MerossNamespace.ConfigWifi, new JsonObject
        {
            ["wifi"] = new JsonObject { ["ssid"] = ssidBase64, ["password"] = passwordBase64 },
        }, ct);

    /// <summary>Read the current on/off state of a channel from a System.All response.</summary>
    public static bool? ReadToggleState(JsonNode systemAll, int channel = 0)
    {
        // digest.togglex is the array on multi-channel + HomeKit firmware; control.toggle{x} on older.
        JsonArray? togglex = systemAll["payload"]?["all"]?["digest"]?["togglex"]?.AsArray();
        if (togglex is not null)
        {
            foreach (JsonNode? item in togglex)
            {
                if (item?["channel"]?.GetValue<int>() == channel)
                    return item["onoff"]?.GetValue<int>() == 1;
            }
        }
        JsonNode? legacy = systemAll["payload"]?["all"]?["control"]?["toggle"];
        if (legacy is not null)
            return legacy["onoff"]?.GetValue<int>() == 1;
        return null;
    }

    /// <summary>
    /// Read the indicator-LED state from a DNDMode response. Meross couples the status LED to
    /// "do not disturb / night mode": <c>mode:0</c> = LED lit, <c>mode:1</c> = LED off. So the
    /// LED is on exactly when DND is off.
    /// </summary>
    public static bool? ReadLedOn(JsonNode dndResponse)
    {
        int? mode = dndResponse["payload"]?["DNDMode"]?["mode"]?.GetValue<int>();
        return mode is null ? null : mode == 0;
    }

    public static string Pretty(JsonNode node) => node.ToJsonString(PrettyJson);
}

public sealed class MerossException : Exception
{
    public int Code { get; }
    public MerossException(string message, int code = 0) : base(message) => Code = code;
}
