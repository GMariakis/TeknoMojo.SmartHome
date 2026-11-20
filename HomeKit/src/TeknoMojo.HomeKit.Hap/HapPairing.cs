using System.Text.Json.Serialization;

namespace TeknoMojo.HomeKit.Hap;

/// <summary>
/// The long-term state left behind after a successful pair-setup: the controller's identity
/// keys plus the accessory's identity that we're allowed to talk to. This is what you need to
/// re-establish an encrypted session with pair-verify later — losing it means re-pairing.
/// </summary>
public sealed record HapPairing
{
    /// <summary>The accessory's HAP identifier (from mDNS TXT <c>id</c>), e.g. "1B:9E:09:03:16:CD".</summary>
    [JsonPropertyName("accessoryId")]
    public required string AccessoryId { get; init; }

    /// <summary>The accessory's Ed25519 long-term public key (32 bytes).</summary>
    [JsonPropertyName("accessoryLtpk")]
    public required byte[] AccessoryLtpk { get; init; }

    /// <summary>
    /// The controller identifier this pairing is registered under, a random UUID-derived
    /// string; the accessory stores this alongside our LTPK on its side.
    /// </summary>
    [JsonPropertyName("controllerId")]
    public required string ControllerId { get; init; }

    /// <summary>The controller's Ed25519 long-term public key (32 bytes).</summary>
    [JsonPropertyName("controllerLtpk")]
    public required byte[] ControllerLtpk { get; init; }

    /// <summary>The controller's Ed25519 long-term private key seed (32 bytes) — SENSITIVE.</summary>
    [JsonPropertyName("controllerLtsk")]
    public required byte[] ControllerLtsk { get; init; }
}
