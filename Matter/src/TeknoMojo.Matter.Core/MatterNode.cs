using System.Net;

namespace TeknoMojo.Matter.Core;

/// <summary>
/// A Matter node discovered on the local network. Covers both operational nodes
/// (<c>_matter._tcp</c>, already commissioned onto some fabric) and commissionable
/// candidates (<c>_matterc._udp</c>, waiting to be onboarded). The
/// <see cref="IsCommissioning"/> flag distinguishes the two.
/// </summary>
public sealed record MatterNode(
    IPAddress Address,
    int Port,
    string InstanceName,
    string HostName,
    IReadOnlyDictionary<string, string> Txt,
    bool IsCommissioning)
{
    /// <summary>
    /// Compressed fabric identifier this node is operational on (first half of the operational
    /// instance name, e.g. <c>FB4B304B6166B4F9</c> for <c>FB4B…-000000001E205019</c>).
    /// Null for commissionable nodes (they aren't on a fabric yet).
    /// </summary>
    public string? CompressedFabricId =>
        IsCommissioning ? null
        : SplitOperationalName(InstanceName).fabric;

    /// <summary>
    /// Operational node id (second half of the operational instance name). Null while commissioning.
    /// </summary>
    public string? NodeId =>
        IsCommissioning ? null
        : SplitOperationalName(InstanceName).node;

    /// <summary>
    /// Vendor ID from the Matter TXT <c>VP</c> record (format <c>vendor+product</c>, decimal).
    /// 4933 = Meross Technology, 4444 = Apple, 4874 = Google, 4448 = Amazon, etc.
    /// </summary>
    public int? VendorId => ParseVp().vendor;

    /// <summary>Product ID from TXT <c>VP</c> — vendor-specific model identifier.</summary>
    public int? ProductId => ParseVp().product;

    /// <summary>
    /// Matter Device Type from TXT <c>DT</c> (commissioning entries only, per spec §4.3.1.3).
    /// 266 = On/Off Plug-in Unit, 268 = Dimmable Plug-in Unit, 256 = On/Off Light, etc.
    /// </summary>
    public int? DeviceType =>
        Txt.TryGetValue("DT", out string? v) && int.TryParse(v, out int i) ? i : null;

    /// <summary>Commissioning discriminator (TXT <c>D</c>) — used to target a specific device during onboarding.</summary>
    public int? Discriminator =>
        Txt.TryGetValue("D", out string? v) && int.TryParse(v, out int i) ? i : null;

    /// <summary>
    /// Commissioning-window mode (TXT <c>CM</c>): 0 = closed, 1 = open with the original passcode
    /// (basic commissioning), 2 = open with an enhanced setup code. Only meaningful for
    /// <see cref="IsCommissioning"/> nodes.
    /// </summary>
    public int? CommissioningMode =>
        Txt.TryGetValue("CM", out string? v) && int.TryParse(v, out int i) ? i : null;

    /// <summary>Human-readable device name if the accessory chose to advertise one (TXT <c>DN</c>).</summary>
    public string? DeviceName =>
        Txt.TryGetValue("DN", out string? v) ? v : null;

    private (int? vendor, int? product) ParseVp()
    {
        if (!Txt.TryGetValue("VP", out string? vp)) return (null, null);
        int plus = vp.IndexOf('+');
        if (plus < 0)
            return (int.TryParse(vp, out int v1) ? v1 : null, null);
        return (
            int.TryParse(vp.AsSpan(0, plus), out int v) ? v : null,
            int.TryParse(vp.AsSpan(plus + 1), out int p) ? p : null);
    }

    private static (string? fabric, string? node) SplitOperationalName(string instance)
    {
        int dash = instance.IndexOf('-');
        return dash <= 0 ? (null, null) : (instance[..dash], instance[(dash + 1)..]);
    }

    public override string ToString() =>
        IsCommissioning
            ? $"[commissioning] {InstanceName}  {Address}:{Port}  vendor={VendorId} product={ProductId} type={DeviceType} D={Discriminator} CM={CommissioningMode}"
            : $"{Address}:{Port}  fabric={CompressedFabricId} node={NodeId} vendor={VendorId} product={ProductId}";
}
