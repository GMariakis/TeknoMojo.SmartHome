using System.Net;

namespace TeknoMojo.HomeKit.Core;

/// <summary>
/// A HomeKit Accessory Protocol (HAP) accessory discovered on the local network via DNS-SD
/// (<c>_hap._tcp</c>). Carries the resolved address plus the standard HAP TXT keys, so a caller can
/// identify an accessory without ever hard-coding an IP.
/// </summary>
public sealed record HapAccessory(
    IPAddress Address,
    int Port,
    string InstanceName,
    string ServiceType,
    string HostName,
    IReadOnlyDictionary<string, string> Txt)
{
    /// <summary>Stable accessory identifier (HAP TXT <c>id</c>, falling back to <c>sn</c>).</summary>
    public string? Id =>
        Txt.TryGetValue("id", out string? id) ? id
        : Txt.TryGetValue("sn", out string? sn) ? sn
        : null;

    /// <summary>Model label (HAP TXT <c>md</c>), e.g. "MSS110".</summary>
    public string? Model => Txt.TryGetValue("md", out string? md) ? md : null;

    /// <summary>Accessory category identifier (HAP TXT <c>ci</c>); 7 = Outlet, 8 = Switch.</summary>
    public int? Category => Txt.TryGetValue("ci", out string? ci) && int.TryParse(ci, out int v) ? v : null;

    /// <summary>Status flags (HAP TXT <c>sf</c>); bit 0 set means "not yet paired".</summary>
    public int? StatusFlags => Txt.TryGetValue("sf", out string? sf) && int.TryParse(sf, out int v) ? v : null;

    public override string ToString()
    {
        string id = Id is null ? "" : $" id={Id}";
        string model = Model is null ? "" : $" model={Model}";
        return $"{Address}  [{InstanceName} / {ServiceType}{model}{id}]";
    }
}
