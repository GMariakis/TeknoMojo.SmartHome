using TeknoMojo.HomeKit.Core;

namespace TeknoMojo.HomeKit.Meross;

/// <summary>
/// Locates Meross accessories on the LAN via mDNS, so control keys on device identity rather than a
/// hard-coded IP. A thin Meross-specific wrapper over the generic <see cref="HapDiscovery"/>: Meross
/// devices advertise HAP, and some also advertise <c>_meross._tcp</c>.
/// </summary>
public sealed class MerossDiscovery
{
    private readonly HapDiscovery _hap = new();

    /// <summary>Service types Meross devices are known to advertise.</summary>
    public static readonly string[] ServiceTypes =
    {
        HapDiscovery.HapServiceType,   // _hap._tcp.local
        "_meross._tcp.local",
        "_http._tcp.local",
    };

    /// <summary>
    /// Browse for Meross accessories. Optionally filter by a case-insensitive substring matching the
    /// instance name, host, or a TXT value (e.g. a model like "MSS110" or a known device id).
    /// </summary>
    public Task<IReadOnlyList<HapAccessory>> DiscoverAsync(
        TimeSpan perTypeTimeout, string? filter = null, int rounds = 4, CancellationToken ct = default) =>
        _hap.DiscoverAsync(perTypeTimeout, filter, ServiceTypes, rounds, ct: ct);
}
