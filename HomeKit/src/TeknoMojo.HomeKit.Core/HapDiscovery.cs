using System.Net;
using System.Net.Sockets;
using TeknoMojo.mDNS.Core.Configuration;
using TeknoMojo.mDNS.Core.ServiceDiscovery;

namespace TeknoMojo.HomeKit.Core;

/// <summary>
/// Discovers HomeKit (HAP) accessories on the local network via DNS-SD, so callers resolve devices
/// by identity rather than a hard-coded IP. Generic to any HAP accessory; not tied to any vendor.
/// </summary>
public sealed class HapDiscovery
{
    /// <summary>The standard HomeKit service type.</summary>
    public const string HapServiceType = "_hap._tcp.local";

    /// <summary>
    /// Browse for accessories and return distinct reachable candidates. Optionally filter by a
    /// substring that must appear in the instance name, host, or a TXT value (e.g. a model like
    /// "MSS110" or a known accessory id).
    /// </summary>
    /// <remarks>
    /// mDNS resolution (PTR then SRV/A) rarely completes inside a single short window, so a lone
    /// browse is unreliable — it can come back empty even when the device is present. We run several
    /// rounds against an overall deadline, letting the browser's cache of fully-resolved records
    /// accumulate, and return early once a filtered match appears.
    /// </remarks>
    /// <param name="perTypeTimeout">Query window per service type per round.</param>
    /// <param name="filter">Optional case-insensitive substring to narrow results.</param>
    /// <param name="serviceTypes">Service types to browse; defaults to <see cref="HapServiceType"/>.</param>
    /// <param name="rounds">How many times to repeat the browse for reliability.</param>
    /// <param name="discoveryOptions">
    /// Optional mDNS options, chiefly to narrow which network interfaces are used
    /// (<see cref="DiscoveryOptions.NetworkInterfaceIndices"/> /
    /// <see cref="DiscoveryOptions.NetworkInterfaceFilter"/>). When <c>null</c>, all eligible
    /// interfaces are queried — the reliable default on multi-homed hosts.
    /// </param>
    public async Task<IReadOnlyList<HapAccessory>> DiscoverAsync(
        TimeSpan perTypeTimeout,
        string? filter = null,
        IReadOnlyList<string>? serviceTypes = null,
        int rounds = 4,
        DiscoveryOptions? discoveryOptions = null,
        CancellationToken ct = default)
    {
        serviceTypes ??= new[] { HapServiceType };

        using var browser = discoveryOptions is null
            ? new ServiceBrowser()
            : new ServiceBrowser(discoveryOptions);
        await browser.StartAsync(ct);

        var byAddress = new Dictionary<IPAddress, HapAccessory>();
        // Keep each query window short; reliability comes from repeating, not from one long wait.
        TimeSpan perCall = perTypeTimeout < TimeSpan.FromSeconds(2) ? perTypeTimeout : TimeSpan.FromSeconds(2);

        try
        {
            for (int round = 0; round < Math.Max(1, rounds) && !ct.IsCancellationRequested; round++)
            {
                foreach (string type in serviceTypes)
                {
                    IEnumerable<ServiceInstance> found = await browser.BrowseAsync(type, perCall, ct);
                    foreach (ServiceInstance svc in found)
                    {
                        if (!Matches(svc, filter)) continue;
                        foreach (IPAddress addr in svc.Addresses)
                        {
                            if (addr.AddressFamily != AddressFamily.InterNetwork)
                                continue; // IPv4 only
                            byAddress.TryAdd(addr, new HapAccessory(addr, svc.Port, svc.InstanceName, svc.ServiceType, svc.HostName, svc.TxtRecords));
                        }
                    }
                }
                // With a filter we expect a single device — stop as soon as it resolves.
                if (filter is not null && byAddress.Count > 0) break;
            }
        }
        finally
        {
            await browser.StopAsync();
        }
        return byAddress.Values.ToList();
    }

    private static bool Matches(ServiceInstance svc, string? filter)
    {
        if (string.IsNullOrEmpty(filter)) return true;
        if (svc.InstanceName.Contains(filter, StringComparison.OrdinalIgnoreCase)) return true;
        if (svc.HostName.Contains(filter, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (KeyValuePair<string, string> kv in svc.TxtRecords)
        {
            if (kv.Key.Contains(filter, StringComparison.OrdinalIgnoreCase)) return true;
            if (kv.Value.Contains(filter, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
