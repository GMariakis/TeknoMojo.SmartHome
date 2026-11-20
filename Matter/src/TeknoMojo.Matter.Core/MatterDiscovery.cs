using System.Net;
using System.Net.Sockets;
using TeknoMojo.mDNS.Core.Configuration;
using TeknoMojo.mDNS.Core.ServiceDiscovery;

namespace TeknoMojo.Matter.Core;

/// <summary>
/// Browses the LAN for Matter nodes: operational (<c>_matter._tcp</c>, already commissioned
/// on some fabric) and commissionable (<c>_matterc._udp</c>, waiting to be onboarded).
/// Vendor-neutral; parses the standard Matter TXT keys into <see cref="MatterNode"/>.
/// </summary>
public sealed class MatterDiscovery
{
    /// <summary>Service type for operational (post-commissioning) Matter nodes over IP.</summary>
    public const string OperationalServiceType = "_matter._tcp.local";

    /// <summary>Service type for Matter nodes advertising an open commissioning window.</summary>
    public const string CommissioningServiceType = "_matterc._udp.local";

    /// <summary>
    /// Browse for Matter nodes and return distinct reachable candidates. Repeats the browse a
    /// few times for reliability (mDNS resolution rarely completes in a single short window).
    /// </summary>
    /// <param name="perTypeTimeout">Query window per service type per round.</param>
    /// <param name="filter">Optional case-insensitive substring narrowing on instance/host/TXT.</param>
    /// <param name="includeOperational">Browse <c>_matter._tcp</c> (commissioned nodes).</param>
    /// <param name="includeCommissioning">Browse <c>_matterc._udp</c> (nodes offering onboarding).</param>
    /// <param name="rounds">How many times to repeat the browse for reliability.</param>
    /// <param name="discoveryOptions">Optional mDNS options (e.g. restrict to specific interfaces).</param>
    public async Task<IReadOnlyList<MatterNode>> DiscoverAsync(
        TimeSpan perTypeTimeout,
        string? filter = null,
        bool includeOperational = true,
        bool includeCommissioning = true,
        int rounds = 4,
        DiscoveryOptions? discoveryOptions = null,
        CancellationToken ct = default)
    {
        var types = new List<string>();
        if (includeOperational) types.Add(OperationalServiceType);
        if (includeCommissioning) types.Add(CommissioningServiceType);
        if (types.Count == 0) return Array.Empty<MatterNode>();

        using var browser = discoveryOptions is null
            ? new ServiceBrowser()
            : new ServiceBrowser(discoveryOptions);
        await browser.StartAsync(ct);

        var byKey = new Dictionary<string, MatterNode>(StringComparer.OrdinalIgnoreCase);
        TimeSpan perCall = perTypeTimeout < TimeSpan.FromSeconds(2) ? perTypeTimeout : TimeSpan.FromSeconds(2);

        try
        {
            for (int round = 0; round < Math.Max(1, rounds) && !ct.IsCancellationRequested; round++)
            {
                foreach (string type in types)
                {
                    IEnumerable<ServiceInstance> found = await browser.BrowseAsync(type, perCall, ct);
                    foreach (ServiceInstance svc in found)
                    {
                        if (!Matches(svc, filter)) continue;
                        bool commissioning = string.Equals(svc.ServiceType, CommissioningServiceType, StringComparison.OrdinalIgnoreCase);
                        foreach (IPAddress addr in svc.Addresses)
                        {
                            // Both families are kept: Matter mandates IPv6 for operational
                            // communication, and plenty of accessories publish their operational
                            // records with AAAA records only. Discarding those made commissioned
                            // devices look absent entirely.
                            if (addr.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                                continue;

                            // A link-local address is meaningless without the interface it was
                            // heard on, and mDNS gives us no way to know which that was here.
                            if (addr.IsIPv6LinkLocal && addr.ScopeId == 0) continue;

                            // Key on (instance + address) so a device that answers on multiple
                            // interfaces still shows up once per unique reachable path.
                            string key = svc.InstanceName + "|" + addr;
                            byKey.TryAdd(key, new MatterNode(addr, svc.Port, svc.InstanceName, svc.HostName, svc.TxtRecords, commissioning));
                        }
                    }
                }
                if (filter is not null && byKey.Count > 0) break;
            }
        }
        finally
        {
            await browser.StopAsync();
        }
        return byKey.Values.ToList();
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
