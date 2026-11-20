using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using TeknoMojo.HomeKit.Core;
using TeknoMojo.HomeKit.Hap;
using TeknoMojo.Matter.Core;
using TeknoMojo.mDNS.Core.Configuration;

// hkscan - a POC that enumerates HomeKit Accessory Protocol (HAP) devices and, once P1 lands,
// pairs with them and dumps their characteristic database. Also scans for Matter devices via
// TeknoMojo.Matter.Core, consumed here as a real NuGet package from the local feed.
//
// Commands:
//   hkscan [scan]       Browse mDNS and list HAP accessories (default).
//   hkscan pair FILTER CODE
//                       Pair with the single accessory matched by FILTER using its 8-digit
//                       setup code (dashes optional).
//   hkscan dump FILTER  Pair-verify with an already-paired accessory and print its
//                       /accessories JSON.
//   hkscan matter       Browse mDNS for Matter (operational + commissionable) nodes.

var (command, rest) = SplitCommand(args);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

return command switch
{
    "scan" or "" => await RunScanAsync(rest, cts.Token),
    "pair" => await RunPairAsync(rest, cts.Token),
    "dump" => await RunDumpAsync(rest, cts.Token),
    "matter" => await RunMatterScanAsync(rest, cts.Token),
    "help" or "-h" or "--help" => PrintTopUsage(),
    _ => Unknown(command),
};

static (string cmd, string[] rest) SplitCommand(string[] args)
{
    if (args.Length == 0) return ("", args);
    string first = args[0];
    return first is "scan" or "pair" or "dump" or "matter" or "help" or "-h" or "--help"
        ? (first, args.Skip(1).ToArray())
        : ("", args);
}

// -------------------- matter --------------------

static async Task<int> RunMatterScanAsync(string[] args, CancellationToken ct)
{
    string? filter = args.Length > 0 ? args[0] : null;
    Console.WriteLine("hkscan matter - scanning for Matter nodes (via TeknoMojo.Matter.Core)...");

    var discovery = new MatterDiscovery();
    var nodes = await discovery.DiscoverAsync(perTypeTimeout: TimeSpan.FromSeconds(3), filter: filter, rounds: 8, ct: ct);

    var operational = nodes.Where(n => !n.IsCommissioning).ToList();
    var commissionable = nodes.Where(n => n.IsCommissioning).ToList();

    if (nodes.Count == 0)
    {
        Console.WriteLine("No Matter nodes found.");
        return 1;
    }

    foreach (var n in operational)
        Console.WriteLine($"[operational]   {n.InstanceName}  {n.Address}:{n.Port}  vendor={n.VendorId} product={n.ProductId} fabric={n.CompressedFabricId} node={n.NodeId}");
    foreach (var n in commissionable)
        Console.WriteLine($"[commissionable] {n.InstanceName}  {n.Address}:{n.Port}  vendor={n.VendorId} product={n.ProductId} deviceType={n.DeviceType}");

    Console.WriteLine($"Total: {operational.Count} operational, {commissionable.Count} commissionable.");
    return 0;
}

static int Unknown(string cmd)
{
    Console.Error.WriteLine($"Unknown command: {cmd}");
    PrintTopUsage();
    return 2;
}

static int PrintTopUsage()
{
    Console.WriteLine("""
        hkscan - HomeKit (HAP) discovery and control POC.

        Commands:
          scan  [options]              (default) enumerate _hap._tcp accessories.
          pair  <filter> <8-digit-code> pair with the matching accessory (persists a HapPairing).
          dump  <filter>               open an encrypted session and print /accessories JSON.
          help                         show this help.

        Run "hkscan scan --help" for scan options.
        """);
    return 0;
}

// -------------------- scan --------------------

static async Task<int> RunScanAsync(string[] args, CancellationToken ct)
{
    var opts = ScanOptions.Parse(args);
    if (opts.ShowHelp) { ScanOptions.PrintUsage(); return 0; }

    Console.WriteLine($"hkscan - scanning for HomeKit (_hap._tcp) accessories...");
    Console.WriteLine(
        $"  window={opts.Timeout.TotalSeconds:0.#}s/round  rounds={opts.Rounds}" +
        (opts.Filter is null ? "" : $"  filter=\"{opts.Filter}\"") +
        (opts.Interface is null ? "" : $"  interface=\"{opts.Interface}\""));
    Console.WriteLine();

    var discoveryOpts = BuildDiscoveryOptions(opts.Interface);
    var devices = await new HapDiscovery().DiscoverAsync(
        perTypeTimeout: opts.Timeout,
        filter: opts.Filter,
        rounds: opts.Rounds,
        discoveryOptions: discoveryOpts,
        ct: ct);

    var ordered = devices.OrderBy(d => d.InstanceName, StringComparer.OrdinalIgnoreCase).ToList();

    if (opts.Json) { JsonReport.Print(ordered); return ordered.Count == 0 ? 1 : 0; }
    if (ordered.Count == 0) { PrintEmptyScanTip(); return 1; }

    Console.WriteLine($"Found {ordered.Count} accessory(ies):");
    Console.WriteLine();

    int n = 0;
    foreach (var d in ordered)
    {
        n++;
        Console.WriteLine($"[{n}] {d.InstanceName}");
        Console.WriteLine($"      Address : {d.Address}:{d.Port}");
        Console.WriteLine($"      Host    : {d.HostName}");
        Console.WriteLine($"      Model   : {d.Model ?? "(unknown)"}");
        Console.WriteLine($"      Category: {HapCategories.Describe(d.Category)}");
        Console.WriteLine($"      Paired  : " + (d.StatusFlags is int sf ? ((sf & 1) != 0 ? "no (available to pair)" : "yes") : "unknown"));
        Console.WriteLine($"      Id      : {d.Id ?? "(none)"}");

        if (opts.Verbose && d.Txt.Count > 0)
        {
            Console.WriteLine("      TXT     :");
            foreach (var kv in d.Txt.OrderBy(k => k.Key, StringComparer.Ordinal))
                Console.WriteLine($"                {kv.Key} = {kv.Value}");
        }
        Console.WriteLine();
    }

    Console.WriteLine(new string('-', 60));
    Console.WriteLine("Categories seen: " + string.Join(", ",
        ordered.GroupBy(d => HapCategories.Describe(d.Category))
               .OrderByDescending(g => g.Count()).Select(g => $"{g.Key} x{g.Count()}")));
    return 0;
}

static void PrintEmptyScanTip()
{
    Console.WriteLine("No HAP accessories found.");
    Console.WriteLine("Tip: increase the window with --timeout 3 --rounds 8, and make sure");
    Console.WriteLine("     this machine is on the same subnet/VLAN as the devices (mDNS is link-local).");
}

// -------------------- pair --------------------

static async Task<int> RunPairAsync(string[] args, CancellationToken ct)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Usage: hkscan pair <filter> <8-digit-code>");
        return 2;
    }
    string filter = args[0];
    string code = args[1];

    var accessory = await FindOneAsync(filter, ct);
    if (accessory is null) return 1;

    if (accessory.StatusFlags is int sf && (sf & 1) == 0)
    {
        Console.Error.WriteLine($"Accessory {accessory.InstanceName} reports it is ALREADY PAIRED (sf=0).");
        Console.Error.WriteLine("Pair-setup will fail unless the accessory is factory-reset or removed from its current controller.");
        return 3;
    }

    Console.WriteLine($"Pairing with {accessory.InstanceName} at {accessory.Address}:{accessory.Port}...");
    var controller = new HapController();
    HapPairing pairing;
    try
    {
        pairing = await controller.PairAsync(accessory, code, ct);
    }
    catch (HapAuthenticationException ex) { Console.Error.WriteLine("Auth failed: " + ex.Message); return 4; }
    catch (HapProtocolException ex) { Console.Error.WriteLine("Protocol error: " + ex.Message); return 5; }

    Console.WriteLine($"Paired. Accessory id: {pairing.AccessoryId}");
    Console.WriteLine($"        Controller id: {pairing.ControllerId}");
    Console.WriteLine("Pairing saved to the local store.");
    return 0;
}

// -------------------- dump --------------------

static async Task<int> RunDumpAsync(string[] args, CancellationToken ct)
{
    if (args.Length < 1)
    {
        Console.Error.WriteLine("Usage: hkscan dump <filter>");
        return 2;
    }
    string filter = args[0];

    var accessory = await FindOneAsync(filter, ct);
    if (accessory is null) return 1;

    var controller = new HapController();
    try
    {
        using var session = await controller.ConnectAsync(accessory, ct);
        string json = await session.GetAccessoriesAsync(ct);
        Console.WriteLine(json);
        return 0;
    }
    catch (InvalidOperationException ex) { Console.Error.WriteLine(ex.Message); return 3; }
    catch (HapAuthenticationException ex) { Console.Error.WriteLine("Auth failed: " + ex.Message); return 4; }
    catch (HapProtocolException ex) { Console.Error.WriteLine("Protocol error: " + ex.Message); return 5; }
}

// -------------------- helpers --------------------

static async Task<HapAccessory?> FindOneAsync(string filter, CancellationToken ct)
{
    Console.Error.WriteLine($"Discovering \"{filter}\"...");
    var discovery = new HapDiscovery();
    var found = await discovery.DiscoverAsync(
        perTypeTimeout: TimeSpan.FromSeconds(2),
        filter: filter,
        rounds: 6,
        ct: ct);
    if (found.Count == 0) { Console.Error.WriteLine("No accessory matched."); return null; }
    if (found.Count > 1)
    {
        Console.Error.WriteLine($"Filter matched {found.Count} accessories; narrow it down:");
        foreach (var f in found) Console.Error.WriteLine($"  {f.InstanceName}  {f.Address}:{f.Port}  id={f.Id}");
        return null;
    }
    return found[0];
}

static DiscoveryOptions? BuildDiscoveryOptions(string? wanted)
{
    if (wanted is null) return null;
    return new DiscoveryOptions
    {
        NetworkInterfaceFilter = ni =>
            ni.Name.Contains(wanted, StringComparison.OrdinalIgnoreCase)
            || ni.GetIPProperties().UnicastAddresses.Any(a =>
                a.Address.AddressFamily == AddressFamily.InterNetwork
                && a.Address.ToString() == wanted),
    };
}

// -------------------- support types --------------------

internal static class HapCategories
{
    private static readonly Dictionary<int, string> Names = new()
    {
        [1] = "Other", [2] = "Bridge", [3] = "Fan", [4] = "Garage Door Opener", [5] = "Lighting",
        [6] = "Lock", [7] = "Outlet", [8] = "Switch", [9] = "Thermostat", [10] = "Sensor",
        [11] = "Security System", [12] = "Door", [13] = "Window", [14] = "Window Covering",
        [15] = "Programmable Switch", [16] = "Range Extender", [17] = "IP Camera",
        [18] = "Video Doorbell", [19] = "Air Purifier", [20] = "Heater", [21] = "Air Conditioner",
        [22] = "Humidifier", [23] = "Dehumidifier", [26] = "Speaker", [27] = "Sprinkler",
        [28] = "Faucet", [29] = "Shower System", [30] = "Television", [31] = "Target Controller",
        [32] = "Router", [33] = "Audio Receiver", [34] = "TV Set-Top Box", [35] = "TV Streaming Stick",
    };
    public static string Describe(int? ci) =>
        ci is null ? "(unknown)"
        : Names.TryGetValue(ci.Value, out var name) ? $"{name} ({ci})"
        : $"Unknown ({ci})";
}

internal static class JsonReport
{
    public static void Print(IReadOnlyList<HapAccessory> devices)
    {
        var items = devices.Select(d => new
        {
            instanceName = d.InstanceName,
            address = d.Address.ToString(),
            port = d.Port,
            host = d.HostName,
            model = d.Model,
            category = d.Category,
            categoryName = HapCategories.Describe(d.Category),
            id = d.Id,
            statusFlags = d.StatusFlags,
            paired = d.StatusFlags is int sf ? (sf & 1) == 0 : (bool?)null,
            txt = d.Txt,
        });
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(
            items, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
}

internal sealed class ScanOptions
{
    public TimeSpan Timeout { get; private set; } = TimeSpan.FromSeconds(2);
    public int Rounds { get; private set; } = 5;
    public string? Filter { get; private set; }
    public string? Interface { get; private set; }
    public bool Verbose { get; private set; }
    public bool Json { get; private set; }
    public bool ShowHelp { get; private set; }

    public static ScanOptions Parse(string[] args)
    {
        var o = new ScanOptions();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help": o.ShowHelp = true; break;
                case "-v" or "--verbose": o.Verbose = true; break;
                case "--json": o.Json = true; break;
                case "-f" or "--filter" when i + 1 < args.Length: o.Filter = args[++i]; break;
                case "-i" or "--interface" when i + 1 < args.Length: o.Interface = args[++i]; break;
                case "-t" or "--timeout" when i + 1 < args.Length:
                    if (double.TryParse(args[++i], CultureInfo.InvariantCulture, out double secs) && secs > 0)
                        o.Timeout = TimeSpan.FromSeconds(secs);
                    break;
                case "-r" or "--rounds" when i + 1 < args.Length:
                    if (int.TryParse(args[++i], out int r) && r > 0) o.Rounds = r;
                    break;
                default:
                    if (!args[i].StartsWith('-') && o.Filter is null) o.Filter = args[i];
                    break;
            }
        }
        return o;
    }

    public static void PrintUsage()
    {
        Console.WriteLine("""
            hkscan scan - enumerate HomeKit (_hap._tcp) accessories.

            Usage:
              hkscan scan [filter] [options]

            Options:
              -f, --filter <text>   Only show accessories whose name/host/TXT contains <text>
                                    (a bare argument is treated as a filter).
              -i, --interface <x>   Restrict scanning to one NIC by name or IPv4 address
                                    (default: all interfaces).
              -t, --timeout <secs>  Browse window per round (default 2).
              -r, --rounds <n>      Number of browse rounds (default 5).
              -v, --verbose         Also print every TXT record for each accessory.
                  --json            Emit results as JSON.
              -h, --help            Show this help.
            """);
    }
}
