using System.Globalization;
using TeknoMojo.Matter.Core;

// mtscan - enumerates Matter nodes on the LAN.
//
// Peer to hkscan (HAP). Later phases will add pair/read/invoke subcommands as the M2-M5
// milestones land; for now it's discovery-only.

var opts = Options.Parse(args);
if (opts.ShowHelp) { Options.PrintUsage(); return 0; }

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

Console.WriteLine("mtscan - scanning for Matter nodes...");
Console.WriteLine(
    $"  window={opts.Timeout.TotalSeconds:0.#}s/round  rounds={opts.Rounds}  " +
    $"types=" + (opts.Commissioning ? "operational+commissioning" : "operational-only") +
    (opts.Filter is null ? "" : $"  filter=\"{opts.Filter}\""));
Console.WriteLine();

var discovery = new MatterDiscovery();
IReadOnlyList<MatterNode> nodes;
try
{
    nodes = await discovery.DiscoverAsync(
        perTypeTimeout: opts.Timeout,
        filter: opts.Filter,
        includeOperational: true,
        includeCommissioning: opts.Commissioning,
        rounds: opts.Rounds,
        ct: cts.Token);
}
catch (OperationCanceledException) { Console.WriteLine("Cancelled."); return 130; }

var operational = nodes.Where(n => !n.IsCommissioning).OrderBy(n => n.InstanceName, StringComparer.OrdinalIgnoreCase).ToList();
var commissioning = nodes.Where(n => n.IsCommissioning).OrderBy(n => n.InstanceName, StringComparer.OrdinalIgnoreCase).ToList();

if (opts.Json) { JsonReport.Print(operational, commissioning); return nodes.Count == 0 ? 1 : 0; }

if (nodes.Count == 0)
{
    Console.WriteLine("No Matter nodes found.");
    Console.WriteLine("Tip: increase --timeout/--rounds, and make sure you're on the same subnet");
    Console.WriteLine("     as the devices (mDNS is link-local).");
    return 1;
}

if (operational.Count > 0)
{
    Console.WriteLine($"Operational nodes ({operational.Count}):");
    Console.WriteLine();
    int n = 0;
    foreach (var node in operational)
    {
        n++;
        Console.WriteLine($"[{n}] {node.InstanceName}");
        Console.WriteLine($"      Address    : {node.Address}:{node.Port}");
        Console.WriteLine($"      Host       : {node.HostName}");
        Console.WriteLine($"      Fabric     : {node.CompressedFabricId}");
        Console.WriteLine($"      Node       : {node.NodeId}");
        Console.WriteLine($"      Vendor     : {DescribeVendor(node.VendorId)}");
        Console.WriteLine($"      Product    : {node.ProductId?.ToString() ?? "(unknown)"}");
        if (opts.Verbose) PrintTxt(node);
        Console.WriteLine();
    }
}

if (commissioning.Count > 0)
{
    Console.WriteLine($"Commissionable nodes ({commissioning.Count}):");
    Console.WriteLine();
    int n = 0;
    foreach (var node in commissioning)
    {
        n++;
        int? cm = node.CommissioningMode;
        string cmDesc = cm switch
        {
            0 => "closed (advertised but not currently accepting)",
            1 => "OPEN (basic setup code)",
            2 => "OPEN (enhanced setup code)",
            _ => "(unknown)",
        };
        Console.WriteLine($"[{n}] {node.InstanceName}");
        Console.WriteLine($"      Address       : {node.Address}:{node.Port}");
        Console.WriteLine($"      Host          : {node.HostName}");
        Console.WriteLine($"      Vendor        : {DescribeVendor(node.VendorId)}");
        Console.WriteLine($"      Product       : {node.ProductId?.ToString() ?? "(unknown)"}");
        Console.WriteLine($"      Device Type   : {DescribeDeviceType(node.DeviceType)}");
        Console.WriteLine($"      Discriminator : {node.Discriminator?.ToString() ?? "(unknown)"}");
        Console.WriteLine($"      Window        : {cmDesc}");
        if (node.DeviceName is not null)
            Console.WriteLine($"      Name          : {node.DeviceName}");
        if (opts.Verbose) PrintTxt(node);
        Console.WriteLine();
    }
}

Console.WriteLine(new string('-', 60));
Console.WriteLine(
    $"Total: {operational.Count} operational, {commissioning.Count} commissionable.");
return 0;

static void PrintTxt(MatterNode n)
{
    if (n.Txt.Count == 0) return;
    Console.WriteLine("      TXT           :");
    foreach (var kv in n.Txt.OrderBy(k => k.Key, StringComparer.Ordinal))
        Console.WriteLine($"                      {kv.Key} = {kv.Value}");
}

static string DescribeVendor(int? id)
{
    if (id is null) return "(unknown)";
    string? name = id switch
    {
        4933 => "Meross",
        4444 => "Apple",
        4874 => "Google",
        4448 => "Amazon",
        4362 => "IKEA",
        4631 => "Nanoleaf",
        4107 => "Signify (Philips Hue)",
        _ => null,
    };
    return name is null ? $"{id}" : $"{name} ({id})";
}

static string DescribeDeviceType(int? id)
{
    if (id is null) return "(unknown)";
    string? name = id switch
    {
        22 => "Root Node",
        256 => "On/Off Light",
        257 => "Dimmable Light",
        266 => "On/Off Plug-in Unit",
        267 => "Dimmable Plug-in Unit",
        268 => "Color Temperature Light",
        269 => "Extended Color Light",
        770 => "Temperature Sensor",
        774 => "Humidity Sensor",
        _ => null,
    };
    return name is null ? $"{id}" : $"{name} ({id})";
}

// -------- helpers --------

internal static class JsonReport
{
    public static void Print(IReadOnlyList<MatterNode> operational, IReadOnlyList<MatterNode> commissioning)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
        {
            operational = operational.Select(n => new
            {
                instanceName = n.InstanceName,
                address = n.Address.ToString(),
                port = n.Port,
                host = n.HostName,
                fabric = n.CompressedFabricId,
                node = n.NodeId,
                vendor = n.VendorId,
                product = n.ProductId,
                txt = n.Txt,
            }),
            commissionable = commissioning.Select(n => new
            {
                instanceName = n.InstanceName,
                address = n.Address.ToString(),
                port = n.Port,
                host = n.HostName,
                vendor = n.VendorId,
                product = n.ProductId,
                deviceType = n.DeviceType,
                discriminator = n.Discriminator,
                commissioningMode = n.CommissioningMode,
                deviceName = n.DeviceName,
                txt = n.Txt,
            }),
        }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
}

internal sealed class Options
{
    public TimeSpan Timeout { get; private set; } = TimeSpan.FromSeconds(2);
    public int Rounds { get; private set; } = 5;
    public string? Filter { get; private set; }
    public bool Verbose { get; private set; }
    public bool Json { get; private set; }
    public bool Commissioning { get; private set; } = true;
    public bool ShowHelp { get; private set; }

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h" or "--help": o.ShowHelp = true; break;
                case "-v" or "--verbose": o.Verbose = true; break;
                case "--json": o.Json = true; break;
                case "--operational-only": o.Commissioning = false; break;
                case "-f" or "--filter" when i + 1 < args.Length: o.Filter = args[++i]; break;
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
            mtscan - enumerate Matter nodes on the LAN.

            Usage:
              mtscan [filter] [options]

            Options:
              -f, --filter <text>    Only show nodes whose name/host/TXT contains <text>.
              -t, --timeout <secs>   Browse window per round (default 2).
              -r, --rounds <n>       Number of browse rounds (default 5).
                  --operational-only Skip _matterc._udp (commissionable) browse.
              -v, --verbose          Also print every TXT record for each node.
                  --json             Emit results as JSON.
              -h, --help             Show this help.
            """);
    }
}
