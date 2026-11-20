using System.Text;
using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>
/// Typed helper for the Network Commissioning cluster (0x0031) — endpoint 0 only. Used during
/// initial commissioning of a device that has never been connected to Wi-Fi: push the SSID and
/// passphrase, then connect. Not needed for a device that already has network credentials
/// (e.g. an existing admin's second-controller "share" flow, or an Ethernet device).
/// </summary>
public sealed class NetworkCommissioningCluster
{
    private readonly MatterInteractionClient _client;
    private const uint Endpoint = 0;

    public NetworkCommissioningCluster(MatterInteractionClient client) => _client = client;

    /// <summary>Add (or update) a Wi-Fi network's credentials on the device.</summary>
    public async Task<NetworkCommissioningStatus> AddOrUpdateWiFiNetworkAsync(
        string ssid, string passphrase, ulong breadcrumb, CancellationToken ct = default)
    {
        byte[] ssidBytes = Encoding.UTF8.GetBytes(ssid);
        byte[] credBytes = Encoding.UTF8.GetBytes(passphrase);
        if (ssidBytes.Length > 32) throw new ArgumentException("SSID must be at most 32 bytes.", nameof(ssid));
        if (credBytes.Length > 64) throw new ArgumentException("Passphrase must be at most 64 bytes.", nameof(passphrase));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), ssidBytes);
        w.WriteByteString(MatterTag.Context(1), credBytes);
        w.WriteUnsignedInt(MatterTag.Context(2), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NetworkCommissioning, NetworkCommissioningCommands.AddOrUpdateWiFiNetwork), w.ToArray(), ct);
        return ParseNetworkConfigStatus(response);
    }

    /// <summary>
    /// Give the device a Thread network to join. The operational dataset is the TLV blob a Thread
    /// border router publishes — channel, PAN ID, network key and the rest — which the commissioner
    /// obtains from the Thread network itself rather than constructing.
    /// </summary>
    public async Task<NetworkCommissioningStatus> AddOrUpdateThreadNetworkAsync(
        byte[] operationalDataset, ulong breadcrumb, CancellationToken ct = default)
    {
        if (operationalDataset.Length == 0)
            throw new ArgumentException("A Thread operational dataset is required.", nameof(operationalDataset));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), operationalDataset);
        w.WriteUnsignedInt(MatterTag.Context(1), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NetworkCommissioning, NetworkCommissioningCommands.AddOrUpdateThreadNetwork), w.ToArray(), ct);
        return ParseNetworkConfigStatus(response);
    }

    /// <summary>
    /// Ask the device which networks it can see. Passing an SSID narrows the scan to that network;
    /// passing none scans for everything in range.
    /// </summary>
    /// <remarks>
    /// The device does its own radio scan, so this can take many seconds — the caller should allow
    /// for the device's advertised ScanMaxTimeSeconds.
    /// </remarks>
    public async Task<IReadOnlyList<ScannedNetwork>> ScanNetworksAsync(
        string? ssid = null, ulong breadcrumb = 0, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        if (ssid is null) w.WriteNull(MatterTag.Context(0));
        else w.WriteByteString(MatterTag.Context(0), Encoding.UTF8.GetBytes(ssid));
        w.WriteUnsignedInt(MatterTag.Context(1), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NetworkCommissioning, NetworkCommissioningCommands.ScanNetworks), w.ToArray(), ct);

        return ParseScanResults(response);
    }

    /// <summary>Forget a network the device was previously given, identified by its NetworkID.</summary>
    public async Task<NetworkCommissioningStatus> RemoveNetworkAsync(
        byte[] networkId, ulong breadcrumb, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), networkId);
        w.WriteUnsignedInt(MatterTag.Context(1), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NetworkCommissioning, NetworkCommissioningCommands.RemoveNetwork), w.ToArray(), ct);
        return ParseNetworkConfigStatus(response);
    }

    /// <summary>One Wi-Fi network a device reported seeing during a scan.</summary>
    /// <param name="Ssid">The network name as raw bytes; it is not required to be valid UTF-8.</param>
    /// <param name="Rssi">Signal strength in dBm, as the device measured it.</param>
    public sealed record ScannedNetwork(byte[] Ssid, byte[] Bssid, ushort Channel, sbyte Rssi)
    {
        /// <summary>The SSID decoded as text, for display. Lossy if the network name is not UTF-8.</summary>
        public string SsidText => Encoding.UTF8.GetString(Ssid);
    }

    /// <summary>ScanNetworksResponse: { 0: status, 1: debugText, 2: wifiScanResults, 3: threadScanResults }.</summary>
    private static IReadOnlyList<ScannedNetwork> ParseScanResults(byte[] responseTlv)
    {
        var results = new List<ScannedNetwork>();
        var r = new MatterTlvReader(responseTlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("ScanNetworksResponse: missing structure");

        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific)
            {
                SkipIfContainer(ref r);
                continue;
            }
            if (r.Tag.TagNumber != 2) { SkipIfContainer(ref r); continue; }

            r.EnterContainer();                       // the Wi-Fi results array
            while (r.Read())
            {
                if (r.ElementType != MatterTlvElementType.Structure) continue;
                results.Add(ReadWiFiScanResult(ref r));
            }
        }
        return results;
    }

    /// <summary>WiFiInterfaceScanResultStruct: { 0: security, 1: ssid, 2: bssid, 3: channel, 4: band, 5: rssi }.</summary>
    private static ScannedNetwork ReadWiFiScanResult(ref MatterTlvReader r)
    {
        byte[] ssid = [], bssid = [];
        ushort channel = 0;
        sbyte rssi = 0;

        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
            switch (r.Tag.TagNumber)
            {
                case 1: ssid = r.GetByteString(); break;
                case 2: bssid = r.GetByteString(); break;
                case 3: channel = (ushort)r.GetUnsignedInt(); break;
                case 5: rssi = (sbyte)r.GetSignedInt(); break;
                default: SkipIfContainer(ref r); break;
            }
        }
        return new ScannedNetwork(ssid, bssid, channel, rssi);
    }

    private static void SkipIfContainer(ref MatterTlvReader r)
    {
        if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
            r.ExitContainer();
    }

    /// <summary>Tell the device to connect to a previously-added network, identified by its SSID bytes (the NetworkID for Wi-Fi is the SSID).</summary>
    public Task<NetworkCommissioningStatus> ConnectNetworkAsync(string ssid, ulong breadcrumb, CancellationToken ct = default) =>
        ConnectNetworkAsync(Encoding.UTF8.GetBytes(ssid), breadcrumb, ct);

    /// <summary>
    /// Connect by raw NetworkID: the SSID bytes for Wi-Fi, or the extended PAN ID for Thread.
    /// </summary>
    public async Task<NetworkCommissioningStatus> ConnectNetworkAsync(byte[] networkId, ulong breadcrumb, CancellationToken ct = default)
    {
        byte[] ssidBytes = networkId;
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), ssidBytes);
        w.WriteUnsignedInt(MatterTag.Context(1), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NetworkCommissioning, NetworkCommissioningCommands.ConnectNetwork), w.ToArray(), ct);

        var r = new MatterTlvReader(response);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("ConnectNetworkResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (NetworkCommissioningStatus)r.GetUnsignedInt();
        }
        throw new FormatException("ConnectNetworkResponse: missing NetworkingStatus");
    }

    private static NetworkCommissioningStatus ParseNetworkConfigStatus(byte[] responseTlv)
    {
        var r = new MatterTlvReader(responseTlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("NetworkConfigResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (NetworkCommissioningStatus)r.GetUnsignedInt();
        }
        throw new FormatException("NetworkConfigResponse: missing NetworkingStatus");
    }
}
