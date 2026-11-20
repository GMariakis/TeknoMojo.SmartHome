using System.Collections.Concurrent;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Ble;
using TeknoMojo.Matter.Ble.Linux.DBus;

namespace TeknoMojo.Matter.Ble.Linux.BlueZ;

/// <summary>
/// Linux implementation of <see cref="IMatterBleCentral"/> via BlueZ over our hand-rolled D-Bus
/// client. Candidates' <see cref="MatterBleCandidate.PlatformAddress"/> is the BlueZ device
/// object path (e.g. <c>/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF</c>) as a string.
/// </summary>
public sealed class LinuxMatterBleCentral : IMatterBleCentral
{
    /// <summary>BlueZ reports ServiceData keyed by the full lowercase 128-bit UUID string.</summary>
    private static readonly string MatterServiceUuidLower = MatterBleUuids.Service.ToString();

    private DBusConnection? _conn;
    private string? _adapterPath;
    private readonly ConcurrentDictionary<string, MatterBleCandidate> _seen = new();
    private bool _scanning;
    private bool _disposed;

    public event EventHandler<MatterBleCandidate>? CandidateFound;

    public IReadOnlyCollection<MatterBleCandidate> Candidates => _seen.Values.ToList();

    private async Task<DBusConnection> EnsureConnectedAsync(CancellationToken ct)
    {
        if (_conn is not null) return _conn;
        _conn = await DBusConnection.ConnectSystemBusAsync(ct);
        _adapterPath = await BlueZObjects.FindFirstAdapterAsync(_conn, ct);
        _conn.SignalReceived += OnSignalReceived;

        // Seed with whatever BlueZ already knows about (devices seen in a prior scan).
        foreach (var obj in await BlueZObjects.GetManagedObjectsAsync(_conn, ct))
        {
            if (TryExtractCandidate(obj.Path, obj.Properties(BlueZObjects.DeviceInterface), out var candidate))
                _seen[obj.Path] = candidate;
        }
        return _conn;
    }

    public void StartScan() => StartScanAsync(CancellationToken.None).GetAwaiter().GetResult();

    private async Task StartScanAsync(CancellationToken ct)
    {
        DBusConnection conn = await EnsureConnectedAsync(ct);
        if (_scanning) return;

        await conn.AddMatchAsync(
            $"type='signal',sender='{BlueZObjects.Service}',interface='{BlueZObjects.ObjectManagerInterface}',member='InterfacesAdded'", ct);
        await conn.AddMatchAsync(
            $"type='signal',interface='{BlueZObjects.PropertiesInterface}',member='PropertiesChanged'", ct);

        await conn.CallAsync(BlueZObjects.Service, _adapterPath!, BlueZObjects.AdapterInterface, "SetDiscoveryFilter",
            "a{sv}", new[] { DBusValue.Dict(("Transport", new DBusValue.Str("le"))) }, ct);
        await conn.CallAsync(BlueZObjects.Service, _adapterPath!, BlueZObjects.AdapterInterface, "StartDiscovery", "", null, ct);
        _scanning = true;
    }

    public void StopScan() => StopScanAsync(CancellationToken.None).GetAwaiter().GetResult();

    private async Task StopScanAsync(CancellationToken ct)
    {
        if (!_scanning || _conn is null) return;
        try { await _conn.CallAsync(BlueZObjects.Service, _adapterPath!, BlueZObjects.AdapterInterface, "StopDiscovery", "", null, ct); }
        catch { /* best-effort */ }
        _scanning = false;
    }

    public async Task<MatterBleCandidate?> WaitForDiscriminatorAsync(ushort discriminator, TimeSpan timeout, CancellationToken ct = default)
    {
        await EnsureConnectedAsync(ct);
        var existing = _seen.Values.FirstOrDefault(c => c.Advertisement.Discriminator == discriminator);
        if (existing is not null) return existing;

        var tcs = new TaskCompletionSource<MatterBleCandidate>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(object? s, MatterBleCandidate c) { if (c.Advertisement.Discriminator == discriminator) tcs.TrySetResult(c); }

        CandidateFound += Handler;
        if (!_scanning) await StartScanAsync(ct);
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await using (cts.Token.Register(() => tcs.TrySetCanceled()))
            {
                try { return await tcs.Task; }
                catch (TaskCanceledException) { return null; }
            }
        }
        finally
        {
            CandidateFound -= Handler;
        }
    }

    public async Task<IMatterTransport> ConnectAsync(MatterBleCandidate candidate, TimeSpan? handshakeTimeout = null, CancellationToken ct = default)
    {
        if (candidate.PlatformAddress is not string devicePath)
            throw new ArgumentException("Candidate was not produced by LinuxMatterBleCentral (PlatformAddress must be a BlueZ object path string).", nameof(candidate));
        DBusConnection conn = await EnsureConnectedAsync(ct);
        return await LinuxMatterBleTransport.ConnectAsync(conn, devicePath, handshakeTimeout, ct);
    }

    private void OnSignalReceived(object? sender, DBusMessage msg)
    {
        try
        {
            if (msg.Interface == BlueZObjects.ObjectManagerInterface && msg.Member == "InterfacesAdded")
            {
                string path = msg.Body[0].AsString();
                var ifacesDict = (DBusValue.Arr)msg.Body[1];
                var deviceProps = FindInterfaceProps(ifacesDict, BlueZObjects.DeviceInterface);
                if (deviceProps is not null && TryExtractCandidate(path, deviceProps, out var candidate))
                {
                    _seen[path] = candidate;
                    CandidateFound?.Invoke(this, candidate);
                }
            }
            else if (msg.Interface == BlueZObjects.PropertiesInterface && msg.Member == "PropertiesChanged" && msg.Path is not null)
            {
                string changedIface = msg.Body[0].AsString();
                if (changedIface != BlueZObjects.DeviceInterface) return;
                var changedProps = (DBusValue.Arr)msg.Body[1];
                var propsDict = ToPropertyDict(changedProps);
                if (TryExtractCandidate(msg.Path, propsDict, out var candidate))
                {
                    _seen[msg.Path] = candidate;
                    CandidateFound?.Invoke(this, candidate);
                }
            }
        }
        catch
        {
            // A malformed/unexpected signal shape shouldn't take down the whole scanner.
        }
    }

    private static IReadOnlyDictionary<string, DBusValue>? FindInterfaceProps(DBusValue.Arr ifacesDict, string iface)
    {
        foreach (DBusValue item in ifacesDict.Items)
        {
            var entry = (DBusValue.DictEntry)item;
            if (entry.Key.AsString() == iface) return ToPropertyDict((DBusValue.Arr)entry.Value);
        }
        return null;
    }

    private static IReadOnlyDictionary<string, DBusValue> ToPropertyDict(DBusValue.Arr propsArray)
    {
        var dict = new Dictionary<string, DBusValue>();
        foreach (DBusValue item in propsArray.Items)
        {
            var entry = (DBusValue.DictEntry)item;
            dict[entry.Key.AsString()] = entry.Value.Unwrap();
        }
        return dict;
    }

    private static bool TryExtractCandidate(string path, IReadOnlyDictionary<string, DBusValue>? props, out MatterBleCandidate candidate)
    {
        candidate = null!;
        if (props is null || !props.TryGetValue("ServiceData", out DBusValue? serviceDataValue))
            return false;
        if (serviceDataValue is not DBusValue.Arr serviceData) return false;

        foreach (DBusValue item in serviceData.Items)
        {
            var entry = (DBusValue.DictEntry)item;
            if (entry.Key.AsString() != MatterServiceUuidLower) continue;

            byte[] bytes = entry.Value.Unwrap().AsByteArray();
            MatterBleAdvertisement adv;
            try { adv = MatterBleAdvertisement.Parse(bytes); }
            catch (FormatException) { return false; }

            short? rssi = props.TryGetValue("RSSI", out DBusValue? r) && r is DBusValue.Int16 rv ? rv.Value : null;
            candidate = new MatterBleCandidate(path, adv, rssi);
            return true;
        }
        return false;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        if (_conn is not null)
        {
            _conn.SignalReceived -= OnSignalReceived;
            try { await StopScanAsync(CancellationToken.None); } catch { /* ignore */ }
            await _conn.DisposeAsync();
        }
    }
}
