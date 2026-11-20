using System.Collections.Concurrent;
using CoreBluetooth;
using Foundation;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Ble;

namespace TeknoMojo.Matter.Ble.MacOS;

/// <summary>
/// macOS implementation of <see cref="IMatterBleCentral"/> via CoreBluetooth (Microsoft's
/// official .NET-for-macOS bindings — first-party, not a third-party wrapper). Candidates'
/// <see cref="MatterBleCandidate.PlatformAddress"/> is the live <see cref="CBPeripheral"/>
/// instance; CoreBluetooth requires holding a strong reference to a peripheral for the duration
/// of any operation on it, so the central retains every peripheral it has seen.
/// </summary>
public sealed class MacOSMatterBleCentral : IMatterBleCentral
{
    private readonly CBCentralManager _manager = new();
    private readonly ConcurrentDictionary<string, MatterBleCandidate> _seen = new();
    private readonly ConcurrentDictionary<string, CBPeripheral> _retained = new();
    private TaskCompletionSource<bool>? _poweredOn;
    private bool _scanning;
    private bool _disposed;

    public event EventHandler<MatterBleCandidate>? CandidateFound;

    public MacOSMatterBleCentral()
    {
        _manager.UpdatedState += (_, _) =>
        {
            if (_manager.State == CBManagerState.PoweredOn)
                _poweredOn?.TrySetResult(true);
        };
        _manager.DiscoveredPeripheral += OnDiscoveredPeripheral;
    }

    public IReadOnlyCollection<MatterBleCandidate> Candidates => _seen.Values.ToList();

    private Task WaitPoweredOnAsync(CancellationToken ct)
    {
        if (_manager.State == CBManagerState.PoweredOn) return Task.CompletedTask;
        _poweredOn ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var reg = ct.Register(() => _poweredOn.TrySetCanceled());
        return _poweredOn.Task;
    }

    public void StartScan() => StartScanAsync(CancellationToken.None).GetAwaiter().GetResult();

    private async Task StartScanAsync(CancellationToken ct)
    {
        if (_scanning) return;
        await WaitPoweredOnAsync(ct);
        _manager.ScanForPeripherals(new[] { CBUUID.FromString(MatterBleUuids.Service.ToString()) });
        _scanning = true;
    }

    public void StopScan()
    {
        if (!_scanning) return;
        _manager.StopScan();
        _scanning = false;
    }

    public async Task<MatterBleCandidate?> WaitForDiscriminatorAsync(ushort discriminator, TimeSpan timeout, CancellationToken ct = default)
    {
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
        if (candidate.PlatformAddress is not CBPeripheral peripheral)
            throw new ArgumentException("Candidate was not produced by MacOSMatterBleCentral (PlatformAddress must be a CBPeripheral).", nameof(candidate));
        return await MacOSMatterBleTransport.ConnectAsync(_manager, peripheral, handshakeTimeout, ct);
    }

    private void OnDiscoveredPeripheral(object? sender, CBDiscoveredPeripheralEventArgs args)
    {
        var adv = new AdvertisementData(args.AdvertisementData);
        NSDictionary<CBUUID, NSData>? serviceData = adv.ServiceData;
        if (serviceData is null) return;

        CBUUID matterUuid = CBUUID.FromString(MatterBleUuids.Service.ToString());
        if (!serviceData.TryGetValue(matterUuid, out NSData? data)) return;

        byte[] bytes = data!.ToArray();
        MatterBleAdvertisement parsed;
        try { parsed = MatterBleAdvertisement.Parse(bytes); }
        catch (FormatException) { return; }

        string id = args.Peripheral.Identifier.AsString();
        _retained[id] = args.Peripheral; // CoreBluetooth requires retaining the peripheral to use it later.

        short? rssi = args.RSSI is not null ? (short)args.RSSI.Int32Value : null;
        var candidate = new MatterBleCandidate(args.Peripheral, parsed, rssi);
        _seen[id] = candidate;
        CandidateFound?.Invoke(this, candidate);
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed) return ValueTask.CompletedTask;
        _disposed = true;
        StopScan();
        _manager.DiscoveredPeripheral -= OnDiscoveredPeripheral;
        _manager.Dispose();
        return ValueTask.CompletedTask;
    }
}
