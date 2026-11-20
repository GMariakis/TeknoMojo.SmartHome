using System.Collections.Concurrent;
using Windows.Devices.Bluetooth.Advertisement;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Ble;

namespace TeknoMojo.Matter.Ble.WinRT;

/// <summary>
/// Windows implementation of <see cref="IMatterBleCentral"/> via WinRT
/// (<c>Windows.Devices.Bluetooth</c>). Candidates' <see cref="MatterBleCandidate.PlatformAddress"/>
/// is a boxed <see cref="ulong"/> BLE address.
/// </summary>
public sealed class WindowsMatterBleCentral : IMatterBleCentral
{
    // The 16-bit AD "Service Data" type code (Bluetooth Core Spec Assigned Numbers §2.3):
    // for a 16-bit service UUID, this is AD type 0x16.
    private const byte ServiceData16BitUuidAdType = 0x16;

    private readonly BluetoothLEAdvertisementWatcher _watcher;
    private readonly ConcurrentDictionary<ulong, MatterBleCandidate> _seen = new();
    private bool _disposed;

    public event EventHandler<MatterBleCandidate>? CandidateFound;

    public WindowsMatterBleCentral()
    {
        _watcher = new BluetoothLEAdvertisementWatcher { ScanningMode = BluetoothLEScanningMode.Active };
        _watcher.Received += OnAdvertisementReceived;
    }

    public void StartScan() => _watcher.Start();
    public void StopScan() => _watcher.Stop();

    public IReadOnlyCollection<MatterBleCandidate> Candidates => _seen.Values.ToList();

    public async Task<MatterBleCandidate?> WaitForDiscriminatorAsync(ushort discriminator, TimeSpan timeout, CancellationToken ct = default)
    {
        var existing = _seen.Values.FirstOrDefault(c => c.Advertisement.Discriminator == discriminator);
        if (existing is not null) return existing;

        var tcs = new TaskCompletionSource<MatterBleCandidate>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(object? s, MatterBleCandidate c)
        {
            if (c.Advertisement.Discriminator == discriminator) tcs.TrySetResult(c);
        }

        CandidateFound += Handler;
        if (_watcher.Status != BluetoothLEAdvertisementWatcherStatus.Started) StartScan();
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
        if (candidate.PlatformAddress is not ulong address)
            throw new ArgumentException("Candidate was not produced by WindowsMatterBleCentral (PlatformAddress must be a ulong BLE address).", nameof(candidate));
        return await WindowsMatterBleTransport.ConnectAsync(address, handshakeTimeout, ct);
    }

    private void OnAdvertisementReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        foreach (var section in args.Advertisement.DataSections)
        {
            if (section.DataType != ServiceData16BitUuidAdType) continue;

            var reader = global::Windows.Storage.Streams.DataReader.FromBuffer(section.Data);
            if (reader.UnconsumedBufferLength < 2 + MatterBleAdvertisement.Size) continue;

            reader.ByteOrder = global::Windows.Storage.Streams.ByteOrder.LittleEndian;
            ushort uuid16 = reader.ReadUInt16();
            if (uuid16 != MatterBleUuids.ServiceUuid16) continue;

            var payload = new byte[MatterBleAdvertisement.Size];
            reader.ReadBytes(payload);

            MatterBleAdvertisement adv;
            try { adv = MatterBleAdvertisement.Parse(payload); }
            catch (FormatException) { continue; }

            var candidate = new MatterBleCandidate(args.BluetoothAddress, adv, args.RawSignalStrengthInDBm);
            _seen[args.BluetoothAddress] = candidate;
            CandidateFound?.Invoke(this, candidate);
        }
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed) return ValueTask.CompletedTask;
        _disposed = true;
        _watcher.Received -= OnAdvertisementReceived;
        if (_watcher.Status == BluetoothLEAdvertisementWatcherStatus.Started)
            _watcher.Stop();
        return ValueTask.CompletedTask;
    }
}
