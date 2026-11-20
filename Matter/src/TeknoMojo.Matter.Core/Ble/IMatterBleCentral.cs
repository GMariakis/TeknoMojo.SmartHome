namespace TeknoMojo.Matter.Core.Ble;

/// <summary>
/// Platform-agnostic BLE central role for Matter commissioning: scan for commissionable
/// devices, connect to one, and hand back a message-oriented <see cref="IMatterTransport"/>
/// built on the BTP framing in this namespace. Each OS gets its own implementation
/// (TeknoMojo.Matter.Ble.Windows via WinRT, TeknoMojo.Matter.Ble.Linux via BlueZ/D-Bus,
/// TeknoMojo.Matter.Ble.MacOS via CoreBluetooth) — application code depends only on this
/// interface and stays portable across all three.
/// </summary>
public interface IMatterBleCentral : IAsyncDisposable
{
    /// <summary>Start scanning for commissionable Matter devices.</summary>
    void StartScan();

    /// <summary>Stop scanning.</summary>
    void StopScan();

    /// <summary>Raised for every distinct commissionable candidate seen since scanning started.</summary>
    event EventHandler<MatterBleCandidate>? CandidateFound;

    /// <summary>Snapshot of every commissionable candidate seen since scanning started.</summary>
    IReadOnlyCollection<MatterBleCandidate> Candidates { get; }

    /// <summary>
    /// Scan (starting the scan if not already running) until a device advertising the given
    /// 12-bit discriminator is found, or <paramref name="timeout"/> elapses.
    /// </summary>
    Task<MatterBleCandidate?> WaitForDiscriminatorAsync(ushort discriminator, TimeSpan timeout, CancellationToken ct = default);

    /// <summary>
    /// Connect to a previously-discovered candidate, resolve the CHIPoBLE GATT service, and run
    /// the BTP capabilities handshake. Returns a ready-to-use transport for PASE/CASE traffic.
    /// </summary>
    Task<IMatterTransport> ConnectAsync(MatterBleCandidate candidate, TimeSpan? handshakeTimeout = null, CancellationToken ct = default);
}

/// <summary>One commissionable Matter device seen advertising over BLE, identified opaquely per platform.</summary>
/// <param name="PlatformAddress">
/// Opaque platform-specific device handle (a WinRT BluetoothAddress as a ulong on Windows, a
/// D-Bus object path string on Linux/BlueZ, a CBPeripheral identifier string on macOS). Callers
/// should treat this as an opaque token and pass it back into <see cref="IMatterBleCentral"/>
/// via the <see cref="MatterBleCandidate"/> itself, never parse or construct it directly.
/// </param>
public sealed record MatterBleCandidate(object PlatformAddress, MatterBleAdvertisement Advertisement, short? RssiDbm);
