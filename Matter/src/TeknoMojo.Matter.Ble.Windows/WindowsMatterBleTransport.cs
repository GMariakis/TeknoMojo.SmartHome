using System.Threading.Channels;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Ble;
using DataReader = global::Windows.Storage.Streams.DataReader;
using DataWriter = global::Windows.Storage.Streams.DataWriter;
using IBuffer = global::Windows.Storage.Streams.IBuffer;

namespace TeknoMojo.Matter.Ble.WinRT;

/// <summary>
/// A live Matter-over-BLE (CHIPoBLE) connection: GATT service/characteristic resolution, the
/// BTP capabilities handshake, and an <see cref="IMatterTransport"/> built on
/// <see cref="BtpFragmentEngine"/> for message-level send/receive. This is the commissioning
/// transport only — once CASE completes, a Matter session moves to IP and this object is
/// disposed. Windows-specific; construct via <see cref="WindowsMatterBleCentral"/> rather than
/// directly, so application code stays on the portable <see cref="IMatterBleCentral"/>/
/// <see cref="IMatterTransport"/> interfaces.
/// </summary>
public sealed class WindowsMatterBleTransport : IMatterTransport
{
    private readonly BluetoothLEDevice _device;
    private readonly GattDeviceService _service;
    private readonly GattCharacteristic _c1Write;
    private readonly GattCharacteristic _c2Indicate;
    private readonly BtpFragmentEngine _btp;
    // Guards _btp: acknowledgements are now emitted from the BLE callback thread while the
    // application may be sending on another.
    private readonly object _btpLock = new();
    private readonly Channel<byte[]> _inboundMessages = Channel.CreateUnbounded<byte[]>();

    /// <summary>
    /// Optional sink for a one-line trace of every BTP fragment sent and received, standalone
    /// acknowledgements included. Null by default; set it to diagnose an exchange that stalls
    /// without having to put a BLE sniffer on the air.
    /// </summary>
    public Action<string>? Trace { get; set; }
    private bool _disposed;

    // The GattDeviceService MUST be kept alive for as long as we need its characteristics'
    // subscriptions to keep delivering — if it's allowed to be garbage-collected, the OS can
    // silently drop the CCCD/indication subscription on _c2Indicate even though the
    // GattCharacteristic object itself remains perfectly usable. Only keeping the two
    // characteristic references (and not the owning service) was the actual cause of indications
    // never arriving despite every other layer (write, MTU, CCCD subscribe) succeeding.
    private WindowsMatterBleTransport(BluetoothLEDevice device, GattDeviceService service, GattCharacteristic c1, GattCharacteristic c2, BtpFragmentEngine btp)
    {
        _device = device;
        _service = service;
        _c1Write = c1;
        _c2Indicate = c2;
        _btp = btp;
        _c2Indicate.ValueChanged += OnIndicationReceived;
    }

    internal static async Task<WindowsMatterBleTransport> ConnectAsync(
        ulong bluetoothAddress, TimeSpan? handshakeTimeout = null, CancellationToken ct = default)
    {
        BluetoothLEDevice? device = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);
        if (device is null)
            throw new InvalidOperationException($"Could not connect to BLE device {bluetoothAddress:X12}.");

        GattDeviceServicesResult svcResult = await device.GetGattServicesForUuidAsync(MatterBleUuids.Service, BluetoothCacheMode.Uncached);
        if (svcResult.Status != GattCommunicationStatus.Success || svcResult.Services.Count == 0)
        {
            device.Dispose();
            throw new InvalidOperationException($"CHIPoBLE service not found on device (status={svcResult.Status}).");
        }
        GattDeviceService service = svcResult.Services[0];

        GattCharacteristic c1 = await GetCharacteristicAsync(service, MatterBleUuids.CharacteristicC1Write);
        GattCharacteristic c2 = await GetCharacteristicAsync(service, MatterBleUuids.CharacteristicC2Indicate);

        ushort mtu = await GetNegotiatedMtuAsync(device);
        var btp = new BtpFragmentEngine(txFragmentSize: mtu - 3, rxFragmentSize: mtu - 3);

        var transport = new WindowsMatterBleTransport(device, service, c1, c2, btp);
        try
        {
            await transport.RunHandshakeAsync(mtu, handshakeTimeout ?? TimeSpan.FromSeconds(10), ct);
        }
        catch
        {
            await transport.DisposeAsync();
            throw;
        }
        return transport;
    }

    /// <summary>
    /// Negotiated ATT MTU for the connection, via <see cref="GattSession"/>. Falls back to the
    /// BLE 4.x default (23) if the session's MaxPduSize is unavailable (0) for any reason —
    /// still usable, just smaller fragments.
    /// </summary>
    private static async Task<ushort> GetNegotiatedMtuAsync(BluetoothLEDevice device)
    {
        GattSession session = await GattSession.FromDeviceIdAsync(device.BluetoothDeviceId);
        uint pdu = session.MaxPduSize;
        return (ushort)Math.Clamp(pdu == 0 ? 23 : pdu, 23, BtpHandshake.MaxAdvertisedAttMtu);
    }

    private static async Task<GattCharacteristic> GetCharacteristicAsync(GattDeviceService service, Guid uuid)
    {
        GattCharacteristicsResult result = await service.GetCharacteristicsForUuidAsync(uuid, BluetoothCacheMode.Uncached);
        if (result.Status != GattCommunicationStatus.Success || result.Characteristics.Count == 0)
            throw new InvalidOperationException($"CHIPoBLE characteristic {uuid} not found (status={result.Status}).");
        return result.Characteristics[0];
    }

    private EventHandler<byte[]>? _rawIndicationForHandshake;

    private async Task RunHandshakeAsync(ushort mtu, TimeSpan timeout, CancellationToken ct)
    {
        var handshakeResponse = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _rawIndicationForHandshake = (_, data) => handshakeResponse.TrySetResult(data);

        var request = BtpHandshake.CapabilitiesRequest.ForCurrentVersion(mtu, windowSize: 6);
        byte[] reqBytes = BtpHandshake.EncodeRequest(request);
        await WriteRawAsync(reqBytes, ct);

        // Subscribe to C2 indications only AFTER writing the request, matching the order a
        // shipping commissioner uses on the air. Accessories appear to treat the subscribe as
        // the trigger to emit the handshake response: the captured reference exchange writes
        // C1, subscribes, and only then receives the response. Subscribing first — the
        // seemingly safer order — leaves at least one accessory silent indefinitely. Our
        // ValueChanged handler is already attached, so no response can be missed here.
        GattCommunicationStatus subStatus = await _c2Indicate.WriteClientCharacteristicConfigurationDescriptorAsync(
            GattClientCharacteristicConfigurationDescriptorValue.Indicate);
        if (subStatus != GattCommunicationStatus.Success)
            throw new InvalidOperationException($"Failed to subscribe to C2 indications (status={subStatus}).");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        byte[] respBytes;
        try
        {
            await using (cts.Token.Register(() => handshakeResponse.TrySetCanceled()))
                respBytes = await handshakeResponse.Task;
        }
        catch (TaskCanceledException)
        {
            throw new TimeoutException("BTP capabilities handshake timed out waiting for the accessory's response.");
        }
        finally
        {
            _rawIndicationForHandshake = null;
        }

        var response = BtpHandshake.DecodeResponse(respBytes);
        if (!response.IsAccepted)
            throw new InvalidOperationException("Accessory rejected BTP handshake (no compatible protocol version).");

        // From here on, both fragment sizes are governed by what the accessory selected.
        // (Our BtpFragmentEngine was constructed with the MTU-based estimate; re-negotiating the
        // engine's fragment size post-handshake would need a mutable engine — acceptable for now
        // since the response fragment size is typically <= the MTU-derived one we already used.)
    }

    private async Task WriteRawAsync(byte[] data, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var writer = new DataWriter();
        writer.WriteBytes(data);
        IBuffer buffer = writer.DetachBuffer();

        // Always a GATT Write Request, never a Write Command, even though C1 advertises
        // WriteWithoutResponse. A shipping commissioner captured off the air uses Write Request
        // for every write to C1 — handshake and SDU segments alike — and the per-write response
        // doubles as flow control we'd otherwise have to invent.
        Trace?.Invoke($"TX {Convert.ToHexString(data)}");
        GattCommunicationStatus status = await _c1Write.WriteValueAsync(buffer, GattWriteOption.WriteWithResponse);
        if (status != GattCommunicationStatus.Success)
            throw new InvalidOperationException($"BLE write to C1 failed (status={status}).");
    }

    private void OnIndicationReceived(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        var reader = DataReader.FromBuffer(args.CharacteristicValue);
        var data = new byte[reader.UnconsumedBufferLength];
        reader.ReadBytes(data);
        Trace?.Invoke($"RX {Convert.ToHexString(data)}");

        if (_rawIndicationForHandshake is { } handshakeHandler)
        {
            handshakeHandler(sender, data);
            return;
        }

        BtpReceiveResult result;
        bool oweAck;
        try
        {
            lock (_btpLock)
            {
                result = _btp.ProcessIncomingFragment(data);
                oweAck = _btp.HasUnackedReceipt;
            }
        }
        catch (Exception ex)
        {
            // A malformed/out-of-sequence fragment breaks the BTP state machine irrecoverably;
            // surface it on the next receive attempt rather than throwing from this event handler.
            _inboundMessages.Writer.TryComplete(
                new InvalidOperationException("BTP fragment reassembly failed; connection is no longer usable.", ex));
            return;
        }

        if (result.CompletedMessage is not null)
        {
            _inboundMessages.Writer.TryWrite(result.CompletedMessage);
        }

        // Every received fragment must be acknowledged, and piggybacking on our next send is not
        // enough: while we are blocked waiting for a response we have nothing to send, so the
        // peer's fragment would go unacknowledged forever and BTP flow control deadlocks. That
        // is exactly what an accessory did here — it acked our request, then waited on an ack
        // from us that never came. Acknowledge straight away instead.
        if (oweAck) _ = SendStandaloneAckAsync();
    }

    private async Task SendStandaloneAckAsync()
    {
        try
        {
            byte[] ack;
            lock (_btpLock)
            {
                if (_disposed || !_btp.HasUnackedReceipt) return;
                ack = _btp.EncodeStandaloneAck();
            }
            await WriteRawAsync(ack, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _inboundMessages.Writer.TryComplete(
                new InvalidOperationException("Failed to send BTP acknowledgement.", ex));
        }
    }

    public async Task SendMessageAsync(ReadOnlyMemory<byte> message, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        List<byte[]> fragments;
        lock (_btpLock) fragments = _btp.EncodeMessage(message.Span);
        foreach (byte[] fragment in fragments)
        {
            ct.ThrowIfCancellationRequested();
            await WriteRawAsync(fragment, ct);
        }
    }

    public async Task<byte[]> ReceiveMessageAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return await _inboundMessages.Reader.ReadAsync(ct);
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed) return ValueTask.CompletedTask;
        _disposed = true;
        _c2Indicate.ValueChanged -= OnIndicationReceived;
        _inboundMessages.Writer.TryComplete();
        _service.Dispose();
        _device.Dispose();
        return ValueTask.CompletedTask;
    }
}
