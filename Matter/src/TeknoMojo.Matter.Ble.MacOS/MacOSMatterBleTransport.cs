using System.Threading.Channels;
using CoreBluetooth;
using Foundation;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Ble;

namespace TeknoMojo.Matter.Ble.MacOS;

/// <summary>
/// A live Matter-over-BLE (CHIPoBLE) connection over CoreBluetooth: GATT service/characteristic
/// resolution, the BTP capabilities handshake, and an <see cref="IMatterTransport"/> built on
/// <see cref="BtpFragmentEngine"/>. Construct via <see cref="MacOSMatterBleCentral"/>, not
/// directly, so application code stays on the portable interfaces.
/// </summary>
public sealed class MacOSMatterBleTransport : IMatterTransport
{
    private static readonly CBUUID ServiceUuid = CBUUID.FromString(MatterBleUuids.Service.ToString());
    private static readonly CBUUID C1Uuid = CBUUID.FromString(MatterBleUuids.CharacteristicC1Write.ToString());
    private static readonly CBUUID C2Uuid = CBUUID.FromString(MatterBleUuids.CharacteristicC2Indicate.ToString());

    private readonly CBCentralManager _manager;
    private readonly CBPeripheral _peripheral;
    private readonly CBCharacteristic _c1;
    private readonly CBCharacteristic _c2;
    private readonly CBCharacteristicWriteType _c1WriteType;
    private readonly BtpFragmentEngine _btp;
    private readonly Channel<byte[]> _inboundMessages = Channel.CreateUnbounded<byte[]>();
    private EventHandler<byte[]>? _rawIndicationForHandshake;
    private bool _disposed;

    private MacOSMatterBleTransport(
        CBCentralManager manager, CBPeripheral peripheral, CBCharacteristic c1, CBCharacteristic c2,
        CBCharacteristicWriteType c1WriteType, BtpFragmentEngine btp)
    {
        _manager = manager;
        _peripheral = peripheral;
        _c1 = c1;
        _c2 = c2;
        _c1WriteType = c1WriteType;
        _btp = btp;
        _peripheral.UpdatedCharacterteristicValue += OnCharacteristicValueUpdated;
    }

    internal static async Task<MacOSMatterBleTransport> ConnectAsync(
        CBCentralManager manager, CBPeripheral peripheral, TimeSpan? handshakeTimeout, CancellationToken ct)
    {
        await ConnectPeripheralAsync(manager, peripheral, ct);

        CBService service = await DiscoverServiceAsync(peripheral, ct);
        (CBCharacteristic c1, CBCharacteristic c2) = await DiscoverCharacteristicsAsync(peripheral, service, ct);

        CBCharacteristicWriteType writeType = c1.Properties.HasFlag(CBCharacteristicProperties.WriteWithoutResponse)
            ? CBCharacteristicWriteType.WithoutResponse
            : CBCharacteristicWriteType.WithResponse;

        // CoreBluetooth's GetMaximumWriteValueLength already accounts for ATT overhead — unlike
        // the raw MTU exposed on Windows/Linux, this is the actual usable payload size.
        int maxWrite = (int)peripheral.GetMaximumWriteValueLength(writeType);
        ushort fragmentSize = (ushort)Math.Clamp(maxWrite, 20, 512);
        var btp = new BtpFragmentEngine(txFragmentSize: fragmentSize, rxFragmentSize: fragmentSize);

        var transport = new MacOSMatterBleTransport(manager, peripheral, c1, c2, writeType, btp);
        try
        {
            await transport.EnableNotificationsAsync(ct);
            await transport.RunHandshakeAsync(fragmentSize, handshakeTimeout ?? TimeSpan.FromSeconds(10), ct);
        }
        catch
        {
            await transport.DisposeAsync();
            throw;
        }
        return transport;
    }

    private static Task ConnectPeripheralAsync(CBCentralManager manager, CBPeripheral peripheral, CancellationToken ct)
    {
        if (peripheral.State == CBPeripheralState.Connected) return Task.CompletedTask;

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler<CBPeripheralEventArgs>? onConnected = null;
        EventHandler<CBPeripheralErrorEventArgs>? onFailed = null;

        onConnected = (_, args) => { if (ReferenceEquals(args.Peripheral, peripheral)) { tcs.TrySetResult(); } };
        onFailed = (_, args) => { if (ReferenceEquals(args.Peripheral, peripheral)) tcs.TrySetException(new InvalidOperationException($"BLE connect failed: {args.Error?.LocalizedDescription}")); };

        manager.ConnectedPeripheral += onConnected;
        manager.FailedToConnectPeripheral += onFailed;
        try
        {
            manager.ConnectPeripheral(peripheral, (PeripheralConnectionOptions?)null!);
            return WaitWithCleanupAsync(tcs.Task, ct);
        }
        finally
        {
            _ = tcs.Task.ContinueWith(_ =>
            {
                manager.ConnectedPeripheral -= onConnected;
                manager.FailedToConnectPeripheral -= onFailed;
            }, TaskScheduler.Default);
        }
    }

    private static async Task<CBService> DiscoverServiceAsync(CBPeripheral peripheral, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler<NSErrorEventArgs> handler = (_, args) =>
        {
            if (args.Error is not null) tcs.TrySetException(new InvalidOperationException($"DiscoverServices failed: {args.Error.LocalizedDescription}"));
            else tcs.TrySetResult();
        };
        peripheral.DiscoveredService += handler;
        try
        {
            peripheral.DiscoverServices(new[] { ServiceUuid });
            await WaitWithCleanupAsync(tcs.Task, ct);
        }
        finally
        {
            peripheral.DiscoveredService -= handler;
        }

        CBService? service = peripheral.Services?.FirstOrDefault(s => s.UUID.Uuid.Equals(ServiceUuid.Uuid, StringComparison.OrdinalIgnoreCase));
        return service ?? throw new InvalidOperationException("CHIPoBLE service not found after DiscoverServices.");
    }

    private static async Task<(CBCharacteristic c1, CBCharacteristic c2)> DiscoverCharacteristicsAsync(CBPeripheral peripheral, CBService service, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler<CBServiceEventArgs> handler = (_, args) =>
        {
            if (!ReferenceEquals(args.Service, service)) return;
            if (args.Error is not null) tcs.TrySetException(new InvalidOperationException($"DiscoverCharacteristics failed: {args.Error.LocalizedDescription}"));
            else tcs.TrySetResult();
        };
        peripheral.DiscoveredCharacteristics += handler;
        try
        {
            peripheral.DiscoverCharacteristics(new[] { C1Uuid, C2Uuid }, service);
            await WaitWithCleanupAsync(tcs.Task, ct);
        }
        finally
        {
            peripheral.DiscoveredCharacteristics -= handler;
        }

        CBCharacteristic[] chars = service.Characteristics ?? Array.Empty<CBCharacteristic>();
        CBCharacteristic? c1 = chars.FirstOrDefault(c => c.UUID.Uuid.Equals(C1Uuid.Uuid, StringComparison.OrdinalIgnoreCase));
        CBCharacteristic? c2 = chars.FirstOrDefault(c => c.UUID.Uuid.Equals(C2Uuid.Uuid, StringComparison.OrdinalIgnoreCase));
        if (c1 is null || c2 is null)
            throw new InvalidOperationException("CHIPoBLE C1/C2 characteristics not found after DiscoverCharacteristics.");
        return (c1, c2);
    }

    private async Task EnableNotificationsAsync(CancellationToken ct)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        EventHandler<CBCharacteristicEventArgs> handler = (_, args) =>
        {
            if (!ReferenceEquals(args.Characteristic, _c2)) return;
            if (args.Error is not null) tcs.TrySetException(new InvalidOperationException($"SetNotifyValue failed: {args.Error.LocalizedDescription}"));
            else tcs.TrySetResult();
        };
        _peripheral.UpdatedNotificationState += handler;
        try
        {
            _peripheral.SetNotifyValue(true, _c2);
            await WaitWithCleanupAsync(tcs.Task, ct);
        }
        finally
        {
            _peripheral.UpdatedNotificationState -= handler;
        }
    }

    private async Task RunHandshakeAsync(ushort fragmentSize, TimeSpan timeout, CancellationToken ct)
    {
        var handshakeResponse = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _rawIndicationForHandshake = (_, data) => handshakeResponse.TrySetResult(data);

        var request = BtpHandshake.CapabilitiesRequest.ForCurrentVersion(fragmentSize, windowSize: 6);
        WriteRaw(BtpHandshake.EncodeRequest(request));

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
    }

    private void WriteRaw(byte[] data)
    {
        using NSData nsData = NSData.FromArray(data);
        _peripheral.WriteValue(nsData, _c1, _c1WriteType);
    }

    private void OnCharacteristicValueUpdated(object? sender, CBCharacteristicEventArgs args)
    {
        if (!ReferenceEquals(args.Characteristic, _c2)) return;
        if (args.Error is not null) return;

        byte[] data = args.Characteristic.Value?.ToArray() ?? Array.Empty<byte>();

        if (_rawIndicationForHandshake is { } handshakeHandler)
        {
            handshakeHandler(this, data);
            return;
        }

        BtpReceiveResult result;
        try { result = _btp.ProcessIncomingFragment(data); }
        catch (Exception ex)
        {
            _inboundMessages.Writer.TryComplete(
                new InvalidOperationException("BTP fragment reassembly failed; connection is no longer usable.", ex));
            return;
        }
        if (result.CompletedMessage is not null)
            _inboundMessages.Writer.TryWrite(result.CompletedMessage);
    }

    public Task SendMessageAsync(ReadOnlyMemory<byte> message, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        foreach (byte[] fragment in _btp.EncodeMessage(message.Span))
        {
            ct.ThrowIfCancellationRequested();
            WriteRaw(fragment);
        }
        return Task.CompletedTask;
    }

    public async Task<byte[]> ReceiveMessageAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return await _inboundMessages.Reader.ReadAsync(ct);
    }

    private static async Task WaitWithCleanupAsync(Task task, CancellationToken ct)
    {
        using var reg = ct.Register(() => { });
        await task.WaitAsync(ct);
    }

    public ValueTask DisposeAsync()
    {
        if (_disposed) return ValueTask.CompletedTask;
        _disposed = true;
        _peripheral.UpdatedCharacterteristicValue -= OnCharacteristicValueUpdated;
        _inboundMessages.Writer.TryComplete();
        if (_peripheral.State is CBPeripheralState.Connected or CBPeripheralState.Connecting)
            _manager.CancelPeripheralConnection(_peripheral);
        return ValueTask.CompletedTask;
    }
}
