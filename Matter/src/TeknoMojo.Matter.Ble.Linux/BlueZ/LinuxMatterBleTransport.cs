using System.Threading.Channels;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Ble;
using TeknoMojo.Matter.Ble.Linux.DBus;

namespace TeknoMojo.Matter.Ble.Linux.BlueZ;

/// <summary>
/// A live Matter-over-BLE (CHIPoBLE) connection over BlueZ: GATT service/characteristic
/// resolution, the BTP capabilities handshake, and an <see cref="IMatterTransport"/> built on
/// <see cref="BtpFragmentEngine"/>. Construct via <see cref="LinuxMatterBleCentral"/>, not
/// directly, so application code stays on the portable interfaces.
/// </summary>
public sealed class LinuxMatterBleTransport : IMatterTransport
{
    private static readonly string MatterServiceUuidLower = MatterBleUuids.Service.ToString();
    private static readonly string CharC1UuidLower = MatterBleUuids.CharacteristicC1Write.ToString();
    private static readonly string CharC2UuidLower = MatterBleUuids.CharacteristicC2Indicate.ToString();

    private readonly DBusConnection _conn;
    private readonly string _c1Path;
    private readonly string _c2Path;
    private readonly bool _c1WriteWithoutResponse;
    private readonly BtpFragmentEngine _btp;
    private readonly Channel<byte[]> _inboundMessages = Channel.CreateUnbounded<byte[]>();
    private EventHandler<byte[]>? _rawIndicationForHandshake;
    private bool _disposed;

    private LinuxMatterBleTransport(DBusConnection conn, string c1Path, string c2Path, bool c1WriteWithoutResponse, BtpFragmentEngine btp)
    {
        _conn = conn;
        _c1Path = c1Path;
        _c2Path = c2Path;
        _c1WriteWithoutResponse = c1WriteWithoutResponse;
        _btp = btp;
        _conn.SignalReceived += OnSignalReceived;
    }

    internal static async Task<LinuxMatterBleTransport> ConnectAsync(
        DBusConnection conn, string devicePath, TimeSpan? handshakeTimeout, CancellationToken ct)
    {
        await conn.CallAsync(BlueZObjects.Service, devicePath, BlueZObjects.DeviceInterface, "Connect", "", null, ct);

        (string c1Path, IReadOnlyDictionary<string, DBusValue> c1Props, string c2Path) = await ResolveGattCharacteristicsAsync(conn, devicePath, ct);

        bool writeWithoutResponse = false;
        if (c1Props.TryGetValue("Flags", out DBusValue? flagsValue) && flagsValue is DBusValue.Arr flagsArr)
            writeWithoutResponse = flagsArr.Items.Any(f => ((DBusValue.Str)f).Value == "write-without-response");

        ushort mtu = 23; // BLE 4.x default; BlueZ exposes a real MTU property once notifications/writes have happened once.
        if (c1Props.TryGetValue("MTU", out DBusValue? mtuValue) && mtuValue is DBusValue.UInt16 mtuU16 && mtuU16.Value > 0)
            mtu = mtuU16.Value;

        var btp = new BtpFragmentEngine(txFragmentSize: mtu - 3, rxFragmentSize: mtu - 3);
        var transport = new LinuxMatterBleTransport(conn, c1Path, c2Path, writeWithoutResponse, btp);
        try
        {
            await conn.CallAsync(BlueZObjects.Service, c2Path, BlueZObjects.GattCharacteristicInterface, "StartNotify", "", null, ct);
            await transport.RunHandshakeAsync(mtu, handshakeTimeout ?? TimeSpan.FromSeconds(10), ct);
        }
        catch
        {
            await transport.DisposeAsync();
            throw;
        }
        return transport;
    }

    private static async Task<(string c1Path, IReadOnlyDictionary<string, DBusValue> c1Props, string c2Path)> ResolveGattCharacteristicsAsync(
        DBusConnection conn, string devicePath, CancellationToken ct)
    {
        // BlueZ populates GATT child objects asynchronously after Connect(); poll briefly.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (true)
        {
            var objects = await BlueZObjects.GetManagedObjectsAsync(conn, ct);
            var underDevice = objects.Where(o => o.Path.StartsWith(devicePath + "/", StringComparison.Ordinal)).ToList();

            var service = underDevice.FirstOrDefault(o =>
                o.Implements(BlueZObjects.GattServiceInterface)
                && string.Equals(o.Properties(BlueZObjects.GattServiceInterface)!["UUID"].AsString(), MatterServiceUuidLower, StringComparison.OrdinalIgnoreCase));

            if (service is not null)
            {
                var chars = underDevice.Where(o =>
                    o.Implements(BlueZObjects.GattCharacteristicInterface)
                    && o.Properties(BlueZObjects.GattCharacteristicInterface)!["Service"].AsString() == service.Path)
                    .ToList();

                var c1 = chars.FirstOrDefault(o => string.Equals(
                    o.Properties(BlueZObjects.GattCharacteristicInterface)!["UUID"].AsString(), CharC1UuidLower, StringComparison.OrdinalIgnoreCase));
                var c2 = chars.FirstOrDefault(o => string.Equals(
                    o.Properties(BlueZObjects.GattCharacteristicInterface)!["UUID"].AsString(), CharC2UuidLower, StringComparison.OrdinalIgnoreCase));

                if (c1 is not null && c2 is not null)
                    return (c1.Path, c1.Properties(BlueZObjects.GattCharacteristicInterface)!, c2.Path);
            }

            if (DateTime.UtcNow >= deadline)
                throw new InvalidOperationException("CHIPoBLE GATT service/characteristics did not appear on the device within the timeout.");
            await Task.Delay(200, ct);
        }
    }

    private async Task RunHandshakeAsync(ushort mtu, TimeSpan timeout, CancellationToken ct)
    {
        var handshakeResponse = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        _rawIndicationForHandshake = (_, data) => handshakeResponse.TrySetResult(data);

        var request = BtpHandshake.CapabilitiesRequest.ForCurrentVersion(mtu, windowSize: 6);
        await WriteRawAsync(BtpHandshake.EncodeRequest(request), ct);

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

    private async Task WriteRawAsync(byte[] data, CancellationToken ct)
    {
        var options = _c1WriteWithoutResponse
            ? DBusValue.Dict(("type", new DBusValue.Str("command")))
            : DBusValue.EmptyArray("{sv}");
        await _conn.CallAsync(BlueZObjects.Service, _c1Path, BlueZObjects.GattCharacteristicInterface, "WriteValue",
            "aya{sv}", new DBusValue[] { DBusValue.ByteArray(data), options }, ct);
    }

    private void OnSignalReceived(object? sender, DBusMessage msg)
    {
        if (msg.Interface != BlueZObjects.PropertiesInterface || msg.Member != "PropertiesChanged" || msg.Path != _c2Path)
            return;
        if (msg.Body.Count < 2 || msg.Body[0].AsString() != BlueZObjects.GattCharacteristicInterface) return;

        var changed = (DBusValue.Arr)msg.Body[1];
        foreach (DBusValue item in changed.Items)
        {
            var entry = (DBusValue.DictEntry)item;
            if (entry.Key.AsString() != "Value") continue;
            byte[] data = entry.Value.Unwrap().AsByteArray();

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
    }

    public async Task SendMessageAsync(ReadOnlyMemory<byte> message, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        foreach (byte[] fragment in _btp.EncodeMessage(message.Span))
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
        _conn.SignalReceived -= OnSignalReceived;
        _inboundMessages.Writer.TryComplete();
        // Note: we do not close the underlying DBusConnection here — it's owned by
        // LinuxMatterBleCentral and shared across connections.
        return ValueTask.CompletedTask;
    }
}
