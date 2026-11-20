using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace TeknoMojo.Matter.Ble.Linux.DBus;

/// <summary>
/// A minimal hand-rolled D-Bus client: connects to the system bus over its Unix domain socket,
/// authenticates with the SASL EXTERNAL mechanism (the standard local-user auth every D-Bus
/// system bus supports), and pumps messages for method calls and signal subscriptions. No
/// third-party D-Bus library — only what BlueZ's API surface actually needs.
/// </summary>
internal sealed class DBusConnection : IAsyncDisposable
{
    [DllImport("libc", SetLastError = true)]
    private static extern uint getuid();

    private readonly Socket _socket;
    private readonly NetworkStream _stream;
    private uint _nextSerial = 1;
    private readonly Dictionary<uint, TaskCompletionSource<DBusMessage>> _pending = new();
    private readonly object _pendingLock = new();
    private Task? _readLoop;
    private CancellationTokenSource? _readLoopCts;

    public event EventHandler<DBusMessage>? SignalReceived;

    private DBusConnection(Socket socket, NetworkStream stream)
    {
        _socket = socket;
        _stream = stream;
    }

    /// <summary>Connect to the system bus (where BlueZ lives) and complete the SASL handshake + Hello.</summary>
    public static async Task<DBusConnection> ConnectSystemBusAsync(CancellationToken ct = default)
    {
        string socketPath = ResolveSystemBusSocketPath();
        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct);
        var stream = new NetworkStream(socket, ownsSocket: false);

        var conn = new DBusConnection(socket, stream);
        await conn.AuthenticateAsync(ct);
        conn.StartReadLoop();
        await conn.CallAsync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", Array.Empty<DBusValue>(), ct);
        return conn;
    }

    private static string ResolveSystemBusSocketPath()
    {
        string? addr = Environment.GetEnvironmentVariable("DBUS_SYSTEM_BUS_ADDRESS");
        if (!string.IsNullOrEmpty(addr))
        {
            // Format: "unix:path=/run/dbus/system_bus_socket" (possibly with more ";"-separated options).
            foreach (string part in addr.Split(';'))
            {
                int eq = part.IndexOf("path=", StringComparison.Ordinal);
                if (eq >= 0) return part.Substring(eq + "path=".Length);
            }
        }
        if (File.Exists("/run/dbus/system_bus_socket")) return "/run/dbus/system_bus_socket";
        return "/var/run/dbus/system_bus_socket";
    }

    private async Task AuthenticateAsync(CancellationToken ct)
    {
        // SASL EXTERNAL: the identity is the ASCII-decimal UID, itself hex-encoded byte-by-byte.
        uint uid = getuid();
        string uidDecimal = uid.ToString();
        string uidHex = Convert.ToHexString(Encoding.ASCII.GetBytes(uidDecimal)).ToLowerInvariant();

        await WriteLineAsync(new byte[] { 0 }, isRaw: true, ct); // initial NUL byte, required before the first SASL command
        await WriteLineAsync(Encoding.ASCII.GetBytes($"AUTH EXTERNAL {uidHex}"), isRaw: false, ct);

        string response = await ReadLineAsync(ct);
        if (!response.StartsWith("OK ", StringComparison.Ordinal))
            throw new InvalidOperationException($"D-Bus SASL auth failed: server said \"{response}\".");

        await WriteLineAsync(Encoding.ASCII.GetBytes("BEGIN"), isRaw: false, ct);
        // From here on, the stream is binary D-Bus protocol — no more SASL lines.
    }

    private async Task WriteLineAsync(byte[] content, bool isRaw, CancellationToken ct)
    {
        byte[] toSend = isRaw ? content : content.Concat(new byte[] { (byte)'\r', (byte)'\n' }).ToArray();
        await _stream.WriteAsync(toSend, ct);
        await _stream.FlushAsync(ct);
    }

    private async Task<string> ReadLineAsync(CancellationToken ct)
    {
        var bytes = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            int n = await _stream.ReadAsync(one, ct);
            if (n == 0) throw new EndOfStreamException("D-Bus connection closed during SASL handshake.");
            if (one[0] == (byte)'\n')
            {
                if (bytes.Count > 0 && bytes[^1] == (byte)'\r') bytes.RemoveAt(bytes.Count - 1);
                break;
            }
            bytes.Add(one[0]);
        }
        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    // ------------------------------------------------------------------ method calls

    public async Task<List<DBusValue>> CallAsync(
        string? destination, string path, string iface, string member,
        string bodySignature = "", IReadOnlyList<DBusValue>? body = null, CancellationToken ct = default)
    {
        var msg = DBusMessage.MethodCall(destination, path, iface, member, bodySignature, body);
        uint serial = Interlocked.Increment(ref _nextSerial);
        msg.Serial = serial;

        var tcs = new TaskCompletionSource<DBusMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_pendingLock) _pending[serial] = tcs;

        byte[] wire = msg.Serialize();
        try
        {
            await _stream.WriteAsync(wire, ct);
            await _stream.FlushAsync(ct);
        }
        catch
        {
            lock (_pendingLock) _pending.Remove(serial);
            throw;
        }

        using var reg = ct.Register(() => tcs.TrySetCanceled());
        DBusMessage reply = await tcs.Task;

        if (reply.Type == DBusMessageType.Error)
        {
            string detail = reply.Body.Count > 0 && reply.Body[0] is DBusValue.Str s ? s.Value : "(no message)";
            throw new DBusCallException(reply.ErrorName ?? "org.freedesktop.DBus.Error.Failed", detail);
        }
        return reply.Body;
    }

    public Task AddMatchAsync(string rule, CancellationToken ct = default) =>
        CallAsync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch",
            "s", new DBusValue[] { new DBusValue.Str(rule) }, ct);

    // ------------------------------------------------------------------ read loop

    private void StartReadLoop()
    {
        _readLoopCts = new CancellationTokenSource();
        _readLoop = Task.Run(() => ReadLoopAsync(_readLoopCts.Token));
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var buffer = new List<byte>(4096);
        var chunk = new byte[4096];

        while (!ct.IsCancellationRequested)
        {
            while (buffer.Count < 16 || !DBusMessage.TryGetTotalLength(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(buffer), out int need) || buffer.Count < need)
            {
                int n = await _stream.ReadAsync(chunk, ct);
                if (n == 0) return; // connection closed
                buffer.AddRange(chunk.AsSpan(0, n).ToArray());
            }

            DBusMessage.TryGetTotalLength(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(buffer), out int total);
            byte[] messageBytes = buffer.GetRange(0, total).ToArray();
            buffer.RemoveRange(0, total);

            DBusMessage msg;
            try { msg = DBusMessage.Parse(messageBytes); }
            catch { continue; } // drop unparsable frames rather than killing the whole connection

            if (msg.Type is DBusMessageType.MethodReturn or DBusMessageType.Error && msg.ReplySerial is { } rs)
            {
                TaskCompletionSource<DBusMessage>? tcs;
                lock (_pendingLock)
                {
                    _pending.Remove(rs, out tcs);
                }
                tcs?.TrySetResult(msg);
            }
            else if (msg.Type == DBusMessageType.Signal)
            {
                SignalReceived?.Invoke(this, msg);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _readLoopCts?.Cancel();
        if (_readLoop is not null)
        {
            try { await _readLoop; } catch { /* ignore */ }
        }
        _stream.Dispose();
        _socket.Dispose();
    }
}

internal sealed class DBusCallException : Exception
{
    public string DBusErrorName { get; }
    public DBusCallException(string errorName, string message) : base($"{errorName}: {message}") => DBusErrorName = errorName;
}
