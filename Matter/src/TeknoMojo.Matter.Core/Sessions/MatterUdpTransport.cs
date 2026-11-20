using System.Net;
using System.Net.Sockets;

namespace TeknoMojo.Matter.Core.Sessions;

/// <summary>
/// <see cref="IMatterTransport"/> over UDP to a device's operational or commissionable IP
/// endpoint — the transport commissioning uses when a device is already reachable over IP
/// (Wi-Fi/Ethernet) rather than only over BLE, e.g. when an existing admin has opened a
/// commissioning window on a device that's already on the network. Each UDP datagram carries
/// exactly one Matter message; no MRP retransmission is implemented — the same simplification
/// <see cref="Messaging.MatterOperationalChannel"/> makes for TCP.
/// </summary>
/// <remarks>
/// Deliberately does NOT call <see cref="UdpClient.Connect(IPEndPoint)"/>: a connected
/// <see cref="UdpClient"/> silently discards any datagram not from the exact IP+port it
/// connected to, and some devices reply to a commissioning exchange from a different local port
/// than the one they're listening on. Using explicit <c>SendTo</c>/<c>ReceiveFrom</c> semantics
/// instead accepts a reply from any port on the target IP.
/// </remarks>
public sealed class MatterUdpTransport : IMatterTransport
{
    private readonly UdpClient _client;
    private readonly IPEndPoint _remoteEndpoint;

    private MatterUdpTransport(UdpClient client, IPEndPoint remoteEndpoint)
    {
        _client = client;
        _remoteEndpoint = remoteEndpoint;
    }

    /// <param name="endpoint">The device's IP and port.</param>
    /// <param name="localAddress">
    /// Optional local IP to bind the socket's source address to. On a multi-homed host (VPNs,
    /// Tailscale, virtual adapters), the OS routing table can send unicast traffic to a LAN
    /// address out the wrong interface even though multicast/mDNS discovery of that same device
    /// worked fine — binding to the known-good local interface's address avoids that. Leave null
    /// to let the OS pick.
    /// </param>
    public static Task<MatterUdpTransport> ConnectAsync(IPEndPoint endpoint, IPAddress? localAddress = null, CancellationToken ct = default)
    {
        var client = localAddress is null
            ? new UdpClient(0, endpoint.AddressFamily) // bind an ephemeral local port; do not Connect()
            : new UdpClient(new IPEndPoint(localAddress, 0));
        return Task.FromResult(new MatterUdpTransport(client, endpoint));
    }

    public async Task SendMessageAsync(ReadOnlyMemory<byte> message, CancellationToken ct = default)
        => await _client.SendAsync(message, _remoteEndpoint, ct);

    /// <summary>UDP carries no reliability of its own, so Matter's MRP applies here.</summary>
    public bool RequiresReliableMessaging => true;

    public async Task<byte[]> ReceiveMessageAsync(CancellationToken ct = default)
    {
        while (true)
        {
            UdpReceiveResult result = await _client.ReceiveAsync(ct);
            // Accept any reply from the target device's IP, regardless of source port.
            if (result.RemoteEndPoint.Address.Equals(_remoteEndpoint.Address))
                return result.Buffer;
        }
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }
}
