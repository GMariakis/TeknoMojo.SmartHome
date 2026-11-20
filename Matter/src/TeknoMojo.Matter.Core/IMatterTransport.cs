namespace TeknoMojo.Matter.Core;

/// <summary>
/// A message-oriented duplex channel to a Matter node, abstracting over the underlying link
/// (BLE/BTP during commissioning, TCP/UDP for an operational session post-commissioning).
/// Each <see cref="SendMessageAsync"/>/<see cref="ReceiveMessageAsync"/> call carries one
/// complete Matter message — any link-layer fragmentation is handled internally by the
/// implementation and never leaks through this interface.
/// </summary>
public interface IMatterTransport : IAsyncDisposable
{
    /// <summary>Send one complete Matter message.</summary>
    Task SendMessageAsync(ReadOnlyMemory<byte> message, CancellationToken ct = default);

    /// <summary>Receive the next complete Matter message.</summary>
    Task<byte[]> ReceiveMessageAsync(CancellationToken ct = default);

    /// <summary>
    /// True when the link provides no reliability of its own and Matter's Message Reliability
    /// Protocol must therefore be used (Spec §4.12) — that is, UDP. BTP acknowledges and windows
    /// its own fragments and TCP is a reliable stream, so both leave MRP switched off.
    /// </summary>
    bool RequiresReliableMessaging => false;
}
