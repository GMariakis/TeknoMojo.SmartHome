namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// A duplex channel for exchanging protocol-header-wrapped, encrypted Matter application
/// messages — the shape <see cref="InteractionModel.MatterInteractionClient"/> needs, regardless
/// of whether the underlying link is a raw TCP stream (<see cref="MatterOperationalChannel"/>)
/// or a message-oriented commissioning transport like BLE (<see cref="MatterSecureMessageChannel"/>).
/// </summary>
public interface IMatterMessageChannel
{
    ushort NextExchangeId();

    Task SendAsync(
        ushort protocolId, byte opcode, ushort exchangeId, ReadOnlyMemory<byte> payload,
        bool isInitiator = true, CancellationToken ct = default);

    Task<(MatterProtocolHeader Header, byte[] Payload)> ReceiveAsync(CancellationToken ct = default);
}
