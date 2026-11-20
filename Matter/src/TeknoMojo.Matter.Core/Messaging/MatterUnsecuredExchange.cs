namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// One unsecured Secure Channel exchange — PASE or CASE — with Message Reliability Protocol
/// applied when the transport needs it (Spec §4.12).
/// </summary>
/// <remarks>
/// Session establishment happens before there is a session to encrypt with, so both PASE and
/// CASE frame their messages the same plain way. Sharing this keeps the reliability rules in one
/// place: over UDP every message asks to be acknowledged and is retransmitted on the spec's
/// backoff until it is, while over BTP — which acknowledges its own fragments — none of that
/// applies and the exchange is a plain send and receive.
/// </remarks>
public sealed class MatterUnsecuredExchange(
    IMatterTransport transport,
    ulong? sourceNodeId = null,
    ushort exchangeId = 0)
{
    private readonly bool _useMrp = transport.RequiresReliableMessaging;
    private uint _messageCounter = (uint)Random.Shared.Next(1, int.MaxValue);
    private byte[]? _unackedFrame;
    private uint _unackedCounter;
    private int _transmissions;

    /// <summary>Reliability policy for this exchange, so a peer's advertised intervals can be adopted.</summary>
    public MatterMrp Mrp { get; } = new();

    /// <summary>
    /// Overall budget for a single request/response step. A peer that accepts a message and never
    /// answers it has to surface as a named timeout rather than a hang.
    /// </summary>
    public TimeSpan StepTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Send one Secure Channel message. Bare acknowledgements pass <paramref name="reliable"/> as
    /// false: a message that only acknowledges must never ask to be acknowledged in turn, or two
    /// peers acknowledge each other indefinitely.
    /// </summary>
    public async Task SendAsync(byte opcode, byte[] payload, CancellationToken ct, bool reliable = true)
    {
        var flags = MatterExchangeFlags.Initiator;
        uint? ack = null;
        if (_useMrp)
        {
            if (reliable) flags |= MatterExchangeFlags.ReliabilityRequested;
            ack = Mrp.TakePendingAck();
            if (ack is not null) flags |= MatterExchangeFlags.AckPresent;
        }

        var protoHeader = new MatterProtocolHeader
        {
            ExchangeFlags = flags,
            Opcode = opcode,
            ExchangeId = exchangeId,
            ProtocolId = MatterProtocolIds.SecureChannel,
            AckMessageCounter = ack,
        };
        byte[] protoBytes = MatterProtocolHeaderCodec.Encode(protoHeader, payload);

        uint counter = _messageCounter++;
        var msgHeader = new MatterMessageHeader
        {
            // An accessory was observed accepting a session-establishment message at the
            // transport layer and then discarding it for want of a source node, so we always
            // identify ourselves even though we are not yet a node on any fabric.
            Flags = sourceNodeId is null ? MatterMessageFlags.None : MatterMessageFlags.SourceNodeIdPresent,
            SourceNodeId = sourceNodeId,
            SessionId = 0,
            SecurityFlags = MatterSecurityFlags.SessionTypeUnicast,
            MessageCounter = counter,
        };
        byte[] headerBytes = MatterMessageCodec.EncodeHeader(msgHeader);

        byte[] frame = new byte[headerBytes.Length + protoBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, frame, 0, headerBytes.Length);
        Buffer.BlockCopy(protoBytes, 0, frame, headerBytes.Length, protoBytes.Length);

        if (_useMrp && reliable)
        {
            _unackedFrame = frame;
            _unackedCounter = counter;
            _transmissions = 1;
        }

        await transport.SendMessageAsync(frame, ct);
    }

    /// <summary>
    /// Wait for the next message carrying an application payload, retransmitting anything still
    /// unacknowledged meanwhile and quietly absorbing bare acknowledgements and duplicates.
    /// </summary>
    /// <param name="expectedOpcode">The opcode this step of the handshake requires.</param>
    /// <param name="step">Human-readable step name, used if this times out.</param>
    public async Task<byte[]> ReceiveAsync(byte expectedOpcode, string step, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(StepTimeout);

        while (true)
        {
            byte[] frame;
            try
            {
                frame = await ReceiveWithRetransmissionAsync(cts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"Timed out after {StepTimeout.TotalSeconds:0}s waiting for {step}. " +
                    "The peer accepted our message at the transport layer but never answered it.");
            }

            var msgHeader = MatterMessageCodec.DecodeHeader(frame, out int consumed);
            byte[] plaintext = frame.AsSpan(consumed).ToArray();
            var (protoHeader, offset) = MatterProtocolHeaderCodec.Decode(plaintext);

            if (_useMrp)
            {
                bool fresh = Mrp.AcceptInbound(msgHeader, protoHeader);
                if (protoHeader.AckMessageCounter == _unackedCounter)
                    _unackedFrame = null;

                bool standaloneAck = protoHeader.ProtocolId == MatterProtocolIds.SecureChannel
                                  && protoHeader.Opcode == MatterSecureChannelOpcodes.MrpStandaloneAck;
                if (standaloneAck || !fresh)
                    continue;
            }

            if (protoHeader.Opcode == MatterSecureChannelOpcodes.StatusReport && expectedOpcode != MatterSecureChannelOpcodes.StatusReport)
                throw new InvalidOperationException(
                    $"{step}: responder sent a StatusReport instead of the expected message.");
            if (protoHeader.Opcode != expectedOpcode)
                throw new InvalidOperationException(
                    $"{step}: expected opcode 0x{expectedOpcode:X2}, got 0x{protoHeader.Opcode:X2}.");

            return plaintext.AsSpan(offset).ToArray();
        }
    }

    /// <summary>
    /// Acknowledge anything outstanding with a message of its own. Needed where an exchange ends
    /// on the peer's message and there is nothing left to piggyback on, or it keeps retransmitting.
    /// </summary>
    public async Task FlushAckAsync(CancellationToken ct)
    {
        if (!_useMrp || !Mrp.HasPendingAck) return;
        await SendAsync(MatterSecureChannelOpcodes.MrpStandaloneAck, [], ct, reliable: false);
    }

    private async Task<byte[]> ReceiveWithRetransmissionAsync(CancellationToken ct)
    {
        if (!_useMrp || _unackedFrame is null)
            return await transport.ReceiveMessageAsync(ct);

        while (true)
        {
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
            attempt.CancelAfter(Mrp.ComputeBackoff(_transmissions));
            try
            {
                return await transport.ReceiveMessageAsync(attempt.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                if (_transmissions >= MatterMrp.MaxTransmissions)
                    throw new TimeoutException(
                        $"No acknowledgement after {MatterMrp.MaxTransmissions} transmissions; the peer is not responding.");

                _transmissions++;
                await transport.SendMessageAsync(_unackedFrame, ct);
            }
        }
    }
}
