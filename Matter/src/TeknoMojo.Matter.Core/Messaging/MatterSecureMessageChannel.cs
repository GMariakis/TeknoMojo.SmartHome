namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// <see cref="IMatterMessageChannel"/> over a message-oriented <see cref="IMatterTransport"/>
/// (BLE/BTP during commissioning) rather than a raw byte stream. No length-prefix framing is
/// needed here — the transport already delivers one complete message per call — but the same
/// outer message header + protocol header + AES-CCM encryption applies as over TCP.
/// </summary>
public sealed class MatterSecureMessageChannel : IMatterMessageChannel, IAsyncDisposable
{
    private readonly IMatterTransport _transport;
    private readonly MatterSecureSession _session;
    private ushort _exchangeId = 1;

    // MRP state. Inert unless the transport needs it (UDP); over BTP the link is already reliable.
    private readonly MatterMrp _mrp = new();
    private readonly bool _useMrp;
    private byte[]? _unackedFrame;
    private uint _unackedCounter;
    private int _transmissions;

    public MatterSecureMessageChannel(IMatterTransport transport, MatterSecureSession session)
    {
        _transport = transport;
        _session = session;
        _useMrp = transport.RequiresReliableMessaging;
    }

    /// <summary>MRP policy for this session, so a peer's advertised intervals can be adopted.</summary>
    public MatterMrp Mrp => _mrp;

    public ushort NextExchangeId() => _exchangeId++;

    public async Task SendAsync(
        ushort protocolId, byte opcode, ushort exchangeId, ReadOnlyMemory<byte> payload,
        bool isInitiator = true, CancellationToken ct = default)
    {
        byte[] frame = BuildFrame(protocolId, opcode, exchangeId, payload.Span, isInitiator,
            reliable: _useMrp, out uint counter);

        if (_useMrp)
        {
            _unackedFrame = frame;
            _unackedCounter = counter;
            _transmissions = 1;
        }

        await _transport.SendMessageAsync(frame, ct);
    }

    private byte[] BuildFrame(
        ushort protocolId, byte opcode, ushort exchangeId, ReadOnlySpan<byte> payload,
        bool isInitiator, bool reliable, out uint counter)
    {
        var flags = isInitiator ? MatterExchangeFlags.Initiator : MatterExchangeFlags.None;
        if (reliable) flags |= MatterExchangeFlags.ReliabilityRequested;

        // Any acknowledgement we owe rides along rather than costing a separate message.
        uint? ack = _useMrp ? _mrp.TakePendingAck() : null;
        if (ack is not null) flags |= MatterExchangeFlags.AckPresent;

        var protoHeader = new MatterProtocolHeader
        {
            ExchangeFlags = flags,
            Opcode = opcode,
            ExchangeId = exchangeId,
            ProtocolId = protocolId,
            AckMessageCounter = ack,
        };
        byte[] protoBytes = MatterProtocolHeaderCodec.Encode(protoHeader, payload);

        counter = _session.NextOutboundCounter();
        var msgHeader = new MatterMessageHeader
        {
            Flags = MatterMessageFlags.None,
            SessionId = _session.PeerSessionId,
            SecurityFlags = MatterSecurityFlags.SessionTypeUnicast,
            MessageCounter = counter,
        };
        byte[] headerBytes = MatterMessageCodec.EncodeHeader(msgHeader);
        byte[] encrypted = _session.Encrypt.Encrypt(msgHeader.SecurityFlags, counter, headerBytes, protoBytes);

        byte[] frame = new byte[headerBytes.Length + encrypted.Length];
        Buffer.BlockCopy(headerBytes, 0, frame, 0, headerBytes.Length);
        Buffer.BlockCopy(encrypted, 0, frame, headerBytes.Length, encrypted.Length);
        return frame;
    }

    /// <summary>
    /// Acknowledge the peer without any payload of our own (Secure Channel opcode 0x10). Needed
    /// when an exchange ends on a message from the peer, since otherwise it keeps retransmitting.
    /// </summary>
    private async Task SendStandaloneAckAsync(CancellationToken ct)
    {
        if (!_useMrp || !_mrp.HasPendingAck) return;
        byte[] frame = BuildFrame(
            MatterProtocolIds.SecureChannel, MatterSecureChannelOpcodes.MrpStandaloneAck,
            _exchangeId, ReadOnlySpan<byte>.Empty, isInitiator: true, reliable: false, out _);
        await _transport.SendMessageAsync(frame, ct);
    }

    public async Task<(MatterProtocolHeader Header, byte[] Payload)> ReceiveAsync(CancellationToken ct = default)
    {
        while (true)
        {
            byte[]? frame = await ReceiveFrameWithRetransmissionAsync(ct);

            var msgHeader = MatterMessageCodec.DecodeHeader(frame, out int consumed);
            byte[] headerBytes = frame.AsSpan(0, consumed).ToArray();
            byte[] ciphertext = frame.AsSpan(consumed).ToArray();

            byte[] plaintext = _session.Decrypt.Decrypt(msgHeader.SecurityFlags, msgHeader.MessageCounter, headerBytes, ciphertext);
            var (protoHeader, offset) = MatterProtocolHeaderCodec.Decode(plaintext);

            if (!_useMrp)
                return (protoHeader, plaintext.AsSpan(offset).ToArray());

            bool fresh = _mrp.AcceptInbound(msgHeader, protoHeader);

            if (protoHeader.AckMessageCounter == _unackedCounter)
                _unackedFrame = null;

            // A bare acknowledgement carries no application payload, and a duplicate has already
            // been delivered once — in both cases keep waiting for the real response, having
            // noted that the peer still wants acknowledging.
            bool standaloneAck = protoHeader.ProtocolId == MatterProtocolIds.SecureChannel
                              && protoHeader.Opcode == MatterSecureChannelOpcodes.MrpStandaloneAck;
            if (standaloneAck || !fresh)
                continue;

            return (protoHeader, plaintext.AsSpan(offset).ToArray());
        }
    }

    /// <summary>
    /// Wait for the next frame, retransmitting anything still unacknowledged on the spec's
    /// backoff schedule until the peer answers or we run out of attempts.
    /// </summary>
    private async Task<byte[]> ReceiveFrameWithRetransmissionAsync(CancellationToken ct)
    {
        if (!_useMrp || _unackedFrame is null)
            return await _transport.ReceiveMessageAsync(ct);

        while (true)
        {
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
            attempt.CancelAfter(_mrp.ComputeBackoff(_transmissions));
            try
            {
                return await _transport.ReceiveMessageAsync(attempt.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                if (_transmissions >= MatterMrp.MaxTransmissions)
                    throw new TimeoutException(
                        $"No acknowledgement after {MatterMrp.MaxTransmissions} transmissions; the peer is not responding.");

                _transmissions++;
                await _transport.SendMessageAsync(_unackedFrame, ct);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Leaving an acknowledgement owed would have the peer retransmit into a closed session.
        try { await SendStandaloneAckAsync(CancellationToken.None); }
        catch { /* the session is going away regardless */ }

        _session.Dispose();
        await _transport.DisposeAsync();
    }
}
