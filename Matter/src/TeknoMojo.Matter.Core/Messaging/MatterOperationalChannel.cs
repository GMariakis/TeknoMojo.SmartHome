using System.Buffers.Binary;

namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// A duplex channel to a Matter node's operational (post-commissioning) endpoint over TCP,
/// framing full Matter messages (outer header + encrypted payload) with the 4-byte
/// little-endian length prefix Matter's TCP transport uses (verified against
/// project-chip/connectedhomeip src/transport/raw/TCP.cpp). Encrypts/decrypts the payload via a
/// <see cref="MatterSecureSession"/> established by CASE.
/// </summary>
/// <remarks>
/// This is a simple half-duplex request/response channel — send one message, then read the
/// next — matching how a controller drives PASE/CASE/Interaction-Model exchanges one at a time.
/// It does not implement Matter's exchange-id multiplexing or MRP retransmission; those matter
/// for a peer juggling multiple concurrent exchanges, which a POC-grade single-purpose
/// controller does not need to.
/// </remarks>
public sealed class MatterOperationalChannel : IMatterMessageChannel, IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly MatterSecureSession _session;
    private readonly ulong _sourceNodeId;
    private readonly ulong _destinationNodeId;
    private ushort _exchangeId = 1;

    public MatterOperationalChannel(Stream stream, MatterSecureSession session, ulong sourceNodeId, ulong destinationNodeId)
    {
        _stream = stream;
        _session = session;
        _sourceNodeId = sourceNodeId;
        _destinationNodeId = destinationNodeId;
    }

    /// <summary>Allocate the next exchange id for a new request/response pair.</summary>
    public ushort NextExchangeId() => _exchangeId++;

    /// <summary>Send one Matter message: protocol header + payload, encrypted and length-framed.</summary>
    public async Task SendAsync(
        ushort protocolId, byte opcode, ushort exchangeId, ReadOnlyMemory<byte> payload,
        bool isInitiator = true, CancellationToken ct = default)
    {
        var protoHeader = new MatterProtocolHeader
        {
            ExchangeFlags = isInitiator ? MatterExchangeFlags.Initiator : MatterExchangeFlags.None,
            Opcode = opcode,
            ExchangeId = exchangeId,
            ProtocolId = protocolId,
        };
        byte[] protoBytes = MatterProtocolHeaderCodec.Encode(protoHeader, payload.Span);

        uint counter = _session.NextOutboundCounter();
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

        byte[] lengthPrefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)frame.Length);
        await _stream.WriteAsync(lengthPrefix, ct);
        await _stream.WriteAsync(frame, ct);
        await _stream.FlushAsync(ct);
    }

    /// <summary>Receive the next Matter message: decrypted protocol header plus payload.</summary>
    public async Task<(MatterProtocolHeader Header, byte[] Payload)> ReceiveAsync(CancellationToken ct = default)
    {
        byte[] lengthPrefix = await ReadExactAsync(4, ct);
        uint frameLength = BinaryPrimitives.ReadUInt32LittleEndian(lengthPrefix);
        byte[] frame = await ReadExactAsync((int)frameLength, ct);

        var msgHeader = MatterMessageCodec.DecodeHeader(frame, out int consumed);
        byte[] headerBytes = frame.AsSpan(0, consumed).ToArray();
        byte[] ciphertext = frame.AsSpan(consumed).ToArray();

        byte[] plaintext = _session.Decrypt.Decrypt(msgHeader.SecurityFlags, msgHeader.MessageCounter, headerBytes, ciphertext);
        var (protoHeader, offset) = MatterProtocolHeaderCodec.Decode(plaintext);
        byte[] payload = plaintext.AsSpan(offset).ToArray();
        return (protoHeader, payload);
    }

    private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
    {
        var buf = new byte[count];
        int total = 0;
        while (total < count)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(total), ct);
            if (n <= 0) throw new EndOfStreamException("Matter operational channel closed while reading a frame.");
            total += n;
        }
        return buf;
    }

    public async ValueTask DisposeAsync()
    {
        _session.Dispose();
        await _stream.DisposeAsync();
    }
}
