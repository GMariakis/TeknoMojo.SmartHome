using System.Buffers.Binary;

namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// Wire codec for the Matter outer message header (Spec §4.4.1). Byte-exact encoder and
/// decoder; the encoder returns the length in bytes so callers can use the encoded header as
/// AAD when they run AES-CCM on the payload.
/// </summary>
public static class MatterMessageCodec
{
    /// <summary>Minimum message-header size: flags + session id + security flags + counter = 8 bytes.</summary>
    public const int MinHeaderSize = 1 + 2 + 1 + 4;

    /// <summary>
    /// Encode the message header (no payload). Returns the bytes; callers who need the header
    /// as AAD for AEAD should keep this buffer around.
    /// </summary>
    public static byte[] EncodeHeader(MatterMessageHeader header)
    {
        int destLen = (header.Flags & MatterMessageFlags.DestNodeId) != 0 ? 8
                     : (header.Flags & MatterMessageFlags.DestGroupId) != 0 ? 2
                     : 0;
        int srcLen = (header.Flags & MatterMessageFlags.SourceNodeIdPresent) != 0 ? 8 : 0;

        var buf = new byte[MinHeaderSize + srcLen + destLen];
        int pos = 0;
        buf[pos++] = (byte)header.Flags;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), header.SessionId); pos += 2;
        buf[pos++] = (byte)header.SecurityFlags;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(pos, 4), header.MessageCounter); pos += 4;

        if (srcLen > 0)
        {
            if (header.SourceNodeId is null)
                throw new InvalidOperationException("SourceNodeIdPresent flag set but SourceNodeId is null");
            BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos, 8), header.SourceNodeId.Value);
            pos += 8;
        }

        if (destLen == 8)
        {
            if (header.DestinationNodeId is null)
                throw new InvalidOperationException("DestNodeId flag set but DestinationNodeId is null");
            BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos, 8), header.DestinationNodeId.Value);
        }
        else if (destLen == 2)
        {
            if (header.DestinationGroupId is null)
                throw new InvalidOperationException("DestGroupId flag set but DestinationGroupId is null");
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), header.DestinationGroupId.Value);
        }

        return buf;
    }

    /// <summary>
    /// Decode the message header from the start of <paramref name="frame"/>. On return,
    /// <paramref name="consumed"/> is the number of bytes the header occupied — the ciphertext
    /// (or plaintext, for unsecured messages) starts at that offset.
    /// </summary>
    public static MatterMessageHeader DecodeHeader(ReadOnlySpan<byte> frame, out int consumed)
    {
        if (frame.Length < MinHeaderSize) throw new FormatException("Matter frame too short for header");

        int pos = 0;
        var flags = (MatterMessageFlags)frame[pos++];
        ushort sessionId = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(pos, 2)); pos += 2;
        var secFlags = (MatterSecurityFlags)frame[pos++];
        uint counter = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(pos, 4)); pos += 4;

        ulong? srcId = null;
        if ((flags & MatterMessageFlags.SourceNodeIdPresent) != 0)
        {
            if (pos + 8 > frame.Length) throw new FormatException("truncated source node id");
            srcId = BinaryPrimitives.ReadUInt64LittleEndian(frame.Slice(pos, 8));
            pos += 8;
        }

        ulong? destNodeId = null;
        ushort? destGroupId = null;
        if ((flags & MatterMessageFlags.DestNodeId) != 0)
        {
            if (pos + 8 > frame.Length) throw new FormatException("truncated destination node id");
            destNodeId = BinaryPrimitives.ReadUInt64LittleEndian(frame.Slice(pos, 8));
            pos += 8;
        }
        else if ((flags & MatterMessageFlags.DestGroupId) != 0)
        {
            if (pos + 2 > frame.Length) throw new FormatException("truncated destination group id");
            destGroupId = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(pos, 2));
            pos += 2;
        }

        consumed = pos;
        return new MatterMessageHeader
        {
            Flags = flags,
            SessionId = sessionId,
            SecurityFlags = secFlags,
            MessageCounter = counter,
            SourceNodeId = srcId,
            DestinationNodeId = destNodeId,
            DestinationGroupId = destGroupId,
        };
    }
}

/// <summary>
/// Wire codec for the protocol header (Spec §4.4.1.6) — the "inner" header carried at the
/// start of the (encrypted or plaintext) payload.
/// </summary>
public static class MatterProtocolHeaderCodec
{
    /// <summary>Minimum protocol-header size: flags + opcode + exchange id + protocol id = 6 bytes.</summary>
    public const int MinHeaderSize = 1 + 1 + 2 + 2;

    public static byte[] Encode(MatterProtocolHeader header, ReadOnlySpan<byte> appPayload)
    {
        int vendorLen = (header.ExchangeFlags & MatterExchangeFlags.VendorPresent) != 0 ? 2 : 0;
        int ackLen = (header.ExchangeFlags & MatterExchangeFlags.AckPresent) != 0 ? 4 : 0;

        var buf = new byte[MinHeaderSize + vendorLen + ackLen + appPayload.Length];
        int pos = 0;
        buf[pos++] = (byte)header.ExchangeFlags;
        buf[pos++] = header.Opcode;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), header.ExchangeId); pos += 2;

        if (vendorLen > 0)
        {
            if (header.VendorId is null)
                throw new InvalidOperationException("VendorPresent flag set but VendorId is null");
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), header.VendorId.Value); pos += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), header.ProtocolId); pos += 2;
        }
        else
        {
            BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), header.ProtocolId); pos += 2;
        }

        if (ackLen > 0)
        {
            if (header.AckMessageCounter is null)
                throw new InvalidOperationException("AckPresent flag set but AckMessageCounter is null");
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(pos, 4), header.AckMessageCounter.Value); pos += 4;
        }

        appPayload.CopyTo(buf.AsSpan(pos));
        return buf;
    }

    /// <summary>Decode the protocol header at the start of <paramref name="payload"/>; returns the header and the app-payload slice offset.</summary>
    public static (MatterProtocolHeader Header, int AppPayloadOffset) Decode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < MinHeaderSize) throw new FormatException("Matter payload too short for protocol header");

        int pos = 0;
        var flags = (MatterExchangeFlags)payload[pos++];
        byte opcode = payload[pos++];
        ushort exchangeId = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos, 2)); pos += 2;

        ushort? vendorId = null;
        ushort protocolId;
        if ((flags & MatterExchangeFlags.VendorPresent) != 0)
        {
            if (pos + 4 > payload.Length) throw new FormatException("truncated vendor+protocol id");
            vendorId = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos, 2)); pos += 2;
            protocolId = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos, 2)); pos += 2;
        }
        else
        {
            if (pos + 2 > payload.Length) throw new FormatException("truncated protocol id");
            protocolId = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(pos, 2)); pos += 2;
        }

        uint? ackCounter = null;
        if ((flags & MatterExchangeFlags.AckPresent) != 0)
        {
            if (pos + 4 > payload.Length) throw new FormatException("truncated ack counter");
            ackCounter = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(pos, 4)); pos += 4;
        }

        var header = new MatterProtocolHeader
        {
            ExchangeFlags = flags,
            Opcode = opcode,
            ExchangeId = exchangeId,
            ProtocolId = protocolId,
            VendorId = vendorId,
            AckMessageCounter = ackCounter,
        };
        return (header, pos);
    }
}
