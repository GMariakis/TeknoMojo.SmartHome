using System.Buffers.Binary;
using System.Text;

namespace TeknoMojo.Matter.Core.Tlv;

/// <summary>
/// Streaming encoder for the Matter TLV format (Matter Core Spec Appendix A).
/// Values are little-endian; integer types automatically choose the narrowest width that
/// preserves the value's exact meaning (per §A.2.4). Callers push elements one at a time and
/// balance container start/end calls; the writer validates neither ordering nor tag legality
/// beyond the wire format itself (that's a layer up).
/// </summary>
public sealed class MatterTlvWriter
{
    private byte[] _buffer;
    private int _pos;

    /// <summary>Number of bytes written so far.</summary>
    public int Length => _pos;

    public MatterTlvWriter(int initialCapacity = 256)
    {
        _buffer = new byte[Math.Max(16, initialCapacity)];
    }

    /// <summary>Return a copy of the encoded bytes.</summary>
    public byte[] ToArray() => _buffer.AsSpan(0, _pos).ToArray();

    /// <summary>Return a view of the encoded bytes (no copy). Valid until the next write.</summary>
    public ReadOnlySpan<byte> AsSpan() => _buffer.AsSpan(0, _pos);

    // ------------------ primitives ------------------

    public void WriteSignedInt(MatterTag tag, long value)
    {
        MatterTlvElementType type = value switch
        {
            >= sbyte.MinValue and <= sbyte.MaxValue => MatterTlvElementType.SignedInt1,
            >= short.MinValue and <= short.MaxValue => MatterTlvElementType.SignedInt2,
            >= int.MinValue and <= int.MaxValue => MatterTlvElementType.SignedInt4,
            _ => MatterTlvElementType.SignedInt8,
        };
        WriteHead(tag, type);
        switch (type)
        {
            case MatterTlvElementType.SignedInt1: WriteRaw((byte)(sbyte)value); break;
            case MatterTlvElementType.SignedInt2: WriteRawShortLE((short)value); break;
            case MatterTlvElementType.SignedInt4: WriteRawIntLE((int)value); break;
            case MatterTlvElementType.SignedInt8: WriteRawLongLE(value); break;
        }
    }

    public void WriteUnsignedInt(MatterTag tag, ulong value)
    {
        MatterTlvElementType type = value switch
        {
            <= byte.MaxValue => MatterTlvElementType.UnsignedInt1,
            <= ushort.MaxValue => MatterTlvElementType.UnsignedInt2,
            <= uint.MaxValue => MatterTlvElementType.UnsignedInt4,
            _ => MatterTlvElementType.UnsignedInt8,
        };
        WriteHead(tag, type);
        switch (type)
        {
            case MatterTlvElementType.UnsignedInt1: WriteRaw((byte)value); break;
            case MatterTlvElementType.UnsignedInt2: WriteRawUShortLE((ushort)value); break;
            case MatterTlvElementType.UnsignedInt4: WriteRawUIntLE((uint)value); break;
            case MatterTlvElementType.UnsignedInt8: WriteRawULongLE(value); break;
        }
    }

    public void WriteBool(MatterTag tag, bool value)
        => WriteHead(tag, value ? MatterTlvElementType.BooleanTrue : MatterTlvElementType.BooleanFalse);

    public void WriteFloat(MatterTag tag, float value)
    {
        WriteHead(tag, MatterTlvElementType.Float);
        WriteRawUIntLE(BitConverter.SingleToUInt32Bits(value));
    }

    public void WriteDouble(MatterTag tag, double value)
    {
        WriteHead(tag, MatterTlvElementType.Double);
        WriteRawULongLE(BitConverter.DoubleToUInt64Bits(value));
    }

    public void WriteNull(MatterTag tag) => WriteHead(tag, MatterTlvElementType.Null);

    public void WriteUtf8String(MatterTag tag, string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        (MatterTlvElementType t, int widthBytes) = ChooseUtf8Type(byteCount);
        WriteHead(tag, t);
        WriteLength(widthBytes, (ulong)byteCount);
        Ensure(byteCount);
        Encoding.UTF8.GetBytes(value, _buffer.AsSpan(_pos, byteCount));
        _pos += byteCount;
    }

    public void WriteByteString(MatterTag tag, ReadOnlySpan<byte> value)
    {
        (MatterTlvElementType t, int widthBytes) = ChooseByteStringType(value.Length);
        WriteHead(tag, t);
        WriteLength(widthBytes, (ulong)value.Length);
        Ensure(value.Length);
        value.CopyTo(_buffer.AsSpan(_pos, value.Length));
        _pos += value.Length;
    }

    // ------------------ containers ------------------

    public void StartStructure(MatterTag tag) => WriteHead(tag, MatterTlvElementType.Structure);
    public void StartArray(MatterTag tag) => WriteHead(tag, MatterTlvElementType.Array);
    public void StartList(MatterTag tag) => WriteHead(tag, MatterTlvElementType.List);

    /// <summary>End the innermost container. Emits the terminator byte 0x18.</summary>
    public void EndContainer()
    {
        Ensure(1);
        _buffer[_pos++] = (byte)MatterTlvElementType.EndOfContainer;
    }

    // ------------------ head (control + tag) ------------------

    private void WriteHead(MatterTag tag, MatterTlvElementType elementType)
    {
        byte control = (byte)(((byte)tag.Control << 5) | ((byte)elementType & 0x1F));
        Ensure(1 + tag.SerializedTagLength);
        _buffer[_pos++] = control;

        switch (tag.Control)
        {
            case MatterTlvTagControl.Anonymous:
                break;
            case MatterTlvTagControl.ContextSpecific:
                _buffer[_pos++] = (byte)tag.TagNumber;
                break;
            case MatterTlvTagControl.CommonProfileShort:
            case MatterTlvTagControl.ImplicitProfileShort:
                WriteRawUShortLE((ushort)tag.TagNumber);
                break;
            case MatterTlvTagControl.CommonProfileLong:
            case MatterTlvTagControl.ImplicitProfileLong:
                WriteRawUIntLE(tag.TagNumber);
                break;
            case MatterTlvTagControl.FullyQualifiedShort:
                WriteRawUShortLE(tag.VendorId);
                WriteRawUShortLE(tag.ProfileNumber);
                WriteRawUShortLE((ushort)tag.TagNumber);
                break;
            case MatterTlvTagControl.FullyQualifiedLong:
                WriteRawUShortLE(tag.VendorId);
                WriteRawUShortLE(tag.ProfileNumber);
                WriteRawUIntLE(tag.TagNumber);
                break;
        }
    }

    // Length always fits in an int in .NET (no 8-byte length variant needed on the writer path).
    // The reader still accepts the 8-byte form for spec conformance.
    private static (MatterTlvElementType, int) ChooseUtf8Type(int length) => length switch
    {
        <= byte.MaxValue => (MatterTlvElementType.Utf8String1, 1),
        <= ushort.MaxValue => (MatterTlvElementType.Utf8String2, 2),
        _ => (MatterTlvElementType.Utf8String4, 4),
    };

    private static (MatterTlvElementType, int) ChooseByteStringType(int length) => length switch
    {
        <= byte.MaxValue => (MatterTlvElementType.ByteString1, 1),
        <= ushort.MaxValue => (MatterTlvElementType.ByteString2, 2),
        _ => (MatterTlvElementType.ByteString4, 4),
    };

    private void WriteLength(int widthBytes, ulong length)
    {
        switch (widthBytes)
        {
            case 1: WriteRaw((byte)length); break;
            case 2: WriteRawUShortLE((ushort)length); break;
            case 4: WriteRawUIntLE((uint)length); break;
            case 8: WriteRawULongLE(length); break;
        }
    }

    // ------------------ low-level ------------------

    private void Ensure(int extra)
    {
        if (_pos + extra <= _buffer.Length) return;
        int newSize = Math.Max(_buffer.Length * 2, _pos + extra);
        Array.Resize(ref _buffer, newSize);
    }

    private void WriteRaw(byte b) { Ensure(1); _buffer[_pos++] = b; }
    private void WriteRawShortLE(short v) { Ensure(2); BinaryPrimitives.WriteInt16LittleEndian(_buffer.AsSpan(_pos, 2), v); _pos += 2; }
    private void WriteRawUShortLE(ushort v) { Ensure(2); BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_pos, 2), v); _pos += 2; }
    private void WriteRawIntLE(int v) { Ensure(4); BinaryPrimitives.WriteInt32LittleEndian(_buffer.AsSpan(_pos, 4), v); _pos += 4; }
    private void WriteRawUIntLE(uint v) { Ensure(4); BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_pos, 4), v); _pos += 4; }
    private void WriteRawLongLE(long v) { Ensure(8); BinaryPrimitives.WriteInt64LittleEndian(_buffer.AsSpan(_pos, 8), v); _pos += 8; }
    private void WriteRawULongLE(ulong v) { Ensure(8); BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_pos, 8), v); _pos += 8; }
}
