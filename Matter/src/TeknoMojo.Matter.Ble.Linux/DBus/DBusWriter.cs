using System.Buffers.Binary;

namespace TeknoMojo.Matter.Ble.Linux.DBus;

/// <summary>Growable little-endian byte writer with D-Bus alignment support, tracking position relative to a fixed origin (message body start).</summary>
internal sealed class DBusWriter
{
    private byte[] _buf;
    private int _pos;

    public DBusWriter(int initialCapacity = 256) => _buf = new byte[Math.Max(16, initialCapacity)];

    public int Position => _pos;

    public byte[] ToArray() => _buf.AsSpan(0, _pos).ToArray();

    public void Align(int alignment)
    {
        int pad = (alignment - (_pos % alignment)) % alignment;
        for (int i = 0; i < pad; i++) WriteByte(0);
    }

    public void WriteByte(byte b) { Ensure(1); _buf[_pos++] = b; }
    public void WriteBytes(ReadOnlySpan<byte> bytes) { Ensure(bytes.Length); bytes.CopyTo(_buf.AsSpan(_pos)); _pos += bytes.Length; }

    public void WriteInt16(short v) { Ensure(2); BinaryPrimitives.WriteInt16LittleEndian(_buf.AsSpan(_pos, 2), v); _pos += 2; }
    public void WriteUInt16(ushort v) { Ensure(2); BinaryPrimitives.WriteUInt16LittleEndian(_buf.AsSpan(_pos, 2), v); _pos += 2; }
    public void WriteInt32(int v) { Ensure(4); BinaryPrimitives.WriteInt32LittleEndian(_buf.AsSpan(_pos, 4), v); _pos += 4; }
    public void WriteUInt32(uint v) { Ensure(4); BinaryPrimitives.WriteUInt32LittleEndian(_buf.AsSpan(_pos, 4), v); _pos += 4; }
    public void WriteInt64(long v) { Ensure(8); BinaryPrimitives.WriteInt64LittleEndian(_buf.AsSpan(_pos, 8), v); _pos += 8; }
    public void WriteUInt64(ulong v) { Ensure(8); BinaryPrimitives.WriteUInt64LittleEndian(_buf.AsSpan(_pos, 8), v); _pos += 8; }
    public void WriteDouble(double v) { Ensure(8); BinaryPrimitives.WriteDoubleLittleEndian(_buf.AsSpan(_pos, 8), v); _pos += 8; }

    /// <summary>Reserve 4 bytes for a length field to be filled in later via <see cref="PatchUInt32"/>; returns the reserved offset.</summary>
    public int ReserveUInt32() { int at = _pos; WriteUInt32(0); return at; }

    public void PatchUInt32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(_buf.AsSpan(at, 4), value);

    private void Ensure(int extra)
    {
        if (_pos + extra <= _buf.Length) return;
        Array.Resize(ref _buf, Math.Max(_buf.Length * 2, _pos + extra));
    }
}

/// <summary>Little-endian byte reader with D-Bus alignment support over a fixed buffer.</summary>
internal sealed class DBusReader
{
    private readonly byte[] _buf;
    private int _pos;

    public DBusReader(byte[] buf, int startOffset = 0) { _buf = buf; _pos = startOffset; }

    public int Position => _pos;

    public void Align(int alignment)
    {
        int pad = (alignment - (_pos % alignment)) % alignment;
        _pos += pad;
    }

    public byte ReadByte() => _buf[_pos++];
    public byte[] ReadBytes(int count) { var r = _buf.AsSpan(_pos, count).ToArray(); _pos += count; return r; }

    public short ReadInt16() { short v = BinaryPrimitives.ReadInt16LittleEndian(_buf.AsSpan(_pos, 2)); _pos += 2; return v; }
    public ushort ReadUInt16() { ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_buf.AsSpan(_pos, 2)); _pos += 2; return v; }
    public int ReadInt32() { int v = BinaryPrimitives.ReadInt32LittleEndian(_buf.AsSpan(_pos, 4)); _pos += 4; return v; }
    public uint ReadUInt32() { uint v = BinaryPrimitives.ReadUInt32LittleEndian(_buf.AsSpan(_pos, 4)); _pos += 4; return v; }
    public long ReadInt64() { long v = BinaryPrimitives.ReadInt64LittleEndian(_buf.AsSpan(_pos, 8)); _pos += 8; return v; }
    public ulong ReadUInt64() { ulong v = BinaryPrimitives.ReadUInt64LittleEndian(_buf.AsSpan(_pos, 8)); _pos += 8; return v; }
    public double ReadDouble() { double v = BinaryPrimitives.ReadDoubleLittleEndian(_buf.AsSpan(_pos, 8)); _pos += 8; return v; }
}
