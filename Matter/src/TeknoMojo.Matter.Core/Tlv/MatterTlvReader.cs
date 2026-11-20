using System.Buffers.Binary;
using System.Text;

namespace TeknoMojo.Matter.Core.Tlv;

/// <summary>
/// Streaming decoder for the Matter TLV format (Matter Core Spec Appendix A).
/// Semantics: call <see cref="Read"/> to advance to the next element; then inspect
/// <see cref="ElementType"/> / <see cref="Tag"/> and call the matching typed accessor. Enter
/// containers with <see cref="EnterContainer"/>, and leave with <see cref="ExitContainer"/>
/// which consumes the terminator byte.
/// </summary>
public ref struct MatterTlvReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _pos;
    private MatterTlvElementType _element;
    private MatterTag _tag;
    private int _valueOffset;
    private int _valueLength; // for strings/byte-strings only; scalar sizes come from element type

    /// <summary>The most recently-read element's type.</summary>
    public MatterTlvElementType ElementType => _element;

    /// <summary>The most recently-read element's tag.</summary>
    public MatterTag Tag => _tag;

    /// <summary>True when the last <see cref="Read"/> returned false (no more data or hit container end).</summary>
    public bool EndOfContainer { get; private set; }

    public MatterTlvReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _pos = 0;
        _element = default;
        _tag = MatterTag.Anonymous;
        _valueOffset = 0;
        _valueLength = 0;
        EndOfContainer = false;
    }

    /// <summary>
    /// Advance to the next element. Returns false and leaves the cursor positioned AFTER the
    /// terminator byte when the innermost container ends; returns false without moving when the
    /// buffer is exhausted at the top level.
    /// </summary>
    public bool Read()
    {
        EndOfContainer = false;

        if (_pos >= _data.Length) return false;

        byte control = _data[_pos];
        MatterTlvElementType type = (MatterTlvElementType)(control & 0x1F);
        MatterTlvTagControl tagControl = (MatterTlvTagControl)((control >> 5) & 0x07);

        if (type == MatterTlvElementType.EndOfContainer)
        {
            _pos++;
            EndOfContainer = true;
            return false;
        }

        _pos++;

        // Decode tag
        _tag = tagControl switch
        {
            MatterTlvTagControl.Anonymous => MatterTag.Anonymous,
            MatterTlvTagControl.ContextSpecific => MatterTag.Context(ReadByte()),
            MatterTlvTagControl.CommonProfileShort => MatterTag.CommonProfile(ReadUShortLE()),
            MatterTlvTagControl.CommonProfileLong => MatterTag.CommonProfile(ReadUIntLE()),
            MatterTlvTagControl.ImplicitProfileShort => MatterTag.ImplicitProfile(ReadUShortLE()),
            MatterTlvTagControl.ImplicitProfileLong => MatterTag.ImplicitProfile(ReadUIntLE()),
            MatterTlvTagControl.FullyQualifiedShort => ReadFullyQualified(shortTag: true),
            MatterTlvTagControl.FullyQualifiedLong => ReadFullyQualified(shortTag: false),
            _ => throw Bad("invalid tag control"),
        };
        _element = type;

        // For value-bearing scalars, remember where the value bytes start so the accessor knows.
        _valueOffset = _pos;
        _valueLength = 0;

        switch (type)
        {
            // Scalars — value width fixed by element type
            case MatterTlvElementType.SignedInt1:
            case MatterTlvElementType.UnsignedInt1: _pos += 1; break;
            case MatterTlvElementType.SignedInt2:
            case MatterTlvElementType.UnsignedInt2: _pos += 2; break;
            case MatterTlvElementType.SignedInt4:
            case MatterTlvElementType.UnsignedInt4:
            case MatterTlvElementType.Float: _pos += 4; break;
            case MatterTlvElementType.SignedInt8:
            case MatterTlvElementType.UnsignedInt8:
            case MatterTlvElementType.Double: _pos += 8; break;

            // Boolean / Null / Container-start / Container-end have no value bytes
            case MatterTlvElementType.BooleanFalse:
            case MatterTlvElementType.BooleanTrue:
            case MatterTlvElementType.Null:
            case MatterTlvElementType.Structure:
            case MatterTlvElementType.Array:
            case MatterTlvElementType.List:
                break;

            // Length-prefixed strings/byte-strings; length field width encoded in element type
            case MatterTlvElementType.Utf8String1:
            case MatterTlvElementType.ByteString1:
                _valueLength = ReadByte();
                _valueOffset = _pos;
                _pos += _valueLength;
                break;
            case MatterTlvElementType.Utf8String2:
            case MatterTlvElementType.ByteString2:
                _valueLength = ReadUShortLE();
                _valueOffset = _pos;
                _pos += _valueLength;
                break;
            case MatterTlvElementType.Utf8String4:
            case MatterTlvElementType.ByteString4:
                {
                    uint n = ReadUIntLE();
                    if (n > int.MaxValue) throw Bad("string > 2GiB");
                    _valueLength = (int)n;
                    _valueOffset = _pos;
                    _pos += _valueLength;
                    break;
                }
            case MatterTlvElementType.Utf8String8:
            case MatterTlvElementType.ByteString8:
                {
                    ulong n = ReadULongLE();
                    if (n > int.MaxValue) throw Bad("string > 2GiB (unsupported in-memory)");
                    _valueLength = (int)n;
                    _valueOffset = _pos;
                    _pos += _valueLength;
                    break;
                }

            default:
                throw Bad($"unknown element type 0x{(byte)type:X2}");
        }

        if (_pos > _data.Length) throw Bad("truncated value");
        return true;
    }

    // ------------- typed accessors -------------

    public long GetSignedInt() => _element switch
    {
        MatterTlvElementType.SignedInt1 => (sbyte)_data[_valueOffset],
        MatterTlvElementType.SignedInt2 => BinaryPrimitives.ReadInt16LittleEndian(_data.Slice(_valueOffset, 2)),
        MatterTlvElementType.SignedInt4 => BinaryPrimitives.ReadInt32LittleEndian(_data.Slice(_valueOffset, 4)),
        MatterTlvElementType.SignedInt8 => BinaryPrimitives.ReadInt64LittleEndian(_data.Slice(_valueOffset, 8)),
        _ => throw Bad($"not a signed integer: {_element}"),
    };

    public ulong GetUnsignedInt() => _element switch
    {
        MatterTlvElementType.UnsignedInt1 => _data[_valueOffset],
        MatterTlvElementType.UnsignedInt2 => BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_valueOffset, 2)),
        MatterTlvElementType.UnsignedInt4 => BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_valueOffset, 4)),
        MatterTlvElementType.UnsignedInt8 => BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_valueOffset, 8)),
        _ => throw Bad($"not an unsigned integer: {_element}"),
    };

    public bool GetBool() => _element switch
    {
        MatterTlvElementType.BooleanFalse => false,
        MatterTlvElementType.BooleanTrue => true,
        _ => throw Bad($"not a boolean: {_element}"),
    };

    public float GetFloat() => _element == MatterTlvElementType.Float
        ? BitConverter.UInt32BitsToSingle(BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_valueOffset, 4)))
        : throw Bad($"not a float: {_element}");

    public double GetDouble() => _element == MatterTlvElementType.Double
        ? BitConverter.UInt64BitsToDouble(BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_valueOffset, 8)))
        : throw Bad($"not a double: {_element}");

    public string GetUtf8String()
    {
        EnsureStringElement(isBinary: false);
        return Encoding.UTF8.GetString(_data.Slice(_valueOffset, _valueLength));
    }

    public byte[] GetByteString()
    {
        EnsureStringElement(isBinary: true);
        return _data.Slice(_valueOffset, _valueLength).ToArray();
    }

    /// <summary>Zero-copy view of a byte-string element (valid while the underlying span is).</summary>
    public ReadOnlySpan<byte> GetByteStringSpan()
    {
        EnsureStringElement(isBinary: true);
        return _data.Slice(_valueOffset, _valueLength);
    }

    // ------------- containers -------------

    /// <summary>
    /// Begin reading inside the current container element (Structure / Array / List). After
    /// entering, <see cref="Read"/> will iterate contained children until it returns false with
    /// <see cref="EndOfContainer"/> set — then call <see cref="ExitContainer"/>… wait,
    /// EnterContainer already consumed the head. The container is left when Read returns false.
    /// </summary>
    public void EnterContainer()
    {
        if (_element != MatterTlvElementType.Structure
            && _element != MatterTlvElementType.Array
            && _element != MatterTlvElementType.List)
            throw Bad($"cannot enter non-container element {_element}");
        // The head was already consumed by Read(); the cursor is positioned at the first child.
    }

    /// <summary>
    /// Skip any remaining children of the current container and swallow its terminator. Useful
    /// when a caller wants to bail out of a nested container early.
    /// </summary>
    public void ExitContainer()
    {
        int depth = 1;
        while (depth > 0 && _pos < _data.Length)
        {
            if (!Read())
            {
                if (EndOfContainer) depth--;
                else break;
            }
            else if (_element is MatterTlvElementType.Structure
                     or MatterTlvElementType.Array
                     or MatterTlvElementType.List)
            {
                depth++;
            }
        }
    }

    // ------------- low-level -------------

    private byte ReadByte()
    {
        if (_pos >= _data.Length) throw Bad("truncated");
        return _data[_pos++];
    }
    private ushort ReadUShortLE()
    {
        if (_pos + 2 > _data.Length) throw Bad("truncated");
        ushort v = BinaryPrimitives.ReadUInt16LittleEndian(_data.Slice(_pos, 2));
        _pos += 2;
        return v;
    }
    private uint ReadUIntLE()
    {
        if (_pos + 4 > _data.Length) throw Bad("truncated");
        uint v = BinaryPrimitives.ReadUInt32LittleEndian(_data.Slice(_pos, 4));
        _pos += 4;
        return v;
    }
    private ulong ReadULongLE()
    {
        if (_pos + 8 > _data.Length) throw Bad("truncated");
        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(_data.Slice(_pos, 8));
        _pos += 8;
        return v;
    }

    private MatterTag ReadFullyQualified(bool shortTag)
    {
        ushort vendor = ReadUShortLE();
        ushort profile = ReadUShortLE();
        uint tag = shortTag ? ReadUShortLE() : ReadUIntLE();
        return MatterTag.FullyQualified(vendor, profile, tag);
    }

    private void EnsureStringElement(bool isBinary)
    {
        bool ok = isBinary
            ? _element is MatterTlvElementType.ByteString1 or MatterTlvElementType.ByteString2
                     or MatterTlvElementType.ByteString4 or MatterTlvElementType.ByteString8
            : _element is MatterTlvElementType.Utf8String1 or MatterTlvElementType.Utf8String2
                     or MatterTlvElementType.Utf8String4 or MatterTlvElementType.Utf8String8;
        if (!ok) throw Bad($"element {_element} is not a {(isBinary ? "byte string" : "utf-8 string")}");
    }

    private static FormatException Bad(string message) => new("Matter TLV: " + message);
}
