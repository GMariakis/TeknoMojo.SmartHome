using System.Text;

namespace TeknoMojo.Matter.Ble.Linux.DBus;

/// <summary>
/// D-Bus wire-format marshaling (D-Bus Specification §"Marshaling (Wire Format)"). Implements
/// exactly the type subset BlueZ's API surface uses: y b n q i u x t d s o g, arrays (including
/// a{sv} dicts), structs, dict-entries, and variants. Always writes little-endian; reads honor
/// the endianness byte in the message header the caller passes in.
/// </summary>
/// <remarks>
/// Alignment rules (all offsets relative to the start of the message body, i.e. header end):
/// <code>
///   y            1-byte,  no alignment
///   b            4-byte,  marshaled as UINT32 0/1
///   n q          2-byte alignment
///   i u          4-byte alignment
///   x t d        8-byte alignment
///   s o          4-byte alignment: UINT32 length (bytes, not incl. NUL) + data + NUL
///   g            1-byte alignment: BYTE length + data + NUL
///   a T (array)  4-byte alignment: UINT32 byte-length of the array body, THEN pad to
///                alignment of T, THEN the elements (padding happens even for a 0-length array)
///   (...) {..}   8-byte alignment always, regardless of contents
///   v            1-byte alignment: signature (as 'g') then the value per its own alignment
/// </code>
/// </remarks>
internal static class DBusMarshal
{
    public static void Write(DBusWriter w, string signature, DBusValue value)
    {
        switch (signature[0])
        {
            case 'y': w.WriteByte(((DBusValue.Byte)value).Value); break;
            case 'b': w.Align(4); w.WriteUInt32(((DBusValue.Bool)value).Value ? 1u : 0u); break;
            case 'n': w.Align(2); w.WriteInt16(((DBusValue.Int16)value).Value); break;
            case 'q': w.Align(2); w.WriteUInt16(((DBusValue.UInt16)value).Value); break;
            case 'i': w.Align(4); w.WriteInt32(((DBusValue.Int32)value).Value); break;
            case 'u': w.Align(4); w.WriteUInt32(((DBusValue.UInt32)value).Value); break;
            case 'x': w.Align(8); w.WriteInt64(((DBusValue.Int64)value).Value); break;
            case 't': w.Align(8); w.WriteUInt64(((DBusValue.UInt64)value).Value); break;
            case 'd': w.Align(8); w.WriteDouble(((DBusValue.Double)value).Value); break;
            case 's': WriteStringLike(w, ((DBusValue.Str)value).Value); break;
            case 'o': WriteStringLike(w, ((DBusValue.ObjectPath)value).Value); break;
            case 'g': WriteSignature(w, ((DBusValue.Signature)value).Value); break;
            case 'v': WriteVariant(w, (DBusValue.Variant)value); break;
            case 'a': WriteArray(w, signature, (DBusValue.Arr)value); break;
            case '(': WriteStruct(w, (DBusValue.Struct)value); break;
            default: throw new NotSupportedException($"DBus write: unsupported signature '{signature}'");
        }
    }

    private static void WriteStringLike(DBusWriter w, string s)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(s);
        w.Align(4);
        w.WriteUInt32((uint)bytes.Length);
        w.WriteBytes(bytes);
        w.WriteByte(0); // NUL terminator, not counted in the length
    }

    private static void WriteSignature(DBusWriter w, string sig)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(sig);
        w.WriteByte((byte)bytes.Length);
        w.WriteBytes(bytes);
        w.WriteByte(0);
    }

    private static void WriteVariant(DBusWriter w, DBusValue.Variant variant)
    {
        WriteSignature(w, variant.TypeSignature);
        Write(w, variant.TypeSignature, variant.Value);
    }

    private static void WriteArray(DBusWriter w, string signature, DBusValue.Arr arr)
    {
        string elemSig = signature.Substring(1); // may itself be nested, e.g. "{sv}" or "y"
        string firstElemType = DBusSignature.FirstCompleteType(elemSig);

        w.Align(4);
        int lengthPos = w.ReserveUInt32();
        w.Align(DBusSignature.AlignmentOf(firstElemType[0]));
        int bodyStart = w.Position;

        foreach (DBusValue item in arr.Items)
        {
            if (firstElemType[0] == '{')
                WriteDictEntry(w, firstElemType, (DBusValue.DictEntry)item);
            else
                Write(w, firstElemType, item);
        }

        uint bodyLength = (uint)(w.Position - bodyStart);
        w.PatchUInt32(lengthPos, bodyLength);
    }

    private static void WriteDictEntry(DBusWriter w, string entrySig, DBusValue.DictEntry entry)
    {
        // entrySig looks like "{sv}" -> key type 's', value type the rest up to the closing brace.
        string inner = entrySig.Substring(1, entrySig.Length - 2);
        string keyType = DBusSignature.FirstCompleteType(inner);
        string valueType = inner.Substring(keyType.Length);

        w.Align(8);
        Write(w, keyType, entry.Key);
        Write(w, valueType, entry.Value);
    }

    private static void WriteStruct(DBusWriter w, DBusValue.Struct s)
    {
        w.Align(8);
        foreach (var field in s.Fields)
            Write(w, DBusValue.SignatureOf(field), field);
    }

    // ------------------------------------------------------------------ reading

    public static DBusValue Read(DBusReader r, string signature)
    {
        return signature[0] switch
        {
            'y' => new DBusValue.Byte(r.ReadByte()),
            'b' => new DBusValue.Bool(ReadBool(r)),
            'n' => new DBusValue.Int16(ReadAligned(r, 2, r.ReadInt16)),
            'q' => new DBusValue.UInt16(ReadAligned(r, 2, r.ReadUInt16)),
            'i' => new DBusValue.Int32(ReadAligned(r, 4, r.ReadInt32)),
            'u' => new DBusValue.UInt32(ReadAligned(r, 4, r.ReadUInt32)),
            'x' => new DBusValue.Int64(ReadAligned(r, 8, r.ReadInt64)),
            't' => new DBusValue.UInt64(ReadAligned(r, 8, r.ReadUInt64)),
            'd' => new DBusValue.Double(ReadAligned(r, 8, r.ReadDouble)),
            's' => new DBusValue.Str(ReadStringLike(r)),
            'o' => new DBusValue.ObjectPath(ReadStringLike(r)),
            'g' => new DBusValue.Signature(ReadSignatureString(r)),
            'v' => ReadVariant(r),
            'a' => ReadArray(r, signature),
            '(' => ReadStruct(r, signature),
            _ => throw new NotSupportedException($"DBus read: unsupported signature '{signature}'"),
        };
    }

    private static T ReadAligned<T>(DBusReader r, int alignment, Func<T> read)
    {
        r.Align(alignment);
        return read();
    }

    private static bool ReadBool(DBusReader r)
    {
        r.Align(4);
        return r.ReadUInt32() != 0;
    }

    private static string ReadStringLike(DBusReader r)
    {
        r.Align(4);
        uint len = r.ReadUInt32();
        string s = Encoding.UTF8.GetString(r.ReadBytes((int)len));
        r.ReadByte(); // NUL
        return s;
    }

    private static string ReadSignatureString(DBusReader r)
    {
        byte len = r.ReadByte();
        string s = Encoding.ASCII.GetString(r.ReadBytes(len));
        r.ReadByte(); // NUL
        return s;
    }

    private static DBusValue ReadVariant(DBusReader r)
    {
        string sig = ReadSignatureString(r);
        DBusValue value = Read(r, sig);
        return new DBusValue.Variant(sig, value);
    }

    private static DBusValue.Arr ReadArray(DBusReader r, string signature)
    {
        string elemSig = signature.Substring(1);
        string firstElemType = DBusSignature.FirstCompleteType(elemSig);

        r.Align(4);
        uint bodyLength = r.ReadUInt32();
        r.Align(DBusSignature.AlignmentOf(firstElemType[0]));
        int bodyStart = r.Position;

        var items = new List<DBusValue>();
        while (r.Position - bodyStart < bodyLength)
        {
            items.Add(firstElemType[0] == '{' ? ReadDictEntry(r, firstElemType) : Read(r, firstElemType));
        }

        return new DBusValue.Arr(firstElemType, items);
    }

    private static DBusValue.DictEntry ReadDictEntry(DBusReader r, string entrySig)
    {
        string inner = entrySig.Substring(1, entrySig.Length - 2);
        string keyType = DBusSignature.FirstCompleteType(inner);
        string valueType = inner.Substring(keyType.Length);

        r.Align(8);
        DBusValue key = Read(r, keyType);
        DBusValue value = Read(r, valueType);
        return new DBusValue.DictEntry(key, value);
    }

    private static DBusValue.Struct ReadStruct(DBusReader r, string signature)
    {
        // signature like "(oa{sa{sv}})" -- strip outer parens, split into complete types.
        string inner = signature.Substring(1, signature.Length - 2);
        r.Align(8);
        var fields = new List<DBusValue>();
        int pos = 0;
        while (pos < inner.Length)
        {
            string t = DBusSignature.FirstCompleteType(inner.Substring(pos));
            fields.Add(Read(r, t));
            pos += t.Length;
        }
        return new DBusValue.Struct(fields);
    }
}

/// <summary>Signature-string parsing helpers shared by the writer and reader.</summary>
internal static class DBusSignature
{
    /// <summary>Alignment in bytes for a given type-code first character.</summary>
    public static int AlignmentOf(char typeCode) => typeCode switch
    {
        'y' or 'g' => 1,
        'n' or 'q' => 2,
        'b' or 'i' or 'u' => 4,
        'x' or 't' or 'd' => 8,
        's' or 'o' or 'a' => 4,
        '(' or '{' => 8,
        'v' => 1,
        _ => throw new NotSupportedException($"Unknown DBus type code '{typeCode}'"),
    };

    /// <summary>
    /// Extract the first complete type from the start of <paramref name="sig"/> — a single
    /// basic type char, an array "a" + its element type, or a parenthesized/braced group.
    /// </summary>
    public static string FirstCompleteType(string sig)
    {
        if (sig.Length == 0) throw new ArgumentException("empty signature");
        char c = sig[0];
        if (c == 'a')
            return "a" + FirstCompleteType(sig.Substring(1));
        if (c is '(' or '{')
        {
            char close = c == '(' ? ')' : '}';
            char open = c;
            int depth = 0;
            for (int i = 0; i < sig.Length; i++)
            {
                if (sig[i] == open) depth++;
                else if (sig[i] == close)
                {
                    depth--;
                    if (depth == 0) return sig.Substring(0, i + 1);
                }
            }
            throw new FormatException($"Unbalanced signature: {sig}");
        }
        // Basic single-char type.
        return sig.Substring(0, 1);
    }

    /// <summary>Split a full signature (e.g. a method's argument list) into its complete types.</summary>
    public static List<string> SplitTypes(string sig)
    {
        var result = new List<string>();
        int pos = 0;
        while (pos < sig.Length)
        {
            string t = FirstCompleteType(sig.Substring(pos));
            result.Add(t);
            pos += t.Length;
        }
        return result;
    }
}
