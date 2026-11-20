namespace TeknoMojo.Matter.Ble.Linux.DBus;

internal enum DBusMessageType : byte
{
    MethodCall = 1,
    MethodReturn = 2,
    Error = 3,
    Signal = 4,
}

/// <summary>Header field type codes (D-Bus Specification, "Header Fields" table).</summary>
internal enum DBusHeaderField : byte
{
    Path = 1,
    Interface = 2,
    Member = 3,
    ErrorName = 4,
    ReplySerial = 5,
    Destination = 6,
    Sender = 7,
    Signature = 8,
    UnixFds = 9,
}

/// <summary>A D-Bus message, header fields and body already decoded into <see cref="DBusValue"/>s.</summary>
internal sealed class DBusMessage
{
    public DBusMessageType Type { get; init; }
    public byte Flags { get; init; }
    public uint Serial { get; set; }
    public uint? ReplySerial { get; init; }
    public string? Path { get; init; }
    public string? Interface { get; init; }
    public string? Member { get; init; }
    public string? ErrorName { get; init; }
    public string? Destination { get; init; }
    public string? Sender { get; init; }
    public string BodySignature { get; init; } = "";
    public List<DBusValue> Body { get; init; } = new();

    public static DBusMessage MethodCall(string? destination, string path, string iface, string member,
        string bodySignature = "", IReadOnlyList<DBusValue>? body = null) => new()
    {
        Type = DBusMessageType.MethodCall,
        Destination = destination,
        Path = path,
        Interface = iface,
        Member = member,
        BodySignature = bodySignature,
        Body = body?.ToList() ?? new List<DBusValue>(),
    };

    /// <summary>Serialize this message to its full wire form (header + body), assigning nothing but reading <see cref="Serial"/> as already-set.</summary>
    public byte[] Serialize()
    {
        // Body first, so we know its length for the fixed header prefix.
        var bodyWriter = new DBusWriter();
        List<string> bodyTypes = DBusSignature.SplitTypes(BodySignature);
        for (int i = 0; i < bodyTypes.Count; i++)
            DBusMarshal.Write(bodyWriter, bodyTypes[i], Body[i]);
        byte[] bodyBytes = bodyWriter.ToArray();

        // Header fields array: a(yv).
        var fields = new List<DBusValue>();
        if (Path is not null) fields.Add(HeaderField(DBusHeaderField.Path, new DBusValue.ObjectPath(Path)));
        if (Interface is not null) fields.Add(HeaderField(DBusHeaderField.Interface, new DBusValue.Str(Interface)));
        if (Member is not null) fields.Add(HeaderField(DBusHeaderField.Member, new DBusValue.Str(Member)));
        if (ErrorName is not null) fields.Add(HeaderField(DBusHeaderField.ErrorName, new DBusValue.Str(ErrorName)));
        if (ReplySerial is not null) fields.Add(HeaderField(DBusHeaderField.ReplySerial, new DBusValue.UInt32(ReplySerial.Value)));
        if (Destination is not null) fields.Add(HeaderField(DBusHeaderField.Destination, new DBusValue.Str(Destination)));
        if (!string.IsNullOrEmpty(BodySignature)) fields.Add(HeaderField(DBusHeaderField.Signature, new DBusValue.Signature(BodySignature)));

        var headerWriter = new DBusWriter();
        headerWriter.WriteByte((byte)'l'); // little-endian
        headerWriter.WriteByte((byte)Type);
        headerWriter.WriteByte(Flags);
        headerWriter.WriteByte(1); // protocol version
        headerWriter.WriteUInt32((uint)bodyBytes.Length);
        headerWriter.WriteUInt32(Serial);
        DBusMarshal.Write(headerWriter, "a(yv)", new DBusValue.Arr("(yv)", fields));
        headerWriter.Align(8); // mandatory: body must start on an 8-byte boundary

        byte[] headerBytes = headerWriter.ToArray();
        var result = new byte[headerBytes.Length + bodyBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
        Buffer.BlockCopy(bodyBytes, 0, result, headerBytes.Length, bodyBytes.Length);
        return result;
    }

    private static DBusValue.Struct HeaderField(DBusHeaderField code, DBusValue value) =>
        new(new DBusValue[] { new DBusValue.Byte((byte)code), new DBusValue.Variant(DBusValue.SignatureOf(value), value) });

    /// <summary>
    /// Parse one message from <paramref name="buffer"/> (must contain at least the full message —
    /// callers use <see cref="TryGetTotalLength"/> first to learn how many bytes to read).
    /// </summary>
    public static DBusMessage Parse(byte[] buffer)
    {
        var r = new DBusReader(buffer);
        byte endian = r.ReadByte();
        if (endian != (byte)'l')
            throw new NotSupportedException("Only little-endian D-Bus messages are supported.");
        var type = (DBusMessageType)r.ReadByte();
        byte flags = r.ReadByte();
        r.ReadByte(); // protocol version
        uint bodyLength = r.ReadUInt32();
        uint serial = r.ReadUInt32();

        var headerArray = (DBusValue.Arr)DBusMarshal.Read(r, "a(yv)");
        r.Align(8);
        int bodyStart = r.Position;

        var msg = new DBusMessage { Type = type, Flags = flags, Serial = serial };
        string? path = null, iface = null, member = null, errorName = null, destination = null, sender = null, sig = "";
        uint? replySerial = null;

        foreach (DBusValue item in headerArray.Items)
        {
            var st = (DBusValue.Struct)item;
            var code = (DBusHeaderField)((DBusValue.Byte)st.Fields[0]).Value;
            var variant = (DBusValue.Variant)st.Fields[1];
            switch (code)
            {
                case DBusHeaderField.Path: path = variant.Value.AsString(); break;
                case DBusHeaderField.Interface: iface = variant.Value.AsString(); break;
                case DBusHeaderField.Member: member = variant.Value.AsString(); break;
                case DBusHeaderField.ErrorName: errorName = variant.Value.AsString(); break;
                case DBusHeaderField.ReplySerial: replySerial = ((DBusValue.UInt32)variant.Value).Value; break;
                case DBusHeaderField.Destination: destination = variant.Value.AsString(); break;
                case DBusHeaderField.Sender: sender = variant.Value.AsString(); break;
                case DBusHeaderField.Signature: sig = ((DBusValue.Signature)variant.Value).Value; break;
            }
        }

        var bodyReader = new DBusReader(buffer, bodyStart);
        var body = new List<DBusValue>();
        foreach (string t in DBusSignature.SplitTypes(sig ?? ""))
            body.Add(DBusMarshal.Read(bodyReader, t));

        return new DBusMessage
        {
            Type = type,
            Flags = flags,
            Serial = serial,
            ReplySerial = replySerial,
            Path = path,
            Interface = iface,
            Member = member,
            ErrorName = errorName,
            Destination = destination,
            Sender = sender,
            BodySignature = sig ?? "",
            Body = body,
        };
    }

    /// <summary>
    /// Peek the fixed 16-byte-ish prefix to learn the header-array length and body length, so
    /// the connection knows exactly how many more bytes to read for one complete message.
    /// Returns the total message length in bytes once at least 16 bytes are available.
    /// </summary>
    public static bool TryGetTotalLength(ReadOnlySpan<byte> availableAtLeast16Bytes, out int totalLength)
    {
        totalLength = 0;
        if (availableAtLeast16Bytes.Length < 16) return false;
        uint bodyLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(availableAtLeast16Bytes.Slice(4, 4));
        uint headerArrayLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(availableAtLeast16Bytes.Slice(12, 4));
        // Fixed prefix (12) + array length field already counted at offset 12..15 (4 bytes) + array body,
        // then padded to 8, then body. We can't know the post-array padding without parsing, but the
        // padding is at most 7 bytes; over-read attempts are handled by the caller retrying with more data.
        long headerEnd = 16 + headerArrayLength;
        long paddedHeaderEnd = (headerEnd + 7) / 8 * 8;
        totalLength = checked((int)(paddedHeaderEnd + bodyLength));
        return true;
    }
}
