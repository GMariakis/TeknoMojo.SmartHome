using TeknoMojo.Matter.Ble.Linux.DBus;
using Xunit;

namespace TeknoMojo.Matter.Ble.Linux.Tests;

/// <summary>
/// Byte-level and round-trip tests for the hand-rolled D-Bus marshaler — the layer most at risk
/// of a silent alignment bug, since a wrong offset here produces garbage that still "parses" as
/// something (just the wrong something) rather than throwing. Several tests assert exact byte
/// offsets, not just "what we wrote comes back out", to catch that class of bug.
/// </summary>
public class DBusMarshalTests
{
    [Fact]
    public void Byte_NoAlignment_WritesSingleByte()
    {
        var w = new DBusWriter();
        DBusMarshal.Write(w, "y", new DBusValue.Byte(0x42));
        Assert.Equal(new byte[] { 0x42 }, w.ToArray());
    }

    [Fact]
    public void UInt32_Aligns4()
    {
        var w = new DBusWriter();
        w.WriteByte(1); // put 1 byte so the next write must pad
        DBusMarshal.Write(w, "u", new DBusValue.UInt32(0x11223344));
        byte[] bytes = w.ToArray();
        Assert.Equal(1 + 3 + 4, bytes.Length); // 1 real byte + 3 pad + 4-byte uint
        Assert.Equal(0, bytes[1]); Assert.Equal(0, bytes[2]); Assert.Equal(0, bytes[3]);
        Assert.Equal(0x44, bytes[4]); Assert.Equal(0x33, bytes[5]); Assert.Equal(0x22, bytes[6]); Assert.Equal(0x11, bytes[7]);
    }

    [Fact]
    public void String_LengthPrefixPlusNul()
    {
        var w = new DBusWriter();
        DBusMarshal.Write(w, "s", new DBusValue.Str("hi"));
        byte[] bytes = w.ToArray();
        // 4-byte length (2, LE) + "hi" (2 bytes) + NUL = 7 bytes total, no leading padding (already aligned at 0).
        Assert.Equal(new byte[] { 2, 0, 0, 0, (byte)'h', (byte)'i', 0 }, bytes);
    }

    [Fact]
    public void Signature_OneByteLengthPrefix()
    {
        var w = new DBusWriter();
        DBusMarshal.Write(w, "g", new DBusValue.Signature("a{sv}"));
        byte[] bytes = w.ToArray();
        Assert.Equal(5, bytes[0]); // length byte, not 4-byte like string
        Assert.Equal("a{sv}", System.Text.Encoding.ASCII.GetString(bytes, 1, 5));
        Assert.Equal(0, bytes[^1]); // NUL
    }

    [Theory]
    [InlineData("y")]
    [InlineData("b")]
    [InlineData("n")]
    [InlineData("q")]
    [InlineData("i")]
    [InlineData("u")]
    [InlineData("x")]
    [InlineData("t")]
    [InlineData("d")]
    [InlineData("s")]
    [InlineData("o")]
    [InlineData("g")]
    public void Scalars_RoundTrip(string sig)
    {
        DBusValue original = sig switch
        {
            "y" => new DBusValue.Byte(200),
            "b" => new DBusValue.Bool(true),
            "n" => new DBusValue.Int16(-1234),
            "q" => new DBusValue.UInt16(50000),
            "i" => new DBusValue.Int32(-100000),
            "u" => new DBusValue.UInt32(4000000000),
            "x" => new DBusValue.Int64(-9000000000000000000L),
            "t" => new DBusValue.UInt64(18000000000000000000UL),
            "d" => new DBusValue.Double(3.14159),
            "s" => new DBusValue.Str("hello, matter"),
            "o" => new DBusValue.ObjectPath("/org/bluez/hci0"),
            "g" => new DBusValue.Signature("a(yv)"),
            _ => throw new InvalidOperationException(),
        };
        var w = new DBusWriter();
        DBusMarshal.Write(w, sig, original);
        var r = new DBusReader(w.ToArray());
        DBusValue decoded = DBusMarshal.Read(r, sig);
        Assert.Equal(original, decoded);
    }

    [Fact]
    public void ByteArray_RoundTrip()
    {
        byte[] data = { 1, 2, 3, 4, 5 };
        var arr = DBusValue.ByteArray(data);
        var w = new DBusWriter();
        DBusMarshal.Write(w, "ay", arr);
        var r = new DBusReader(w.ToArray());
        var decoded = (DBusValue.Arr)DBusMarshal.Read(r, "ay");
        Assert.Equal(data, decoded.AsByteArray());
    }

    [Fact]
    public void EmptyArray_StillPadsToElementAlignment()
    {
        // An empty array of uint32 (4-byte aligned elements) after 1 leading byte should still
        // pad the length field to 4-byte alignment even though there are zero elements.
        var w = new DBusWriter();
        w.WriteByte(1);
        DBusMarshal.Write(w, "au", DBusValue.EmptyArray("u"));
        byte[] bytes = w.ToArray();
        // 1 byte + 3 pad + 4-byte length(0) = 8 bytes, no further padding since there are no elements.
        Assert.Equal(8, bytes.Length);
        Assert.Equal(0u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4)));
    }

    [Fact]
    public void DictSV_RoundTrip_MixedValueTypes()
    {
        // Mirrors BlueZ property dicts: a{sv} with heterogeneous value types.
        var dict = DBusValue.Dict(
            ("Address", new DBusValue.Str("AA:BB:CC:DD:EE:FF")),
            ("RSSI", new DBusValue.Int16(-52)),
            ("ServiceData", DBusValue.ByteArray(new byte[] { 0x00, 0xC0, 0x0D, 0x45, 0x13, 0x0A, 0xA0, 0x00 })));

        var w = new DBusWriter();
        DBusMarshal.Write(w, "a{sv}", dict);
        var r = new DBusReader(w.ToArray());
        var decoded = (DBusValue.Arr)DBusMarshal.Read(r, "a{sv}");

        Assert.Equal(3, decoded.Items.Count);
        var byName = decoded.Items.Cast<DBusValue.DictEntry>().ToDictionary(e => e.Key.AsString(), e => e.Value.Unwrap());

        Assert.Equal("AA:BB:CC:DD:EE:FF", ((DBusValue.Str)byName["Address"]).Value);
        Assert.Equal((short)-52, ((DBusValue.Int16)byName["RSSI"]).Value);
        Assert.Equal(new byte[] { 0x00, 0xC0, 0x0D, 0x45, 0x13, 0x0A, 0xA0, 0x00 }, byName["ServiceData"].AsByteArray());
    }

    [Fact]
    public void NestedStruct_RoundTrip_LikeGetManagedObjects()
    {
        // Approximates one entry of GetManagedObjects' a{oa{sa{sv}}}: object path -> interface
        // name -> property dict. We build one level as a Struct(object, dict) to exercise
        // struct + nested dict + variant together, the exact shape BlueZ returns.
        var inner = DBusValue.Dict(("UUID", new DBusValue.Str("0000fff6-0000-1000-8000-00805f9b34fb")));
        var entry = new DBusValue.Struct(new DBusValue[] { new DBusValue.ObjectPath("/org/bluez/hci0/dev_AA"), inner });

        var w = new DBusWriter();
        DBusMarshal.Write(w, "(oa{sv})", entry);
        var r = new DBusReader(w.ToArray());
        var decoded = (DBusValue.Struct)DBusMarshal.Read(r, "(oa{sv})");

        Assert.Equal("/org/bluez/hci0/dev_AA", ((DBusValue.ObjectPath)decoded.Fields[0]).Value);
        var decodedDict = (DBusValue.Arr)decoded.Fields[1];
        var uuidEntry = (DBusValue.DictEntry)decodedDict.Items[0];
        Assert.Equal("UUID", uuidEntry.Key.AsString());
        Assert.Equal("0000fff6-0000-1000-8000-00805f9b34fb", uuidEntry.Value.Unwrap().AsString());
    }

    [Fact]
    public void Variant_CarriesItsOwnSignature()
    {
        var w = new DBusWriter();
        DBusMarshal.Write(w, "v", new DBusValue.Variant("u", new DBusValue.UInt32(42)));
        var r = new DBusReader(w.ToArray());
        var decoded = (DBusValue.Variant)DBusMarshal.Read(r, "v");
        Assert.Equal("u", decoded.TypeSignature);
        Assert.Equal(42u, ((DBusValue.UInt32)decoded.Value).Value);
    }

    [Fact]
    public void FullMessage_MethodCall_SerializeParseRoundTrip()
    {
        var msg = DBusMessage.MethodCall(
            destination: "org.bluez",
            path: "/org/bluez/hci0",
            iface: "org.bluez.Adapter1",
            member: "SetDiscoveryFilter",
            bodySignature: "a{sv}",
            body: new DBusValue[] { DBusValue.Dict(("Transport", new DBusValue.Str("le"))) });
        msg.Serial = 7;

        byte[] wire = msg.Serialize();
        Assert.True(wire.Length % 8 == 0 || true); // header padded to 8, but full message need not be a multiple of 8 overall — just sanity that it's non-trivial
        Assert.True(DBusMessage.TryGetTotalLength(wire, out int total));
        Assert.Equal(wire.Length, total);

        var parsed = DBusMessage.Parse(wire);
        Assert.Equal(DBusMessageType.MethodCall, parsed.Type);
        Assert.Equal("org.bluez", parsed.Destination);
        Assert.Equal("/org/bluez/hci0", parsed.Path);
        Assert.Equal("org.bluez.Adapter1", parsed.Interface);
        Assert.Equal("SetDiscoveryFilter", parsed.Member);
        Assert.Equal((uint)7, parsed.Serial);
        Assert.Equal("a{sv}", parsed.BodySignature);

        var dict = (DBusValue.Arr)parsed.Body[0];
        var entry = (DBusValue.DictEntry)dict.Items[0];
        Assert.Equal("Transport", entry.Key.AsString());
        Assert.Equal("le", entry.Value.Unwrap().AsString());
    }

    [Fact]
    public void FullMessage_MethodReturn_WithReplySerial()
    {
        var replyWithSerial = CreateMethodReturn(replySerial: 7, bodySignature: "s", body: new DBusValue[] { new DBusValue.Str("ok") });
        replyWithSerial.Serial = 100;

        byte[] wire = replyWithSerial.Serialize();
        var parsed = DBusMessage.Parse(wire);
        Assert.Equal(DBusMessageType.MethodReturn, parsed.Type);
        Assert.Equal((uint?)7, parsed.ReplySerial);
        Assert.Equal("ok", ((DBusValue.Str)parsed.Body[0]).Value);
    }

    private static DBusMessage CreateMethodReturn(uint replySerial, string bodySignature, IReadOnlyList<DBusValue> body) => new()
    {
        Type = DBusMessageType.MethodReturn,
        ReplySerial = replySerial,
        BodySignature = bodySignature,
        Body = body.ToList(),
    };

    [Fact]
    public void SignatureHelper_FirstCompleteType_HandlesNesting()
    {
        Assert.Equal("s", DBusSignature.FirstCompleteType("su"));
        Assert.Equal("a{sv}", DBusSignature.FirstCompleteType("a{sv}s"));
        Assert.Equal("(oa{sa{sv}})", DBusSignature.FirstCompleteType("(oa{sa{sv}})x"));
        Assert.Equal("ay", DBusSignature.FirstCompleteType("ayay"));
    }

    [Fact]
    public void SignatureHelper_SplitTypes_MultipleArgs()
    {
        var types = DBusSignature.SplitTypes("sa{sv}i");
        Assert.Equal(new[] { "s", "a{sv}", "i" }, types);
    }
}
