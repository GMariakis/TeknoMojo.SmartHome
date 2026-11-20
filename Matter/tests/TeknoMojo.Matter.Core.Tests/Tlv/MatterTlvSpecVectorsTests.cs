using System.Text;
using TeknoMojo.Matter.Core.Tlv;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Tlv;

/// <summary>
/// Byte-exact conformance tests derived from the encoding examples in Matter Core Spec
/// Appendix A.11 ("Application Notes / Examples"). Any of these failing indicates our TLV
/// codec is off the wire format — a bug the crypto and interaction-model layers cannot recover
/// from — so these tests are load-bearing for the entire Matter stack above.
/// </summary>
public class MatterTlvSpecVectorsTests
{
    // A.11.1 - Boolean false, anonymous tag        → 08
    // A.11.1 - Boolean true, anonymous tag         → 09
    [Fact] public void Bool_False_Anonymous() =>
        AssertEncoded(w => w.WriteBool(MatterTag.Anonymous, false), "08");
    [Fact] public void Bool_True_Anonymous() =>
        AssertEncoded(w => w.WriteBool(MatterTag.Anonymous, true), "09");

    // Signed Integer, 1-octet, Value 42          → 00 2A
    [Fact] public void Signed1_42() =>
        AssertEncoded(w => w.WriteSignedInt(MatterTag.Anonymous, 42), "00 2A");

    // Signed Integer, 1-octet, Value -17         → 00 EF
    [Fact] public void Signed1_Neg17() =>
        AssertEncoded(w => w.WriteSignedInt(MatterTag.Anonymous, -17), "00 EF");

    // Unsigned Integer, 1-octet, Value 42U       → 04 2A
    [Fact] public void Unsigned1_42() =>
        AssertEncoded(w => w.WriteUnsignedInt(MatterTag.Anonymous, 42), "04 2A");

    // Unsigned Integer, 2-octet, Value 0xFFFF    → 05 FF FF
    [Fact] public void Unsigned2_0xFFFF() =>
        AssertEncoded(w => w.WriteUnsignedInt(MatterTag.Anonymous, 0xFFFF), "05 FF FF");

    // Signed Integer, 4-octet, Value -170000     → 02 F0 67 FD FF
    [Fact] public void Signed4_Neg170000() =>
        AssertEncoded(w => w.WriteSignedInt(MatterTag.Anonymous, -170000), "02 F0 67 FD FF");

    // Unsigned Integer, 8-octet, Value 40000000000
    //   40_000_000_000 = 0x00_00_00_09_50_2F_90_00 (LE)
    [Fact] public void Unsigned8_40Billion() =>
        AssertEncoded(w => w.WriteUnsignedInt(MatterTag.Anonymous, 40_000_000_000UL),
            "07 00 90 2F 50 09 00 00 00");

    // UTF-8 String, 1-octet length, "Hello!"     → 0C 06 48 65 6C 6C 6F 21
    [Fact] public void Utf8_Hello() =>
        AssertEncoded(w => w.WriteUtf8String(MatterTag.Anonymous, "Hello!"),
            "0C 06 48 65 6C 6C 6F 21");

    // Octet String, 1-octet length, {00 01 02 03 04}  → 10 05 00 01 02 03 04
    [Fact] public void ByteString_5() =>
        AssertEncoded(w => w.WriteByteString(MatterTag.Anonymous, new byte[] { 0, 1, 2, 3, 4 }),
            "10 05 00 01 02 03 04");

    // Null                                         → 14
    [Fact] public void Null_Anonymous() =>
        AssertEncoded(w => w.WriteNull(MatterTag.Anonymous), "14");

    // Single-precision Float, 17.9                 → 0A 33 33 8F 41
    //   17.9f -> 0x418F3333, little-endian bytes 33 33 8F 41
    [Fact] public void Float_17_9() =>
        AssertEncoded(w => w.WriteFloat(MatterTag.Anonymous, 17.9f), "0A 33 33 8F 41");

    // Empty Structure {}, Anonymous                → 15 18
    [Fact] public void Struct_Empty() =>
        AssertEncoded(w => { w.StartStructure(MatterTag.Anonymous); w.EndContainer(); }, "15 18");

    // Empty Array [], Anonymous                    → 16 18
    [Fact] public void Array_Empty() =>
        AssertEncoded(w => { w.StartArray(MatterTag.Anonymous); w.EndContainer(); }, "16 18");

    // Structure with context tag 0, containing UInt tag 1 = 1
    //   Structure(anon)            → 15
    //     UInt1, ctx tag 0, val 20 → 24 00 14
    //     UInt1, ctx tag 1, val 1  → 24 01 01
    //   End                        → 18
    [Fact] public void Struct_WithContextTaggedFields()
    {
        var enc = Encode(w =>
        {
            w.StartStructure(MatterTag.Anonymous);
            w.WriteUnsignedInt(MatterTag.Context(0), 20);
            w.WriteUnsignedInt(MatterTag.Context(1), 1);
            w.EndContainer();
        });
        AssertHexEqual("15 24 00 14 24 01 01 18", enc);
    }

    // A.11.7 — Fully-qualified tag: VendorID=0xFFF1, Profile=0xDEED, TagNumber=0xAA55,
    //          value = UInt-1 0x42
    //   Control: FullyQualifiedShort (0b110 << 5) | UnsignedInt1 (0x04) = 0xC4
    //   Tag bytes (LE): F1 FF ED DE 55 AA
    //   Value: 42
    [Fact] public void FullyQualified_ShortTag_UInt1()
    {
        var tag = MatterTag.FullyQualified(0xFFF1, 0xDEED, 0xAA55);
        AssertEncoded(w => w.WriteUnsignedInt(tag, 0x42), "C4 F1 FF ED DE 55 AA 42");
    }

    // Round-trip: encode then decode a mixed document and get the same values out.
    [Fact]
    public void RoundTrip_MixedDocument()
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), 42);
        w.WriteSignedInt(MatterTag.Context(1), -1_000_000);
        w.WriteBool(MatterTag.Context(2), true);
        w.WriteUtf8String(MatterTag.Context(3), "café");
        w.WriteByteString(MatterTag.Context(4), new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
        w.WriteNull(MatterTag.Context(5));
        w.StartArray(MatterTag.Context(6));
        w.WriteUnsignedInt(MatterTag.Anonymous, 1);
        w.WriteUnsignedInt(MatterTag.Anonymous, 2);
        w.WriteUnsignedInt(MatterTag.Anonymous, 3);
        w.EndContainer();
        w.EndContainer();

        var r = new MatterTlvReader(w.AsSpan());
        Assert.True(r.Read()); Assert.Equal(MatterTlvElementType.Structure, r.ElementType);
        r.EnterContainer();

        Assert.True(r.Read()); Assert.Equal(0u, r.Tag.TagNumber); Assert.Equal(42u, (uint)r.GetUnsignedInt());
        Assert.True(r.Read()); Assert.Equal(1u, r.Tag.TagNumber); Assert.Equal(-1_000_000, r.GetSignedInt());
        Assert.True(r.Read()); Assert.Equal(2u, r.Tag.TagNumber); Assert.True(r.GetBool());
        Assert.True(r.Read()); Assert.Equal(3u, r.Tag.TagNumber); Assert.Equal("café", r.GetUtf8String());
        Assert.True(r.Read()); Assert.Equal(4u, r.Tag.TagNumber); Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, r.GetByteString());
        Assert.True(r.Read()); Assert.Equal(5u, r.Tag.TagNumber); Assert.Equal(MatterTlvElementType.Null, r.ElementType);
        Assert.True(r.Read()); Assert.Equal(6u, r.Tag.TagNumber); Assert.Equal(MatterTlvElementType.Array, r.ElementType);
        r.EnterContainer();
        Assert.True(r.Read()); Assert.Equal(1u, (uint)r.GetUnsignedInt());
        Assert.True(r.Read()); Assert.Equal(2u, (uint)r.GetUnsignedInt());
        Assert.True(r.Read()); Assert.Equal(3u, (uint)r.GetUnsignedInt());
        Assert.False(r.Read()); Assert.True(r.EndOfContainer);
        Assert.False(r.Read()); Assert.True(r.EndOfContainer);
    }

    [Fact]
    public void FragmentedStrings_Widths()
    {
        // 200-byte string uses 1-byte length
        var s200 = new string('a', 200);
        var b200 = Encode(w => w.WriteUtf8String(MatterTag.Anonymous, s200));
        Assert.Equal((byte)MatterTlvElementType.Utf8String1, b200[0]);
        Assert.Equal(200, b200[1]);

        // 500-byte string uses 2-byte length
        var s500 = new string('a', 500);
        var b500 = Encode(w => w.WriteUtf8String(MatterTag.Anonymous, s500));
        Assert.Equal((byte)MatterTlvElementType.Utf8String2, b500[0]);
        Assert.Equal(500, BitConverter.ToUInt16(b500, 1));

        // 100_000-byte string uses 4-byte length
        var s100k = new string('a', 100_000);
        var b100k = Encode(w => w.WriteUtf8String(MatterTag.Anonymous, s100k));
        Assert.Equal((byte)MatterTlvElementType.Utf8String4, b100k[0]);
        Assert.Equal(100_000u, BitConverter.ToUInt32(b100k, 1));
    }

    [Fact]
    public void Int_ChoosesSmallestWidth()
    {
        // 42 fits in 1 byte
        Assert.Equal((byte)MatterTlvElementType.SignedInt1, Encode(w => w.WriteSignedInt(MatterTag.Anonymous, 42))[0]);
        // -200 doesn't fit in sbyte, must be 2 bytes
        Assert.Equal((byte)MatterTlvElementType.SignedInt2, Encode(w => w.WriteSignedInt(MatterTag.Anonymous, -200))[0]);
        // 100_000 needs 4 bytes
        Assert.Equal((byte)MatterTlvElementType.SignedInt4, Encode(w => w.WriteSignedInt(MatterTag.Anonymous, 100_000))[0]);
        // 5_000_000_000 needs 8 bytes
        Assert.Equal((byte)MatterTlvElementType.SignedInt8, Encode(w => w.WriteSignedInt(MatterTag.Anonymous, 5_000_000_000L))[0]);

        // Unsigned side
        Assert.Equal((byte)MatterTlvElementType.UnsignedInt1, Encode(w => w.WriteUnsignedInt(MatterTag.Anonymous, 255))[0]);
        Assert.Equal((byte)MatterTlvElementType.UnsignedInt2, Encode(w => w.WriteUnsignedInt(MatterTag.Anonymous, 256))[0]);
        Assert.Equal((byte)MatterTlvElementType.UnsignedInt4, Encode(w => w.WriteUnsignedInt(MatterTag.Anonymous, 65_536))[0]);
        Assert.Equal((byte)MatterTlvElementType.UnsignedInt8, Encode(w => w.WriteUnsignedInt(MatterTag.Anonymous, uint.MaxValue + 1UL))[0]);
    }

    [Fact]
    public void ExitContainer_SkipsRemainingChildren()
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), 1);
        w.WriteUnsignedInt(MatterTag.Context(1), 2);
        w.WriteUnsignedInt(MatterTag.Context(2), 3);
        w.EndContainer();
        w.WriteUnsignedInt(MatterTag.Anonymous, 999); // sibling AFTER the structure

        var r = new MatterTlvReader(w.AsSpan());
        Assert.True(r.Read()); // structure
        r.EnterContainer();
        Assert.True(r.Read()); Assert.Equal(1u, (uint)r.GetUnsignedInt());
        // Bail out early via ExitContainer — should swallow the remaining 2, 3 and the End byte.
        r.ExitContainer();
        // Next Read should now see the trailing 999.
        Assert.True(r.Read());
        Assert.Equal(999u, (uint)r.GetUnsignedInt());
    }

    // ------- helpers -------

    private static byte[] Encode(Action<MatterTlvWriter> writer)
    {
        var w = new MatterTlvWriter();
        writer(w);
        return w.ToArray();
    }

    private static void AssertEncoded(Action<MatterTlvWriter> writer, string expectedHex)
        => AssertHexEqual(expectedHex, Encode(writer));

    private static void AssertHexEqual(string expectedHex, byte[] actual)
    {
        byte[] expected = expectedHex
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(h => Convert.ToByte(h, 16))
            .ToArray();
        Assert.Equal(HexDump(expected), HexDump(actual));
    }

    private static string HexDump(byte[] bytes)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(bytes[i].ToString("X2"));
        }
        return sb.ToString();
    }
}
