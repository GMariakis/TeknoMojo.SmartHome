namespace TeknoMojo.Matter.Core.Tlv;

/// <summary>
/// Matter TLV element type identifiers (Matter Core Spec Appendix A.7.1). These occupy the
/// lower 5 bits of the control byte; the upper 3 bits are the <see cref="MatterTlvTagControl"/>.
/// Integer / string element types encode both the semantic type AND the width of the length /
/// value field, so choosing the smallest width is part of encoding.
/// </summary>
public enum MatterTlvElementType : byte
{
    SignedInt1 = 0x00,
    SignedInt2 = 0x01,
    SignedInt4 = 0x02,
    SignedInt8 = 0x03,
    UnsignedInt1 = 0x04,
    UnsignedInt2 = 0x05,
    UnsignedInt4 = 0x06,
    UnsignedInt8 = 0x07,
    BooleanFalse = 0x08,
    BooleanTrue = 0x09,
    Float = 0x0A,
    Double = 0x0B,
    Utf8String1 = 0x0C,
    Utf8String2 = 0x0D,
    Utf8String4 = 0x0E,
    Utf8String8 = 0x0F,
    ByteString1 = 0x10,
    ByteString2 = 0x11,
    ByteString4 = 0x12,
    ByteString8 = 0x13,
    Null = 0x14,
    Structure = 0x15,
    Array = 0x16,
    List = 0x17,
    EndOfContainer = 0x18,
}

/// <summary>
/// Matter TLV tag-control values (upper 3 bits of the control byte, Spec Appendix A.7.2).
/// Determines how many bytes follow the control byte for the tag before the length/value.
/// </summary>
public enum MatterTlvTagControl : byte
{
    Anonymous = 0b000,                  // 0 tag bytes
    ContextSpecific = 0b001,            // 1 tag byte
    CommonProfileShort = 0b010,         // 2 tag bytes (tag number, LE)
    CommonProfileLong = 0b011,          // 4 tag bytes (tag number, LE)
    ImplicitProfileShort = 0b100,       // 2 tag bytes
    ImplicitProfileLong = 0b101,        // 4 tag bytes
    FullyQualifiedShort = 0b110,        // 6 tag bytes (VID + Profile + Tag16)
    FullyQualifiedLong = 0b111,         // 8 tag bytes (VID + Profile + Tag32)
}
