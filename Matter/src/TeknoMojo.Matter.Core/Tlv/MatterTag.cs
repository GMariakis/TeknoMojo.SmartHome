namespace TeknoMojo.Matter.Core.Tlv;

/// <summary>
/// A Matter TLV element tag (Spec Appendix A.2). Tags fall into five namespaces:
/// anonymous (no tag), context-specific (unique inside the enclosing container),
/// common-profile, implicit-profile, and fully-qualified (VendorId + ProfileNumber + TagNumber).
/// Use the static factory methods rather than the raw constructor.
/// </summary>
public readonly struct MatterTag : IEquatable<MatterTag>
{
    /// <summary>The tag-control category (which namespace, and short vs long tag number).</summary>
    public MatterTlvTagControl Control { get; }

    /// <summary>Vendor identifier — meaningful only for <see cref="MatterTlvTagControl.FullyQualifiedShort"/>/<see cref="MatterTlvTagControl.FullyQualifiedLong"/>.</summary>
    public ushort VendorId { get; }

    /// <summary>Profile number — meaningful only for the fully-qualified controls.</summary>
    public ushort ProfileNumber { get; }

    /// <summary>Tag number. Width depends on <see cref="Control"/> (8 / 16 / 32 bits).</summary>
    public uint TagNumber { get; }

    private MatterTag(MatterTlvTagControl control, ushort vendorId, ushort profileNumber, uint tagNumber)
    {
        Control = control;
        VendorId = vendorId;
        ProfileNumber = profileNumber;
        TagNumber = tagNumber;
    }

    /// <summary>No tag: used for elements inside arrays and for top-level anonymous elements.</summary>
    public static MatterTag Anonymous { get; } = new(MatterTlvTagControl.Anonymous, 0, 0, 0);

    /// <summary>Context-specific tag (1 byte). The only tag kind valid inside a structure or list.</summary>
    public static MatterTag Context(byte tagNumber) => new(MatterTlvTagControl.ContextSpecific, 0, 0, tagNumber);

    /// <summary>Common-profile tag, encoded as 2 or 4 bytes depending on the value's width.</summary>
    public static MatterTag CommonProfile(uint tagNumber) =>
        tagNumber <= ushort.MaxValue
            ? new(MatterTlvTagControl.CommonProfileShort, 0, 0, tagNumber)
            : new(MatterTlvTagControl.CommonProfileLong, 0, 0, tagNumber);

    /// <summary>Implicit-profile tag (rare — used when the profile context is derivable from the stream).</summary>
    public static MatterTag ImplicitProfile(uint tagNumber) =>
        tagNumber <= ushort.MaxValue
            ? new(MatterTlvTagControl.ImplicitProfileShort, 0, 0, tagNumber)
            : new(MatterTlvTagControl.ImplicitProfileLong, 0, 0, tagNumber);

    /// <summary>Fully-qualified tag: VendorId + ProfileNumber + TagNumber (16- or 32-bit).</summary>
    public static MatterTag FullyQualified(ushort vendorId, ushort profileNumber, uint tagNumber) =>
        tagNumber <= ushort.MaxValue
            ? new(MatterTlvTagControl.FullyQualifiedShort, vendorId, profileNumber, tagNumber)
            : new(MatterTlvTagControl.FullyQualifiedLong, vendorId, profileNumber, tagNumber);

    /// <summary>How many bytes the tag occupies on the wire (excluding the control byte).</summary>
    public int SerializedTagLength => Control switch
    {
        MatterTlvTagControl.Anonymous => 0,
        MatterTlvTagControl.ContextSpecific => 1,
        MatterTlvTagControl.CommonProfileShort or MatterTlvTagControl.ImplicitProfileShort => 2,
        MatterTlvTagControl.CommonProfileLong or MatterTlvTagControl.ImplicitProfileLong => 4,
        MatterTlvTagControl.FullyQualifiedShort => 6,
        MatterTlvTagControl.FullyQualifiedLong => 8,
        _ => throw new InvalidOperationException("unreachable"),
    };

    public bool Equals(MatterTag other) =>
        Control == other.Control && VendorId == other.VendorId
        && ProfileNumber == other.ProfileNumber && TagNumber == other.TagNumber;

    public override bool Equals(object? obj) => obj is MatterTag t && Equals(t);
    public override int GetHashCode() => HashCode.Combine((byte)Control, VendorId, ProfileNumber, TagNumber);
    public static bool operator ==(MatterTag a, MatterTag b) => a.Equals(b);
    public static bool operator !=(MatterTag a, MatterTag b) => !a.Equals(b);

    public override string ToString() => Control switch
    {
        MatterTlvTagControl.Anonymous => "anon",
        MatterTlvTagControl.ContextSpecific => $"ctx({TagNumber})",
        MatterTlvTagControl.CommonProfileShort or MatterTlvTagControl.CommonProfileLong => $"common({TagNumber})",
        MatterTlvTagControl.ImplicitProfileShort or MatterTlvTagControl.ImplicitProfileLong => $"implicit({TagNumber})",
        MatterTlvTagControl.FullyQualifiedShort or MatterTlvTagControl.FullyQualifiedLong
            => $"fq(vendor={VendorId},profile={ProfileNumber},tag={TagNumber})",
        _ => "?",
    };
}
