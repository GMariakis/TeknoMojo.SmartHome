using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.InteractionModel;

/// <summary>
/// Encoders/decoders for the Interaction Model message bodies (Matter Core Spec, Interaction
/// Model chapter). Tag numbers verified against the Apache-2.0 reference implementation
/// (project-chip/connectedhomeip, src/app/MessageDef/*.h) — the one exception is
/// AttributeStatusIB, whose tags aren't directly sourced here but follow the same
/// Path(0)/Status(1) shape as the verified CommandStatusIB.
/// </summary>
/// <remarks>
/// <see cref="MatterTlvReader"/> is a <c>ref struct</c> holding its position as value-type
/// fields, so every helper below that must advance the caller's read position takes it by
/// <c>ref</c> — passing it by value would silently operate on a throwaway copy and leave the
/// caller's reader stuck at the position it had before the call.
/// </remarks>
public static class InteractionModelCodec
{
    // ---------------------------------------------------------------- AttributePathIB / CommandPathIB

    private static void WriteAttributePath(MatterTlvWriter w, MatterTag tag, AttributePath path)
    {
        // AttributePathIB is a TLV List, not a Structure (Spec §10.6) — see WriteCommandPath.
        w.StartList(tag);
        if (path.Endpoint is { } ep) w.WriteUnsignedInt(MatterTag.Context(2), ep);
        if (path.Cluster is { } cl) w.WriteUnsignedInt(MatterTag.Context(3), cl);
        if (path.Attribute is { } at) w.WriteUnsignedInt(MatterTag.Context(4), at);
        if (path.ListIndex is { } li) w.WriteUnsignedInt(MatterTag.Context(5), li);
        w.EndContainer();
    }

    private static AttributePath ReadAttributePath(ref MatterTlvReader r)
    {
        r.EnterContainer();
        uint? endpoint = null, cluster = null, attribute = null, listIndex = null;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            switch (r.Tag.TagNumber)
            {
                case 2: endpoint = (uint)r.GetUnsignedInt(); break;
                case 3: cluster = (uint)r.GetUnsignedInt(); break;
                case 4: attribute = (uint)r.GetUnsignedInt(); break;
                case 5: listIndex = (uint)r.GetUnsignedInt(); break;
            }
        }
        return new AttributePath(endpoint, cluster, attribute, listIndex);
    }

    private static void WriteCommandPath(MatterTlvWriter w, MatterTag tag, CommandPath path)
    {
        // CommandPathIB is a TLV List, not a Structure (Spec §10.6). Encoding it as a Structure
        // round-trips fine against our own decoder but is rejected on the wire as InvalidAction.
        w.StartList(tag);
        w.WriteUnsignedInt(MatterTag.Context(0), path.Endpoint);
        w.WriteUnsignedInt(MatterTag.Context(1), path.Cluster);
        w.WriteUnsignedInt(MatterTag.Context(2), path.Command);
        w.EndContainer();
    }

    private static CommandPath ReadCommandPath(ref MatterTlvReader r)
    {
        r.EnterContainer();
        uint endpoint = 0, cluster = 0, command = 0;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            switch (r.Tag.TagNumber)
            {
                case 0: endpoint = (uint)r.GetUnsignedInt(); break;
                case 1: cluster = (uint)r.GetUnsignedInt(); break;
                case 2: command = (uint)r.GetUnsignedInt(); break;
            }
        }
        return new CommandPath(endpoint, cluster, command);
    }

    private static void WriteStatusIB(MatterTlvWriter w, MatterTag tag, MatterStatus status, uint? clusterStatus)
    {
        w.StartStructure(tag);
        w.WriteUnsignedInt(MatterTag.Context(0), (byte)status);
        if (clusterStatus is { } cs) w.WriteUnsignedInt(MatterTag.Context(1), cs);
        w.EndContainer();
    }

    private static (MatterStatus status, uint? clusterStatus) ReadStatusIB(ref MatterTlvReader r)
    {
        r.EnterContainer();
        MatterStatus status = MatterStatus.Failure;
        uint? clusterStatus = null;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            if (r.Tag.TagNumber == 0) status = (MatterStatus)r.GetUnsignedInt();
            else if (r.Tag.TagNumber == 1) clusterStatus = (uint)r.GetUnsignedInt();
        }
        return (status, clusterStatus);
    }

    // ---------------------------------------------------------------- ReadRequestMessage (opcode 0x02)

    public static byte[] EncodeReadRequest(IReadOnlyList<AttributePath> attributes, bool isFabricFiltered = true)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.StartArray(MatterTag.Context(0));
        foreach (var path in attributes) WriteAttributePath(w, MatterTag.Anonymous, path);
        w.EndContainer();
        w.WriteBool(MatterTag.Context(3), isFabricFiltered);
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();
        return w.ToArray();
    }

    // ---------------------------------------------------------------- SubscribeRequestMessage (opcode 0x03)

    /// <summary>
    /// Ask the device to report these attributes whenever they change, and at least once per
    /// <paramref name="maxIntervalCeilingSeconds"/> even if nothing does.
    /// </summary>
    /// <param name="minIntervalFloorSeconds">
    /// The device will not report more often than this, however fast the value actually changes —
    /// it is what stops a noisy sensor saturating the network.
    /// </param>
    /// <param name="keepSubscriptions">
    /// False tears down this fabric's existing subscriptions on the device first, which is the
    /// safe default: a controller that reconnects repeatedly would otherwise accumulate them.
    /// </param>
    public static byte[] EncodeSubscribeRequest(
        IReadOnlyList<AttributePath> attributes,
        ushort minIntervalFloorSeconds,
        ushort maxIntervalCeilingSeconds,
        bool keepSubscriptions = false,
        bool isFabricFiltered = true)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteBool(MatterTag.Context(0), keepSubscriptions);
        w.WriteUnsignedInt(MatterTag.Context(1), minIntervalFloorSeconds);
        w.WriteUnsignedInt(MatterTag.Context(2), maxIntervalCeilingSeconds);
        w.StartArray(MatterTag.Context(3));
        foreach (var path in attributes) WriteAttributePath(w, MatterTag.Anonymous, path);
        w.EndContainer();
        w.WriteBool(MatterTag.Context(7), isFabricFiltered);
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();
        return w.ToArray();
    }

    // ---------------------------------------------------------------- SubscribeResponseMessage (opcode 0x04)

    /// <summary>
    /// The device's confirmation, carrying the subscription id and the maximum interval it
    /// actually settled on — which may be longer than the ceiling we asked for.
    /// </summary>
    public static (uint SubscriptionId, ushort MaxInterval) DecodeSubscribeResponse(byte[] tlv)
    {
        uint? subscriptionId = null;
        ushort maxInterval = 0;

        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("SubscribeResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
            switch (r.Tag.TagNumber)
            {
                case 0: subscriptionId = (uint)r.GetUnsignedInt(); break;
                case 2: maxInterval = (ushort)r.GetUnsignedInt(); break;
                default: SkipIfContainer(ref r); break;
            }
        }

        return subscriptionId is { } id
            ? (id, maxInterval)
            : throw new FormatException("SubscribeResponse: missing SubscriptionId");
    }

    // ---------------------------------------------------------------- ReportDataMessage (opcode 0x05)

    public static List<AttributeReport> DecodeReportData(byte[] tlv, out uint? subscriptionId, out bool moreChunkedMessages)
    {
        subscriptionId = null;
        moreChunkedMessages = false;
        var reports = new List<AttributeReport>();

        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("ReportData: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific)
            {
                SkipIfContainer(ref r);
                continue;
            }
            switch (r.Tag.TagNumber)
            {
                case 0: subscriptionId = (uint)r.GetUnsignedInt(); break;
                case 1: // AttributeReportIBs array
                    r.EnterContainer();
                    while (r.Read())
                    {
                        reports.Add(ReadAttributeReportIB(ref r));
                    }
                    break;
                case 3: moreChunkedMessages = r.GetBool(); break;
                default: SkipIfContainer(ref r); break;
            }
        }
        return reports;
    }

    private static AttributeReport ReadAttributeReportIB(ref MatterTlvReader r)
    {
        // AttributeReportIB is a Structure with tag 0 = AttributeStatus, tag 1 = AttributeData (choice).
        r.EnterContainer();
        AttributeReport? result = null;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
            if (r.Tag.TagNumber == 0) // AttributeStatusIB: { 0: Path, 1: Status }
            {
                r.EnterContainer();
                AttributePath? path = null;
                MatterStatus status = MatterStatus.Failure;
                uint? clusterStatus = null;
                while (r.Read())
                {
                    if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
                    if (r.Tag.TagNumber == 0) path = ReadAttributePath(ref r);
                    else if (r.Tag.TagNumber == 1) (status, clusterStatus) = ReadStatusIB(ref r);
                }
                result = new AttributeReport.Status(path ?? new AttributePath(null, null, null), status, clusterStatus);
            }
            else if (r.Tag.TagNumber == 1) // AttributeDataIB: { 0: DataVersion, 1: Path, 2: Data }
            {
                r.EnterContainer();
                AttributePath? path = null;
                uint? dataVersion = null;
                byte[]? valueTlv = null;
                while (r.Read())
                {
                    if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
                    switch (r.Tag.TagNumber)
                    {
                        case 0: dataVersion = (uint)r.GetUnsignedInt(); break;
                        case 1: path = ReadAttributePath(ref r); break;
                        case 2: valueTlv = CaptureElement(ref r); break;
                    }
                }
                result = new AttributeReport.Data(path ?? new AttributePath(null, null, null), valueTlv ?? Array.Empty<byte>(), dataVersion);
            }
            else
            {
                SkipIfContainer(ref r);
            }
        }
        return result ?? throw new FormatException("AttributeReportIB: neither Status nor Data present");
    }

    // ---------------------------------------------------------------- InvokeRequestMessage (opcode 0x08)

    public static byte[] EncodeInvokeRequest(IReadOnlyList<CommandInvocation> commands, bool suppressResponse = false, bool timedRequest = false)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteBool(MatterTag.Context(0), suppressResponse);
        w.WriteBool(MatterTag.Context(1), timedRequest);
        w.StartArray(MatterTag.Context(2));
        foreach (var cmd in commands)
        {
            // CommandDataIB: { 0: Path, 1: Fields }
            w.StartStructure(MatterTag.Anonymous);
            WriteCommandPath(w, MatterTag.Context(0), cmd.Path);
            // Fields is itself a Structure; splice the caller's pre-encoded structure body in in
            // place of writing a nested TLV document, by re-parsing and re-emitting its fields.
            WriteRawStructureField(w, MatterTag.Context(1), cmd.FieldsTlv);
            w.EndContainer();
        }
        w.EndContainer();
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();
        return w.ToArray();
    }

    // ---------------------------------------------------------------- InvokeResponseMessage (opcode 0x09)

    public static List<InvokeResult> DecodeInvokeResponse(byte[] tlv)
    {
        var results = new List<InvokeResult>();
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("InvokeResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
            if (r.Tag.TagNumber == 1) // InvokeResponses array
            {
                r.EnterContainer();
                while (r.Read())
                {
                    results.Add(ReadInvokeResponseIB(ref r));
                }
            }
            else
            {
                SkipIfContainer(ref r);
            }
        }
        return results;
    }

    private static InvokeResult ReadInvokeResponseIB(ref MatterTlvReader r)
    {
        // InvokeResponseIB: { 0: Command (CommandDataIB), 1: Status (CommandStatusIB) } — choice.
        r.EnterContainer();
        InvokeResult? result = null;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
            if (r.Tag.TagNumber == 0) // CommandDataIB: { 0: Path, 1: Fields }
            {
                r.EnterContainer();
                CommandPath? path = null;
                byte[]? fields = null;
                while (r.Read())
                {
                    if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
                    if (r.Tag.TagNumber == 0) path = ReadCommandPath(ref r);
                    else if (r.Tag.TagNumber == 1) fields = CaptureElement(ref r);
                }
                result = new InvokeResult.Data(path ?? new CommandPath(0, 0, 0), fields ?? Array.Empty<byte>());
            }
            else if (r.Tag.TagNumber == 1) // CommandStatusIB: { 0: Path, 1: ErrorStatus(StatusIB), 2: Ref }
            {
                r.EnterContainer();
                CommandPath? path = null;
                MatterStatus status = MatterStatus.Failure;
                uint? clusterStatus = null;
                while (r.Read())
                {
                    if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { SkipIfContainer(ref r); continue; }
                    if (r.Tag.TagNumber == 0) path = ReadCommandPath(ref r);
                    else if (r.Tag.TagNumber == 1) (status, clusterStatus) = ReadStatusIB(ref r);
                    else SkipIfContainer(ref r);
                }
                result = new InvokeResult.Status(path ?? new CommandPath(0, 0, 0), status, clusterStatus);
            }
            else
            {
                SkipIfContainer(ref r);
            }
        }
        return result ?? throw new FormatException("InvokeResponseIB: neither Command nor Status present");
    }

    // ---------------------------------------------------------------- StatusResponseMessage (opcode 0x01)

    public static byte[] EncodeStatusResponse(MatterStatus status)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), (byte)status);
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();
        return w.ToArray();
    }

    public static MatterStatus DecodeStatusResponse(byte[] tlv)
    {
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("StatusResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (MatterStatus)r.GetUnsignedInt();
        }
        throw new FormatException("StatusResponse: missing Status");
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>Read the current element (of any type, including containers) and return its raw re-encoded TLV bytes.</summary>
    private static byte[] CaptureElement(ref MatterTlvReader r)
    {
        // Re-encode by type; for containers, recursively copy children under an anonymous tag.
        var w = new MatterTlvWriter();
        CopyElement(ref r, w, MatterTag.Anonymous);
        return w.ToArray();
    }

    private static void CopyElement(ref MatterTlvReader r, MatterTlvWriter w, MatterTag tag)
    {
        switch (r.ElementType)
        {
            case MatterTlvElementType.SignedInt1 or MatterTlvElementType.SignedInt2 or MatterTlvElementType.SignedInt4 or MatterTlvElementType.SignedInt8:
                w.WriteSignedInt(tag, r.GetSignedInt()); break;
            case MatterTlvElementType.UnsignedInt1 or MatterTlvElementType.UnsignedInt2 or MatterTlvElementType.UnsignedInt4 or MatterTlvElementType.UnsignedInt8:
                w.WriteUnsignedInt(tag, r.GetUnsignedInt()); break;
            case MatterTlvElementType.BooleanTrue or MatterTlvElementType.BooleanFalse:
                w.WriteBool(tag, r.GetBool()); break;
            case MatterTlvElementType.Float: w.WriteFloat(tag, r.GetFloat()); break;
            case MatterTlvElementType.Double: w.WriteDouble(tag, r.GetDouble()); break;
            case MatterTlvElementType.Utf8String1 or MatterTlvElementType.Utf8String2 or MatterTlvElementType.Utf8String4 or MatterTlvElementType.Utf8String8:
                w.WriteUtf8String(tag, r.GetUtf8String()); break;
            case MatterTlvElementType.ByteString1 or MatterTlvElementType.ByteString2 or MatterTlvElementType.ByteString4 or MatterTlvElementType.ByteString8:
                w.WriteByteString(tag, r.GetByteStringSpan()); break;
            case MatterTlvElementType.Null: w.WriteNull(tag); break;
            case MatterTlvElementType.Structure:
                w.StartStructure(tag);
                r.EnterContainer();
                while (r.Read()) CopyElement(ref r, w, r.Tag);
                w.EndContainer();
                break;
            case MatterTlvElementType.Array:
                w.StartArray(tag);
                r.EnterContainer();
                while (r.Read()) CopyElement(ref r, w, MatterTag.Anonymous);
                w.EndContainer();
                break;
            case MatterTlvElementType.List:
                w.StartList(tag);
                r.EnterContainer();
                while (r.Read()) CopyElement(ref r, w, r.Tag);
                w.EndContainer();
                break;
            default:
                throw new NotSupportedException($"CopyElement: unsupported type {r.ElementType}");
        }
    }

    /// <summary>Write a caller-supplied pre-encoded Structure (its full anonymous-tagged TLV bytes) under a new tag.</summary>
    private static void WriteRawStructureField(MatterTlvWriter w, MatterTag tag, byte[] structureTlv)
    {
        var reader = new MatterTlvReader(structureTlv);
        if (!reader.Read() || reader.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("Command fields must be a TLV Structure.");
        w.StartStructure(tag);
        reader.EnterContainer();
        while (reader.Read()) CopyElement(ref reader, w, reader.Tag);
        w.EndContainer();
    }

    private static void SkipIfContainer(ref MatterTlvReader r)
    {
        if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
            r.ExitContainer();
    }
}
