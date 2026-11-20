using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.InteractionModel;

public class InteractionModelCodecTests
{
    [Fact]
    public void EncodeReadRequest_RoundTripsThroughRawTlv()
    {
        byte[] req = InteractionModelCodec.EncodeReadRequest(
            new[] { AttributePath.Exact(1, 0x0006, 0x0000) }, isFabricFiltered: true);

        // Sanity: it's a structure, tag 0 present as an array with one AttributePathIB.
        var r = new MatterTlvReader(req);
        Assert.True(r.Read());
        Assert.Equal(MatterTlvElementType.Structure, r.ElementType);
        r.EnterContainer();
        bool sawArray = false, sawRevision = false;
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
            {
                sawArray = true;
                Assert.Equal(MatterTlvElementType.Array, r.ElementType);
                r.ExitContainer(); // must skip past the array body, else the next Read() descends into it
            }
            else if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == InteractionModelRevision.Tag)
            {
                sawRevision = true;
                Assert.Equal((ulong)InteractionModelRevision.Revision, r.GetUnsignedInt());
            }
        }
        Assert.True(sawArray);
        Assert.True(sawRevision);
    }

    [Fact]
    public void DecodeReportData_ParsesAttributeDataAndStatus()
    {
        // Hand-build a ReportDataMessage with one AttributeData entry (OnOff = true) and one
        // AttributeStatus entry (UnsupportedAttribute), mirroring what a real device would send.
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), 42); // SubscriptionId
        w.StartArray(MatterTag.Context(1)); // AttributeReportIBs
        {
            // AttributeReportIB #1: Data
            w.StartStructure(MatterTag.Anonymous);
            w.StartStructure(MatterTag.Context(1)); // AttributeDataIB
            w.WriteUnsignedInt(MatterTag.Context(0), 5); // DataVersion
            w.StartStructure(MatterTag.Context(1)); // Path
            w.WriteUnsignedInt(MatterTag.Context(2), 1u);      // Endpoint
            w.WriteUnsignedInt(MatterTag.Context(3), 0x0006u); // Cluster (OnOff)
            w.WriteUnsignedInt(MatterTag.Context(4), 0x0000u); // Attribute (OnOff)
            w.EndContainer();
            w.WriteBool(MatterTag.Context(2), true); // Data: the OnOff value itself
            w.EndContainer(); // AttributeDataIB
            w.EndContainer(); // AttributeReportIB #1

            // AttributeReportIB #2: Status
            w.StartStructure(MatterTag.Anonymous);
            w.StartStructure(MatterTag.Context(0)); // AttributeStatusIB
            w.StartStructure(MatterTag.Context(0)); // Path
            w.WriteUnsignedInt(MatterTag.Context(2), 1u);
            w.WriteUnsignedInt(MatterTag.Context(3), 0x0006u);
            w.WriteUnsignedInt(MatterTag.Context(4), 0x0099u); // some unsupported attribute
            w.EndContainer();
            w.StartStructure(MatterTag.Context(1)); // Status
            w.WriteUnsignedInt(MatterTag.Context(0), (byte)MatterStatus.UnsupportedAttribute);
            w.EndContainer();
            w.EndContainer(); // AttributeStatusIB
            w.EndContainer(); // AttributeReportIB #2
        }
        w.EndContainer(); // array
        w.WriteBool(MatterTag.Context(3), false); // MoreChunkedMessages
        w.EndContainer(); // top structure

        var reports = InteractionModelCodec.DecodeReportData(w.ToArray(), out uint? subId, out bool more);
        Assert.Equal(42u, subId);
        Assert.False(more);
        Assert.Equal(2, reports.Count);

        var data = Assert.IsType<AttributeReport.Data>(reports[0]);
        Assert.Equal(1u, data.Path.Endpoint);
        Assert.Equal(0x0006u, data.Path.Cluster);
        Assert.Equal(0x0000u, data.Path.Attribute);
        Assert.Equal(5u, data.DataVersion);
        var valueReader = new MatterTlvReader(data.ValueTlv);
        Assert.True(valueReader.Read());
        Assert.True(valueReader.GetBool());

        var status = Assert.IsType<AttributeReport.Status>(reports[1]);
        Assert.Equal(MatterStatus.UnsupportedAttribute, status.Status_);
        Assert.Equal(0x0099u, status.Path.Attribute);
    }

    [Fact]
    public void EncodeInvokeRequest_SplicesCommandFields()
    {
        // Build "On" command fields for OnOff cluster (empty struct — On/Off/Toggle take no args).
        var fieldsWriter = new MatterTlvWriter();
        fieldsWriter.StartStructure(MatterTag.Anonymous);
        fieldsWriter.EndContainer();

        byte[] invoke = InteractionModelCodec.EncodeInvokeRequest(new[]
        {
            new CommandInvocation(new CommandPath(1, 0x0006, 0x0001), fieldsWriter.ToArray()),
        });

        var r = new MatterTlvReader(invoke);
        Assert.True(r.Read());
        r.EnterContainer();
        bool sawRequests = false;
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 2)
            {
                sawRequests = true;
                r.EnterContainer();
                Assert.True(r.Read()); // one CommandDataIB
                Assert.Equal(MatterTlvElementType.Structure, r.ElementType);
                r.EnterContainer();
                bool sawPath = false, sawFields = false;
                while (r.Read())
                {
                    if (r.Tag.TagNumber == 0) { sawPath = true; r.ExitContainer(); }
                    else if (r.Tag.TagNumber == 1) { sawFields = true; r.ExitContainer(); }
                }
                Assert.True(sawPath);
                Assert.True(sawFields);
            }
        }
        Assert.True(sawRequests);
    }

    [Fact]
    public void DecodeInvokeResponse_ParsesDataAndStatus()
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteBool(MatterTag.Context(0), false);
        w.StartArray(MatterTag.Context(1));
        {
            // Response #1: Command data (e.g. a hypothetical response payload)
            w.StartStructure(MatterTag.Anonymous);
            w.StartStructure(MatterTag.Context(0)); // Command (CommandDataIB)
            w.StartStructure(MatterTag.Context(0)); // Path
            w.WriteUnsignedInt(MatterTag.Context(0), 1u);
            w.WriteUnsignedInt(MatterTag.Context(1), 0x0006u);
            w.WriteUnsignedInt(MatterTag.Context(2), 0x00u);
            w.EndContainer();
            w.StartStructure(MatterTag.Context(1)); // Fields
            w.WriteUnsignedInt(MatterTag.Context(0), 7u);
            w.EndContainer();
            w.EndContainer();
            w.EndContainer();

            // Response #2: Status
            w.StartStructure(MatterTag.Anonymous);
            w.StartStructure(MatterTag.Context(1)); // Status (CommandStatusIB)
            w.StartStructure(MatterTag.Context(0)); // Path
            w.WriteUnsignedInt(MatterTag.Context(0), 1u);
            w.WriteUnsignedInt(MatterTag.Context(1), 0x0006u);
            w.WriteUnsignedInt(MatterTag.Context(2), 0x01u);
            w.EndContainer();
            w.StartStructure(MatterTag.Context(1)); // ErrorStatus
            w.WriteUnsignedInt(MatterTag.Context(0), (byte)MatterStatus.Success);
            w.EndContainer();
            w.EndContainer();
            w.EndContainer();
        }
        w.EndContainer();
        w.EndContainer();

        var results = InteractionModelCodec.DecodeInvokeResponse(w.ToArray());
        Assert.Equal(2, results.Count);

        var data = Assert.IsType<InvokeResult.Data>(results[0]);
        Assert.Equal(0x0006u, data.Path.Cluster);

        var status = Assert.IsType<InvokeResult.Status>(results[1]);
        Assert.Equal(MatterStatus.Success, status.Status_);
        Assert.Equal(0x01u, status.Path.Command);
    }

    [Fact]
    public void StatusResponse_RoundTrips()
    {
        byte[] wire = InteractionModelCodec.EncodeStatusResponse(MatterStatus.Busy);
        Assert.Equal(MatterStatus.Busy, InteractionModelCodec.DecodeStatusResponse(wire));
    }

    [Fact]
    public void InvokeRequest_CommandPathIsEncodedAsList()
    {
        // CommandPathIB is a TLV List on the wire, not a Structure. Round-tripping through our
        // own decoder cannot catch this — a real accessory answers InvalidAction instead.
        byte[] wire = InteractionModelCodec.EncodeInvokeRequest(
            [new CommandInvocation(new CommandPath(0, 0x0030, 0x00), EmptyStructure())]);

        var r = new MatterTlvReader(wire);
        Assert.True(r.Read());
        r.EnterContainer();
        while (r.Read() && !(r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 2)) { }
        r.EnterContainer();          // InvokeRequests array
        Assert.True(r.Read());       // CommandDataIB structure
        r.EnterContainer();
        Assert.True(r.Read());       // its first field: the command path
        Assert.Equal(MatterTlvElementType.List, r.ElementType);
    }

    private static byte[] EmptyStructure()
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.EndContainer();
        return w.ToArray();
    }
}
