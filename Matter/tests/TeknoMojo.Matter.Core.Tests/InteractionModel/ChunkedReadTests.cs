using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Messaging;
using TeknoMojo.Matter.Core.Tlv;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.InteractionModel;

/// <summary>
/// A response too large for one message arrives in chunks, each acknowledged before the next is
/// sent. The caller should never have to know that happened.
/// </summary>
public class ChunkedReadTests
{
    [Fact]
    public async Task ReadReassemblesChunkedReportsAndAcknowledgesEachChunk()
    {
        // Three chunks of one attribute each; only the last clears MoreChunkedMessages.
        var channel = new ScriptedChannel(
        [
            ReportData(cluster: 0x0030, attribute: 1, value: 11, more: true),
            ReportData(cluster: 0x0030, attribute: 2, value: 22, more: true),
            ReportData(cluster: 0x0030, attribute: 3, value: 33, more: false),
        ]);

        var client = new MatterInteractionClient(channel);
        var reports = await client.ReadAttributesAsync([new AttributePath(0, 0x0030, 1)]);

        Assert.Equal(3, reports.Count);
        Assert.All(reports, r => Assert.IsType<AttributeReport.Data>(r));

        // One ReadRequest, then a Success StatusResponse for each non-final chunk.
        Assert.Equal(InteractionModelOpcodes.ReadRequest, channel.Sent[0].Opcode);
        Assert.Equal(2, channel.Sent.Count(s => s.Opcode == InteractionModelOpcodes.StatusResponse));

        // Every acknowledgement must ride the same exchange as the read itself.
        Assert.All(channel.Sent, s => Assert.Equal(channel.Sent[0].ExchangeId, s.ExchangeId));
    }

    [Fact]
    public async Task SingleChunkResponseSendsNoAcknowledgement()
    {
        var channel = new ScriptedChannel([ReportData(0x0030, 1, 11, more: false)]);
        var reports = await new MatterInteractionClient(channel).ReadAttributesAsync([new AttributePath(0, 0x0030, 1)]);

        Assert.Single(reports);
        Assert.Single(channel.Sent);   // just the ReadRequest
    }

    private static byte[] ReportData(uint cluster, uint attribute, ulong value, bool more)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.StartArray(MatterTag.Context(1));
        w.StartStructure(MatterTag.Anonymous);          // AttributeReportIB
        w.StartStructure(MatterTag.Context(1));         // AttributeDataIB
        w.WriteUnsignedInt(MatterTag.Context(0), 1);    // DataVersion
        w.StartList(MatterTag.Context(1));              // AttributePathIB
        w.WriteUnsignedInt(MatterTag.Context(2), 0);
        w.WriteUnsignedInt(MatterTag.Context(3), cluster);
        w.WriteUnsignedInt(MatterTag.Context(4), attribute);
        w.EndContainer();
        w.WriteUnsignedInt(MatterTag.Context(2), value);
        w.EndContainer();
        w.EndContainer();
        w.EndContainer();
        if (more) w.WriteBool(MatterTag.Context(3), true);
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>A channel that replays a fixed sequence of ReportData messages and records what we sent.</summary>
    private sealed class ScriptedChannel(IReadOnlyList<byte[]> responses) : IMatterMessageChannel
    {
        private int _next;
        public List<(ushort ProtocolId, byte Opcode, ushort ExchangeId)> Sent { get; } = [];

        public ushort NextExchangeId() => 7;

        public Task SendAsync(ushort protocolId, byte opcode, ushort exchangeId, ReadOnlyMemory<byte> payload,
            bool isInitiator = true, CancellationToken ct = default)
        {
            Sent.Add((protocolId, opcode, exchangeId));
            return Task.CompletedTask;
        }

        public Task<(MatterProtocolHeader Header, byte[] Payload)> ReceiveAsync(CancellationToken ct = default)
        {
            byte[] payload = responses[_next++];
            var header = new MatterProtocolHeader
            {
                ExchangeFlags = MatterExchangeFlags.None,
                Opcode = InteractionModelOpcodes.ReportData,
                ExchangeId = 7,
                ProtocolId = MatterProtocolIds.InteractionModel,
            };
            return Task.FromResult((header, payload));
        }
    }
}
