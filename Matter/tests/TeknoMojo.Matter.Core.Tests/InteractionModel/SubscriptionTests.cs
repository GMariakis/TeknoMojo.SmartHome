using System.Threading.Channels;
using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Messaging;
using TeknoMojo.Matter.Core.Tlv;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.InteractionModel;

/// <summary>
/// Subscriptions outlive the exchange that created them: the device primes with current values,
/// confirms, then reports on change. Every report has to be acknowledged or the device gives up.
/// </summary>
public class SubscriptionTests
{
    [Fact]
    public async Task PrimingReportIsAvailableWithoutRacingTheEvent()
    {
        var channel = new PushChannel();
        channel.Push(InteractionModelOpcodes.ReportData, Report(attribute: 1, value: 42, more: false));
        channel.Push(InteractionModelOpcodes.SubscribeResponse, SubscribeResponse(subscriptionId: 9, maxInterval: 30));

        await using var subscription = await MatterSubscription.CreateAsync(
            channel, [new AttributePath(0, 0x0006, 0)]);

        // Exposed as data, so a handler attached after this line cannot have missed it.
        Assert.Single(subscription.InitialReports);
        Assert.Equal(9u, subscription.SubscriptionId);
        Assert.Equal(30, subscription.MaxInterval);
    }

    [Fact]
    public async Task ChunkedPrimingReportIsReassembledBeforeConfirmation()
    {
        var channel = new PushChannel();
        channel.Push(InteractionModelOpcodes.ReportData, Report(1, 11, more: true));
        channel.Push(InteractionModelOpcodes.ReportData, Report(2, 22, more: false));
        channel.Push(InteractionModelOpcodes.SubscribeResponse, SubscribeResponse(1, 60));

        await using var subscription = await MatterSubscription.CreateAsync(
            channel, [new AttributePath(0, 0x0006, 0)]);

        Assert.Equal(2, subscription.InitialReports.Count);
    }

    [Fact]
    public async Task SubsequentReportsAreRaisedAndAcknowledged()
    {
        var channel = new PushChannel();
        channel.Push(InteractionModelOpcodes.ReportData, Report(1, 11, more: false));
        channel.Push(InteractionModelOpcodes.SubscribeResponse, SubscribeResponse(1, 60));

        await using var subscription = await MatterSubscription.CreateAsync(
            channel, [new AttributePath(0, 0x0006, 0)]);

        var received = new TaskCompletionSource<IReadOnlyList<AttributeReport>>();
        subscription.Reported += reports => received.TrySetResult(reports);

        int acksBefore = channel.SentOpcodes.Count(o => o == InteractionModelOpcodes.StatusResponse);
        channel.Push(InteractionModelOpcodes.ReportData, Report(1, 99, more: false));

        var reports = await received.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(reports);

        // A device that stops being acknowledged tears the subscription down, so this matters.
        Assert.True(channel.SentOpcodes.Count(o => o == InteractionModelOpcodes.StatusResponse) > acksBefore);
    }

    [Fact]
    public async Task DeviceRefusingTheSubscriptionSurfacesItsStatus()
    {
        var channel = new PushChannel();
        channel.Push(InteractionModelOpcodes.StatusResponse,
            InteractionModelCodec.EncodeStatusResponse(MatterStatus.ResourceExhausted));

        var ex = await Assert.ThrowsAsync<MatterInteractionException>(() =>
            MatterSubscription.CreateAsync(channel, [new AttributePath(0, 0x0006, 0)]));
        Assert.Equal(MatterStatus.ResourceExhausted, ex.Status);
    }

    private static byte[] SubscribeResponse(uint subscriptionId, ushort maxInterval)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), subscriptionId);
        w.WriteUnsignedInt(MatterTag.Context(2), maxInterval);
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();
        return w.ToArray();
    }

    private static byte[] Report(uint attribute, ulong value, bool more)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.StartArray(MatterTag.Context(1));
        w.StartStructure(MatterTag.Anonymous);
        w.StartStructure(MatterTag.Context(1));
        w.WriteUnsignedInt(MatterTag.Context(0), 1);
        w.StartList(MatterTag.Context(1));
        w.WriteUnsignedInt(MatterTag.Context(2), 0);
        w.WriteUnsignedInt(MatterTag.Context(3), 0x0006);
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

    /// <summary>A channel a test can push messages into at any time, standing in for a live device.</summary>
    private sealed class PushChannel : IMatterMessageChannel
    {
        private readonly Channel<(byte Opcode, byte[] Payload)> _inbound = Channel.CreateUnbounded<(byte, byte[])>();

        public List<byte> SentOpcodes { get; } = [];

        public void Push(byte opcode, byte[] payload) => _inbound.Writer.TryWrite((opcode, payload));

        public ushort NextExchangeId() => 3;

        public Task SendAsync(ushort protocolId, byte opcode, ushort exchangeId, ReadOnlyMemory<byte> payload,
            bool isInitiator = true, CancellationToken ct = default)
        {
            lock (SentOpcodes) SentOpcodes.Add(opcode);
            return Task.CompletedTask;
        }

        public async Task<(MatterProtocolHeader Header, byte[] Payload)> ReceiveAsync(CancellationToken ct = default)
        {
            var (opcode, payload) = await _inbound.Reader.ReadAsync(ct);
            var header = new MatterProtocolHeader
            {
                ExchangeFlags = MatterExchangeFlags.None,
                Opcode = opcode,
                ExchangeId = 3,
                ProtocolId = MatterProtocolIds.InteractionModel,
            };
            return (header, payload);
        }
    }
}
