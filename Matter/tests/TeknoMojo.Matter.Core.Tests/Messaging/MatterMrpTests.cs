using TeknoMojo.Matter.Core.Messaging;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Messaging;

/// <summary>
/// Message Reliability Protocol policy (Spec §4.12): the retransmission schedule, duplicate
/// suppression, and what we owe the peer an acknowledgement for.
/// </summary>
public class MatterMrpTests
{
    private static MatterMessageHeader Message(uint counter) => new()
    {
        Flags = MatterMessageFlags.None,
        SessionId = 0,
        SecurityFlags = MatterSecurityFlags.SessionTypeUnicast,
        MessageCounter = counter,
    };

    private static MatterProtocolHeader Protocol(MatterExchangeFlags flags) => new()
    {
        ExchangeFlags = flags,
        Opcode = 0x20,
        ExchangeId = 1,
        ProtocolId = MatterProtocolIds.SecureChannel,
    };

    [Fact]
    public void ReliableMessageCreatesAnAcknowledgementDebt()
    {
        var mrp = new MatterMrp();
        Assert.False(mrp.HasPendingAck);

        mrp.AcceptInbound(Message(7), Protocol(MatterExchangeFlags.ReliabilityRequested));

        Assert.True(mrp.HasPendingAck);
        Assert.Equal(7u, mrp.TakePendingAck());
        Assert.False(mrp.HasPendingAck);   // taking it clears the debt
    }

    [Fact]
    public void MessageWithoutReliabilityRequestedNeedsNoAcknowledgement()
    {
        var mrp = new MatterMrp();
        mrp.AcceptInbound(Message(7), Protocol(MatterExchangeFlags.None));
        Assert.False(mrp.HasPendingAck);
    }

    [Fact]
    public void DuplicatesAreReportedButStillNeedAcknowledging()
    {
        var mrp = new MatterMrp();
        var reliable = Protocol(MatterExchangeFlags.ReliabilityRequested);

        Assert.True(mrp.AcceptInbound(Message(3), reliable));
        mrp.TakePendingAck();

        // The peer only resent because our acknowledgement never arrived, so the payload is a
        // duplicate but the debt is real.
        Assert.False(mrp.AcceptInbound(Message(3), reliable));
        Assert.True(mrp.HasPendingAck);
    }

    [Fact]
    public void BackoffGrowsExponentiallyAfterTheThreshold()
    {
        var mrp = new MatterMrp { PeerIdleInterval = TimeSpan.FromMilliseconds(1000) };
        var noJitter = new StubRandom(0.0);

        // Below the threshold the interval is just the peer's, plus the margin.
        double first = mrp.ComputeBackoff(MatterMrp.BackoffThreshold, noJitter).TotalMilliseconds;
        Assert.Equal(1000 * MatterMrp.BackoffMargin, first, precision: 3);

        // Each retry beyond it multiplies by the base.
        double second = mrp.ComputeBackoff(MatterMrp.BackoffThreshold + 1, noJitter).TotalMilliseconds;
        Assert.Equal(first * MatterMrp.BackoffBase, second, precision: 3);
    }

    [Fact]
    public void BackoffJitterOnlyEverExtendsTheInterval()
    {
        var mrp = new MatterMrp { PeerIdleInterval = TimeSpan.FromMilliseconds(1000) };

        double none = mrp.ComputeBackoff(1, new StubRandom(0.0)).TotalMilliseconds;
        double most = mrp.ComputeBackoff(1, new StubRandom(1.0)).TotalMilliseconds;

        Assert.True(most > none);
        Assert.Equal(none * (1 + MatterMrp.BackoffJitter), most, precision: 3);
    }

    [Fact]
    public void HearingFromThePeerSelectsTheActiveInterval()
    {
        var mrp = new MatterMrp
        {
            PeerIdleInterval = TimeSpan.FromMilliseconds(1000),
            PeerActiveInterval = TimeSpan.FromMilliseconds(100),
        };
        Assert.False(mrp.PeerIsActive);

        mrp.AcceptInbound(Message(1), Protocol(MatterExchangeFlags.None));

        Assert.True(mrp.PeerIsActive);
        Assert.Equal(100 * MatterMrp.BackoffMargin,
            mrp.ComputeBackoff(MatterMrp.BackoffThreshold, new StubRandom(0.0)).TotalMilliseconds, precision: 3);
    }

    [Fact]
    public void PeerSessionParametersAreAdoptedButZeroMeansUnspecified()
    {
        var mrp = new MatterMrp();
        mrp.ApplyPeerSessionParameters(idleIntervalMs: 4000, activeIntervalMs: 0);

        Assert.Equal(TimeSpan.FromMilliseconds(4000), mrp.PeerIdleInterval);
        Assert.Equal(TimeSpan.FromMilliseconds(300), mrp.PeerActiveInterval); // default retained
    }

    private sealed class StubRandom(double value) : Random
    {
        public override double NextDouble() => value;
    }
}
