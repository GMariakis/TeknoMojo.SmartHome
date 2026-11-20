using System.Text;
using TeknoMojo.Matter.Core.Ble;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Ble;

/// <summary>
/// BTP handshake and fragmentation tests. Byte layout is verified against the Apache-2.0
/// reference implementation (project-chip/connectedhomeip src/ble/BleLayer.h/.cpp and
/// BtpEngine.h/.cpp), so these tests check both our own round-trip AND (via literal byte
/// assertions) conformance to that reference wire format.
/// </summary>
public class BtpTests
{
    [Fact]
    public void CapabilitiesRequest_MagicBytesAndLength_MatchReference()
    {
        var req = BtpHandshake.CapabilitiesRequest.ForCurrentVersion(mtu: 247, windowSize: 6);
        byte[] wire = BtpHandshake.EncodeRequest(req);

        Assert.Equal(9, wire.Length); // 2 magic + 4 versions + 2 mtu + 1 window
        Assert.Equal(BtpHandshake.CheckByte1, wire[0]); // 0x65
        Assert.Equal(BtpHandshake.CheckByte2, wire[1]); // 0x6C

        // Version 4 packed into the low nibble of the first version byte. Matches a shipping
        // commissioner's handshake captured over the air: 65 6C 04 00 00 00 B9 00 06.
        Assert.Equal(0x04, wire[2]);
        Assert.Equal(0, wire[3]); Assert.Equal(0, wire[4]); Assert.Equal(0, wire[5]);

        // MTU little-endian: 247 = 0x00F7
        Assert.Equal(0xF7, wire[6]); Assert.Equal(0x00, wire[7]);
        Assert.Equal(6, wire[8]);
    }

    [Fact]
    public void CapabilitiesRequest_RoundTrips()
    {
        var req = BtpHandshake.CapabilitiesRequest.ForCurrentVersion(mtu: 185, windowSize: 3);
        var decoded = BtpHandshake.DecodeRequest(BtpHandshake.EncodeRequest(req));
        Assert.Equal(req.SupportedProtocolVersions, decoded.SupportedProtocolVersions);
        Assert.Equal(req.Mtu, decoded.Mtu);
        Assert.Equal(req.WindowSize, decoded.WindowSize);
    }

    [Fact]
    public void CapabilitiesResponse_RoundTrips_AndReportsAcceptance()
    {
        var resp = new BtpHandshake.CapabilitiesResponse(SelectedProtocolVersion: 4, FragmentSize: 182, WindowSize: 6);
        byte[] wire = BtpHandshake.EncodeResponse(resp);
        Assert.Equal(6, wire.Length);

        var decoded = BtpHandshake.DecodeResponse(wire);
        Assert.True(decoded.IsAccepted);
        Assert.Equal(resp.FragmentSize, decoded.FragmentSize);
        Assert.Equal(resp.WindowSize, decoded.WindowSize);

        var rejected = new BtpHandshake.CapabilitiesResponse(0, 0, 0);
        Assert.False(BtpHandshake.DecodeResponse(BtpHandshake.EncodeResponse(rejected)).IsAccepted);
    }

    [Fact]
    public void DecodeRequest_WrongMagic_Throws()
    {
        byte[] bad = new byte[BtpHandshake.RequestLength];
        bad[0] = 0xAA; bad[1] = 0xBB;
        Assert.Throws<FormatException>(() => BtpHandshake.DecodeRequest(bad));
    }

    [Fact]
    public void FragmentEngine_SingleFragmentMessage_RoundTrips()
    {
        var tx = new BtpFragmentEngine(txFragmentSize: 50, rxFragmentSize: 50);
        var rx = new BtpFragmentEngine(txFragmentSize: 50, rxFragmentSize: 50);

        byte[] message = Encoding.UTF8.GetBytes("hello matter");
        var fragments = tx.EncodeMessage(message);
        Assert.Single(fragments);

        BtpReceiveResult? result = null;
        foreach (var frag in fragments)
            result = rx.ProcessIncomingFragment(frag);

        Assert.NotNull(result!.Value.CompletedMessage);
        Assert.Equal(message, result.Value.CompletedMessage);
    }

    [Fact]
    public void FragmentEngine_MultiFragmentMessage_RoundTrips()
    {
        // Small fragment size forces splitting; header overhead per fragment is 2 (flags+seq) or
        // 4 for the start fragment (flags+seq+2-byte length) -- pick a size that forces 4+ fragments.
        var tx = new BtpFragmentEngine(txFragmentSize: 10, rxFragmentSize: 10);
        var rx = new BtpFragmentEngine(txFragmentSize: 10, rxFragmentSize: 10);

        byte[] message = Enumerable.Range(0, 137).Select(i => (byte)i).ToArray();
        var fragments = tx.EncodeMessage(message);
        Assert.True(fragments.Count > 3, $"expected multiple fragments, got {fragments.Count}");

        // Every fragment must fit within the negotiated size.
        Assert.All(fragments, f => Assert.True(f.Length <= 10));

        byte[]? completed = null;
        foreach (var frag in fragments)
        {
            var result = rx.ProcessIncomingFragment(frag);
            if (result.CompletedMessage is not null) completed = result.CompletedMessage;
        }

        Assert.NotNull(completed);
        Assert.Equal(message, completed);
    }

    [Fact]
    public void FragmentEngine_EmptyMessage_ProducesOneFragment()
    {
        var tx = new BtpFragmentEngine(50, 50);
        var rx = new BtpFragmentEngine(50, 50);

        var fragments = tx.EncodeMessage(ReadOnlySpan<byte>.Empty);
        Assert.Single(fragments);

        var result = rx.ProcessIncomingFragment(fragments[0]);
        Assert.NotNull(result.CompletedMessage);
        Assert.Empty(result.CompletedMessage!);
    }

    [Fact]
    public void FragmentEngine_BidirectionalPiggybackAck()
    {
        // Alice sends a message to Bob; Bob's reply piggybacks an ack of Alice's last sequence number.
        var alice = new BtpFragmentEngine(20, 20);
        var bob = new BtpFragmentEngine(20, 20);

        byte[] request = Encoding.UTF8.GetBytes("ping-ping-ping"); // forces >1 fragment at size 20
        BtpReceiveResult? bobResult = null;
        foreach (var frag in alice.EncodeMessage(request))
            bobResult = bob.ProcessIncomingFragment(frag);
        Assert.Equal(request, bobResult!.Value.CompletedMessage);
        Assert.True(bob.HasUnackedReceipt);

        byte[] reply = Encoding.UTF8.GetBytes("pong");
        var replyFragments = bob.EncodeMessage(reply);
        Assert.False(bob.HasUnackedReceipt); // consumed as piggyback on the first reply fragment

        BtpReceiveResult? aliceResult = null;
        byte? ackSeen = null;
        foreach (var frag in replyFragments)
        {
            var r = alice.ProcessIncomingFragment(frag);
            if (r.ReceivedAck is not null) ackSeen = r.ReceivedAck;
            if (r.CompletedMessage is not null) aliceResult = r;
        }
        Assert.NotNull(ackSeen);
        Assert.Equal(reply, aliceResult!.Value.CompletedMessage);
    }

    [Fact]
    public void FragmentEngine_OutOfOrderSequence_Throws()
    {
        var tx = new BtpFragmentEngine(50, 50);
        var rx = new BtpFragmentEngine(50, 50);
        var fragments = tx.EncodeMessage(new byte[200]);
        Assert.True(fragments.Count > 1, "test needs a multi-fragment message");

        // The first fragment establishes whatever sequence number the peer starts at, so a gap
        // is only detectable from the second fragment onwards.
        rx.ProcessIncomingFragment(fragments[0]);

        // Corrupt the sequence number byte (index 1, since no ack flag here: [flags][seq]...).
        fragments[1][1] = 99;
        Assert.Throws<InvalidOperationException>(() => rx.ProcessIncomingFragment(fragments[1]));
    }

    [Fact]
    public void FragmentEngine_StandaloneAckDoesNotRequireAcknowledgement()
    {
        // Otherwise two peers ping-pong bare acks forever, which is exactly what a live
        // accessory did until this was fixed.
        var a = new BtpFragmentEngine(50, 50);
        var b = new BtpFragmentEngine(50, 50);

        b.ProcessIncomingFragment(a.EncodeMessage(new byte[] { 1, 2, 3 })[0]);
        Assert.True(b.HasUnackedReceipt);

        byte[] ack = b.EncodeStandaloneAck();
        a.ProcessIncomingFragment(ack);
        Assert.False(a.HasUnackedReceipt);
    }

    [Fact]
    public void FragmentEngine_PeerMayStartSequenceAtOne()
    {
        // Observed on the air: some accessories send their first post-handshake fragment as
        // seq 1 rather than 0, having counted the handshake response as 0.
        var tx = new BtpFragmentEngine(50, 50);
        var rx = new BtpFragmentEngine(50, 50);
        var fragments = tx.EncodeMessage(new byte[] { 1, 2, 3 });
        fragments[0][1] = 1;

        var result = rx.ProcessIncomingFragment(fragments[0]);
        Assert.Equal(new byte[] { 1, 2, 3 }, result.CompletedMessage);
    }

    [Fact]
    public void FragmentEngine_ManySequentialMessages_SeqNumbersAdvance()
    {
        var tx = new BtpFragmentEngine(50, 50);
        var rx = new BtpFragmentEngine(50, 50);

        for (int i = 0; i < 10; i++)
        {
            byte[] msg = { (byte)i, (byte)(i * 2) };
            BtpReceiveResult? result = null;
            foreach (var f in tx.EncodeMessage(msg))
                result = rx.ProcessIncomingFragment(f);
            Assert.Equal(msg, result!.Value.CompletedMessage);
        }
    }
}
