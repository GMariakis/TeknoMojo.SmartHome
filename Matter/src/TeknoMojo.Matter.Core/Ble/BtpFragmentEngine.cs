using System.Buffers.Binary;

namespace TeknoMojo.Matter.Core.Ble;

/// <summary>BTP fragment header flag bits (Matter Core Spec §4.19.5 / chip BtpEngine::HeaderFlags).</summary>
[Flags]
public enum BtpHeaderFlags : byte
{
    None = 0,
    StartMessage = 0x01,
    ContinueMessage = 0x02,
    EndMessage = 0x04,
    FragmentAck = 0x08,
}

/// <summary>
/// BTP fragmentation/reassembly engine: turns an arbitrary-length Matter message into a
/// sequence of GATT-sized fragments to send, and reassembles inbound fragments back into a
/// complete message. Mirrors the wire format of chip's <c>BtpEngine</c>
/// (project-chip/connectedhomeip, src/ble/BtpEngine.h/.cpp) byte-for-byte:
/// <code>
/// Header byte layout (little-endian):
///   [0]      HeaderFlags (1 byte)
///   [1]      Ack number (1 byte) -- present only if FragmentAck flag set
///   [1 or 2] Sequence number (1 byte) -- always present
///   [+2]     Total message length (uint16 LE) -- present only if StartMessage flag set
///   [...]    Payload
/// </code>
/// </summary>
/// <remarks>
/// Flow-control simplification: this engine implements exactly one message in flight per
/// direction at a time (no pipelining, no sliding-window retransmission) — sufficient for a
/// commissioner that sends one Matter message and waits for the reply, which is the entire
/// shape of PASE/CASE/Interaction-Model request-response traffic during commissioning. A
/// production peer-to-peer stack under lossy radio conditions would want chip's full windowed
/// retransmission; that is out of scope for the commissioning use case this targets.
/// </remarks>
public sealed class BtpFragmentEngine
{
    private readonly int _txFragmentSize;
    private readonly int _rxFragmentSize;

    private byte _txNextSeqNum;
    private byte _rxNextSeqNum;
    private bool _rxSeqNumLatched;
    private byte _rxNewestUnackedSeqNum;
    private bool _rxHasUnacked;

    // Reassembly state
    private List<byte>? _rxBuffer;
    private int _rxExpectedLength;
    private bool _rxInProgress;

    public BtpFragmentEngine(int txFragmentSize, int rxFragmentSize)
    {
        if (txFragmentSize < 4) throw new ArgumentOutOfRangeException(nameof(txFragmentSize), "fragment size too small for a BTP header");
        if (rxFragmentSize < 4) throw new ArgumentOutOfRangeException(nameof(rxFragmentSize), "fragment size too small for a BTP header");
        _txFragmentSize = txFragmentSize;
        _rxFragmentSize = rxFragmentSize;
    }

    /// <summary>
    /// Split <paramref name="message"/> into wire-ready BTP fragments. The first fragment carries
    /// StartMessage + the total length; the last carries EndMessage; a single-fragment message
    /// carries both. If we have an unacked received sequence number, it is piggybacked as
    /// FragmentAck on the FIRST fragment only (matching chip's behavior).
    /// </summary>
    public List<byte[]> EncodeMessage(ReadOnlySpan<byte> message)
    {
        if (message.Length > ushort.MaxValue)
            throw new ArgumentException("BTP message exceeds 65535 bytes (single-pbuf limit).", nameof(message));

        var fragments = new List<byte[]>();
        int offset = 0;
        bool first = true;
        // Header overhead varies by fragment (start fragment carries 2 extra length bytes).
        do
        {
            bool isStart = first;
            int headerSize = 1 /*flags*/ + 1 /*seq*/ + (isStart ? 2 : 0) + (first && _rxHasUnacked ? 1 : 0);
            int payloadCapacity = Math.Max(0, _txFragmentSize - headerSize);
            int remaining = message.Length - offset;
            int chunk = Math.Min(payloadCapacity, remaining);
            bool isEnd = offset + chunk >= message.Length;

            var flags = BtpHeaderFlags.None;
            if (isStart) flags |= BtpHeaderFlags.StartMessage;
            else flags |= BtpHeaderFlags.ContinueMessage;
            if (isEnd) flags |= BtpHeaderFlags.EndMessage;

            bool piggybackAck = first && _rxHasUnacked;
            if (piggybackAck) flags |= BtpHeaderFlags.FragmentAck;

            var buf = new byte[headerSize + chunk];
            int pos = 0;
            buf[pos++] = (byte)flags;
            if (piggybackAck)
            {
                buf[pos++] = _rxNewestUnackedSeqNum;
                _rxHasUnacked = false;
            }
            buf[pos++] = _txNextSeqNum++;
            if (isStart)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), (ushort)message.Length);
                pos += 2;
            }
            message.Slice(offset, chunk).CopyTo(buf.AsSpan(pos));

            fragments.Add(buf);
            offset += chunk;
            first = false;
        } while (offset < message.Length);
        // Note: the do-while always runs at least once, so a zero-length message still emits
        // exactly one Start+End fragment with no payload — no special-casing needed.

        return fragments;
    }

    /// <summary>Encode a stand-alone acknowledgement fragment (no message payload) for the given sequence number.</summary>
    public byte[] EncodeStandaloneAck()
    {
        if (!_rxHasUnacked) throw new InvalidOperationException("No unacked sequence number to acknowledge.");
        var buf = new byte[3];
        buf[0] = (byte)BtpHeaderFlags.FragmentAck;
        buf[1] = _rxNewestUnackedSeqNum;
        buf[2] = _txNextSeqNum++;
        _rxHasUnacked = false;
        return buf;
    }

    /// <summary>True if we have received data we have not yet acknowledged (caller should send a standalone ack soon).</summary>
    public bool HasUnackedReceipt => _rxHasUnacked;

    /// <summary>
    /// Feed one received fragment. Returns the reassembled message once the final fragment
    /// arrives; returns null while a message is still in progress or the fragment was a
    /// stand-alone ack.
    /// </summary>
    public BtpReceiveResult ProcessIncomingFragment(ReadOnlySpan<byte> fragment)
    {
        if (fragment.Length < 2) throw new FormatException("BTP fragment too short for header.");
        int pos = 0;
        var flags = (BtpHeaderFlags)fragment[pos++];

        byte? receivedAck = null;
        if ((flags & BtpHeaderFlags.FragmentAck) != 0)
        {
            if (pos >= fragment.Length) throw new FormatException("BTP fragment: FragmentAck flag set but ack byte missing.");
            receivedAck = fragment[pos++];
        }

        if (pos >= fragment.Length) throw new FormatException("BTP fragment: sequence number missing.");
        byte seqNum = fragment[pos++];

        // Peers disagree on where the post-handshake sequence starts: some send their first data
        // fragment as 0, others as 1 (having counted the handshake response as 0). Both are seen
        // on the air from shipping implementations, so latch whatever the peer opens with and
        // require strict increments only from then on.
        if (!_rxSeqNumLatched)
        {
            _rxNextSeqNum = seqNum;
            _rxSeqNumLatched = true;
        }
        else if (seqNum != _rxNextSeqNum)
        {
            throw new InvalidOperationException($"BTP sequence error: expected {_rxNextSeqNum}, got {seqNum}.");
        }
        _rxNextSeqNum++;

        bool hasData = (flags & (BtpHeaderFlags.StartMessage | BtpHeaderFlags.ContinueMessage | BtpHeaderFlags.EndMessage)) != 0;

        // Only data-bearing fragments create an obligation to acknowledge. A stand-alone ack is
        // never itself acknowledged: if it were, two peers with nothing left to say would trade
        // bare acks forever, each one obliging the next.
        if (hasData)
        {
            _rxNewestUnackedSeqNum = seqNum;
            _rxHasUnacked = true;
        }

        if (!hasData)
        {
            // Stand-alone ack: no payload for the reassembler.
            return new BtpReceiveResult(null, receivedAck);
        }

        if ((flags & BtpHeaderFlags.StartMessage) != 0)
        {
            if (pos + 2 > fragment.Length) throw new FormatException("BTP start fragment missing total length.");
            _rxExpectedLength = BinaryPrimitives.ReadUInt16LittleEndian(fragment.Slice(pos, 2));
            pos += 2;
            _rxBuffer = new List<byte>(_rxExpectedLength);
            _rxInProgress = true;
        }
        else
        {
            if (!_rxInProgress || _rxBuffer is null)
                throw new InvalidOperationException("BTP: received continuation/end fragment without an in-progress message.");
        }

        _rxBuffer!.AddRange(fragment.Slice(pos).ToArray());

        if ((flags & BtpHeaderFlags.EndMessage) != 0)
        {
            if (_rxBuffer.Count != _rxExpectedLength)
                throw new InvalidOperationException(
                    $"BTP reassembly length mismatch: expected {_rxExpectedLength}, got {_rxBuffer.Count}.");
            byte[] complete = _rxBuffer.ToArray();
            _rxBuffer = null;
            _rxInProgress = false;
            return new BtpReceiveResult(complete, receivedAck);
        }

        return new BtpReceiveResult(null, receivedAck);
    }
}

/// <summary>Result of processing one inbound BTP fragment.</summary>
/// <param name="CompletedMessage">Non-null once the final fragment of a message has arrived.</param>
/// <param name="ReceivedAck">The piggybacked ack sequence number, if the fragment carried one.</param>
public readonly record struct BtpReceiveResult(byte[]? CompletedMessage, byte? ReceivedAck);
