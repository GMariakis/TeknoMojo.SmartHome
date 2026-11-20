namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// Message Reliability Protocol state for one exchange (Spec §4.12).
/// </summary>
/// <remarks>
/// MRP applies only to links that are not themselves reliable — in practice UDP. BTP carries its
/// own acknowledgements and windowing, and TCP is a stream, so both suppress MRP entirely; see
/// <see cref="IMatterTransport.RequiresReliableMessaging"/>.
///
/// This type holds the policy and bookkeeping (backoff schedule, duplicate detection, what we owe
/// an acknowledgement for). Actually writing bytes stays with the caller, because the unsecured
/// PASE path and an encrypted session frame their messages differently.
/// </remarks>
public sealed class MatterMrp
{
    /// <summary>Spec §4.12.8 MRP_BACKOFF_BASE — the exponential base for successive retries.</summary>
    public const double BackoffBase = 1.6;

    /// <summary>Spec §4.12.8 MRP_BACKOFF_JITTER — added as a random 0..25% on top of each interval.</summary>
    public const double BackoffJitter = 0.25;

    /// <summary>Spec §4.12.8 MRP_BACKOFF_MARGIN — compensates for the peer's clock running slow.</summary>
    public const double BackoffMargin = 1.1;

    /// <summary>Spec §4.12.8 MRP_BACKOFF_THRESHOLD — retries before the backoff starts growing.</summary>
    public const int BackoffThreshold = 1;

    /// <summary>Spec §4.12.8 MRP_MAX_TRANSMISSIONS — the original send plus its retries.</summary>
    public const int MaxTransmissions = 5;

    /// <summary>
    /// The peer's SESSION_IDLE_INTERVAL: how long it may take to respond when its receiver is
    /// idle. Learned from the peer's SessionParameters; the spec default is 500 ms.
    /// </summary>
    public TimeSpan PeerIdleInterval { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>
    /// The peer's SESSION_ACTIVE_INTERVAL: the equivalent once it is known to be awake. Spec
    /// default is 300 ms.
    /// </summary>
    public TimeSpan PeerActiveInterval { get; set; } = TimeSpan.FromMilliseconds(300);

    /// <summary>
    /// True once we have heard from the peer recently enough to treat it as awake, which selects
    /// the shorter retransmission interval.
    /// </summary>
    public bool PeerIsActive { get; private set; }

    private readonly HashSet<uint> _seenCounters = [];
    private uint? _pendingAck;

    /// <summary>
    /// Backoff before retransmission number <paramref name="transmissionNumber"/> (1 for the
    /// interval after the very first send). Spec §4.12.2.1.
    /// </summary>
    public TimeSpan ComputeBackoff(int transmissionNumber, Random? random = null)
    {
        double baseInterval = (PeerIsActive ? PeerActiveInterval : PeerIdleInterval).TotalMilliseconds * BackoffMargin;

        int exponent = Math.Max(0, transmissionNumber - BackoffThreshold);
        double interval = baseInterval * Math.Pow(BackoffBase, exponent);

        double jitter = 1.0 + BackoffJitter * (random ?? Random.Shared).NextDouble();
        return TimeSpan.FromMilliseconds(interval * jitter);
    }

    /// <summary>
    /// Record an inbound message. Returns false when it is a duplicate that should be dropped —
    /// though a duplicate still has to be acknowledged again, since the peer resent it precisely
    /// because our previous acknowledgement never arrived.
    /// </summary>
    public bool AcceptInbound(MatterMessageHeader message, MatterProtocolHeader protocol)
    {
        PeerIsActive = true;

        if ((protocol.ExchangeFlags & MatterExchangeFlags.ReliabilityRequested) != 0)
            _pendingAck = message.MessageCounter;

        return _seenCounters.Add(message.MessageCounter);
    }

    /// <summary>Take the acknowledgement we owe the peer, if any, clearing it.</summary>
    public uint? TakePendingAck()
    {
        uint? ack = _pendingAck;
        _pendingAck = null;
        return ack;
    }

    /// <summary>Whether we still owe the peer an acknowledgement.</summary>
    public bool HasPendingAck => _pendingAck is not null;

    /// <summary>
    /// Adopt the peer's advertised retransmission intervals, as carried in the SessionParameters
    /// of PBKDFParamResponse or Sigma2. Values of zero mean "unspecified", so keep the defaults.
    /// </summary>
    public void ApplyPeerSessionParameters(uint idleIntervalMs, uint activeIntervalMs)
    {
        if (idleIntervalMs > 0) PeerIdleInterval = TimeSpan.FromMilliseconds(idleIntervalMs);
        if (activeIntervalMs > 0) PeerActiveInterval = TimeSpan.FromMilliseconds(activeIntervalMs);
    }
}
