using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>
/// Typed helper for the Time Synchronization cluster (0x0038) — endpoint 0 only.
/// </summary>
/// <remarks>
/// A commissioner is expected to give the device the time when the device says it needs it: a
/// node with no clock of its own cannot judge certificate validity or schedule anything until an
/// administrator tells it what time it is. Every command here is conditional on what the device
/// actually exposes, which is why commissioning reads its capabilities first.
/// </remarks>
public sealed class TimeSynchronizationCluster
{
    private readonly MatterInteractionClient _client;
    private const uint Endpoint = 0;

    public TimeSynchronizationCluster(MatterInteractionClient client) => _client = client;

    /// <summary>Matter's epoch: midnight 1 January 2000 UTC, as opposed to the Unix epoch.</summary>
    public static readonly DateTime MatterEpoch = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>Microseconds since the Matter epoch, the unit every time field in this cluster uses.</summary>
    public static ulong ToMatterEpochMicroseconds(DateTimeOffset when) =>
        (ulong)((when.UtcDateTime - MatterEpoch).Ticks / 10);

    /// <summary>Tell the device the current UTC time.</summary>
    public Task SetUtcTimeAsync(
        DateTimeOffset now, TimeGranularity granularity = TimeGranularity.SecondsGranularity,
        TimeSource source = TimeSource.Admin, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), ToMatterEpochMicroseconds(now));
        w.WriteUnsignedInt(MatterTag.Context(1), (byte)granularity);
        w.WriteUnsignedInt(MatterTag.Context(2), (byte)source);
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.TimeSynchronization, TimeSynchronizationCommands.SetUtcTime), w.ToArray(), ct);
    }

    /// <summary>
    /// Set the device's time zone as a single entry covering all time, which is what a
    /// commissioner sends when it has no schedule of future transitions to offer.
    /// </summary>
    public Task SetTimeZoneAsync(TimeSpan offsetFromUtc, string? name = null, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.StartArray(MatterTag.Context(0));           // TimeZone list
        w.StartStructure(MatterTag.Anonymous);        // TimeZoneStruct
        w.WriteSignedInt(MatterTag.Context(0), (long)offsetFromUtc.TotalSeconds);
        w.WriteUnsignedInt(MatterTag.Context(1), 0);  // ValidAt 0 = valid from the beginning of time
        if (name is not null) w.WriteUtf8String(MatterTag.Context(2), name);
        w.EndContainer();
        w.EndContainer();
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.TimeSynchronization, TimeSynchronizationCommands.SetTimeZone), w.ToArray(), ct);
    }

    /// <summary>
    /// Set the daylight-saving offset. An empty list means "no DST applies", which is the honest
    /// answer when the commissioner has no transition schedule to hand.
    /// </summary>
    public Task SetDstOffsetAsync(IReadOnlyList<(int OffsetSeconds, ulong ValidStartingUtcUs)>? offsets = null, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.StartArray(MatterTag.Context(0));
        foreach (var (offsetSeconds, validStarting) in offsets ?? [])
        {
            w.StartStructure(MatterTag.Anonymous);
            w.WriteSignedInt(MatterTag.Context(0), offsetSeconds);
            w.WriteUnsignedInt(MatterTag.Context(1), validStarting);
            w.WriteNull(MatterTag.Context(2));        // ValidUntil null = until further notice
            w.EndContainer();
        }
        w.EndContainer();
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.TimeSynchronization, TimeSynchronizationCommands.SetDstOffset), w.ToArray(), ct);
    }

    /// <summary>
    /// Nominate a node on the fabric whose clock this device should follow, for devices with no
    /// clock of their own and no route to an NTP server. Passing null clears it.
    /// </summary>
    public Task SetTrustedTimeSourceAsync(ulong? nodeId, ushort endpoint = 0, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        if (nodeId is null)
        {
            w.WriteNull(MatterTag.Context(0));
        }
        else
        {
            w.StartStructure(MatterTag.Context(0));            // FabricScopedTrustedTimeSourceStruct
            w.WriteUnsignedInt(MatterTag.Context(0), nodeId.Value);
            w.WriteUnsignedInt(MatterTag.Context(1), endpoint);
            w.EndContainer();
        }
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.TimeSynchronization, TimeSynchronizationCommands.SetTrustedTimeSource), w.ToArray(), ct);
    }

    /// <summary>Give the device an NTP server to fall back on once it is on the network.</summary>
    public Task SetDefaultNtpAsync(string? ntpServer, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        if (ntpServer is null) w.WriteNull(MatterTag.Context(0));
        else w.WriteUtf8String(MatterTag.Context(0), ntpServer);
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.TimeSynchronization, TimeSynchronizationCommands.SetDefaultNtp), w.ToArray(), ct);
    }
}
