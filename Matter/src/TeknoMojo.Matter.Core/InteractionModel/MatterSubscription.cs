using TeknoMojo.Matter.Core.Messaging;

namespace TeknoMojo.Matter.Core.InteractionModel;

/// <summary>
/// A live subscription: the device reports the attributes it was asked about whenever they change,
/// and at least once per its maximum interval so silence stays distinguishable from a dead link.
/// </summary>
/// <remarks>
/// Unlike a read, a subscription outlives the exchange that created it. Each ReportData the device
/// sends must be acknowledged with a Success StatusResponse — a device that stops being
/// acknowledged eventually tears the subscription down, so pumping is not optional.
/// </remarks>
public sealed class MatterSubscription : IAsyncDisposable
{
    private readonly IMatterMessageChannel _channel;
    private readonly ushort _exchangeId;
    private readonly CancellationTokenSource _stopped = new();
    private Task? _pump;

    private MatterSubscription(IMatterMessageChannel channel, ushort exchangeId, uint subscriptionId, ushort maxInterval)
    {
        _channel = channel;
        _exchangeId = exchangeId;
        SubscriptionId = subscriptionId;
        MaxInterval = maxInterval;
    }

    /// <summary>Identifies this subscription in the reports the device sends.</summary>
    public uint SubscriptionId { get; }

    /// <summary>
    /// The longest the device will stay silent. Hearing nothing for appreciably longer than this
    /// means the subscription or the link is gone, not that nothing changed.
    /// </summary>
    public ushort MaxInterval { get; }

    /// <summary>
    /// The device's opening report of current values, captured before this object was handed back.
    /// It is exposed as data rather than raised as an event so a caller cannot miss it by
    /// attaching a handler a moment too late.
    /// </summary>
    public IReadOnlyList<AttributeReport> InitialReports { get; private init; } = [];

    /// <summary>Raised for each report after the initial one.</summary>
    public event Action<IReadOnlyList<AttributeReport>>? Reported;

    /// <summary>
    /// Raised if the subscription ends unexpectedly — the channel closed, or a report could not be
    /// processed. Not raised for an ordinary <see cref="DisposeAsync"/>.
    /// </summary>
    public event Action<Exception>? Faulted;

    /// <summary>
    /// Subscribe to <paramref name="paths"/>, returning once the device has confirmed. Reports
    /// arrive on <see cref="Reported"/> from then on, starting with the initial priming report.
    /// </summary>
    public static async Task<MatterSubscription> CreateAsync(
        IMatterMessageChannel channel,
        IReadOnlyList<AttributePath> paths,
        ushort minIntervalFloorSeconds = 0,
        ushort maxIntervalCeilingSeconds = 60,
        CancellationToken ct = default)
    {
        ushort exchangeId = channel.NextExchangeId();
        byte[] body = InteractionModelCodec.EncodeSubscribeRequest(
            paths, minIntervalFloorSeconds, maxIntervalCeilingSeconds);
        await channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.SubscribeRequest,
            exchangeId, body, ct: ct);

        // The device primes the subscription with a full report of the current values, possibly
        // chunked, and only then confirms with a SubscribeResponse.
        var priming = new List<AttributeReport>();
        while (true)
        {
            var (header, payload) = await channel.ReceiveAsync(ct);

            if (header.Opcode == InteractionModelOpcodes.StatusResponse)
                throw new MatterInteractionException(InteractionModelCodec.DecodeStatusResponse(payload));

            if (header.Opcode == InteractionModelOpcodes.ReportData)
            {
                priming.AddRange(InteractionModelCodec.DecodeReportData(payload, out _, out bool more));
                await AcknowledgeAsync(channel, exchangeId, ct);
                if (more) continue;
                continue;   // the confirmation still follows the priming report
            }

            if (header.Opcode == InteractionModelOpcodes.SubscribeResponse)
            {
                var (id, maxInterval) = InteractionModelCodec.DecodeSubscribeResponse(payload);
                var subscription = new MatterSubscription(channel, exchangeId, id, maxInterval)
                {
                    InitialReports = priming,
                };
                subscription.Start();
                return subscription;
            }

            throw new InvalidOperationException($"Subscribe: unexpected response opcode 0x{header.Opcode:X2}.");
        }
    }

    private void Start()
    {
        _pump = Task.Run(async () =>
        {
            try
            {
                while (!_stopped.IsCancellationRequested)
                {
                    var (header, payload) = await _channel.ReceiveAsync(_stopped.Token);
                    if (header.Opcode != InteractionModelOpcodes.ReportData) continue;

                    var reports = InteractionModelCodec.DecodeReportData(payload, out _, out _);
                    await AcknowledgeAsync(_channel, _exchangeId, _stopped.Token);
                    if (reports.Count > 0) Reported?.Invoke(reports);
                }
            }
            catch (OperationCanceledException) when (_stopped.IsCancellationRequested)
            {
                // Ordinary shutdown.
            }
            catch (Exception ex)
            {
                Faulted?.Invoke(ex);
            }
        });
    }

    private static Task AcknowledgeAsync(IMatterMessageChannel channel, ushort exchangeId, CancellationToken ct) =>
        channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.StatusResponse, exchangeId,
            InteractionModelCodec.EncodeStatusResponse(MatterStatus.Success), ct: ct);

    /// <summary>
    /// Stop listening. The device keeps the subscription until it times out for want of
    /// acknowledgement, or until the session goes away.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        await _stopped.CancelAsync();
        if (_pump is not null)
        {
            try { await _pump; } catch { /* shutdown races are not interesting */ }
        }
        _stopped.Dispose();
    }
}
