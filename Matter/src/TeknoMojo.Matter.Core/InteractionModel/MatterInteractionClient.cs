using TeknoMojo.Matter.Core.Messaging;

namespace TeknoMojo.Matter.Core.InteractionModel;

/// <summary>
/// Interaction Model client operating over an established <see cref="MatterOperationalChannel"/>
/// (i.e. after CASE). Provides the two operations a controller needs most: reading attributes
/// and invoking commands. Persistent subscriptions (Subscribe + ongoing ReportData) are not yet
/// implemented — out of scope for the commissioning/read/invoke milestones this targets first.
/// </summary>
public sealed class MatterInteractionClient
{
    private readonly IMatterMessageChannel _channel;

    public MatterInteractionClient(IMatterMessageChannel channel) => _channel = channel;

    /// <summary>
    /// Read one or more attributes and return every report entry (data or per-path status).
    /// </summary>
    /// <remarks>
    /// A response too large for one message arrives in chunks: each ReportData sets
    /// MoreChunkedMessages, and the device sends the next only once we acknowledge the previous
    /// with a Success StatusResponse. The chunks are reassembled here, so callers see one list.
    /// </remarks>
    public async Task<List<AttributeReport>> ReadAttributesAsync(IReadOnlyList<AttributePath> paths, CancellationToken ct = default)
    {
        ushort exchangeId = _channel.NextExchangeId();
        byte[] body = InteractionModelCodec.EncodeReadRequest(paths);
        await _channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.ReadRequest, exchangeId, body, ct: ct);

        var all = new List<AttributeReport>();
        while (true)
        {
            var (header, payload) = await _channel.ReceiveAsync(ct);
            EnsureProtocol(header, MatterProtocolIds.InteractionModel);

            if (header.Opcode == InteractionModelOpcodes.StatusResponse)
                throw new MatterInteractionException(InteractionModelCodec.DecodeStatusResponse(payload));
            if (header.Opcode != InteractionModelOpcodes.ReportData)
                throw new InvalidOperationException($"ReadAttributes: unexpected response opcode 0x{header.Opcode:X2}.");

            all.AddRange(InteractionModelCodec.DecodeReportData(payload, out _, out bool more));
            if (!more) return all;

            // The device waits for this before sending the next chunk.
            await _channel.SendAsync(
                MatterProtocolIds.InteractionModel, InteractionModelOpcodes.StatusResponse, exchangeId,
                InteractionModelCodec.EncodeStatusResponse(MatterStatus.Success), ct: ct);
        }
    }

    /// <summary>Read a single attribute and return its raw TLV value bytes, throwing if the path came back as a status instead of data.</summary>
    public async Task<byte[]> ReadAttributeAsync(AttributePath path, CancellationToken ct = default)
    {
        var reports = await ReadAttributesAsync(new[] { path }, ct);
        return reports switch
        {
            [AttributeReport.Data data] => data.ValueTlv,
            [AttributeReport.Status status] => throw new MatterInteractionException(status.Status_),
            [] => throw new InvalidOperationException("ReadAttribute: no report returned for the requested path."),
            _ => throw new InvalidOperationException("ReadAttribute: multiple reports returned for a single path."),
        };
    }

    /// <summary>Invoke one or more commands and return every result (data or per-command status).</summary>
    public async Task<List<InvokeResult>> InvokeCommandsAsync(IReadOnlyList<CommandInvocation> commands, CancellationToken ct = default)
    {
        ushort exchangeId = _channel.NextExchangeId();
        byte[] body = InteractionModelCodec.EncodeInvokeRequest(commands);
        await _channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.InvokeCommandRequest, exchangeId, body, ct: ct);

        var (header, payload) = await _channel.ReceiveAsync(ct);
        EnsureProtocol(header, MatterProtocolIds.InteractionModel);

        if (header.Opcode == InteractionModelOpcodes.InvokeCommandResponse)
            return InteractionModelCodec.DecodeInvokeResponse(payload);
        if (header.Opcode == InteractionModelOpcodes.StatusResponse)
            throw new MatterInteractionException(InteractionModelCodec.DecodeStatusResponse(payload));

        throw new InvalidOperationException($"InvokeCommands: unexpected response opcode 0x{header.Opcode:X2}.");
    }

    /// <summary>Invoke a single command with no meaningful response payload expected (the common case: On/Off/Toggle/ArmFailSafe/...).</summary>
    public async Task InvokeCommandAsync(CommandPath path, byte[] fieldsTlv, CancellationToken ct = default)
    {
        var results = await InvokeCommandsAsync(new[] { new CommandInvocation(path, fieldsTlv) }, ct);
        foreach (var result in results)
        {
            if (result is InvokeResult.Status { Status_: not MatterStatus.Success } status)
                throw new MatterInteractionException(status.Status_);
        }
    }

    /// <summary>Invoke a single command and return its response fields TLV (for commands like CSRRequest that reply with data).</summary>
    public async Task<byte[]> InvokeCommandForDataAsync(CommandPath path, byte[] fieldsTlv, CancellationToken ct = default)
    {
        var results = await InvokeCommandsAsync(new[] { new CommandInvocation(path, fieldsTlv) }, ct);
        return results switch
        {
            [InvokeResult.Data data] => data.FieldsTlv,
            [InvokeResult.Status { Status_: not MatterStatus.Success } status] => throw new MatterInteractionException(status.Status_),
            _ => throw new InvalidOperationException("InvokeCommandForData: expected exactly one data result."),
        };
    }

    private static void EnsureProtocol(MatterProtocolHeader header, ushort expected)
    {
        if (header.ProtocolId != expected)
            throw new InvalidOperationException($"Expected protocol 0x{expected:X4}, got 0x{header.ProtocolId:X4}.");
    }
}

/// <summary>A Matter Interaction Model call came back with a non-Success status.</summary>
public sealed class MatterInteractionException : Exception
{
    public MatterStatus Status { get; }
    public MatterInteractionException(MatterStatus status) : base($"Interaction Model status: {status}") => Status = status;
}
