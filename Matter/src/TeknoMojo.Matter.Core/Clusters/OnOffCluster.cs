using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>
/// Typed helper for the OnOff cluster (0x0006) — the cluster your Meross on/off plug implements.
/// Thin wrapper over <see cref="MatterInteractionClient"/>; no state of its own.
/// </summary>
public sealed class OnOffCluster
{
    private readonly MatterInteractionClient _client;
    private readonly uint _endpoint;

    public OnOffCluster(MatterInteractionClient client, uint endpoint)
    {
        _client = client;
        _endpoint = endpoint;
    }

    /// <summary>Read the current OnOff attribute value.</summary>
    public async Task<bool> ReadOnOffAsync(CancellationToken ct = default)
    {
        byte[] valueTlv = await _client.ReadAttributeAsync(
            AttributePath.Exact(_endpoint, ClusterIds.OnOff, OnOffAttributes.OnOff), ct);
        var r = new MatterTlvReader(valueTlv);
        if (!r.Read()) throw new FormatException("OnOff attribute: empty value.");
        return r.GetBool();
    }

    public Task TurnOnAsync(CancellationToken ct = default) => InvokeNoArgsAsync(OnOffCommands.On, ct);
    public Task TurnOffAsync(CancellationToken ct = default) => InvokeNoArgsAsync(OnOffCommands.Off, ct);
    public Task ToggleAsync(CancellationToken ct = default) => InvokeNoArgsAsync(OnOffCommands.Toggle, ct);

    private Task InvokeNoArgsAsync(uint command, CancellationToken ct)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.EndContainer();
        return _client.InvokeCommandAsync(new CommandPath(_endpoint, ClusterIds.OnOff, command), w.ToArray(), ct);
    }
}
