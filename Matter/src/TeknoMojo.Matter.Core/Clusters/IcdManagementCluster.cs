using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>
/// Typed helper for the ICD Management cluster (0x0046) — endpoint 0 only.
/// </summary>
/// <remarks>
/// An Intermittently Connected Device is one that sleeps to save battery and is therefore not
/// reachable most of the time. Rather than have controllers poll a device that is not listening,
/// the device notifies registered clients when it wakes. Registering during commissioning is what
/// makes a controller one of those clients; skip it and the controller may simply never hear from
/// a battery-powered device again.
/// </remarks>
public sealed class IcdManagementCluster
{
    private readonly MatterInteractionClient _client;
    private const uint Endpoint = 0;

    public IcdManagementCluster(MatterInteractionClient client) => _client = client;

    /// <summary>
    /// Register to be told when the device wakes.
    /// </summary>
    /// <param name="checkInNodeId">The node the device should check in with — normally the controller.</param>
    /// <param name="monitoredSubject">The subject the device monitors on our behalf; usually the same node.</param>
    /// <param name="key">
    /// A 16-byte shared key used to authenticate check-ins. It is a secret between this controller
    /// and the device, so it must be random and kept alongside the fabric credentials.
    /// </param>
    /// <returns>The device's check-in counter, which a client persists to detect missed check-ins.</returns>
    public async Task<uint> RegisterClientAsync(
        ulong checkInNodeId, ulong monitoredSubject, byte[] key,
        IcdClientType clientType = IcdClientType.Permanent, CancellationToken ct = default)
    {
        if (key.Length != 16)
            throw new ArgumentException("The ICD check-in key must be 16 bytes.", nameof(key));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), checkInNodeId);
        w.WriteUnsignedInt(MatterTag.Context(1), monitoredSubject);
        w.WriteByteString(MatterTag.Context(2), key);
        w.WriteUnsignedInt(MatterTag.Context(4), (byte)clientType);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.IcdManagement, IcdManagementCommands.RegisterClient), w.ToArray(), ct);

        var r = new MatterTlvReader(response);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("RegisterClientResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (uint)r.GetUnsignedInt();
        }
        throw new FormatException("RegisterClientResponse: missing ICDCounter");
    }

    /// <summary>Stop being notified when the device wakes.</summary>
    public Task UnregisterClientAsync(ulong checkInNodeId, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), checkInNodeId);
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.IcdManagement, IcdManagementCommands.UnregisterClient), w.ToArray(), ct);
    }

    /// <summary>
    /// Ask a sleepy device to stay awake a while longer, so a burst of work can complete without
    /// it dropping off mid-exchange.
    /// </summary>
    public Task RequestStayActiveAsync(uint durationMilliseconds, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), durationMilliseconds);
        w.EndContainer();

        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.IcdManagement, IcdManagementCommands.StayActiveRequest), w.ToArray(), ct);
    }
}
