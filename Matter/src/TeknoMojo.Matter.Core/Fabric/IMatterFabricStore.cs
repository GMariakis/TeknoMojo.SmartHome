namespace TeknoMojo.Matter.Core.Fabric;

/// <summary>
/// A device we commissioned onto a fabric, and what we need to talk to it again.
/// </summary>
/// <param name="NocDer">The operational certificate we issued it, kept so its identity can be audited later.</param>
public sealed record MatterCommissionedNode(ulong NodeId, byte[] NocDer, byte[] PublicKeyUncompressed);

/// <summary>A fabric together with the nodes commissioned onto it.</summary>
public sealed record MatterFabricRecord(MatterFabric Fabric, IReadOnlyList<MatterCommissionedNode> Nodes)
{
    public MatterFabricRecord With(MatterCommissionedNode node) =>
        this with { Nodes = [.. Nodes.Where(n => n.NodeId != node.NodeId), node] };
}

/// <summary>
/// Persistence for fabrics — the Matter analogue of <c>IHapPairingStore</c>. Commissioning a device
/// is a one-off act; without somewhere to keep the fabric credentials, every restart would orphan
/// every device already commissioned, since only the holder of the fabric's keys can open a CASE
/// session with them.
/// </summary>
/// <remarks>
/// What is stored is highly sensitive: the fabric's root CA private key, this controller's
/// operational private key, and the Identity Protection Key. Anything holding those can
/// impersonate the administrator of every device on the fabric. Implementations should protect
/// them accordingly — <see cref="FileMatterFabricStore"/> deliberately does not pretend to.
/// </remarks>
public interface IMatterFabricStore
{
    Task<MatterFabricRecord?> LoadAsync(ulong fabricId, CancellationToken ct = default);
    Task SaveAsync(MatterFabricRecord record, CancellationToken ct = default);
    Task DeleteAsync(ulong fabricId, CancellationToken ct = default);
    Task<IReadOnlyList<ulong>> ListFabricIdsAsync(CancellationToken ct = default);
}
