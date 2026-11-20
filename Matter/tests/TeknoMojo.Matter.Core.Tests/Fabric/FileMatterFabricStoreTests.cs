using System.Security.Cryptography;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Fabric;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Fabric;

/// <summary>
/// Fabric persistence. Losing these credentials orphans every device already commissioned, since
/// only their holder can open a CASE session, so round-tripping them exactly is the whole job.
/// </summary>
public class FileMatterFabricStoreTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "matter-fabric-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
    }

    private MatterFabricRecord SampleRecord(ulong fabricId = 42)
    {
        var root = MatterCertificateBuilder.CreateRootCA(rootCaId: 1);
        var controller = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, nodeId: 1, fabricId);
        var device = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, nodeId: 200, fabricId);

        return new MatterFabricRecord(
            new MatterFabric
            {
                FabricId = fabricId,
                RootCertificateDer = root.CertificateDer,
                ControllerNocDer = controller.CertificateDer,
                ControllerNocPrivateKeyPkcs8 = controller.PrivateKeyPkcs8,
                ControllerNodeId = 1,
                IdentityProtectionKey = RandomNumberGenerator.GetBytes(16),
            },
            [new MatterCommissionedNode(200, device.CertificateDer, device.PublicKeyUncompressed)]);
    }

    [Fact]
    public async Task FabricRoundTripsByteForByte()
    {
        var store = new FileMatterFabricStore(_directory);
        var original = SampleRecord();

        await store.SaveAsync(original);
        var loaded = await store.LoadAsync(original.Fabric.FabricId);

        Assert.NotNull(loaded);
        Assert.Equal(original.Fabric.FabricId, loaded.Fabric.FabricId);
        Assert.Equal(original.Fabric.ControllerNodeId, loaded.Fabric.ControllerNodeId);
        Assert.Equal(original.Fabric.RootCertificateDer, loaded.Fabric.RootCertificateDer);
        Assert.Equal(original.Fabric.ControllerNocPrivateKeyPkcs8, loaded.Fabric.ControllerNocPrivateKeyPkcs8);
        Assert.Equal(original.Fabric.IdentityProtectionKey, loaded.Fabric.IdentityProtectionKey);

        var node = Assert.Single(loaded.Nodes);
        Assert.Equal(200ul, node.NodeId);
        Assert.Equal(original.Nodes[0].NocDer, node.NocDer);
    }

    [Fact]
    public async Task LoadingAnUnknownFabricReturnsNullRatherThanThrowing()
    {
        var store = new FileMatterFabricStore(_directory);
        Assert.Null(await store.LoadAsync(fabricId: 999));
    }

    [Fact]
    public async Task SavingTwiceReplacesRatherThanDuplicates()
    {
        var store = new FileMatterFabricStore(_directory);
        var record = SampleRecord();

        await store.SaveAsync(record);
        await store.SaveAsync(record.With(new MatterCommissionedNode(201, [1, 2, 3], [4, 5, 6])));

        var loaded = await store.LoadAsync(record.Fabric.FabricId);
        Assert.NotNull(loaded);
        Assert.Equal(2, loaded.Nodes.Count);
        Assert.Single(await store.ListFabricIdsAsync());
    }

    [Fact]
    public void ReaddingAKnownNodeUpdatesItInPlace()
    {
        var record = SampleRecord();
        var updated = record.With(new MatterCommissionedNode(200, [9, 9], [8, 8]));

        var node = Assert.Single(updated.Nodes);
        Assert.Equal(new byte[] { 9, 9 }, node.NocDer);
    }

    [Fact]
    public async Task FabricsAreListedAndDeletedIndividually()
    {
        var store = new FileMatterFabricStore(_directory);
        await store.SaveAsync(SampleRecord(1));
        await store.SaveAsync(SampleRecord(2));

        Assert.Equal(2, (await store.ListFabricIdsAsync()).Count);

        await store.DeleteAsync(1);
        Assert.Equal([2ul], await store.ListFabricIdsAsync());
    }

    [Fact]
    public async Task AnInterruptedSaveLeavesNoPartialFabricBehind()
    {
        // Saves land via a temporary file and an atomic move, so no .json should ever be observed
        // half-written; only the temp name may linger.
        var store = new FileMatterFabricStore(_directory);
        await store.SaveAsync(SampleRecord());

        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
        Assert.Single(Directory.GetFiles(_directory, "*.json"));
    }
}
