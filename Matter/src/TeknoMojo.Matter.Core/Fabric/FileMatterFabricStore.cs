using System.Text.Json;
using System.Text.Json.Serialization;

namespace TeknoMojo.Matter.Core.Fabric;

/// <summary>
/// Default <see cref="IMatterFabricStore"/>: one JSON file per fabric under a directory, named by
/// fabric id.
/// </summary>
/// <remarks>
/// The contents are plaintext, including the fabric's root CA private key, this controller's
/// operational private key and the Identity Protection Key. That is stated plainly rather than
/// obscured: anyone who can read these files can administer every device on the fabric. On a
/// single-user desktop, per-user file permissions are usually the intended protection; anywhere
/// else, back <see cref="IMatterFabricStore"/> with a keychain, DPAPI, or a vault instead.
/// </remarks>
public sealed class FileMatterFabricStore : IMatterFabricStore
{
    private readonly string _directory;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public FileMatterFabricStore(string directory)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
        Directory.CreateDirectory(_directory);
    }

    /// <summary>Store under <c>%LOCALAPPDATA%\TeknoMojo\Matter\Fabrics</c> (Windows) or the XDG equivalent.</summary>
    public static FileMatterFabricStore Default()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new FileMatterFabricStore(Path.Combine(root, "TeknoMojo", "Matter", "Fabrics"));
    }

    public async Task<MatterFabricRecord?> LoadAsync(ulong fabricId, CancellationToken ct = default)
    {
        string path = FileFor(fabricId);
        if (!File.Exists(path)) return null;

        await using var stream = File.OpenRead(path);
        var dto = await JsonSerializer.DeserializeAsync<FabricDto>(stream, JsonOpts, ct);
        return dto?.ToRecord();
    }

    public async Task SaveAsync(MatterFabricRecord record, CancellationToken ct = default)
    {
        // Write to a temporary file and move it into place, so an interrupted save cannot leave a
        // half-written fabric behind — which would lose every device commissioned onto it.
        string path = FileFor(record.Fabric.FabricId);
        string temp = path + ".tmp";

        await using (var stream = File.Create(temp))
        {
            await JsonSerializer.SerializeAsync(stream, FabricDto.From(record), JsonOpts, ct);
        }
        File.Move(temp, path, overwrite: true);
    }

    public Task DeleteAsync(ulong fabricId, CancellationToken ct = default)
    {
        string path = FileFor(fabricId);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<ulong>> ListFabricIdsAsync(CancellationToken ct = default)
    {
        var ids = new List<ulong>();
        foreach (string file in Directory.EnumerateFiles(_directory, "*.json"))
        {
            if (ulong.TryParse(Path.GetFileNameWithoutExtension(file),
                    System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out ulong id))
            {
                ids.Add(id);
            }
        }
        return Task.FromResult<IReadOnlyList<ulong>>(ids);
    }

    private string FileFor(ulong fabricId) => Path.Combine(_directory, $"{fabricId:X16}.json");

    /// <summary>
    /// Serialisation shape. Binary fields are base64 rather than JSON number arrays, which keeps
    /// the files legible and an order of magnitude smaller.
    /// </summary>
    private sealed record FabricDto
    {
        public ulong FabricId { get; init; }
        public required string RootCertificate { get; init; }
        public string? IntermediateCertificate { get; init; }
        public required string ControllerNoc { get; init; }
        public required string ControllerNocPrivateKey { get; init; }
        public ulong ControllerNodeId { get; init; }
        public required string IdentityProtectionKey { get; init; }
        public List<NodeDto> Nodes { get; init; } = [];

        public static FabricDto From(MatterFabricRecord record) => new()
        {
            FabricId = record.Fabric.FabricId,
            RootCertificate = Convert.ToBase64String(record.Fabric.RootCertificateDer),
            IntermediateCertificate = record.Fabric.IntermediateCertificateDer is { } icac
                ? Convert.ToBase64String(icac)
                : null,
            ControllerNoc = Convert.ToBase64String(record.Fabric.ControllerNocDer),
            ControllerNocPrivateKey = Convert.ToBase64String(record.Fabric.ControllerNocPrivateKeyPkcs8),
            ControllerNodeId = record.Fabric.ControllerNodeId,
            IdentityProtectionKey = Convert.ToBase64String(record.Fabric.IdentityProtectionKey),
            Nodes = [.. record.Nodes.Select(NodeDto.From)],
        };

        public MatterFabricRecord ToRecord() => new(
            new MatterFabric
            {
                FabricId = FabricId,
                RootCertificateDer = Convert.FromBase64String(RootCertificate),
                IntermediateCertificateDer = IntermediateCertificate is null ? null : Convert.FromBase64String(IntermediateCertificate),
                ControllerNocDer = Convert.FromBase64String(ControllerNoc),
                ControllerNocPrivateKeyPkcs8 = Convert.FromBase64String(ControllerNocPrivateKey),
                ControllerNodeId = ControllerNodeId,
                IdentityProtectionKey = Convert.FromBase64String(IdentityProtectionKey),
            },
            [.. Nodes.Select(n => n.ToNode())]);
    }

    private sealed record NodeDto
    {
        public ulong NodeId { get; init; }
        public required string Noc { get; init; }
        public required string PublicKey { get; init; }

        public static NodeDto From(MatterCommissionedNode node) => new()
        {
            NodeId = node.NodeId,
            Noc = Convert.ToBase64String(node.NocDer),
            PublicKey = Convert.ToBase64String(node.PublicKeyUncompressed),
        };

        public MatterCommissionedNode ToNode() =>
            new(NodeId, Convert.FromBase64String(Noc), Convert.FromBase64String(PublicKey));
    }
}
