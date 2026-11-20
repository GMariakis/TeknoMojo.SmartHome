using System.Text.Json;

namespace TeknoMojo.HomeKit.Hap;

/// <summary>
/// Default <see cref="IHapPairingStore"/>: one JSON file per accessory under a directory.
/// Files are named by a filesystem-safe hash of the accessory id (which contains ':'), so the
/// caller can drop this on any OS without worrying about escaping.
/// </summary>
public sealed class FileHapPairingStore : IHapPairingStore
{
    private readonly string _directory;
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public FileHapPairingStore(string directory)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
        Directory.CreateDirectory(_directory);
    }

    /// <summary>Store under <c>%LOCALAPPDATA%\TeknoMojo\HomeKit\Pairings</c> (Windows) or the XDG equivalent.</summary>
    public static FileHapPairingStore Default()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new FileHapPairingStore(Path.Combine(root, "TeknoMojo", "HomeKit", "Pairings"));
    }

    public async Task<HapPairing?> LoadAsync(string accessoryId, CancellationToken ct = default)
    {
        string path = FileFor(accessoryId);
        if (!File.Exists(path)) return null;
        await using var fs = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<HapPairing>(fs, JsonOpts, ct);
    }

    public async Task SaveAsync(HapPairing pairing, CancellationToken ct = default)
    {
        string path = FileFor(pairing.AccessoryId);
        // Write to a temp file then rename, so a crash mid-write doesn't leave a truncated pairing.
        string tmp = path + ".tmp";
        await using (var fs = File.Create(tmp))
        {
            await JsonSerializer.SerializeAsync(fs, pairing, JsonOpts, ct);
        }
        File.Move(tmp, path, overwrite: true);
    }

    public Task DeleteAsync(string accessoryId, CancellationToken ct = default)
    {
        string path = FileFor(accessoryId);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<string>> ListAccessoryIdsAsync(CancellationToken ct = default)
    {
        var ids = new List<string>();
        foreach (string file in Directory.EnumerateFiles(_directory, "*.json"))
        {
            try
            {
                using var fs = File.OpenRead(file);
                var p = JsonSerializer.Deserialize<HapPairing>(fs, JsonOpts);
                if (p is not null) ids.Add(p.AccessoryId);
            }
            catch { /* skip malformed file */ }
        }
        return Task.FromResult<IReadOnlyList<string>>(ids);
    }

    private string FileFor(string accessoryId)
    {
        // Accessory ids look like "AA:BB:...", not a valid filename on Windows.
        string safe = accessoryId.Replace(':', '-').Replace('/', '_').Replace('\\', '_');
        return Path.Combine(_directory, safe + ".json");
    }
}
