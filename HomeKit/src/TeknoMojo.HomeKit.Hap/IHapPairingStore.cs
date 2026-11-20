namespace TeknoMojo.HomeKit.Hap;

/// <summary>
/// Persistence for <see cref="HapPairing"/> records — one per accessory. Callers pair once and
/// then look the pairing up by accessory id for every future session. The default implementation
/// is <see cref="FileHapPairingStore"/> (JSON files under a directory); alternatives can back
/// this with a database or vault.
/// </summary>
public interface IHapPairingStore
{
    Task<HapPairing?> LoadAsync(string accessoryId, CancellationToken ct = default);
    Task SaveAsync(HapPairing pairing, CancellationToken ct = default);
    Task DeleteAsync(string accessoryId, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAccessoryIdsAsync(CancellationToken ct = default);
}
