using System.Text;
using TeknoMojo.HomeKit.Core;
using TeknoMojo.HomeKit.Hap.Http;
using TeknoMojo.HomeKit.Hap.Pairing;

namespace TeknoMojo.HomeKit.Hap;

/// <summary>
/// Entry point for the HAP controller: pair with a new accessory, look pairings up in a store,
/// open a verified session, and issue characteristic reads/writes.
/// </summary>
/// <remarks>
/// P1 scope: <see cref="PairAsync"/>, <see cref="ConnectAsync"/>, and
/// <see cref="HapSession.GetAccessoriesAsync"/>. Writes and event subscriptions land in P2/P3.
/// </remarks>
public sealed class HapController
{
    private readonly IHapPairingStore _store;

    public HapController(IHapPairingStore? store = null)
    {
        _store = store ?? FileHapPairingStore.Default();
    }

    /// <summary>
    /// Run pair-setup with <paramref name="accessory"/> using its 8-digit setup code, persist
    /// the resulting <see cref="HapPairing"/> in the store, and return it. Idempotent-ish: if
    /// the accessory is already paired with this controller, re-running will replace the entry
    /// (the accessory itself may reject a second pair-setup — use RemovePairing later).
    /// </summary>
    public async Task<HapPairing> PairAsync(HapAccessory accessory, string setupCode, CancellationToken ct = default)
    {
        var pairing = await PairSetup.RunAsync(accessory, setupCode, ct: ct);
        await _store.SaveAsync(pairing, ct);
        return pairing;
    }

    /// <summary>
    /// Open a verified encrypted session to an already-paired accessory. Loads the
    /// <see cref="HapPairing"/> from the store by <paramref name="accessory"/>'s HAP id.
    /// </summary>
    public async Task<HapSession> ConnectAsync(HapAccessory accessory, CancellationToken ct = default)
    {
        if (accessory.Id is null)
            throw new ArgumentException("Accessory has no HAP id in its TXT records.", nameof(accessory));

        HapPairing? pairing = await _store.LoadAsync(accessory.Id, ct);
        if (pairing is null)
            throw new InvalidOperationException($"No stored pairing for accessory {accessory.Id}. Run PairAsync first.");

        var verified = await PairVerify.RunAsync(accessory, pairing, ct);
        return new HapSession(verified, pairing);
    }

    /// <summary>The underlying pairing store, for callers that want to inspect or manage pairings directly.</summary>
    public IHapPairingStore Store => _store;
}

/// <summary>
/// A live encrypted HAP session. Read/write characteristics through here; dispose to close.
/// </summary>
public sealed class HapSession : IDisposable
{
    private readonly HapVerifiedSession _verified;

    public HapPairing Pairing { get; }

    internal HapSession(HapVerifiedSession verified, HapPairing pairing)
    {
        _verified = verified;
        Pairing = pairing;
    }

    /// <summary>
    /// Fetch the accessory's characteristic database (<c>GET /accessories</c>). Returns the raw
    /// JSON as a string — the schema is stable enough that a caller can deserialize it into
    /// their own typed model, and P2 will layer typed helpers on top.
    /// </summary>
    public async Task<string> GetAccessoriesAsync(CancellationToken ct = default)
    {
        await HapHttp.WriteRequestAsync(_verified.Stream, "GET", "/accessories", "", body: null, ct);
        var resp = await HapHttp.ReadResponseAsync(_verified.Stream, ct);
        if (resp.Status != 200)
            throw new HapProtocolException($"GET /accessories returned HTTP {resp.Status}");
        return Encoding.UTF8.GetString(resp.Body);
    }

    public void Dispose() => _verified.Dispose();
}
