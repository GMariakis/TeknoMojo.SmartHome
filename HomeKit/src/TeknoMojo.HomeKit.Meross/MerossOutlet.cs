using System.Text.Json.Nodes;

namespace TeknoMojo.HomeKit.Meross;

/// <summary>
/// High-level control of a Meross outlet on the LAN, independent of firmware generation.
///
/// Meross firmware comes in two flavours for local control: older builds accept plaintext signed
/// writes; newer ones (e.g. MSS110 fw 7.3.46) drop plaintext writes and require an ECDHE-encrypted
/// session. This class tries plaintext first and transparently falls back to the encrypted path the
/// first time a write is refused, then sticks with whichever works for the rest of its lifetime.
///
/// It exposes the relay and the indicator LED as <b>separate</b> low-level operations, plus a
/// composed <see cref="SetPowerAsync"/> that drives both together so the LED always reflects the
/// actual circuit state. Callers who want to move the LED on its own can still call
/// <see cref="SetLedAsync"/>; the next power operation re-asserts the affinity.
/// </summary>
public sealed class MerossOutlet : IDisposable
{
    private readonly string _host;
    private readonly string _key;
    private readonly MerossHttpTransport _transport;
    private readonly MerossClient _plain;
    private EcdheHttpSession? _encrypted;
    private bool _useEncrypted; // sticky: set once the device proves it refuses plaintext writes

    public MerossOutlet(string host, string key)
    {
        _host = host;
        _key = key;
        _transport = new MerossHttpTransport(host);
        _plain = new MerossClient(_transport, key);
    }

    /// <summary>True once this outlet has fallen back to the encrypted transport.</summary>
    public bool UsingEncryptedTransport => _useEncrypted;

    // --- low-level, single-concern operations -------------------------------------------------

    /// <summary>Switch the relay (the actual power circuit) on a channel.</summary>
    public Task SetRelayAsync(bool on, int channel = 0, CancellationToken ct = default) =>
        ExecuteAsync("SET", MerossNamespace.ToggleX, new JsonObject
        {
            ["togglex"] = new JsonObject { ["channel"] = channel, ["onoff"] = on ? 1 : 0 },
        }, ct);

    /// <summary>Switch only the indicator LED (Meross night mode); does not touch the relay.</summary>
    public Task SetLedAsync(bool on, CancellationToken ct = default) =>
        ExecuteAsync("SET", MerossNamespace.DndMode, new JsonObject
        {
            // mode 0 = LED lit, mode 1 = night mode / LED off.
            ["DNDMode"] = new JsonObject { ["mode"] = on ? 0 : 1 },
        }, ct);

    public async Task<bool?> GetRelayAsync(int channel = 0, CancellationToken ct = default)
    {
        JsonNode all = await ExecuteAsync("GET", MerossNamespace.SystemAll, null, ct);
        return MerossClient.ReadToggleState(all, channel);
    }

    public async Task<bool?> GetLedAsync(CancellationToken ct = default)
    {
        JsonNode dnd = await ExecuteAsync("GET", MerossNamespace.DndMode, null, ct);
        return MerossClient.ReadLedOn(dnd);
    }

    /// <summary>Current (relay, led) state in one shot.</summary>
    public async Task<(bool? Relay, bool? Led)> GetStateAsync(int channel = 0, CancellationToken ct = default)
        => (await GetRelayAsync(channel, ct), await GetLedAsync(ct));

    // --- composed, higher-level operation -----------------------------------------------------

    /// <summary>
    /// Turn the outlet on or off, keeping the LED bound to the circuit: on = relay on + LED on,
    /// off = relay off + LED off. Ordered so the LED never advertises a state the relay isn't in —
    /// on ON we energise the circuit before lighting the LED; on OFF we darken the LED before cutting
    /// power.
    /// </summary>
    public async Task SetPowerAsync(bool on, int channel = 0, CancellationToken ct = default)
    {
        if (on)
        {
            await SetRelayAsync(true, channel, ct);
            await SetLedAsync(true, ct);
        }
        else
        {
            await SetLedAsync(false, ct);
            await SetRelayAsync(false, channel, ct);
        }
    }

    // --- transport selection with plaintext-first, encrypted fallback -------------------------

    private async Task<JsonNode> ExecuteAsync(string method, string ns, JsonObject? payload, CancellationToken ct)
    {
        if (!_useEncrypted)
        {
            try
            {
                return await _plain.InvokeAsync(method, ns, payload, ct);
            }
            catch (HttpRequestException)
            {
                // Connection closed with no reply — strict firmware refusing a plaintext write.
                _useEncrypted = true;
            }
            catch (MerossException ex) when (ex.Code == 0)
            {
                // Empty/unparseable reply (code 0), not a genuine device error like 5001 sign error.
                _useEncrypted = true;
            }
        }

        EcdheHttpSession session = await EnsureEncryptedAsync(ct);
        return await session.InvokeAsync(method, ns, payload ?? new JsonObject(), ct);
    }

    private async Task<EcdheHttpSession> EnsureEncryptedAsync(CancellationToken ct)
    {
        if (_encrypted is { IsEstablished: true }) return _encrypted;
        _encrypted?.Dispose();
        _encrypted = new EcdheHttpSession(_host, _key);
        await _encrypted.HandshakeAsync(ct);
        return _encrypted;
    }

    public void Dispose()
    {
        _encrypted?.Dispose();
        _transport.Dispose();
    }
}
