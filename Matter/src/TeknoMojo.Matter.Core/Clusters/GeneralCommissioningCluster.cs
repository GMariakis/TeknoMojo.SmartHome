using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>Typed helper for the General Commissioning cluster (0x0030) — endpoint 0 only.</summary>
public sealed class GeneralCommissioningCluster
{
    private readonly MatterInteractionClient _client;
    private const uint Endpoint = 0;

    public GeneralCommissioningCluster(MatterInteractionClient client) => _client = client;

    /// <summary>Arm (or, with a zero expiry, disarm) the fail-safe timer. Required before any commissioning writes.</summary>
    public async Task<CommissioningError> ArmFailSafeAsync(ushort expiryLengthSeconds, ulong breadcrumb, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), expiryLengthSeconds);
        w.WriteUnsignedInt(MatterTag.Context(1), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.GeneralCommissioning, GeneralCommissioningCommands.ArmFailSafe), w.ToArray(), ct);
        return ParseCommissioningError(response);
    }

    /// <summary>
    /// Tell the device which regulatory regime it is operating under. A commissioner is expected
    /// to send this between arming the fail-safe and provisioning the network, because it governs
    /// which radio channels and powers the device may use once it joins.
    /// </summary>
    /// <param name="countryCode">Two-character ISO 3166-1 alpha-2 code, or "XX" when not known.</param>
    public async Task<CommissioningError> SetRegulatoryConfigAsync(
        RegulatoryLocation location, string countryCode, ulong breadcrumb, CancellationToken ct = default)
    {
        if (countryCode.Length != 2)
            throw new ArgumentException("Country code must be exactly two characters.", nameof(countryCode));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), (byte)location);
        w.WriteUtf8String(MatterTag.Context(1), countryCode);
        w.WriteUnsignedInt(MatterTag.Context(2), breadcrumb);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.GeneralCommissioning, GeneralCommissioningCommands.SetRegulatoryConfig), w.ToArray(), ct);
        return ParseCommissioningError(response);
    }

    /// <summary>
    /// Record which terms and conditions the user accepted, for devices that will not finish
    /// commissioning until told.
    /// </summary>
    /// <param name="version">The terms version the user was shown; must be at least TCMinRequiredVersion.</param>
    /// <param name="userResponse">
    /// Bitmap of the terms the user actually agreed to. This represents a human's decision, so it
    /// is the caller's to supply — it cannot be inferred here.
    /// </param>
    public async Task<CommissioningError> SetTermsAndConditionsAsync(
        ushort version, ushort userResponse, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), version);
        w.WriteUnsignedInt(MatterTag.Context(1), userResponse);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.GeneralCommissioning, GeneralCommissioningCommands.SetTcAcknowledgements), w.ToArray(), ct);
        return ParseCommissioningError(response);
    }

    /// <summary>Signal that commissioning is finished; the device switches from the fail-safe window to normal operation.</summary>
    public async Task<CommissioningError> CommissioningCompleteAsync(CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.GeneralCommissioning, GeneralCommissioningCommands.CommissioningComplete), w.ToArray(), ct);
        return ParseCommissioningError(response);
    }

    private static CommissioningError ParseCommissioningError(byte[] responseTlv)
    {
        var r = new MatterTlvReader(responseTlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("Commissioning response: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (CommissioningError)r.GetUnsignedInt();
        }
        throw new FormatException("Commissioning response: missing ErrorCode");
    }
}
