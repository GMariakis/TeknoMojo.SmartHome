using TeknoMojo.Matter.Core.Clusters;
using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Commissioning;

/// <summary>
/// What a device says about itself before commissioning begins, read in a single batch so the
/// rest of the flow can follow the device rather than assume.
/// </summary>
/// <remarks>
/// Every field is optional: a device legitimately lacks whole clusters — a mains-powered plug has
/// no Time Synchronization or ICD management — and answers those reads with a per-path status
/// rather than data. Absence is information, not an error.
/// </remarks>
public sealed record MatterCommissioningInfo
{
    /// <summary>The fail-safe duration the device itself recommends, from BasicCommissioningInfo.</summary>
    public ushort? RecommendedFailSafeSeconds { get; init; }

    /// <summary>The regulatory regime the device is currently configured for.</summary>
    public RegulatoryLocation? CurrentRegulatoryLocation { get; init; }

    /// <summary>
    /// The most permissive regime the device is physically capable of. Declaring a location it
    /// cannot support is rejected, so this bounds what we may set.
    /// </summary>
    public RegulatoryLocation? LocationCapability { get; init; }

    /// <summary>
    /// False when the device cannot stay reachable on the commissioning channel while joining the
    /// operational network — it will drop BLE the moment it connects to Wi-Fi.
    /// </summary>
    public bool SupportsConcurrentConnection { get; init; } = true;

    public ushort? VendorId { get; init; }
    public ushort? ProductId { get; init; }

    /// <summary>How long the device may take to join a network, from ConnectMaxTimeSeconds.</summary>
    public ushort? NetworkConnectMaxSeconds { get; init; }

    /// <summary>True when the device exposes Time Synchronization and is waiting to be told the time.</summary>
    public bool RequiresUtcTime { get; init; }

    /// <summary>True when the device accepts a time zone list.</summary>
    public bool RequiresTimeZone { get; init; }

    /// <summary>True when the device accepts a DST offset list.</summary>
    public bool RequiresDstOffset { get; init; }

    /// <summary>True when the device exposes a DefaultNTP attribute that is currently unset.</summary>
    public bool RequiresDefaultNtp { get; init; }

    /// <summary>True when the device will follow another node's clock and has not been told which.</summary>
    public bool RequiresTrustedTimeSource { get; init; }

    /// <summary>True when the device will not complete commissioning until told the user accepted its terms.</summary>
    public bool RequiresTermsAcceptance { get; init; }

    /// <summary>The lowest terms version the device will accept.</summary>
    public ushort? MinimumTermsVersion { get; init; }

    /// <summary>
    /// True when the device sleeps and expects controllers to register for check-ins. A
    /// controller that skips registration may never hear from it again.
    /// </summary>
    public bool IsIntermittentlyConnected { get; init; }

    /// <summary>Reads the above in one batch. Paths the device does not implement come back as statuses and are simply left unset.</summary>
    public static async Task<MatterCommissioningInfo> ReadAsync(MatterInteractionClient client, CancellationToken ct = default)
    {
        AttributePath Path(uint cluster, uint attribute) => new(Endpoint: 0, cluster, attribute);

        var paths = new[]
        {
            Path(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.BasicCommissioningInfo),
            Path(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.RegulatoryConfig),
            Path(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.LocationCapability),
            Path(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.SupportsConcurrentConnection),
            Path(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.TcAcknowledgementsRequired),
            Path(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.TcMinRequiredVersion),
            Path(ClusterIds.BasicInformation, CommissioningInfoAttributes.VendorId),
            Path(ClusterIds.BasicInformation, CommissioningInfoAttributes.ProductId),
            Path(ClusterIds.NetworkCommissioning, CommissioningInfoAttributes.ConnectMaxTimeSeconds),
            Path(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.UtcTime),
            Path(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.TimeZoneListMaxSize),
            Path(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.DstOffsetListMaxSize),
            Path(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.DefaultNtp),
            Path(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.TrustedTimeSource),
            Path(ClusterIds.IcdManagement, CommissioningInfoAttributes.IcdIdleModeDuration),
        };

        var reports = await client.ReadAttributesAsync(paths, ct);
        var data = new Dictionary<(uint Cluster, uint Attribute), byte[]>();
        foreach (var report in reports)
        {
            if (report is AttributeReport.Data d && d.Path.Cluster is { } cluster && d.Path.Attribute is { } attribute)
                data[(cluster, attribute)] = d.ValueTlv;
        }

        byte[]? Value(uint cluster, uint attribute) =>
            data.TryGetValue((cluster, attribute), out byte[]? v) ? v : null;

        return new MatterCommissioningInfo
        {
            RecommendedFailSafeSeconds = ReadFailSafeExpiry(Value(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.BasicCommissioningInfo)),
            CurrentRegulatoryLocation = (RegulatoryLocation?)ReadByte(Value(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.RegulatoryConfig)),
            LocationCapability = (RegulatoryLocation?)ReadByte(Value(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.LocationCapability)),
            SupportsConcurrentConnection = ReadBool(Value(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.SupportsConcurrentConnection)) ?? true,
            VendorId = (ushort?)ReadUnsigned(Value(ClusterIds.BasicInformation, CommissioningInfoAttributes.VendorId)),
            ProductId = (ushort?)ReadUnsigned(Value(ClusterIds.BasicInformation, CommissioningInfoAttributes.ProductId)),
            NetworkConnectMaxSeconds = (ushort?)ReadUnsigned(Value(ClusterIds.NetworkCommissioning, CommissioningInfoAttributes.ConnectMaxTimeSeconds)),

            // Presence of the attribute is what matters here: a device exposing UTCTime is one
            // that expects an administrator to set it.
            RequiresUtcTime = Value(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.UtcTime) is not null,
            RequiresTimeZone = (ReadUnsigned(Value(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.TimeZoneListMaxSize)) ?? 0) > 0,
            RequiresDstOffset = (ReadUnsigned(Value(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.DstOffsetListMaxSize)) ?? 0) > 0,
            RequiresDefaultNtp = Value(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.DefaultNtp) is not null,
            RequiresTrustedTimeSource = Value(ClusterIds.TimeSynchronization, CommissioningInfoAttributes.TrustedTimeSource) is not null,
            RequiresTermsAcceptance = ReadBool(Value(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.TcAcknowledgementsRequired)) ?? false,
            MinimumTermsVersion = (ushort?)ReadUnsigned(Value(ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.TcMinRequiredVersion)),
            IsIntermittentlyConnected = Value(ClusterIds.IcdManagement, CommissioningInfoAttributes.IcdIdleModeDuration) is not null,
        };
    }

    /// <summary>BasicCommissioningInfo is a struct whose field 0 is the recommended fail-safe expiry.</summary>
    private static ushort? ReadFailSafeExpiry(byte[]? tlv)
    {
        if (tlv is null) return null;
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) return null;
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (ushort)r.GetUnsignedInt();
        }
        return null;
    }

    private static ulong? ReadUnsigned(byte[]? tlv)
    {
        if (tlv is null) return null;
        var r = new MatterTlvReader(tlv);
        if (!r.Read()) return null;
        return r.ElementType is MatterTlvElementType.UnsignedInt1 or MatterTlvElementType.UnsignedInt2
            or MatterTlvElementType.UnsignedInt4 or MatterTlvElementType.UnsignedInt8
            ? r.GetUnsignedInt()
            : null;
    }

    private static byte? ReadByte(byte[]? tlv) => (byte?)ReadUnsigned(tlv);

    private static bool? ReadBool(byte[]? tlv)
    {
        if (tlv is null) return null;
        var r = new MatterTlvReader(tlv);
        if (!r.Read()) return null;
        return r.ElementType is MatterTlvElementType.BooleanTrue or MatterTlvElementType.BooleanFalse
            ? r.GetBool()
            : null;
    }
}
