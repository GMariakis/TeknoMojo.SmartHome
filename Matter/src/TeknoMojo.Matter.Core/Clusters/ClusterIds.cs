namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>
/// Cluster, attribute, and command identifiers used by the commissioning flow and the OnOff
/// cluster. Verified against the Matter Data Model XML shipped in
/// project-chip/connectedhomeip (src/app/zap-templates/zcl/data-model/chip/*.xml).
/// </summary>
public static class ClusterIds
{
    public const uint OnOff = 0x0006;
    public const uint BasicInformation = 0x0028;
    public const uint GeneralCommissioning = 0x0030;
    public const uint NetworkCommissioning = 0x0031;
    public const uint TimeSynchronization = 0x0038;
    public const uint NodeOperationalCredentials = 0x003E;
    public const uint IcdManagement = 0x0046;
}

/// <summary>Attributes read up front to learn what a device needs before commissioning it.</summary>
public static class CommissioningInfoAttributes
{
    // General Commissioning (0x0030)
    public const uint BasicCommissioningInfo = 0x0001;
    public const uint RegulatoryConfig = 0x0002;
    public const uint LocationCapability = 0x0003;
    public const uint SupportsConcurrentConnection = 0x0004;

    // General Commissioning, terms and conditions
    public const uint TcMinRequiredVersion = 0x0006;
    public const uint TcAcknowledgementsRequired = 0x0008;

    // Basic Information (0x0028)
    public const uint VendorId = 0x0002;
    public const uint ProductId = 0x0004;

    // Network Commissioning (0x0031)
    public const uint ScanMaxTimeSeconds = 0x0006;
    public const uint ConnectMaxTimeSeconds = 0x0007;

    // Time Synchronization (0x0038)
    public const uint UtcTime = 0x0000;
    public const uint TrustedTimeSource = 0x0003;
    public const uint DefaultNtp = 0x0004;
    public const uint TimeZone = 0x0005;
    public const uint TimeZoneListMaxSize = 0x000A;
    public const uint DstOffsetListMaxSize = 0x000B;

    // ICD Management (0x0046); presence of this attribute is what marks a device as sleepy.
    public const uint IcdIdleModeDuration = 0x0000;

    /// <summary>Global attribute present on every cluster; tells us which optional features exist.</summary>
    public const uint FeatureMap = 0xFFFC;
}

public static class IcdManagementCommands
{
    public const uint RegisterClient = 0x00;
    public const uint RegisterClientResponse = 0x01;
    public const uint UnregisterClient = 0x02;
    public const uint StayActiveRequest = 0x03;
    public const uint StayActiveResponse = 0x04;
}

/// <summary>What kind of client is registering for check-ins (ICD Management ClientTypeEnum).</summary>
public enum IcdClientType : byte
{
    /// <summary>Permanently available, such as a hub or controller that is always powered.</summary>
    Permanent = 0,

    /// <summary>Only present sometimes, such as a phone app.</summary>
    Ephemeral = 1,
}

/// <summary>Optional capabilities of an intermittently-connected device, from its FeatureMap.</summary>
[Flags]
public enum IcdFeature : uint
{
    None = 0,

    /// <summary>The device can notify registered clients when it wakes.</summary>
    CheckInProtocolSupport = 1u << 0,

    /// <summary>A person can wake the device deliberately, e.g. by pressing a button.</summary>
    UserActiveModeTrigger = 1u << 1,

    /// <summary>The device may sleep for long periods rather than short ones.</summary>
    LongIdleTimeSupport = 1u << 2,

    /// <summary>The device can switch between short- and long-idle behaviour at runtime.</summary>
    DynamicSitLitSupport = 1u << 3,
}

public static class TimeSynchronizationCommands
{
    public const uint SetUtcTime = 0x00;
    public const uint SetTrustedTimeSource = 0x01;
    public const uint SetTimeZone = 0x02;
    public const uint SetDstOffset = 0x04;
    public const uint SetDefaultNtp = 0x05;
}

/// <summary>How precise a time source is, sent alongside SetUTCTime.</summary>
public enum TimeGranularity : byte
{
    NoTimeGranularity = 0,
    MinutesGranularity = 1,
    SecondsGranularity = 2,
    MillisecondsGranularity = 3,
    MicrosecondsGranularity = 4,
}

/// <summary>Where a node's time came from, sent alongside SetUTCTime.</summary>
public enum TimeSource : byte
{
    None = 0,
    Unknown = 1,
    Admin = 2,
    NodeTimeCluster = 3,
}

public static class NetworkCommissioningCommands
{
    public const uint ScanNetworks = 0x00;
    public const uint ScanNetworksResponse = 0x01;
    public const uint AddOrUpdateWiFiNetwork = 0x02;
    public const uint AddOrUpdateThreadNetwork = 0x03;
    public const uint RemoveNetwork = 0x04;
    public const uint NetworkConfigResponse = 0x05;
    public const uint ConnectNetwork = 0x06;
    public const uint ConnectNetworkResponse = 0x07;
    public const uint ReorderNetwork = 0x08;
}

/// <summary>
/// Which kinds of network a device can join, from the Network Commissioning cluster's FeatureMap.
/// A device reports exactly one of Wi-Fi/Thread/Ethernet per network interface endpoint.
/// </summary>
[Flags]
public enum NetworkCommissioningFeature : uint
{
    None = 0,
    WiFi = 1u << 0,
    Thread = 1u << 1,
    Ethernet = 1u << 2,
    PerDeviceCredentials = 1u << 3,
}

/// <summary>NetworkCommissioningStatusEnum, returned in NetworkConfigResponse/ConnectNetworkResponse.</summary>
public enum NetworkCommissioningStatus : byte
{
    Success = 0x00,
    OutOfRange = 0x01,
    BoundsExceeded = 0x02,
    NetworkIdNotFound = 0x03,
    DuplicateNetworkId = 0x04,
    NetworkNotFound = 0x05,
    RegulatoryError = 0x06,
    AuthFailure = 0x07,
    UnsupportedSecurity = 0x08,
    OtherConnectionFailure = 0x09,
    Ipv6Failed = 0x0A,
    IpBindFailed = 0x0B,
    UnknownError = 0x0C,
}

public static class OnOffAttributes
{
    public const uint OnOff = 0x0000;
}

public static class OnOffCommands
{
    public const uint Off = 0x00;
    public const uint On = 0x01;
    public const uint Toggle = 0x02;
}

public static class GeneralCommissioningCommands
{
    public const uint ArmFailSafe = 0x00;
    public const uint ArmFailSafeResponse = 0x01;
    public const uint SetRegulatoryConfig = 0x02;
    public const uint SetRegulatoryConfigResponse = 0x03;
    public const uint CommissioningComplete = 0x04;
    public const uint CommissioningCompleteResponse = 0x05;
    public const uint SetTcAcknowledgements = 0x06;
    public const uint SetTcAcknowledgementsResponse = 0x07;
}

/// <summary>
/// Where the device is permitted to operate, which governs the radio rules it applies
/// (General Commissioning cluster, RegulatoryLocationTypeEnum).
/// </summary>
public enum RegulatoryLocation : byte
{
    Indoor = 0,
    Outdoor = 1,
    IndoorOutdoor = 2,
}

public static class NocCommands
{
    public const uint AttestationRequest = 0x00;
    public const uint AttestationResponse = 0x01;
    public const uint CertificateChainRequest = 0x02;
    public const uint CertificateChainResponse = 0x03;
    public const uint CSRRequest = 0x04;
    public const uint CSRResponse = 0x05;
    public const uint AddNOC = 0x06;
    public const uint NOCResponse = 0x08;
    public const uint AddTrustedRootCertificate = 0x0B;
}

/// <summary>Which certificate in the device's attestation chain to fetch (CertificateChainTypeEnum).</summary>
public enum CertificateChainType : byte
{
    /// <summary>Device Attestation Certificate: unique to this device, signed by the PAI.</summary>
    DeviceAttestation = 0x01,

    /// <summary>Product Attestation Intermediate: the vendor's signing certificate, issued by a PAA.</summary>
    ProductAttestationIntermediate = 0x02,
}

/// <summary>CommissioningErrorEnum, returned in ArmFailSafeResponse/CommissioningCompleteResponse.</summary>
public enum CommissioningError : byte
{
    Ok = 0x00,
    ValueOutsideRange = 0x01,
    InvalidAuthentication = 0x02,
    NoFailSafe = 0x03,
    BusyWithOtherAdmin = 0x04,
}

/// <summary>NodeOperationalCertStatusEnum, returned in NOCResponse.</summary>
public enum NodeOperationalCertStatus : byte
{
    Ok = 0x00,
    InvalidPublicKey = 0x01,
    InvalidNodeOpId = 0x02,
    InvalidNOC = 0x03,
    MissingCsr = 0x04,
    TableFull = 0x05,
    InvalidAdminSubject = 0x06,
    FabricConflict = 0x09,
    LabelConflict = 0x0A,
    InvalidFabricIndex = 0x0B,
}
