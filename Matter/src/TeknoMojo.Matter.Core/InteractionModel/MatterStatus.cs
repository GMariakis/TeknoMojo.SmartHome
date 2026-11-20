namespace TeknoMojo.Matter.Core.InteractionModel;

/// <summary>
/// Interaction Model global status codes (Matter Core Spec, Interaction Model chapter,
/// "Status Code Table"). Verified against the Apache-2.0 reference implementation
/// (project-chip/connectedhomeip, src/protocols/interaction_model/StatusCodeList.h).
/// </summary>
public enum MatterStatus : byte
{
    Success = 0x00,
    Failure = 0x01,
    InvalidSubscription = 0x7D,
    UnsupportedAccess = 0x7E,
    UnsupportedEndpoint = 0x7F,
    InvalidAction = 0x80,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86,
    ConstraintError = 0x87,
    UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89,
    NotFound = 0x8B,
    UnreportableAttribute = 0x8C,
    InvalidDataType = 0x8D,
    UnsupportedRead = 0x8F,
    DataVersionMismatch = 0x92,
    Timeout = 0x94,
    Busy = 0x9C,
    AccessRestricted = 0x9D,
    UnsupportedCluster = 0xC3,
    NoUpstreamSubscription = 0xC5,
    NeedsTimedInteraction = 0xC6,
    UnsupportedEvent = 0xC7,
    PathsExhausted = 0xC8,
    TimedRequestMismatch = 0xC9,
    FailsafeRequired = 0xCA,
    InvalidInState = 0xCB,
    NoCommandResponse = 0xCC,
    DynamicConstraintError = 0xCF,
    AlreadyExists = 0xD0,
    InvalidTransportType = 0xD1,
}
