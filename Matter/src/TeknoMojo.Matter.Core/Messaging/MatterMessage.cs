namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>Matter Message Flags bitfield (Spec §4.4.1.2). Version is 0 in this release of the spec.</summary>
[Flags]
public enum MatterMessageFlags : byte
{
    None = 0,
    SourceNodeIdPresent = 0b0000_0100,   // Bit 2 (S) - see §4.4.1.2

    // DSIZ bits 0-1 encode destination-id kind. 00 = none, 01 = 8-byte Node ID, 10 = 2-byte Group ID.
    DestNone = 0b0000_0000,
    DestNodeId = 0b0000_0001,
    DestGroupId = 0b0000_0010,
}

/// <summary>Matter Security Flags bitfield (Spec §4.4.1.3).</summary>
[Flags]
public enum MatterSecurityFlags : byte
{
    None = 0,
    Privacy = 0b1000_0000,               // P
    ControlMessage = 0b0100_0000,        // C
    MessageExtensions = 0b0010_0000,     // MX

    // Session Type in bits 0-1: 0 = unicast, 1 = group. (2,3 reserved.)
    SessionTypeUnicast = 0b0000_0000,
    SessionTypeGroup = 0b0000_0001,
}

/// <summary>
/// A Matter message header (the "outer" header — Spec §4.4.1). This is the part that is NOT
/// encrypted; instead it serves as the AAD for the AEAD ciphertext that follows. For unsecured
/// sessions (PASE / CASE messages before keys are derived) there is no MIC and no ciphertext —
/// the payload is plaintext.
/// </summary>
public sealed record MatterMessageHeader
{
    public MatterMessageFlags Flags { get; init; }
    public ushort SessionId { get; init; }
    public MatterSecurityFlags SecurityFlags { get; init; }
    public uint MessageCounter { get; init; }
    public ulong? SourceNodeId { get; init; }

    /// <summary>
    /// Destination node ID (present when <see cref="Flags"/> includes <see cref="MatterMessageFlags.DestNodeId"/>).
    /// Group ID (16-bit) is passed via <see cref="DestinationGroupId"/> instead when
    /// <see cref="MatterMessageFlags.DestGroupId"/> is set.
    /// </summary>
    public ulong? DestinationNodeId { get; init; }

    public ushort? DestinationGroupId { get; init; }
}

/// <summary>
/// Protocol header — the "inner" header that lives inside the encrypted payload (Spec §4.4.1.6).
/// Carries the Matter exchange layer: which exchange this message belongs to (Exchange ID),
/// which protocol (SecureChannel / InteractionModel / BDX / etc.), the opcode, and optional
/// piggyback ACK. Also called the "Payload Header" in some Matter documentation.
/// </summary>
public sealed record MatterProtocolHeader
{
    public MatterExchangeFlags ExchangeFlags { get; init; }
    public byte Opcode { get; init; }
    public ushort ExchangeId { get; init; }
    public ushort ProtocolId { get; init; }
    public ushort? VendorId { get; init; }        // present when ExchangeFlags.VendorPresent is set
    public uint? AckMessageCounter { get; init; } // present when ExchangeFlags.AckPresent is set
}

/// <summary>Exchange Flags (Spec §4.4.1.6.1).</summary>
[Flags]
public enum MatterExchangeFlags : byte
{
    None = 0,
    Initiator = 0b0000_0001,             // I - this endpoint originated the exchange
    AckPresent = 0b0000_0010,            // A - Ack Message Counter follows
    ReliabilityRequested = 0b0000_0100,  // R - the sender expects an ACK
    SecuredExtensions = 0b0000_1000,     // SX
    VendorPresent = 0b0001_0000,         // V
}

/// <summary>
/// Well-known Matter protocol identifiers (assigned by the CSA; Spec Appendix H).
/// Only the ones the current stack cares about are enumerated here.
/// </summary>
public static class MatterProtocolIds
{
    /// <summary>0x0000 — Secure Channel (PASE, CASE, session termination, MRP acks).</summary>
    public const ushort SecureChannel = 0x0000;

    /// <summary>0x0001 — Interaction Model (attribute/command/event operations).</summary>
    public const ushort InteractionModel = 0x0001;

    /// <summary>0x0002 — BDX (Bulk Data Exchange, e.g. OTA).</summary>
    public const ushort BulkDataExchange = 0x0002;

    /// <summary>0x0003 — User-Directed Commissioning.</summary>
    public const ushort UserDirectedCommissioning = 0x0003;

    /// <summary>0x0004 — For Testing.</summary>
    public const ushort ForTesting = 0x0004;
}

/// <summary>
/// Secure Channel opcodes (Protocol ID 0x0000). Includes PASE and CASE handshake opcodes plus
/// the message-reliability layer (MRP) acks and status reports.
/// </summary>
public static class MatterSecureChannelOpcodes
{
    public const byte MrpStandaloneAck = 0x10;
    public const byte PbkdfParamRequest = 0x20;
    public const byte PbkdfParamResponse = 0x21;
    public const byte Pake1 = 0x22;
    public const byte Pake2 = 0x23;
    public const byte Pake3 = 0x24;
    public const byte PakeError = 0x25;
    public const byte CaseSigma1 = 0x30;
    public const byte CaseSigma2 = 0x31;
    public const byte CaseSigma3 = 0x32;
    public const byte CaseSigma2Resume = 0x33;
    public const byte StatusReport = 0x40;
}
