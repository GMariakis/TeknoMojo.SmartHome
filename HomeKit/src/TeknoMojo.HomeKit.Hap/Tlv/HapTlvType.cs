namespace TeknoMojo.HomeKit.Hap.Tlv;

/// <summary>
/// TLV8 tag types used by HAP pair-setup and pair-verify (HAP Specification R2, section 5).
/// </summary>
public static class HapTlvType
{
    public const byte Method = 0x00;         // 1 byte
    public const byte Identifier = 0x01;     // UTF-8
    public const byte Salt = 0x02;           // 16 bytes
    public const byte PublicKey = 0x03;      // Curve/SRP-dependent
    public const byte Proof = 0x04;          // 64 bytes (SRP)
    public const byte EncryptedData = 0x05;  // ChaCha20-Poly1305 output (cipher || tag)
    public const byte State = 0x06;          // 1 byte (M1..M6)
    public const byte Error = 0x07;          // 1 byte
    public const byte RetryDelay = 0x08;     // seconds
    public const byte Certificate = 0x09;
    public const byte Signature = 0x0A;      // 64 bytes (Ed25519)
    public const byte Permissions = 0x0B;    // 1 byte (0=user, 1=admin)
    public const byte FragmentData = 0x0C;
    public const byte FragmentLast = 0x0D;
    public const byte Separator = 0xFF;      // zero-length, delimits list items
}

/// <summary>HAP pair-setup and pair-verify state values (TLV8 tag 0x06).</summary>
public static class HapPairingState
{
    public const byte M1 = 1;
    public const byte M2 = 2;
    public const byte M3 = 3;
    public const byte M4 = 4;
    public const byte M5 = 5;
    public const byte M6 = 6;
}

/// <summary>Pair-setup / pair-verify method identifier (TLV8 tag 0x00).</summary>
public static class HapPairingMethod
{
    public const byte PairSetup = 0;
    public const byte PairSetupWithAuth = 1;
    public const byte PairVerify = 2;
    public const byte AddPairing = 3;
    public const byte RemovePairing = 4;
    public const byte ListPairings = 5;
}

/// <summary>HAP TLV8 error codes (tag 0x07).</summary>
public enum HapTlvError : byte
{
    Unknown = 0x01,
    Authentication = 0x02,
    Backoff = 0x03,
    MaxPeers = 0x04,
    MaxTries = 0x05,
    Unavailable = 0x06,
    Busy = 0x07,
}
