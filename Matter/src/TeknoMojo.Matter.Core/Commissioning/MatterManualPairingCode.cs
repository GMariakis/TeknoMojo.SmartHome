namespace TeknoMojo.Matter.Core.Commissioning;

/// <summary>
/// Decodes the Matter Manual Pairing Code — the 11-digit (short) or 21-digit (long, with
/// vendor/product IDs) decimal code shown when a commissioning window is opened, e.g.
/// "2033-022-0861" (dashes are cosmetic grouping and are stripped). This is a bit-packed
/// encoding of the discriminator and the actual PAKE setup PIN code plus a Verhoeff check
/// digit — NOT the PIN itself in plain decimal, and not the same thing as a HomeKit-style
/// 8-digit setup code.
/// </summary>
/// <remarks>
/// Bit layout and character-length constants verified against the Apache-2.0 reference
/// implementation (project-chip/connectedhomeip, src/setup_payload/SetupPayload.h and
/// ManualSetupPayloadParser.cpp).
/// </remarks>
public static class MatterManualPairingCode
{
    private const int Chunk1CharLength = 1;
    private const int Chunk2CharLength = 5;
    private const int Chunk3CharLength = 4;
    private const int VendorIdCharLength = 5;
    private const int ProductIdCharLength = 5;
    private const int ShortCodeCharLength = 10; // digits before the check digit
    private const int LongCodeCharLength = 20;

    private const int Chunk1DiscriminatorMsbitsPos = 0;
    private const int Chunk1DiscriminatorMsbitsLength = 2;
    private const int Chunk1VidPidPresentBitPos = Chunk1DiscriminatorMsbitsPos + Chunk1DiscriminatorMsbitsLength; // 2

    private const int Chunk2PinCodeLsbitsPos = 0;
    private const int Chunk2PinCodeLsbitsLength = 14;
    private const int Chunk2DiscriminatorLsbitsPos = Chunk2PinCodeLsbitsPos + Chunk2PinCodeLsbitsLength; // 14
    private const int Chunk2DiscriminatorLsbitsLength = 2;

    private const int Chunk3PinCodeMsbitsPos = 0;
    private const int Chunk3PinCodeMsbitsLength = 13;

    /// <summary>Decoded contents of a manual pairing code.</summary>
    /// <param name="SetupPinCode">The actual PAKE setup PIN — feed this into PASE, not the manual code's digits.</param>
    /// <param name="ShortDiscriminator">
    /// The top 4 bits of the full 12-bit discriminator. Manual codes only narrow to one of 16
    /// buckets, not an exact device — match candidates via <see cref="MatchesShortDiscriminator"/>.
    /// </param>
    public sealed record Decoded(uint SetupPinCode, byte ShortDiscriminator, bool IsLongCode, ushort? VendorId, ushort? ProductId)
    {
        /// <summary>True if <paramref name="fullDiscriminator"/> (the 12-bit value from a BLE/mDNS advertisement) falls in this code's short-discriminator bucket.</summary>
        public bool MatchesShortDiscriminator(ushort fullDiscriminator) => (byte)(fullDiscriminator >> 8) == ShortDiscriminator;
    }

    /// <summary>Decode a manual pairing code string (dashes optional/ignored).</summary>
    public static Decoded Decode(string code)
    {
        string digits = new string(code.Where(char.IsDigit).ToArray());
        if (digits.Length < 2)
            throw new FormatException("Manual pairing code too short.");

        string body = digits[..^1];
        char checkDigit = digits[^1];
        if (Verhoeff10.Compute(body) != checkDigit)
            throw new FormatException("Manual pairing code check digit is invalid — check for a transcription error.");

        int offset = 0;
        uint chunk1 = ReadDigits(body, ref offset, Chunk1CharLength);
        uint chunk2 = ReadDigits(body, ref offset, Chunk2CharLength);
        uint chunk3 = ReadDigits(body, ref offset, Chunk3CharLength);

        if (chunk1 is 8 or 9)
            throw new FormatException("Unrecognized manual pairing code version.");

        bool isLongCode = ((chunk1 >> Chunk1VidPidPresentBitPos) & 1) == 1;
        int expectedLength = isLongCode ? LongCodeCharLength : ShortCodeCharLength;
        if (body.Length != expectedLength)
            throw new FormatException($"Manual pairing code length mismatch: expected {expectedLength} digits before the check digit, got {body.Length}.");

        uint discriminatorMsbMask = (1u << Chunk1DiscriminatorMsbitsLength) - 1;
        uint discriminatorLsbMask = (1u << Chunk2DiscriminatorLsbitsLength) - 1;
        byte shortDiscriminator = (byte)(
            ((chunk2 >> Chunk2DiscriminatorLsbitsPos) & discriminatorLsbMask)
            | (((chunk1 >> Chunk1DiscriminatorMsbitsPos) & discriminatorMsbMask) << Chunk2DiscriminatorLsbitsLength));

        uint pinMsbMask = (1u << Chunk3PinCodeMsbitsLength) - 1;
        uint pinLsbMask = (1u << Chunk2PinCodeLsbitsLength) - 1;
        uint setupPin = ((chunk2 >> Chunk2PinCodeLsbitsPos) & pinLsbMask)
            | (((chunk3 >> Chunk3PinCodeMsbitsPos) & pinMsbMask) << Chunk2PinCodeLsbitsLength);

        if (setupPin == 0)
            throw new FormatException("Manual pairing code decoded to a zero setup PIN — invalid code.");

        ushort? vendorId = null, productId = null;
        if (isLongCode)
        {
            vendorId = (ushort)ReadDigits(body, ref offset, VendorIdCharLength);
            productId = (ushort)ReadDigits(body, ref offset, ProductIdCharLength);
        }

        return new Decoded(setupPin, shortDiscriminator, isLongCode, vendorId, productId);
    }

    private static uint ReadDigits(string s, ref int offset, int count)
    {
        uint value = uint.Parse(s.Substring(offset, count));
        offset += count;
        return value;
    }
}

/// <summary>
/// Verhoeff checksum (ISO/IEC 7064-independent, public dihedral-group algorithm — not Matter- or
/// vendor-specific). Used by Matter's manual pairing code as its check digit.
/// </summary>
internal static class Verhoeff10
{
    private static readonly int[,] D =
    {
        {0,1,2,3,4,5,6,7,8,9},{1,2,3,4,0,6,7,8,9,5},{2,3,4,0,1,7,8,9,5,6},{3,4,0,1,2,8,9,5,6,7},
        {4,0,1,2,3,9,5,6,7,8},{5,9,8,7,6,0,4,3,2,1},{6,5,9,8,7,1,0,4,3,2},{7,6,5,9,8,2,1,0,4,3},
        {8,7,6,5,9,3,2,1,0,4},{9,8,7,6,5,4,3,2,1,0},
    };
    private static readonly int[,] P =
    {
        {0,1,2,3,4,5,6,7,8,9},{1,5,7,6,2,8,3,0,9,4},{5,8,0,3,7,9,6,1,4,2},{8,9,1,6,0,4,3,5,2,7},
        {9,4,5,3,1,2,6,8,7,0},{4,2,8,6,5,7,3,9,0,1},{2,7,9,3,8,0,6,4,1,5},{7,0,4,6,9,1,3,2,5,8},
    };
    private static readonly int[] Inv = { 0, 4, 3, 2, 1, 5, 6, 7, 8, 9 };

    /// <summary>Compute the Verhoeff check digit that should follow <paramref name="digitsWithoutCheck"/>.</summary>
    public static char Compute(string digitsWithoutCheck)
    {
        int c = 0;
        char[] digits = digitsWithoutCheck.ToCharArray();
        Array.Reverse(digits);
        for (int i = 0; i < digits.Length; i++)
        {
            int digit = digits[i] - '0';
            c = D[c, P[(i + 1) % 8, digit]];
        }
        return (char)('0' + Inv[c]);
    }
}
