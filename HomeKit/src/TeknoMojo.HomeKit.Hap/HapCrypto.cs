using System.Security.Cryptography;
using System.Text;

namespace TeknoMojo.HomeKit.Hap;

/// <summary>
/// HAP-specific crypto helpers: HKDF-SHA-512 with HAP salts/infos, and the ChaCha20-Poly1305
/// nonce shape (12 bytes = 4 zero bytes || 8-byte little-endian counter or ASCII label).
/// </summary>
internal static class HapCrypto
{
    /// <summary>HKDF-SHA-512 with UTF-8 salt and info strings (HAP uses this everywhere).</summary>
    public static byte[] HkdfSha512(ReadOnlySpan<byte> ikm, string salt, string info, int length = 32)
    {
        Span<byte> saltBytes = stackalloc byte[Encoding.UTF8.GetByteCount(salt)];
        Encoding.UTF8.GetBytes(salt, saltBytes);
        Span<byte> infoBytes = stackalloc byte[Encoding.UTF8.GetByteCount(info)];
        Encoding.UTF8.GetBytes(info, infoBytes);
        var output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, output, saltBytes, infoBytes);
        return output;
    }

    /// <summary>
    /// Build the 12-byte ChaCha20-Poly1305 nonce for a pairing message: 4 zero bytes followed
    /// by the 8-byte ASCII label (e.g. "PS-Msg05", "PV-Msg02"), padded with zeros on the left
    /// as needed. HAP §5.6.5.2.
    /// </summary>
    public static byte[] PairingNonce(string label)
    {
        if (label.Length > 8) throw new ArgumentException("nonce label must be <= 8 ASCII bytes", nameof(label));
        var nonce = new byte[12];
        Encoding.ASCII.GetBytes(label, nonce.AsSpan(12 - label.Length));
        return nonce;
    }

    /// <summary>
    /// Build the 12-byte session nonce for the Nth encrypted record on one direction: 4 zero
    /// bytes followed by an 8-byte little-endian counter. HAP §5.5.2.
    /// </summary>
    public static byte[] SessionNonce(ulong counter)
    {
        var nonce = new byte[12];
        BitConverter.TryWriteBytes(nonce.AsSpan(4), counter); // BitConverter is little-endian on all supported archs.
        return nonce;
    }
}
