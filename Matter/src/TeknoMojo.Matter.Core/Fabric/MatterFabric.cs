using System.Security.Cryptography;
using System.Text;

namespace TeknoMojo.Matter.Core.Fabric;

/// <summary>
/// A fabric this controller participates in — everything needed to open CASE sessions with any
/// node commissioned onto it. Persisted per fabric; a controller can join multiple fabrics.
/// </summary>
public sealed record MatterFabric
{
    /// <summary>The 64-bit fabric identifier.</summary>
    public required ulong FabricId { get; init; }

    /// <summary>DER-encoded RCAC (self-signed root certificate) — the fabric's identity anchor.</summary>
    public required byte[] RootCertificateDer { get; init; }

    /// <summary>Optional DER-encoded ICAC (intermediate) if we issue via one.</summary>
    public byte[]? IntermediateCertificateDer { get; init; }

    /// <summary>DER-encoded NOC for THIS controller's node identity on this fabric.</summary>
    public required byte[] ControllerNocDer { get; init; }

    /// <summary>PKCS#8-encoded private key matching <see cref="ControllerNocDer"/>. SENSITIVE.</summary>
    public required byte[] ControllerNocPrivateKeyPkcs8 { get; init; }

    /// <summary>Controller's own 64-bit operational Node ID on this fabric.</summary>
    public required ulong ControllerNodeId { get; init; }

    /// <summary>16-byte Identity Protection Key — the fabric-wide symmetric secret used to derive Destination IDs and session keys.</summary>
    public required byte[] IdentityProtectionKey { get; init; }

    /// <summary>
    /// The 8-byte compressed fabric identifier used in the Matter mDNS operational instance name
    /// and in CASE Destination ID derivation. Formula (Spec §4.13.2.4):
    ///   CompressedFabricId = HKDF(HMAC-SHA-256, IKM=FabricId_be, salt=RootPublicKey_uncompressed, info="CompressedFabric", 8 bytes)
    /// </summary>
    public byte[] ComputeCompressedFabricId(byte[] rootPublicKeyUncompressed) =>
        ComputeCompressedFabricId(FabricId, rootPublicKeyUncompressed);

    /// <inheritdoc cref="ComputeCompressedFabricId(byte[])"/>
    public static byte[] ComputeCompressedFabricId(ulong fabricId, byte[] rootPublicKeyUncompressed)
    {
        var fabricIdBe = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(fabricIdBe, fabricId);

        // The key material is the root public key and the salt is the fabric ID — not the other
        // way round — and the leading 0x04 uncompressed-point marker is not part of it. Getting
        // either wrong yields a plausible-looking 8 bytes that simply never matches the identifier
        // the device advertises, so commissioned nodes appear to vanish from the network.
        byte[] rootKey = rootPublicKeyUncompressed.Length == 65 && rootPublicKeyUncompressed[0] == 0x04
            ? rootPublicKeyUncompressed[1..]
            : rootPublicKeyUncompressed;

        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: rootKey,
            outputLength: 8,
            salt: fabricIdBe,
            info: Encoding.UTF8.GetBytes("CompressedFabric"));
    }
}
