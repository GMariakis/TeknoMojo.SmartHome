using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Tlv;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace TeknoMojo.Matter.Core.Crypto;

/// <summary>
/// Pure-function primitives for Matter's CASE (Certificate-Authenticated Session Establishment,
/// Spec §4.13.2). CASE is a SIGMA-I-based mutual-authentication key exchange between two nodes
/// that already share a fabric: both sides have Node Operational Credentials signed by the same
/// root, and the fabric-wide IPK. On success it yields a pair of 16-byte AES-CCM session keys
/// (I2R and R2I) that plug into <see cref="Messaging.MatterSecureDirection"/>.
/// </summary>
/// <remarks>
/// This file provides the crypto glue and the CASE message TLV shape. The actual send/receive
/// state machine (Sigma1 → Sigma2 → Sigma3 over Secure Channel) is layered on top by the
/// commissioner/session code and is not the crypto's concern.
/// </remarks>
public static class MatterCase
{
    private static readonly X9ECParameters P256 = NistNamedCurves.GetByName("P-256");
    private static readonly ECDomainParameters Domain = new(P256.Curve, P256.G, P256.N, P256.H, P256.GetSeed());

    // ------------------------------------------------------------------ Destination ID

    /// <summary>
    /// Compute the Matter CASE Destination Identifier (§4.13.2.5.1):
    /// <c>DestinationID = HMAC-SHA-256(IPK, RandomA || InitiatorRootPublicKey || FabricId || DestinationNodeId)</c>.
    /// The initiator sends this in Sigma1 so a responder that participates in many fabrics can
    /// figure out which fabric+node identity the initiator wants to talk to, without revealing
    /// which one until authentication has succeeded.
    /// </summary>
    /// <param name="ipk">16-byte Identity Protection Key for the target fabric.</param>
    /// <param name="randomA">32-byte initiator random (also in Sigma1).</param>
    /// <param name="rootPublicKeyUncompressed">The RCAC's raw public key (65 bytes).</param>
    /// <param name="fabricId">The 64-bit fabric ID.</param>
    /// <param name="destinationNodeId">The 64-bit operational Node ID being addressed.</param>
    public static byte[] ComputeDestinationId(
        byte[] ipk, byte[] randomA, byte[] rootPublicKeyUncompressed, ulong fabricId, ulong destinationNodeId)
    {
        if (ipk is null || ipk.Length != 16) throw new ArgumentException("IPK must be 16 bytes", nameof(ipk));
        if (randomA is null || randomA.Length != 32) throw new ArgumentException("RandomA must be 32 bytes", nameof(randomA));
        if (rootPublicKeyUncompressed is null || rootPublicKeyUncompressed.Length != 65) throw new ArgumentException("Root pub key must be uncompressed P-256 (65 bytes)", nameof(rootPublicKeyUncompressed));

        var payload = new byte[32 + 65 + 8 + 8];
        int pos = 0;
        randomA.CopyTo(payload.AsSpan(pos)); pos += 32;
        rootPublicKeyUncompressed.CopyTo(payload.AsSpan(pos)); pos += 65;
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(pos, 8), fabricId); pos += 8;
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(pos, 8), destinationNodeId);
        return HMACSHA256.HashData(ipk, payload);
    }

    // ------------------------------------------------------------------ ephemeral keys / ECDH

    /// <summary>A freshly-generated ephemeral P-256 key pair used for one CASE handshake.</summary>
    public sealed record EphemeralKey(byte[] PrivateScalar, byte[] PublicKeyUncompressed);

    /// <summary>Generate a fresh ephemeral P-256 keypair; the caller keeps the private part for one handshake.</summary>
    public static EphemeralKey GenerateEphemeralKey() => GenerateEphemeralKey(RandomScalar());

    /// <summary>Overload for deterministic testing.</summary>
    public static EphemeralKey GenerateEphemeralKey(BigInteger privateScalar)
    {
        ECPoint pub = P256.G.Multiply(privateScalar).Normalize();
        return new EphemeralKey(ScalarToBytes(privateScalar), pub.GetEncoded(false));
    }

    /// <summary>
    /// ECDH shared secret Z = <paramref name="privateScalar"/> · peerPub. Returned as the x-coordinate
    /// only (32 bytes, big-endian), which is what Matter's HKDF inputs expect.
    /// </summary>
    public static byte[] Ecdh(byte[] privateScalar, byte[] peerPublicKeyUncompressed)
    {
        var d = new BigInteger(1, privateScalar);
        ECPoint peer = P256.Curve.DecodePoint(peerPublicKeyUncompressed).Normalize();
        ECPoint shared = peer.Multiply(d).Normalize();
        return shared.AffineXCoord.GetEncoded();
    }

    // ------------------------------------------------------------------ key derivation

    /// <summary>
    /// Sigma2 encryption key: <c>S2K = HKDF-SHA-256(salt=IPK || SHA-256(Sigma1_TLV), ikm=Z, info="Sigma2", 16 bytes)</c>.
    /// </summary>
    public static byte[] DeriveS2K(byte[] ipk, byte[] sharedZ, byte[] transcriptHash1)
        => DeriveKey(ipk, sharedZ, transcriptHash1, "Sigma2", 16);

    /// <summary>
    /// Sigma3 encryption key: <c>S3K = HKDF-SHA-256(salt=IPK || SHA-256(Sigma1||Sigma2), ikm=Z, info="Sigma3", 16 bytes)</c>.
    /// </summary>
    public static byte[] DeriveS3K(byte[] ipk, byte[] sharedZ, byte[] transcriptHash12)
        => DeriveKey(ipk, sharedZ, transcriptHash12, "Sigma3", 16);

    /// <summary>
    /// Final CASE session key material (§4.13.2.14): 3×16 bytes derived post-handshake as
    /// I2RKey (16) || R2IKey (16) || AttestationChallenge (16), using
    /// <c>salt=IPK || SHA-256(Sigma1||Sigma2||Sigma3)</c> and <c>info="SessionKeys"</c>.
    /// </summary>
    public static (byte[] I2R, byte[] R2I, byte[] AttestationChallenge) DeriveSessionKeys(
        byte[] ipk, byte[] sharedZ, byte[] transcriptHash123)
    {
        byte[] material = DeriveKey(ipk, sharedZ, transcriptHash123, "SessionKeys", 48);
        return (material.AsSpan(0, 16).ToArray(), material.AsSpan(16, 16).ToArray(), material.AsSpan(32, 16).ToArray());
    }

    private static byte[] DeriveKey(byte[] ipk, byte[] sharedZ, byte[] transcriptHash, string info, int length)
    {
        var salt = new byte[ipk.Length + transcriptHash.Length];
        Buffer.BlockCopy(ipk, 0, salt, 0, ipk.Length);
        Buffer.BlockCopy(transcriptHash, 0, salt, ipk.Length, transcriptHash.Length);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedZ, length, salt, Encoding.UTF8.GetBytes(info));
    }

    // ------------------------------------------------------------------ TBS / TBE construction

    /// <summary>
    /// Build the TBSData input for a CASE signature (§4.13.2.10). Encoded as a Matter TLV
    /// structure with context tags 1..4: senderNOC, senderICAC (optional), senderEphPub,
    /// receiverEphPub. This is what both Sigma2 (responder signs) and Sigma3 (initiator signs)
    /// bind their signatures to; the receiver runs ECDSA verify with the sender's NOC public key.
    /// </summary>
    public static byte[] BuildTbsData(
        byte[] senderNocTlv,
        byte[]? senderIcacTlv,
        byte[] senderEphPub,
        byte[] receiverEphPub)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), senderNocTlv);
        if (senderIcacTlv is not null)
            w.WriteByteString(MatterTag.Context(2), senderIcacTlv);
        w.WriteByteString(MatterTag.Context(3), senderEphPub);
        w.WriteByteString(MatterTag.Context(4), receiverEphPub);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>
    /// Build the plaintext TBEData for Sigma2 or Sigma3 (§4.13.2.9): sender NOC + ICAC(?) + signature.
    /// Sigma2 additionally carries a resumption ID at context tag 4; pass it via
    /// <paramref name="resumptionId"/> if applicable.
    /// </summary>
    public static byte[] BuildTbeData(
        byte[] senderNocTlv, byte[]? senderIcacTlv, byte[] rawSignature, byte[]? resumptionId = null)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), senderNocTlv);
        if (senderIcacTlv is not null)
            w.WriteByteString(MatterTag.Context(2), senderIcacTlv);
        w.WriteByteString(MatterTag.Context(3), rawSignature);
        if (resumptionId is not null)
            w.WriteByteString(MatterTag.Context(4), resumptionId);
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>Parsed contents of a decrypted TBEData blob.</summary>
    public sealed record TbeData(byte[] SenderNocTlv, byte[]? SenderIcacTlv, byte[] RawSignature, byte[]? ResumptionId);

    /// <summary>Parse a plaintext TBEData produced by <see cref="BuildTbeData"/>.</summary>
    public static TbeData ParseTbeData(byte[] tbePlaintext)
    {
        byte[]? noc = null, icac = null, sig = null, rid = null;
        var r = new MatterTlvReader(tbePlaintext);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("TBEData: outer structure missing");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            switch (r.Tag.TagNumber)
            {
                case 1: noc = r.GetByteString(); break;
                case 2: icac = r.GetByteString(); break;
                case 3: sig = r.GetByteString(); break;
                case 4: rid = r.GetByteString(); break;
            }
        }
        if (noc is null || sig is null)
            throw new FormatException("TBEData: missing required NOC or signature");
        return new TbeData(noc, icac, sig, rid);
    }

    // ------------------------------------------------------------------ AES-CCM for TBEData

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> as CASE TBEData with the fixed nonce
    /// <paramref name="nonceLabel"/> (either "NCASE_Sigma2" or "NCASE_Sigma3", per §4.13.2.9).
    /// Returns ciphertext || 16-byte tag. AAD is empty for CASE TBEData.
    /// </summary>
    public static byte[] EncryptTbe(byte[] key, string nonceLabel, byte[] plaintext)
    {
        using var ccm = new AesCcm(key);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        ccm.Encrypt(BuildCaseNonce(nonceLabel), plaintext, cipher, tag);
        var output = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, output, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, output, cipher.Length, tag.Length);
        return output;
    }

    /// <summary>Reverse of <see cref="EncryptTbe"/>.</summary>
    public static byte[] DecryptTbe(byte[] key, string nonceLabel, byte[] ciphertextAndTag)
    {
        if (ciphertextAndTag.Length < 16) throw new CryptographicException("CASE TBE payload shorter than tag");
        int cipherLen = ciphertextAndTag.Length - 16;
        using var ccm = new AesCcm(key);
        var plain = new byte[cipherLen];
        ccm.Decrypt(BuildCaseNonce(nonceLabel), ciphertextAndTag.AsSpan(0, cipherLen), ciphertextAndTag.AsSpan(cipherLen, 16), plain);
        return plain;
    }

    /// <summary>
    /// CASE TBEData nonce is the fixed 13-byte ASCII label ("NCASE_Sigma2" / "NCASE_Sigma3"),
    /// left-padded with zeros if shorter.
    /// </summary>
    public static byte[] BuildCaseNonce(string label)
    {
        if (label.Length > 13) throw new ArgumentException("nonce label must be <= 13 bytes", nameof(label));
        var nonce = new byte[13];
        Encoding.ASCII.GetBytes(label, nonce.AsSpan(13 - label.Length));
        return nonce;
    }

    // ------------------------------------------------------------------ Sigma1/2/3 TLV shapes

    /// <summary>Sigma1 fields the initiator sends first (§4.13.2.5, Structure tags 1..7).</summary>
    public sealed record Sigma1(
        byte[] InitiatorRandom,
        ushort InitiatorSessionId,
        byte[] DestinationId,
        byte[] InitiatorEphPubKey,
        byte[]? ResumptionId = null,
        byte[]? ResumeMic = null);

    public static byte[] EncodeSigma1(Sigma1 s1)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), s1.InitiatorRandom);
        w.WriteUnsignedInt(MatterTag.Context(2), s1.InitiatorSessionId);
        w.WriteByteString(MatterTag.Context(3), s1.DestinationId);
        w.WriteByteString(MatterTag.Context(4), s1.InitiatorEphPubKey);
        // tag 5 (session params) intentionally omitted; a session-params encoder can be added later.
        if (s1.ResumptionId is not null) w.WriteByteString(MatterTag.Context(6), s1.ResumptionId);
        if (s1.ResumeMic is not null) w.WriteByteString(MatterTag.Context(7), s1.ResumeMic);
        w.EndContainer();
        return w.ToArray();
    }

    public static Sigma1 DecodeSigma1(byte[] tlv)
    {
        byte[]? initiatorRandom = null, destinationId = null, ephPub = null, resumptionId = null, resumeMic = null;
        ushort sessionId = 0;
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("Sigma1: outer structure missing");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific)
            {
                if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                    r.ExitContainer();
                continue;
            }
            switch (r.Tag.TagNumber)
            {
                case 1: initiatorRandom = r.GetByteString(); break;
                case 2: sessionId = (ushort)r.GetUnsignedInt(); break;
                case 3: destinationId = r.GetByteString(); break;
                case 4: ephPub = r.GetByteString(); break;
                case 6: resumptionId = r.GetByteString(); break;
                case 7: resumeMic = r.GetByteString(); break;
                default:
                    if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                        r.ExitContainer();
                    break;
            }
        }
        if (initiatorRandom is null || destinationId is null || ephPub is null)
            throw new FormatException("Sigma1: missing required field");
        return new Sigma1(initiatorRandom, sessionId, destinationId, ephPub, resumptionId, resumeMic);
    }

    /// <summary>Sigma2 fields the responder returns (§4.13.2.7, Structure tags 1..5).</summary>
    public sealed record Sigma2(
        byte[] ResponderRandom,
        ushort ResponderSessionId,
        byte[] ResponderEphPubKey,
        byte[] Encrypted2);

    public static byte[] EncodeSigma2(Sigma2 s2)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), s2.ResponderRandom);
        w.WriteUnsignedInt(MatterTag.Context(2), s2.ResponderSessionId);
        w.WriteByteString(MatterTag.Context(3), s2.ResponderEphPubKey);
        w.WriteByteString(MatterTag.Context(4), s2.Encrypted2);
        w.EndContainer();
        return w.ToArray();
    }

    public static Sigma2 DecodeSigma2(byte[] tlv)
    {
        byte[]? rr = null, ephPub = null, enc2 = null;
        ushort sid = 0;
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("Sigma2: outer structure missing");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific)
            {
                if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                    r.ExitContainer();
                continue;
            }
            switch (r.Tag.TagNumber)
            {
                case 1: rr = r.GetByteString(); break;
                case 2: sid = (ushort)r.GetUnsignedInt(); break;
                case 3: ephPub = r.GetByteString(); break;
                case 4: enc2 = r.GetByteString(); break;
                default:
                    if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                        r.ExitContainer();
                    break;
            }
        }
        if (rr is null || ephPub is null || enc2 is null) throw new FormatException("Sigma2: missing required field");
        return new Sigma2(rr, sid, ephPub, enc2);
    }

    /// <summary>Sigma3 fields the initiator returns (§4.13.2.13). Single field: Encrypted3.</summary>
    public sealed record Sigma3(byte[] Encrypted3);

    public static byte[] EncodeSigma3(Sigma3 s3)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), s3.Encrypted3);
        w.EndContainer();
        return w.ToArray();
    }

    public static Sigma3 DecodeSigma3(byte[] tlv)
    {
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException("Sigma3: outer structure missing");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 1)
                return new Sigma3(r.GetByteString());
        }
        throw new FormatException("Sigma3: missing Encrypted3");
    }

    // ------------------------------------------------------------------ signature helpers

    /// <summary>
    /// ECDSA-with-SHA256 sign the given TBSData using a PKCS#8 P-256 private key; returns the
    /// 64-byte fixed-width r||s form Matter uses on the wire (not the ASN.1 SEQUENCE form).
    /// Uses BouncyCastle end-to-end (rather than importing into .NET's ECDsa) because BC's own
    /// PKCS#8 output does not always round-trip through CNG's importer.
    /// </summary>
    public static byte[] SignTbs(byte[] pkcs8PrivateKey, byte[] tbsData)
    {
        var priv = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(pkcs8PrivateKey);

        var signer = new ECDsaSigner(new HMacDsaKCalculator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest()));
        signer.Init(forSigning: true, priv);
        byte[] hash = SHA256.HashData(tbsData);
        BigInteger[] rs = signer.GenerateSignature(hash);

        var sig = new byte[64];
        byte[] r = rs[0].ToByteArrayUnsigned();
        byte[] s = rs[1].ToByteArrayUnsigned();
        Buffer.BlockCopy(r, 0, sig, 32 - r.Length, r.Length);
        Buffer.BlockCopy(s, 0, sig, 64 - s.Length, s.Length);
        return sig;
    }

    /// <summary>Verify a 64-byte r||s ECDSA signature against a raw uncompressed P-256 public key.</summary>
    public static bool VerifyTbs(byte[] publicKeyUncompressed, byte[] tbsData, byte[] rawSignature)
    {
        if (publicKeyUncompressed.Length != 65 || publicKeyUncompressed[0] != 0x04) return false;
        if (rawSignature.Length != 64) return false;

        ECPoint q = P256.Curve.DecodePoint(publicKeyUncompressed);
        var pub = new ECPublicKeyParameters(q, Domain);

        var signer = new ECDsaSigner();
        signer.Init(forSigning: false, pub);
        byte[] hash = SHA256.HashData(tbsData);
        var r = new BigInteger(1, rawSignature.AsSpan(0, 32).ToArray());
        var s = new BigInteger(1, rawSignature.AsSpan(32, 32).ToArray());
        return signer.VerifySignature(hash, r, s);
    }

    // ------------------------------------------------------------------ misc

    private static BigInteger RandomScalar()
    {
        int bytes = (P256.N.BitLength + 7) / 8;
        byte[] buf = new byte[bytes];
        while (true)
        {
            RandomNumberGenerator.Fill(buf);
            var candidate = new BigInteger(1, buf);
            if (candidate.CompareTo(BigInteger.One) >= 0 && candidate.CompareTo(P256.N) < 0)
                return candidate;
        }
    }

    private static byte[] ScalarToBytes(BigInteger v)
    {
        byte[] raw = v.ToByteArrayUnsigned();
        if (raw.Length == 32) return raw;
        if (raw.Length > 32) throw new InvalidOperationException("scalar > P-256 order");
        var padded = new byte[32];
        Buffer.BlockCopy(raw, 0, padded, 32 - raw.Length, raw.Length);
        return padded;
    }
}
