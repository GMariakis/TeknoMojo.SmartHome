using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Certificates;

/// <summary>
/// Convert Matter operational X.509 certificates between DER and the compact Matter-TLV form
/// defined in Matter Core Spec §6.5.11. The TLV form is what CASE Sigma2/Sigma3 messages carry
/// on the wire and what the AddNOC command expects — DER is convenient for our internal APIs
/// and for interop with any tooling that understands standard X.509.
/// </summary>
public static class MatterCertificateTlv
{
    // TLV context tag numbers for the top-level MatterCertificate structure (§6.5.11.1).
    private const byte TagSerialNumber = 1;
    private const byte TagSignatureAlgorithm = 2;
    private const byte TagIssuer = 3;
    private const byte TagNotBefore = 4;
    private const byte TagNotAfter = 5;
    private const byte TagSubject = 6;
    private const byte TagPublicKeyAlgorithm = 7;
    private const byte TagEllipticCurveIdentifier = 8;
    private const byte TagEllipticCurvePublicKey = 9;
    private const byte TagExtensions = 10;
    private const byte TagSignature = 11;

    // DN attribute context tags (§6.5.6.1).
    // 17–22 are the Matter attribute types (matched to OIDs); 1–16 are standard X.520 types.
    private const byte DnMatterNodeId = 17;
    private const byte DnMatterFirmwareSigningId = 18;
    private const byte DnMatterIcacId = 19;
    private const byte DnMatterRcacId = 20;
    private const byte DnMatterFabricId = 21;
    private const byte DnMatterCaseAuthTag = 22;

    // Extension context tags (§6.5.11.7).
    private const byte ExtBasicConstraints = 1;
    private const byte ExtKeyUsage = 2;
    private const byte ExtExtendedKeyUsage = 3;
    private const byte ExtSubjectKeyIdentifier = 4;
    private const byte ExtAuthorityKeyIdentifier = 5;
    private const byte ExtFutureExtension = 6;

    // Basic Constraints inner fields
    private const byte BcIsCa = 1;
    private const byte BcPathLen = 2;

    // Public-key / signature algorithm enumerations
    private const byte SigAlgEcdsaWithSha256 = 1;
    private const byte PubAlgEcPublicKey = 1;
    private const byte CurveIdPrime256v1 = 1;

    // Matter epoch: 2000-01-01T00:00:00Z (§4.7.6).
    private static readonly DateTime MatterEpoch = new(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>Encode a DER-encoded Matter cert into the Matter TLV compact form.</summary>
    public static byte[] FromDer(byte[] derCertificate)
    {
        var parser = new X509CertificateParser();
        X509Certificate bcCert = parser.ReadCertificate(derCertificate);

        // Parse the raw DER once more to extract the signature bytes and TBSCertificate portion
        // — BouncyCastle's high-level cert only surfaces the ASN.1 signature (r,s SEQUENCE), and
        // Matter needs it as the raw concatenation r || s (32 bytes each for P-256).
        var certAsn1 = (Asn1Sequence)Asn1Object.FromByteArray(derCertificate);
        var tbs = (Asn1Sequence)certAsn1[0];
        // signatureValue is a BIT STRING at index 2 of the outer SEQUENCE.
        var sigBitString = (DerBitString)certAsn1[2];
        byte[] sigRawAsn1 = sigBitString.GetBytes();
        byte[] sigRawConcat = EcdsaAsn1ToConcat(sigRawAsn1);

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);

        w.WriteByteString(MatterTag.Context(TagSerialNumber), bcCert.SerialNumber.ToByteArrayUnsigned());
        w.WriteUnsignedInt(MatterTag.Context(TagSignatureAlgorithm), SigAlgEcdsaWithSha256);

        EncodeDn(w, TagIssuer, bcCert.IssuerDN);

        w.WriteUnsignedInt(MatterTag.Context(TagNotBefore), ToMatterEpoch(bcCert.NotBefore));
        w.WriteUnsignedInt(MatterTag.Context(TagNotAfter), ToMatterEpoch(bcCert.NotAfter));

        EncodeDn(w, TagSubject, bcCert.SubjectDN);

        w.WriteUnsignedInt(MatterTag.Context(TagPublicKeyAlgorithm), PubAlgEcPublicKey);
        w.WriteUnsignedInt(MatterTag.Context(TagEllipticCurveIdentifier), CurveIdPrime256v1);

        // Uncompressed EC public key from the SPKI (65 bytes).
        var ecPub = (ECPublicKeyParameters)bcCert.GetPublicKey();
        byte[] pubUncompressed = ecPub.Q.GetEncoded(false);
        w.WriteByteString(MatterTag.Context(TagEllipticCurvePublicKey), pubUncompressed);

        EncodeExtensions(w, bcCert);

        w.WriteByteString(MatterTag.Context(TagSignature), sigRawConcat);

        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>
    /// Peek at the subject Node ID (or 0 if none present) inside a Matter TLV cert. Convenience
    /// for CASE where the peer's cert identifies which node we ended up talking to.
    /// </summary>
    public static ulong? ExtractSubjectNodeId(byte[] tlvCert)
    {
        return ExtractDnAttr(tlvCert, DnMatterNodeId);
    }

    /// <summary>Peek at the subject Fabric ID inside a Matter TLV cert.</summary>
    public static ulong? ExtractSubjectFabricId(byte[] tlvCert)
    {
        return ExtractDnAttr(tlvCert, DnMatterFabricId);
    }

    /// <summary>
    /// Peek at the uncompressed EC public key inside a Matter TLV cert. Enough to run ECDSA
    /// verification of a CASE signature without the caller having to re-decode the whole thing.
    /// </summary>
    public static byte[]? ExtractPublicKey(byte[] tlvCert)
    {
        var r = new MatterTlvReader(tlvCert);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) return null;
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific
                && r.Tag.TagNumber == TagEllipticCurvePublicKey
                && r.ElementType is MatterTlvElementType.ByteString1 or MatterTlvElementType.ByteString2)
            {
                return r.GetByteString();
            }
            // Sibling containers we're not interested in must have their bodies skipped;
            // otherwise Read() would descend into their children on the next iteration.
            if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                r.ExitContainer();
        }
        return null;
    }

    // ---------------- DN encoding ----------------

    private static void EncodeDn(MatterTlvWriter w, byte topTag, X509Name dn)
    {
        w.StartList(MatterTag.Context(topTag));

        var oids = dn.GetOidList();
        var values = dn.GetValueList();
        for (int i = 0; i < oids.Count; i++)
        {
            var oid = (DerObjectIdentifier)oids[i]!;
            var value = (string)values[i]!;

            byte? matterTag = MatterOidToDnTag(oid);
            if (matterTag is null)
                continue; // ignore non-Matter DN attrs (Matter DNs shouldn't have any anyway)

            // Matter DN attribute values are the ID's 64-bit numeric value encoded as UInt.
            if (ulong.TryParse(value, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out ulong id))
            {
                w.WriteUnsignedInt(MatterTag.Context(matterTag.Value), id);
            }
            else
            {
                // Fall back to string encoding (shouldn't happen for standards-compliant Matter certs).
                w.WriteUtf8String(MatterTag.Context(matterTag.Value), value);
            }
        }
        w.EndContainer();
    }

    private static byte? MatterOidToDnTag(DerObjectIdentifier oid)
    {
        if (oid.Equals(MatterOids.NodeId)) return DnMatterNodeId;
        if (oid.Equals(MatterOids.FirmwareSigningId)) return DnMatterFirmwareSigningId;
        if (oid.Equals(MatterOids.IcacId)) return DnMatterIcacId;
        if (oid.Equals(MatterOids.RcacId)) return DnMatterRcacId;
        if (oid.Equals(MatterOids.FabricId)) return DnMatterFabricId;
        if (oid.Equals(MatterOids.CaseAuthenticatedTag)) return DnMatterCaseAuthTag;
        return null;
    }

    // ---------------- extensions ----------------

    private static void EncodeExtensions(MatterTlvWriter w, X509Certificate cert)
    {
        w.StartList(MatterTag.Context(TagExtensions));

        // Basic Constraints
        var bc = cert.GetBasicConstraints();
        // bc: -1 = extension absent; 0..N = pathlen for a CA; int.MaxValue = CA with no limit
        if (bc != -1)
        {
            w.StartStructure(MatterTag.Context(ExtBasicConstraints));
            w.WriteBool(MatterTag.Context(BcIsCa), true);
            if (bc >= 0 && bc != int.MaxValue)
                w.WriteUnsignedInt(MatterTag.Context(BcPathLen), (ulong)bc);
            w.EndContainer();
        }
        else if (cert.Version == 3)
        {
            // Not a CA — emit is-ca=false explicitly.
            w.StartStructure(MatterTag.Context(ExtBasicConstraints));
            w.WriteBool(MatterTag.Context(BcIsCa), false);
            w.EndContainer();
        }

        // Key Usage (encoded as a UInt bit-flags value in Matter TLV form).
        bool[]? ku = cert.GetKeyUsage();
        if (ku is { Length: > 0 })
        {
            int bits = 0;
            for (int i = 0; i < ku.Length; i++)
                if (ku[i]) bits |= 1 << i;
            w.WriteUnsignedInt(MatterTag.Context(ExtKeyUsage), (ulong)bits);
        }

        // Extended Key Usage — Matter TLV encodes as Array of UInt, one per KeyPurposeID enum value.
        var eku = cert.GetExtendedKeyUsage();
        if (eku is { Count: > 0 })
        {
            w.StartArray(MatterTag.Context(ExtExtendedKeyUsage));
            foreach (var purpose in eku)
            {
                // We only ever emit serverAuth (1) and clientAuth (2) per Matter §6.5.7.4.
                ulong val = purpose.ToString() switch
                {
                    "1.3.6.1.5.5.7.3.1" => 1, // serverAuth
                    "1.3.6.1.5.5.7.3.2" => 2, // clientAuth
                    "1.3.6.1.5.5.7.3.3" => 3, // codeSigning
                    "1.3.6.1.5.5.7.3.4" => 4, // emailProtection
                    "1.3.6.1.5.5.7.3.8" => 5, // timeStamping
                    "1.3.6.1.5.5.7.3.9" => 6, // ocspSigning
                    _ => 0,
                };
                w.WriteUnsignedInt(MatterTag.Anonymous, val);
            }
            w.EndContainer();
        }

        // Subject Key Identifier — extension value is a DER OCTET STRING containing the 20-byte hash.
        var ski = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        if (ski is not null)
        {
            var inner = (DerOctetString)Asn1Object.FromByteArray(ski.GetOctets());
            w.WriteByteString(MatterTag.Context(ExtSubjectKeyIdentifier), inner.GetOctets());
        }

        // Authority Key Identifier — extension value is a DER SEQUENCE per RFC 5280 §4.2.1.1.
        var aki = cert.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        if (aki is not null)
        {
            var akiObj = AuthorityKeyIdentifier.GetInstance(Asn1Object.FromByteArray(aki.GetOctets()));
            byte[]? keyId = akiObj.KeyIdentifier?.GetOctets();
            if (keyId is not null)
                w.WriteByteString(MatterTag.Context(ExtAuthorityKeyIdentifier), keyId);
        }

        w.EndContainer();
    }

    // ---------------- helpers ----------------

    /// <summary>
    /// Convert an X9.62 ECDSA signature (ASN.1 SEQUENCE(INTEGER r, INTEGER s)) into the raw
    /// r || s form Matter uses (fixed 32 bytes per component for P-256).
    /// </summary>
    public static byte[] EcdsaAsn1ToConcat(byte[] asn1Signature)
    {
        var seq = (Asn1Sequence)Asn1Object.FromByteArray(asn1Signature);
        var r = ((DerInteger)seq[0]).PositiveValue.ToByteArrayUnsigned();
        var s = ((DerInteger)seq[1]).PositiveValue.ToByteArrayUnsigned();
        var buf = new byte[64];
        Buffer.BlockCopy(r, 0, buf, 32 - r.Length, r.Length);
        Buffer.BlockCopy(s, 0, buf, 64 - s.Length, s.Length);
        return buf;
    }

    /// <summary>Reverse of <see cref="EcdsaAsn1ToConcat"/>.</summary>
    public static byte[] EcdsaConcatToAsn1(byte[] rawRS)
    {
        if (rawRS.Length != 64) throw new ArgumentException("expected 64 bytes for P-256 r||s", nameof(rawRS));
        var r = new Org.BouncyCastle.Math.BigInteger(1, rawRS.AsSpan(0, 32).ToArray());
        var s = new Org.BouncyCastle.Math.BigInteger(1, rawRS.AsSpan(32, 32).ToArray());
        var v = new Asn1EncodableVector { new DerInteger(r), new DerInteger(s) };
        return new DerSequence(v).GetDerEncoded();
    }

    private static uint ToMatterEpoch(DateTime utc)
    {
        var seconds = (utc.ToUniversalTime() - MatterEpoch).TotalSeconds;
        if (seconds < 0) return 0;
        if (seconds > uint.MaxValue) return uint.MaxValue;
        return (uint)seconds;
    }

    private static ulong? ExtractDnAttr(byte[] tlvCert, byte dnTag)
    {
        var r = new MatterTlvReader(tlvCert);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) return null;
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific
                && r.Tag.TagNumber == TagSubject
                && r.ElementType == MatterTlvElementType.List)
            {
                r.EnterContainer();
                while (r.Read())
                {
                    if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == dnTag)
                        return r.GetUnsignedInt();
                }
                return null;
            }
            // Skip past any other container we encounter before Subject (e.g. Issuer).
            if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                r.ExitContainer();
        }
        return null;
    }
}
