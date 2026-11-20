using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Tests.Commissioning;

/// <summary>
/// A genuine PAI → DAC attestation chain with real signatures, so the commissioner's attestation
/// checks are exercised for real rather than waved through.
/// </summary>
internal sealed class FakeAttestationChain
{
    private static readonly Org.BouncyCastle.Asn1.X9.X9ECParameters P256 = NistNamedCurves.GetByName("P-256");
    private static readonly ECDomainParameters Domain = new ECNamedDomainParameters(
        NistNamedCurves.GetOid("P-256"), P256.Curve, P256.G, P256.N, P256.H, P256.GetSeed());

    private readonly AsymmetricKeyParameter _dacPrivateKey;

    public byte[] PaiDer { get; }
    public byte[] DacDer { get; }

    public FakeAttestationChain(ushort vendorId = 0xFFF1, ushort productId = 0x8000)
    {
        var paiKeys = GenerateKeyPair();
        var dacKeys = GenerateKeyPair();
        _dacPrivateKey = dacKeys.Private;

        var paiName = new X509Name(
            [MatterOids.VendorId],
            [vendorId.ToString("X4")]);
        PaiDer = IssueCertificate(paiName, paiName, paiKeys.Public, paiKeys.Private, isCa: true);

        var dacName = new X509Name(
            [MatterOids.VendorId, MatterOids.ProductId],
            [vendorId.ToString("X4"), productId.ToString("X4")]);
        DacDer = IssueCertificate(dacName, paiName, dacKeys.Public, paiKeys.Private, isCa: false);
    }

    /// <summary>
    /// Produce attestation elements echoing the commissioner's nonce, and sign elements||nonce
    /// with the DAC key — exactly what a real device does.
    /// </summary>
    public (byte[] Elements, byte[] Signature) Sign(byte[] nonce)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), [0x01, 0x02, 0x03]);   // certification declaration
        w.WriteByteString(MatterTag.Context(2), nonce);
        w.WriteUnsignedInt(MatterTag.Context(3), 0);                   // timestamp
        w.EndContainer();
        byte[] elements = w.ToArray();

        byte[] tbs = [.. elements, .. nonce];
        var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
        signer.Init(true, _dacPrivateKey);
        signer.BlockUpdate(tbs, 0, tbs.Length);

        // Matter carries the signature raw, not DER.
        return (elements, MatterCertificateTlv.EcdsaAsn1ToConcat(signer.GenerateSignature()));
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var gen = new ECKeyPairGenerator("ECDSA");
        gen.Init(new ECKeyGenerationParameters(Domain, new SecureRandom()));
        return gen.GenerateKeyPair();
    }

    private static byte[] IssueCertificate(
        X509Name subject, X509Name issuer, AsymmetricKeyParameter subjectKey,
        AsymmetricKeyParameter issuerPrivateKey, bool isCa)
    {
        var now = DateTime.UtcNow;
        var cert = new X509V3CertificateGenerator();
        cert.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue)));
        cert.SetIssuerDN(issuer);
        cert.SetSubjectDN(subject);
        cert.SetNotBefore(now.AddMinutes(-5));
        cert.SetNotAfter(now.AddYears(10));
        cert.SetPublicKey(subjectKey);
        cert.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));
        cert.AddExtension(X509Extensions.KeyUsage, true,
            new KeyUsage(isCa ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature));

        return cert.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", issuerPrivateKey)).GetEncoded();
    }
}
