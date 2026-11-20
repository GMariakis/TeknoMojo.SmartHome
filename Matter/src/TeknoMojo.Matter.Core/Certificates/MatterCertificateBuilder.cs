using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace TeknoMojo.Matter.Core.Certificates;

/// <summary>
/// Builds Matter operational X.509 certificates (Matter Core Spec §6.5) in DER form using
/// BouncyCastle's cert generator. Emits RCAC (self-signed root) and NOC (issued by RCAC or ICAC)
/// with the Matter-specific DN attribute types, correct BasicConstraints/KeyUsage/ExtendedKeyUsage
/// extensions, and Subject/Authority Key Identifiers. Signature algorithm is always ecdsa-with-SHA256.
/// </summary>
public static class MatterCertificateBuilder
{
    private static readonly X9ECParameters P256 = NistNamedCurves.GetByName("P-256");

    /// <summary>
    /// Named — not plain — domain parameters, so the SubjectPublicKeyInfo carries the
    /// prime256v1 OID instead of a full explicit curve description. Matter's TLV certificate
    /// records only <c>ec-curve-id</c>, so a peer reconstructs the TBS with the named form; a
    /// certificate signed over explicitly-parameterised DER then fails that peer's signature
    /// check and is rejected outright.
    /// </summary>
    private static readonly ECDomainParameters Domain = new ECNamedDomainParameters(
        NistNamedCurves.GetOid("P-256"), P256.Curve, P256.G, P256.N, P256.H, P256.GetSeed());

    /// <summary>
    /// A freshly-generated Matter operational credential: the PEM-less cert bytes plus its
    /// matching private key in PKCS#8 form. Used both as the return value from RCAC creation
    /// (where the private key stays with the controller) and for the controller's own NOC.
    /// </summary>
    public sealed record MatterCertBundle(byte[] CertificateDer, byte[] PrivateKeyPkcs8, byte[] PublicKeyUncompressed);

    /// <summary>
    /// Generate a fresh self-signed Root CA certificate for a new fabric. The returned private
    /// key IS the fabric root key — treat with the same care as any CA key.
    /// </summary>
    /// <param name="rootCaId">64-bit RCAC ID; identifies this root inside a single controller's set of roots.</param>
    /// <param name="validity">Cert lifetime; recommended ≥ 20 years for roots.</param>
    public static MatterCertBundle CreateRootCA(ulong rootCaId, TimeSpan? validity = null)
    {
        var (keyPair, privateKeyPkcs8, pubUncompressed) = GenerateP256KeyPair();

        var name = new X509NameBuilder()
            .Add(MatterOids.RcacId, FormatMatterId64(rootCaId))
            .Build();

        var now = DateTime.UtcNow;
        var cert = new X509V3CertificateGenerator();
        cert.SetSerialNumber(RandomSerialNumber());
        cert.SetIssuerDN(name);
        cert.SetSubjectDN(name);
        cert.SetNotBefore(now.AddMinutes(-5));
        cert.SetNotAfter(now.Add(validity ?? TimeSpan.FromDays(365 * 20)));
        cert.SetPublicKey(keyPair.Public);

        cert.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: true));
        cert.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        cert.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false, MakeSki(pubUncompressed));
        cert.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false, new AuthorityKeyIdentifier(MakeSki(pubUncompressed).GetKeyIdentifier()));

        var signer = new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private);
        var derCert = cert.Generate(signer).GetEncoded();
        return new MatterCertBundle(derCert, privateKeyPkcs8, pubUncompressed);
    }

    /// <summary>
    /// Issue a Node Operational Certificate (NOC) for <paramref name="nodeId"/> on
    /// <paramref name="fabricId"/>, signed by the caller-supplied issuer (typically the root).
    /// The NOC's private key is generated fresh and returned; the resulting bundle is what a
    /// commissioner sends to the accessory during onboarding (AddNOC) or keeps for itself.
    /// </summary>
    /// <param name="issuerCertDer">DER-encoded RCAC or ICAC that will sign this NOC.</param>
    /// <param name="issuerPrivateKeyPkcs8">Private key matching <paramref name="issuerCertDer"/>.</param>
    /// <param name="nodeId">64-bit operational Node ID for the subject.</param>
    /// <param name="fabricId">64-bit Fabric ID this NOC belongs to.</param>
    /// <param name="validity">Cert lifetime; ~5 years is typical for NOCs.</param>
    public static MatterCertBundle IssueNoc(
        byte[] issuerCertDer,
        byte[] issuerPrivateKeyPkcs8,
        ulong nodeId,
        ulong fabricId,
        TimeSpan? validity = null)
    {
        var (subjectKeyPair, subjectPrivKeyPkcs8, subjectPubUncompressed) = GenerateP256KeyPair();
        byte[] derCert = IssueNocForPublicKey(issuerCertDer, issuerPrivateKeyPkcs8, subjectKeyPair.Public, nodeId, fabricId, validity);
        return new MatterCertBundle(derCert, subjectPrivKeyPkcs8, subjectPubUncompressed);
    }

    /// <summary>
    /// Issue a NOC for a public key we do NOT hold the private key for — the normal commissioning
    /// case, where the accessory generates its own keypair, sends us a CSR, and we sign only its
    /// public key. Returns the DER certificate; there is no private key to hand back.
    /// </summary>
    public static byte[] IssueNocForDeviceCsr(
        byte[] issuerCertDer,
        byte[] issuerPrivateKeyPkcs8,
        byte[] devicePublicKeyUncompressed,
        ulong nodeId,
        ulong fabricId,
        TimeSpan? validity = null)
    {
        var point = P256.Curve.DecodePoint(devicePublicKeyUncompressed);
        var publicKey = new ECPublicKeyParameters(point, Domain);
        return IssueNocForPublicKey(issuerCertDer, issuerPrivateKeyPkcs8, publicKey, nodeId, fabricId, validity);
    }

    private static byte[] IssueNocForPublicKey(
        byte[] issuerCertDer,
        byte[] issuerPrivateKeyPkcs8,
        AsymmetricKeyParameter subjectPublicKey,
        ulong nodeId,
        ulong fabricId,
        TimeSpan? validity)
    {
        var issuerCert = new X509CertificateParser().ReadCertificate(issuerCertDer);
        var issuerPrivKey = PrivateKeyFactory.CreateKey(issuerPrivateKeyPkcs8);
        byte[] subjectPubUncompressed = ((ECPublicKeyParameters)subjectPublicKey).Q.GetEncoded(false);

        var subject = new X509NameBuilder()
            .Add(MatterOids.NodeId, FormatMatterId64(nodeId))
            .Add(MatterOids.FabricId, FormatMatterId64(fabricId))
            .Build();

        var now = DateTime.UtcNow;
        var cert = new X509V3CertificateGenerator();
        cert.SetSerialNumber(RandomSerialNumber());
        cert.SetIssuerDN(issuerCert.SubjectDN);
        cert.SetSubjectDN(subject);
        cert.SetNotBefore(now.AddMinutes(-5));
        cert.SetNotAfter(now.Add(validity ?? TimeSpan.FromDays(365 * 5)));
        cert.SetPublicKey(subjectPublicKey);

        cert.AddExtension(X509Extensions.BasicConstraints, critical: true, new BasicConstraints(cA: false));
        cert.AddExtension(X509Extensions.KeyUsage, critical: true, new KeyUsage(KeyUsage.DigitalSignature));
        cert.AddExtension(X509Extensions.ExtendedKeyUsage, critical: true,
            new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth, KeyPurposeID.id_kp_clientAuth));

        var subjectSki = MakeSki(subjectPubUncompressed);
        cert.AddExtension(X509Extensions.SubjectKeyIdentifier, critical: false, subjectSki);

        // Authority Key ID = SKI of issuer, so verifiers can chain up correctly.
        var issuerPubEncoded = ((ECPublicKeyParameters)issuerCert.GetPublicKey()).Q.GetEncoded(false);
        cert.AddExtension(X509Extensions.AuthorityKeyIdentifier, critical: false,
            new AuthorityKeyIdentifier(MakeSki(issuerPubEncoded).GetKeyIdentifier()));

        var signer = new Asn1SignatureFactory("SHA256WITHECDSA", issuerPrivKey);
        return cert.Generate(signer).GetEncoded();
    }

    /// <summary>
    /// Format a 64-bit Matter ID as the 16-character uppercase-hex UTF-8 string that goes in a
    /// certificate DN attribute value (Spec §6.5.6, "The 64-bit value is encoded in
    /// hexadecimal as a UTF-8 string").
    /// </summary>
    public static string FormatMatterId64(ulong id) => id.ToString("X16");

    // ---------- helpers ----------

    private static (AsymmetricCipherKeyPair keyPair, byte[] pkcs8, byte[] publicUncompressed) GenerateP256KeyPair()
    {
        var gen = new ECKeyPairGenerator("ECDSA");
        gen.Init(new ECKeyGenerationParameters(Domain, new SecureRandom()));
        var kp = gen.GenerateKeyPair();

        byte[] pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private).GetDerEncoded();
        byte[] pub = ((ECPublicKeyParameters)kp.Public).Q.GetEncoded(false);
        return (kp, pkcs8, pub);
    }

    private static BigInteger RandomSerialNumber()
    {
        byte[] buf = new byte[20];
        RandomNumberGenerator.Fill(buf);
        buf[0] &= 0x7F; // keep positive; DER integer sign
        return new BigInteger(1, buf);
    }

    private static SubjectKeyIdentifier MakeSki(byte[] publicKeyUncompressed)
        => new(SHA1.HashData(publicKeyUncompressed));
}

/// <summary>Small fluent helper for building X.500 names with our OIDs.</summary>
internal sealed class X509NameBuilder
{
    private readonly List<DerObjectIdentifier> _oids = new();
    private readonly List<string> _values = new();

    public X509NameBuilder Add(DerObjectIdentifier oid, string value)
    {
        _oids.Add(oid); _values.Add(value); return this;
    }

    public X509Name Build() => new(_oids, _values);
}

/// <summary>
/// Turn a controller-owned private key (PKCS#8) into a <see cref="X509Certificate2"/> tied to
/// its DER cert — handy for interop with anything in the .NET X.509 ecosystem (verification,
/// TLS if we ever needed it, dumping to disk). Not required at runtime but useful for testing.
/// </summary>
public static class MatterCertExtensions
{
    public static X509Certificate2 ToX509Certificate2(this MatterCertificateBuilder.MatterCertBundle bundle)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(bundle.PrivateKeyPkcs8, out _);
        var cert = X509CertificateLoader.LoadCertificate(bundle.CertificateDer);
        return cert.CopyWithPrivateKey(ecdsa);
    }
}
