using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Fabric;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Certificates;

/// <summary>
/// Tests for the Matter certificate authority: cert generation shape, chain verification, and
/// round-trip through the Matter TLV compact form.
/// </summary>
public class MatterCertificateTests
{
    [Fact]
    public void CreateRootCA_ProducesSelfSignedP256Cert_WithMatterRcacIdSubject()
    {
        ulong rcacId = 0x00000000_00000001;
        var root = MatterCertificateBuilder.CreateRootCA(rcacId);

        Assert.NotEmpty(root.CertificateDer);
        Assert.NotEmpty(root.PrivateKeyPkcs8);
        Assert.Equal(65, root.PublicKeyUncompressed.Length); // uncompressed P-256
        Assert.Equal(0x04, root.PublicKeyUncompressed[0]);

        using var cert = X509CertificateLoader.LoadCertificate(root.CertificateDer);
        Assert.Contains(MatterCertificateBuilder.FormatMatterId64(rcacId), cert.Subject);
        Assert.Equal(cert.Subject, cert.Issuer); // self-signed
        // Basic Constraints CA:TRUE and Key Usage keyCertSign — both present.
        Assert.Contains(cert.Extensions.OfType<X509BasicConstraintsExtension>(), e => e.CertificateAuthority);
        Assert.Contains(cert.Extensions.OfType<X509KeyUsageExtension>(),
            e => (e.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0);
    }

    [Fact]
    public void IssueNoc_ChainsBackToRoot_AndCarriesFabricAndNodeIds()
    {
        ulong rcacId = 1;
        ulong fabricId = 0x00000000_00000042;
        ulong nodeId = 0x0000000000BADF00;

        var root = MatterCertificateBuilder.CreateRootCA(rcacId);
        var noc = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, nodeId, fabricId);

        using var rootCert = X509CertificateLoader.LoadCertificate(root.CertificateDer);
        using var nocCert = X509CertificateLoader.LoadCertificate(noc.CertificateDer);

        // The NOC subject carries both matter-node-id and matter-fabric-id as hex.
        Assert.Contains(MatterCertificateBuilder.FormatMatterId64(nodeId), nocCert.Subject);
        Assert.Contains(MatterCertificateBuilder.FormatMatterId64(fabricId), nocCert.Subject);

        // Chain verification via X509Chain — the root is the trust anchor.
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(rootCert);
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        bool built = chain.Build(nocCert);

        // Any residual failure would be listed here — Matter certs lack CN, which some verifiers dislike;
        // we accept the chain when the only complaint is UntrustedRoot resolved by our custom trust.
        Assert.True(built, "chain: " + string.Join(",",
            chain.ChainStatus.Select(s => $"{s.Status}:{s.StatusInformation}")));
    }

    [Fact]
    public void CertificateTlv_RoundTrip_PreservesIds()
    {
        ulong fabricId = 0x1122334455667788;
        ulong nodeId = 0xAABBCCDDEEFF0011;

        var root = MatterCertificateBuilder.CreateRootCA(1);
        var noc = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, nodeId, fabricId);

        byte[] tlv = MatterCertificateTlv.FromDer(noc.CertificateDer);
        Assert.NotEmpty(tlv);

        // The TLV form is significantly smaller than DER — this is one of the reasons Matter uses it.
        Assert.True(tlv.Length < noc.CertificateDer.Length,
            $"expected TLV < DER; got TLV={tlv.Length} DER={noc.CertificateDer.Length}");

        // Peek helpers surface subject IDs directly from the TLV cert.
        Assert.Equal(nodeId, MatterCertificateTlv.ExtractSubjectNodeId(tlv));
        Assert.Equal(fabricId, MatterCertificateTlv.ExtractSubjectFabricId(tlv));

        // Public key survives round-trip and matches what the DER cert holds.
        byte[]? pubFromTlv = MatterCertificateTlv.ExtractPublicKey(tlv);
        Assert.NotNull(pubFromTlv);
        Assert.Equal(noc.PublicKeyUncompressed, pubFromTlv);
    }

    [Fact]
    public void Signature_AsnConcatRoundTrip()
    {
        // Sign something with a fresh P-256 key, convert the DER signature to Matter's raw
        // concat form and back, and confirm it still verifies.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] data = new byte[] { 1, 2, 3, 4, 5 };
        byte[] asn1Sig = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        byte[] concat = MatterCertificateTlv.EcdsaAsn1ToConcat(asn1Sig);
        Assert.Equal(64, concat.Length);

        byte[] asn1Again = MatterCertificateTlv.EcdsaConcatToAsn1(concat);
        Assert.True(ecdsa.VerifyData(data, asn1Again, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    [Fact]
    public void CompressedFabricId_IsEightBytes_AndDeterministic()
    {
        var root = MatterCertificateBuilder.CreateRootCA(1);
        var fabric = new MatterFabric
        {
            FabricId = 0x0000_0000_0000_0042,
            RootCertificateDer = root.CertificateDer,
            ControllerNocDer = new byte[] { 1 },
            ControllerNocPrivateKeyPkcs8 = new byte[] { 2 },
            ControllerNodeId = 1,
            IdentityProtectionKey = new byte[16],
        };
        var id1 = fabric.ComputeCompressedFabricId(root.PublicKeyUncompressed);
        var id2 = fabric.ComputeCompressedFabricId(root.PublicKeyUncompressed);
        Assert.Equal(8, id1.Length);
        Assert.Equal(id1, id2);
    }

    [Fact]
    public void GeneratedCertificatesUseTheNamedCurveNotExplicitParameters()
    {
        // Matter's TLV certificate records only ec-curve-id, so a peer rebuilds the TBS with the
        // named-curve SPKI. A certificate signed over explicitly-parameterised DER therefore
        // fails the peer's signature check and is rejected — invisible to a round-trip test.
        var root = MatterCertificateBuilder.CreateRootCA(rootCaId: 1);
        var noc = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, nodeId: 5, fabricId: 7);

        foreach (byte[] der in new[] { root.CertificateDer, noc.CertificateDer })
        {
            var spki = Org.BouncyCastle.Asn1.X509.X509CertificateStructure
                .GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(der))
                .SubjectPublicKeyInfo;

            var parameters = Assert.IsType<Org.BouncyCastle.Asn1.DerObjectIdentifier>(
                spki.Algorithm.Parameters.ToAsn1Object());
            Assert.Equal(Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.Prime256v1.Id, parameters.Id);
        }
    }
}
