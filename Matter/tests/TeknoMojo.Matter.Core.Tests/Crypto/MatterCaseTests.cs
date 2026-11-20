using System.Security.Cryptography;
using System.Text;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Crypto;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Crypto;

/// <summary>
/// CASE (Certificate-Authenticated Session Establishment) tests. Runs an end-to-end
/// initiator↔responder handshake in-process using the pure crypto primitives, proving both
/// sides derive identical session keys and that signatures verify against the peer's NOC.
/// </summary>
public class MatterCaseTests
{
    [Fact]
    public void DestinationId_IsDeterministic_32Bytes()
    {
        byte[] ipk = new byte[16];
        RandomNumberGenerator.Fill(ipk);
        byte[] randomA = RandomNumberGenerator.GetBytes(32);
        byte[] rootPub = new byte[65];
        rootPub[0] = 0x04;
        RandomNumberGenerator.Fill(rootPub.AsSpan(1));

        byte[] a = MatterCase.ComputeDestinationId(ipk, randomA, rootPub, fabricId: 0x42, destinationNodeId: 0x1234);
        byte[] b = MatterCase.ComputeDestinationId(ipk, randomA, rootPub, fabricId: 0x42, destinationNodeId: 0x1234);
        Assert.Equal(32, a.Length);
        Assert.Equal(a, b);

        byte[] c = MatterCase.ComputeDestinationId(ipk, randomA, rootPub, fabricId: 0x42, destinationNodeId: 0x9999);
        Assert.NotEqual(a, c);
    }

    [Fact]
    public void EcdhIsSymmetric_UsesXCoordinateOnly()
    {
        var alice = MatterCase.GenerateEphemeralKey();
        var bob = MatterCase.GenerateEphemeralKey();

        byte[] zA = MatterCase.Ecdh(alice.PrivateScalar, bob.PublicKeyUncompressed);
        byte[] zB = MatterCase.Ecdh(bob.PrivateScalar, alice.PublicKeyUncompressed);
        Assert.Equal(32, zA.Length);
        Assert.Equal(zA, zB);
    }

    [Fact]
    public void Sigma1_Sigma2_Sigma3_RoundTripThroughTlv()
    {
        var s1 = new MatterCase.Sigma1(
            InitiatorRandom: Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(),
            InitiatorSessionId: 0x1234,
            DestinationId: Enumerable.Range(32, 32).Select(i => (byte)i).ToArray(),
            InitiatorEphPubKey: MakePub(0xAA));
        byte[] s1Enc = MatterCase.EncodeSigma1(s1);
        var s1Dec = MatterCase.DecodeSigma1(s1Enc);
        Assert.Equal(s1.InitiatorRandom, s1Dec.InitiatorRandom);
        Assert.Equal(s1.InitiatorSessionId, s1Dec.InitiatorSessionId);
        Assert.Equal(s1.DestinationId, s1Dec.DestinationId);
        Assert.Equal(s1.InitiatorEphPubKey, s1Dec.InitiatorEphPubKey);

        var s2 = new MatterCase.Sigma2(
            ResponderRandom: RandomNumberGenerator.GetBytes(32),
            ResponderSessionId: 0xABCD,
            ResponderEphPubKey: MakePub(0xBB),
            Encrypted2: new byte[] { 1, 2, 3, 4, 5 });
        var s2Dec = MatterCase.DecodeSigma2(MatterCase.EncodeSigma2(s2));
        Assert.Equal(s2.Encrypted2, s2Dec.Encrypted2);

        var s3 = new MatterCase.Sigma3(new byte[] { 9, 8, 7 });
        var s3Dec = MatterCase.DecodeSigma3(MatterCase.EncodeSigma3(s3));
        Assert.Equal(s3.Encrypted3, s3Dec.Encrypted3);
    }

    [Fact]
    public void TbeData_RoundTrip_ThroughEncrypt()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] plaintext = MatterCase.BuildTbeData(
            senderNocTlv: new byte[] { 1, 2, 3 },
            senderIcacTlv: null,
            rawSignature: new byte[64]);

        byte[] ct = MatterCase.EncryptTbe(key, "NCASE_Sigma2", plaintext);
        Assert.Equal(plaintext.Length + 16, ct.Length);

        byte[] round = MatterCase.DecryptTbe(key, "NCASE_Sigma2", ct);
        Assert.Equal(plaintext, round);

        var parsed = MatterCase.ParseTbeData(round);
        Assert.Equal(new byte[] { 1, 2, 3 }, parsed.SenderNocTlv);
        Assert.Null(parsed.SenderIcacTlv);
        Assert.Equal(64, parsed.RawSignature.Length);
    }

    [Fact]
    public void SignTbs_VerifyTbs_RoundTripsUnderIssuedNoc()
    {
        var root = MatterCertificateBuilder.CreateRootCA(1);
        var noc = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, nodeId: 42, fabricId: 100);

        byte[] tbs = Encoding.UTF8.GetBytes("some CASE transcript data");
        byte[] sig = MatterCase.SignTbs(noc.PrivateKeyPkcs8, tbs);
        Assert.Equal(64, sig.Length);

        Assert.True(MatterCase.VerifyTbs(noc.PublicKeyUncompressed, tbs, sig));

        // Tampering with the TBS causes verify to fail.
        tbs[0] ^= 0xFF;
        Assert.False(MatterCase.VerifyTbs(noc.PublicKeyUncompressed, tbs, sig));
    }

    /// <summary>
    /// The full CASE handshake end-to-end, in process. Both sides derive the same session keys
    /// and both signatures verify. This is the acceptance test for M2d: if this passes, the
    /// crypto is right and the only work remaining for real-device CASE is the transport plumbing.
    /// </summary>
    [Fact]
    public void EndToEnd_CaseHandshake_DerivesMatchingSessionKeys()
    {
        // Bootstrap a fabric with two nodes: initiator (us) and responder (device).
        ulong fabricId = 0x0000000000000042;
        ulong initiatorNodeId = 0x0000000000000001;
        ulong responderNodeId = 0x0000000000BEEF00;

        var root = MatterCertificateBuilder.CreateRootCA(rootCaId: 1);
        var initiatorNoc = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, initiatorNodeId, fabricId);
        var responderNoc = MatterCertificateBuilder.IssueNoc(root.CertificateDer, root.PrivateKeyPkcs8, responderNodeId, fabricId);
        byte[] initiatorNocTlv = MatterCertificateTlv.FromDer(initiatorNoc.CertificateDer);
        byte[] responderNocTlv = MatterCertificateTlv.FromDer(responderNoc.CertificateDer);

        byte[] ipk = RandomNumberGenerator.GetBytes(16);

        // ---- Sigma1 (initiator) ----
        var initEph = MatterCase.GenerateEphemeralKey();
        byte[] initRandom = RandomNumberGenerator.GetBytes(32);
        byte[] destId = MatterCase.ComputeDestinationId(ipk, initRandom, root.PublicKeyUncompressed, fabricId, responderNodeId);
        var sigma1 = new MatterCase.Sigma1(initRandom, InitiatorSessionId: 1000, destId, initEph.PublicKeyUncompressed);
        byte[] sigma1Wire = MatterCase.EncodeSigma1(sigma1);

        // ---- Sigma2 (responder) ----
        var respEph = MatterCase.GenerateEphemeralKey();
        byte[] respRandom = RandomNumberGenerator.GetBytes(32);
        byte[] zResp = MatterCase.Ecdh(respEph.PrivateScalar, sigma1.InitiatorEphPubKey);
        byte[] th1 = SHA256.HashData(sigma1Wire);
        byte[] s2k = MatterCase.DeriveS2K(ipk, zResp, th1);

        byte[] tbs2 = MatterCase.BuildTbsData(responderNocTlv, null, respEph.PublicKeyUncompressed, sigma1.InitiatorEphPubKey);
        byte[] sig2 = MatterCase.SignTbs(responderNoc.PrivateKeyPkcs8, tbs2);
        byte[] tbe2Plain = MatterCase.BuildTbeData(responderNocTlv, null, sig2);
        byte[] enc2 = MatterCase.EncryptTbe(s2k, "NCASE_Sigma2", tbe2Plain);

        var sigma2 = new MatterCase.Sigma2(respRandom, ResponderSessionId: 2000, respEph.PublicKeyUncompressed, enc2);
        byte[] sigma2Wire = MatterCase.EncodeSigma2(sigma2);

        // ---- Sigma3 (initiator processes Sigma2, then builds Sigma3) ----
        byte[] zInit = MatterCase.Ecdh(initEph.PrivateScalar, sigma2.ResponderEphPubKey);
        Assert.Equal(zResp, zInit); // ECDH agrees

        byte[] s2kInit = MatterCase.DeriveS2K(ipk, zInit, th1);
        Assert.Equal(s2k, s2kInit);

        byte[] tbe2Decoded = MatterCase.DecryptTbe(s2kInit, "NCASE_Sigma2", sigma2.Encrypted2);
        var parsed2 = MatterCase.ParseTbeData(tbe2Decoded);
        // Verify responder signature under responder's NOC pub key.
        byte[]? respPubFromNoc = MatterCertificateTlv.ExtractPublicKey(parsed2.SenderNocTlv);
        Assert.NotNull(respPubFromNoc);
        byte[] tbs2Reco = MatterCase.BuildTbsData(parsed2.SenderNocTlv, parsed2.SenderIcacTlv, sigma2.ResponderEphPubKey, sigma1.InitiatorEphPubKey);
        Assert.True(MatterCase.VerifyTbs(respPubFromNoc, tbs2Reco, parsed2.RawSignature));

        // Build Sigma3
        byte[] th12 = SHA256.HashData(Concat(sigma1Wire, sigma2Wire));
        byte[] s3k = MatterCase.DeriveS3K(ipk, zInit, th12);
        byte[] tbs3 = MatterCase.BuildTbsData(initiatorNocTlv, null, initEph.PublicKeyUncompressed, sigma2.ResponderEphPubKey);
        byte[] sig3 = MatterCase.SignTbs(initiatorNoc.PrivateKeyPkcs8, tbs3);
        byte[] tbe3Plain = MatterCase.BuildTbeData(initiatorNocTlv, null, sig3);
        byte[] enc3 = MatterCase.EncryptTbe(s3k, "NCASE_Sigma3", tbe3Plain);
        var sigma3 = new MatterCase.Sigma3(enc3);
        byte[] sigma3Wire = MatterCase.EncodeSigma3(sigma3);

        // ---- Responder processes Sigma3 ----
        byte[] s3kResp = MatterCase.DeriveS3K(ipk, zResp, th12);
        Assert.Equal(s3k, s3kResp);
        byte[] tbe3Dec = MatterCase.DecryptTbe(s3kResp, "NCASE_Sigma3", sigma3.Encrypted3);
        var parsed3 = MatterCase.ParseTbeData(tbe3Dec);
        byte[]? initPubFromNoc = MatterCertificateTlv.ExtractPublicKey(parsed3.SenderNocTlv);
        Assert.NotNull(initPubFromNoc);
        byte[] tbs3Reco = MatterCase.BuildTbsData(parsed3.SenderNocTlv, parsed3.SenderIcacTlv, sigma1.InitiatorEphPubKey, sigma2.ResponderEphPubKey);
        Assert.True(MatterCase.VerifyTbs(initPubFromNoc, tbs3Reco, parsed3.RawSignature));

        // ---- Both sides derive session keys ----
        byte[] th123 = SHA256.HashData(Concat(sigma1Wire, sigma2Wire, sigma3Wire));
        var (i2rInit, r2iInit, chalInit) = MatterCase.DeriveSessionKeys(ipk, zInit, th123);
        var (i2rResp, r2iResp, chalResp) = MatterCase.DeriveSessionKeys(ipk, zResp, th123);

        Assert.Equal(i2rInit, i2rResp);
        Assert.Equal(r2iInit, r2iResp);
        Assert.Equal(chalInit, chalResp);
        Assert.Equal(16, i2rInit.Length);
        Assert.NotEqual(i2rInit, r2iInit); // different directions -> different keys
    }

    // ---- helpers ----

    private static byte[] MakePub(byte fill)
    {
        var pub = new byte[65];
        pub[0] = 0x04;
        Array.Fill(pub, fill, 1, 64);
        return pub;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = parts.Sum(p => p.Length);
        var buf = new byte[total];
        int pos = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, buf, pos, p.Length); pos += p.Length; }
        return buf;
    }
}
