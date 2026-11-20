using System.Security.Cryptography;
using TeknoMojo.Matter.Core.Commissioning;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Commissioning;

/// <summary>
/// Device attestation (Spec §6.2). These check the cases that actually matter: that a genuine
/// chain is accepted, and that each way of faking one is refused.
/// </summary>
public class MatterDeviceAttestationTests
{
    private static (byte[] Elements, byte[] Signature, byte[] Nonce, FakeAttestationChain Chain) Attest()
    {
        var chain = new FakeAttestationChain();
        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        var (elements, signature) = chain.Sign(nonce);
        return (elements, signature, nonce, chain);
    }

    [Fact]
    public void GenuineAttestationIsAccepted()
    {
        var (elements, signature, nonce, chain) = Attest();

        var result = MatterAttestationVerifier.Verify(
            elements, signature, nonce, chain.DacDer, chain.PaiDer, trustStore: null);

        Assert.Equal((ushort?)0xFFF1, result.CertificateVendorId);
        Assert.Equal((ushort?)0x8000, result.CertificateProductId);

        // No trust store was supplied, so the chain is coherent but not anchored.
        Assert.False(result.ChainsToTrustedRoot);
    }

    [Fact]
    public void AttestationCapturedForADifferentNonceIsRejected()
    {
        // The whole point of the nonce: a recorded attestation must not be replayable.
        var (elements, signature, _, chain) = Attest();
        byte[] someoneElsesNonce = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<MatterAttestationException>(() => MatterAttestationVerifier.Verify(
            elements, signature, someoneElsesNonce, chain.DacDer, chain.PaiDer, trustStore: null));
    }

    [Fact]
    public void TamperedSignatureIsRejected()
    {
        var (elements, signature, nonce, chain) = Attest();
        signature[0] ^= 0xFF;

        Assert.Throws<MatterAttestationException>(() => MatterAttestationVerifier.Verify(
            elements, signature, nonce, chain.DacDer, chain.PaiDer, trustStore: null));
    }

    [Fact]
    public void CertificateNotIssuedByTheSuppliedIntermediateIsRejected()
    {
        // A device presenting someone else's intermediate alongside its own certificate.
        var (elements, signature, nonce, chain) = Attest();
        var unrelated = new FakeAttestationChain();

        Assert.Throws<MatterAttestationException>(() => MatterAttestationVerifier.Verify(
            elements, signature, nonce, chain.DacDer, unrelated.PaiDer, trustStore: null));
    }

    [Fact]
    public void ChainAnchorsOnlyToARootTheCallerTrusts()
    {
        var (elements, signature, nonce, chain) = Attest();

        // Our fake intermediate is self-signed, so trusting it is equivalent to trusting the PAA.
        var trusting = new MatterAttestationTrustStore().Add(chain.PaiDer);
        Assert.True(MatterAttestationVerifier
            .Verify(elements, signature, nonce, chain.DacDer, chain.PaiDer, trusting).ChainsToTrustedRoot);

        var trustingSomeoneElse = new MatterAttestationTrustStore().Add(new FakeAttestationChain().PaiDer);
        Assert.False(MatterAttestationVerifier
            .Verify(elements, signature, nonce, chain.DacDer, chain.PaiDer, trustingSomeoneElse).ChainsToTrustedRoot);
    }
}
