using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Commissioning;

/// <summary>
/// Device Attestation (Spec §6.2): proof that a device is what it claims to be, signed by a key
/// the manufacturer put in it at the factory.
/// </summary>
/// <remarks>
/// The chain runs DAC → PAI → PAA. The DAC is unique to the device, the PAI belongs to the
/// vendor, and the PAA is a root the CSA has certified. We verify the device's signature over the
/// attestation elements with the DAC's key, verify the DAC really was issued by the PAI, and — if
/// the caller supplies a trust store — that the PAI chains to a root they accept.
///
/// Without such a store this establishes that the device holds the private key for a coherent
/// certificate chain and that the chain matches the vendor and product it claims. It cannot
/// establish that the chain is CSA-certified, because nothing here knows which roots those are.
/// <see cref="MatterAttestationTrustStore"/> is how a caller closes that gap.
/// </remarks>
public sealed record MatterDeviceAttestation
{
    /// <summary>The device's own attestation certificate, DER encoded.</summary>
    public required byte[] DeviceAttestationCertificateDer { get; init; }

    /// <summary>The vendor's intermediate certificate that issued the DAC, DER encoded.</summary>
    public required byte[] ProductAttestationIntermediateDer { get; init; }

    /// <summary>The raw attestation elements the device signed, needed verbatim for the CSR transcript.</summary>
    public required byte[] AttestationElements { get; init; }

    /// <summary>Vendor ID asserted by the device's attestation certificate.</summary>
    public ushort? CertificateVendorId { get; init; }

    /// <summary>Product ID asserted by the device's attestation certificate.</summary>
    public ushort? CertificateProductId { get; init; }

    /// <summary>True when the PAI chained to a root the caller trusts. False when no store was supplied.</summary>
    public bool ChainsToTrustedRoot { get; init; }
}

/// <summary>Roots a caller is willing to accept as the top of an attestation chain.</summary>
/// <remarks>
/// Production roots (PAAs) are published by the CSA and are deliberately not bundled here: which
/// roots to trust is the caller's policy decision, not this library's, and a stale or invented
/// list would be worse than none.
/// </remarks>
public sealed class MatterAttestationTrustStore
{
    private readonly List<X509Certificate> _roots = [];

    /// <summary>Add a DER-encoded Product Attestation Authority certificate.</summary>
    public MatterAttestationTrustStore Add(byte[] paaCertificateDer)
    {
        _roots.Add(new X509CertificateParser().ReadCertificate(paaCertificateDer));
        return this;
    }

    /// <summary>True when <paramref name="pai"/> was issued by one of the roots held here.</summary>
    public bool Verifies(X509Certificate pai)
    {
        foreach (var root in _roots)
        {
            try
            {
                pai.Verify(root.GetPublicKey());
                return true;
            }
            catch (Exception)
            {
                // Wrong root for this chain; keep looking.
            }
        }
        return false;
    }
}

/// <summary>Raised when a device's attestation does not hold up.</summary>
public sealed class MatterAttestationException(string message) : Exception(message);

internal static class MatterAttestationVerifier
{
    /// <summary>
    /// Check the device's attestation. Throws <see cref="MatterAttestationException"/> rather than
    /// returning a flag, because continuing to commission a device that failed this is not a
    /// decision to make implicitly.
    /// </summary>
    public static MatterDeviceAttestation Verify(
        byte[] attestationElements, byte[] attestationSignature, byte[] attestationNonce,
        byte[] dacDer, byte[] paiDer, MatterAttestationTrustStore? trustStore)
    {
        var parser = new X509CertificateParser();
        X509Certificate dac = parser.ReadCertificate(dacDer);
        X509Certificate pai = parser.ReadCertificate(paiDer);

        // The DAC must genuinely have been issued by the PAI, or the chain means nothing.
        try
        {
            dac.Verify(pai.GetPublicKey());
        }
        catch (Exception ex)
        {
            throw new MatterAttestationException(
                $"The device's attestation certificate was not issued by the intermediate it supplied: {ex.Message}");
        }

        // The signature covers the attestation elements followed by the nonce we chose, which is
        // what stops a recorded attestation from being replayed at us.
        byte[] tbs = [.. attestationElements, .. attestationNonce];
        if (!VerifyEcdsa(dac, tbs, attestationSignature))
            throw new MatterAttestationException("The device's attestation signature did not verify against its attestation certificate.");

        // The nonce we sent must also appear inside the signed elements.
        var elements = ParseAttestationElements(attestationElements);
        if (elements.Nonce is null || !CryptographicOperations.FixedTimeEquals(elements.Nonce, attestationNonce))
            throw new MatterAttestationException("The attestation elements did not echo the nonce we supplied.");

        bool trusted = trustStore?.Verifies(pai) ?? false;

        return new MatterDeviceAttestation
        {
            DeviceAttestationCertificateDer = dacDer,
            ProductAttestationIntermediateDer = paiDer,
            AttestationElements = attestationElements,
            CertificateVendorId = MatterOids.ExtractDnVendorId(dac),
            CertificateProductId = MatterOids.ExtractDnProductId(dac),
            ChainsToTrustedRoot = trusted,
        };
    }

    private static bool VerifyEcdsa(X509Certificate certificate, byte[] message, byte[] rawSignature)
    {
        // Matter carries ECDSA signatures as raw r||s; .NET and BouncyCastle want DER here.
        byte[] der = MatterCertificateTlv.EcdsaConcatToAsn1(rawSignature);
        var key = (ECPublicKeyParameters)certificate.GetPublicKey();

        var verifier = SignerUtilities.GetSigner("SHA-256withECDSA");
        verifier.Init(false, key);
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(der);
    }

    /// <summary>AttestationElements is a TLV structure; tag 2 is the nonce we sent back to us.</summary>
    private static (byte[]? Nonce, uint? Timestamp) ParseAttestationElements(byte[] tlv)
    {
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) return (null, null);
        r.EnterContainer();

        byte[]? nonce = null;
        uint? timestamp = null;
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
                case 2: nonce = r.GetByteString(); break;
                case 3: timestamp = (uint)r.GetUnsignedInt(); break;
                default:
                    if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
                        r.ExitContainer();
                    break;
            }
        }
        return (nonce, timestamp);
    }
}
