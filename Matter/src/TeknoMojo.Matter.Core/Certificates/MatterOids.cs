using Org.BouncyCastle.Asn1;

namespace TeknoMojo.Matter.Core.Certificates;

/// <summary>
/// Matter-specific ASN.1 object identifiers (Matter Core Spec §6.5.6, table "Matter Certificate
/// DN Attributes"). These live under the CSA arc 1.3.6.1.4.1.37244.1 and are used as X.520
/// Distinguished-Name attribute types in the subject/issuer of Matter operational certificates.
/// </summary>
public static class MatterOids
{
    /// <summary>1.3.6.1.4.1.37244.1.1 — Matter Node ID (64-bit, hex in UTF8).</summary>
    public static readonly DerObjectIdentifier NodeId = new("1.3.6.1.4.1.37244.1.1");

    /// <summary>1.3.6.1.4.1.37244.1.2 — Matter Firmware Signing ID.</summary>
    public static readonly DerObjectIdentifier FirmwareSigningId = new("1.3.6.1.4.1.37244.1.2");

    /// <summary>1.3.6.1.4.1.37244.1.3 — Matter Intermediate CA ID.</summary>
    public static readonly DerObjectIdentifier IcacId = new("1.3.6.1.4.1.37244.1.3");

    /// <summary>1.3.6.1.4.1.37244.1.4 — Matter Root CA ID.</summary>
    public static readonly DerObjectIdentifier RcacId = new("1.3.6.1.4.1.37244.1.4");

    /// <summary>1.3.6.1.4.1.37244.1.5 — Matter Fabric ID.</summary>
    public static readonly DerObjectIdentifier FabricId = new("1.3.6.1.4.1.37244.1.5");

    /// <summary>1.3.6.1.4.1.37244.1.6 — Matter CASE Authenticated Tag (repeated allowed).</summary>
    public static readonly DerObjectIdentifier CaseAuthenticatedTag = new("1.3.6.1.4.1.37244.1.6");

    /// <summary>1.3.6.1.4.1.37244.2.1 — Matter Vendor ID, carried in an attestation certificate's DN.</summary>
    public static readonly DerObjectIdentifier VendorId = new("1.3.6.1.4.1.37244.2.1");

    /// <summary>1.3.6.1.4.1.37244.2.2 — Matter Product ID, carried in an attestation certificate's DN.</summary>
    public static readonly DerObjectIdentifier ProductId = new("1.3.6.1.4.1.37244.2.2");

    /// <summary>The Vendor ID asserted by an attestation certificate's subject, if it carries one.</summary>
    public static ushort? ExtractDnVendorId(Org.BouncyCastle.X509.X509Certificate certificate) =>
        ExtractDnHexId(certificate, VendorId);

    /// <summary>The Product ID asserted by an attestation certificate's subject, if it carries one.</summary>
    public static ushort? ExtractDnProductId(Org.BouncyCastle.X509.X509Certificate certificate) =>
        ExtractDnHexId(certificate, ProductId);

    /// <summary>These DN attributes hold their value as a hex string rather than an integer.</summary>
    private static ushort? ExtractDnHexId(Org.BouncyCastle.X509.X509Certificate certificate, DerObjectIdentifier oid)
    {
        var dn = certificate.SubjectDN;
        var oids = dn.GetOidList();
        var values = dn.GetValueList();
        for (int i = 0; i < oids.Count; i++)
        {
            if (!oid.Equals(oids[i])) continue;
            if (ushort.TryParse((string)values[i]!, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out ushort id))
                return id;
        }
        return null;
    }
}

/// <summary>
/// Matter operational certificate role. Determines Basic Constraints, Key Usage, and how the
/// DN is composed.
/// </summary>
public enum MatterCertificateRole
{
    /// <summary>Root CA (self-signed). BasicConstraints CA:TRUE, KeyUsage keyCertSign|cRLSign.</summary>
    Rcac,
    /// <summary>Intermediate CA (optional). BasicConstraints CA:TRUE, pathLen:0.</summary>
    Icac,
    /// <summary>Node Operational Certificate. CA:FALSE, EKU serverAuth+clientAuth, KeyUsage digitalSignature.</summary>
    Noc,
}
