using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Clusters;

/// <summary>Typed helper for the Node Operational Credentials cluster (0x003E) — endpoint 0 only.</summary>
/// <remarks>
/// The <c>NOCSRElements</c> TLV tag numbers here (1 = csr, 2 = CSRNonce) follow the convention
/// used by other independent Matter implementations (matter.js, python-matter-server); unlike
/// the rest of this codebase's protocol constants, they were not independently re-verified
/// against the primary CSA specification text in this session — the usual source-grounding
/// step (fetching the exact chip header) was blocked by rate limiting. Flagging this explicitly
/// so it gets first scrutiny if a real device's CSRResponse ever fails to parse.
/// </remarks>
public sealed class NodeOperationalCredentialsCluster
{
    private readonly MatterInteractionClient _client;
    private const uint Endpoint = 0;

    public NodeOperationalCredentialsCluster(MatterInteractionClient client) => _client = client;

    /// <summary>Ask the device to generate a CSR for its NOC key, returning the parsed CSR public key and the raw CSRResponse fields.</summary>
    public async Task<(byte[] DevicePublicKeyUncompressed, byte[] NocsrElements, byte[] AttestationSignature)> RequestCsrAsync(
        byte[] csrNonce, CancellationToken ct = default)
    {
        if (csrNonce.Length != 32) throw new ArgumentException("CSRNonce must be 32 bytes.", nameof(csrNonce));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), csrNonce);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NodeOperationalCredentials, NocCommands.CSRRequest), w.ToArray(), ct);

        var r = new MatterTlvReader(response);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("CSRResponse: missing structure");
        r.EnterContainer();
        byte[]? nocsrElements = null, attestationSignature = null;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            if (r.Tag.TagNumber == 0) nocsrElements = r.GetByteString();
            else if (r.Tag.TagNumber == 1) attestationSignature = r.GetByteString();
        }
        if (nocsrElements is null || attestationSignature is null)
            throw new FormatException("CSRResponse: missing NOCSRElements or AttestationSignature");

        byte[] csrDer = ExtractCsrFromNocsrElements(nocsrElements);
        byte[] devicePublicKey = ExtractPublicKeyFromCsr(csrDer);

        return (devicePublicKey, nocsrElements, attestationSignature);
    }

    private static byte[] ExtractCsrFromNocsrElements(byte[] nocsrElements)
    {
        var r = new MatterTlvReader(nocsrElements);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("NOCSRElements: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 1)
                return r.GetByteString();
        }
        throw new FormatException("NOCSRElements: missing csr field (tag 1).");
    }

    private static byte[] ExtractPublicKeyFromCsr(byte[] csrDer)
    {
        var csr = new Pkcs10CertificationRequest(csrDer);
        var publicKey = (ECPublicKeyParameters)csr.GetPublicKey();
        if (!csr.Verify())
            throw new InvalidOperationException("Device CSR self-signature did not verify — refusing to issue a NOC for it.");
        return publicKey.Q.GetEncoded(false);
    }

    /// <summary>Install the fabric's root certificate on the device (must precede AddNOC).</summary>
    /// <summary>
    /// Fetch one certificate from the device's attestation chain. The DAC identifies this
    /// individual device; the PAI is the vendor certificate that issued it.
    /// </summary>
    public async Task<byte[]> GetCertificateChainAsync(CertificateChainType type, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteUnsignedInt(MatterTag.Context(0), (byte)type);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NodeOperationalCredentials, NocCommands.CertificateChainRequest), w.ToArray(), ct);

        return ReadByteStringField(response, tag: 0, "CertificateChainResponse.Certificate");
    }

    /// <summary>
    /// Ask the device to sign a statement about itself using its factory-provisioned attestation
    /// key. The nonce is ours, which is what makes a recorded response useless to a replayer.
    /// </summary>
    public async Task<(byte[] Elements, byte[] Signature)> RequestAttestationAsync(byte[] nonce, CancellationToken ct = default)
    {
        if (nonce.Length != 32) throw new ArgumentException("Attestation nonce must be 32 bytes.", nameof(nonce));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), nonce);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NodeOperationalCredentials, NocCommands.AttestationRequest), w.ToArray(), ct);

        return (ReadByteStringField(response, 0, "AttestationResponse.AttestationElements"),
                ReadByteStringField(response, 1, "AttestationResponse.AttestationSignature"));
    }

    private static byte[] ReadByteStringField(byte[] responseTlv, uint tag, string what)
    {
        var r = new MatterTlvReader(responseTlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure)
            throw new FormatException($"{what}: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == tag)
                return r.GetByteString();
        }
        throw new FormatException($"{what}: field not present");
    }

    public Task AddTrustedRootCertificateAsync(byte[] rootCaCertificateTlv, CancellationToken ct = default)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), rootCaCertificateTlv);
        w.EndContainer();
        return _client.InvokeCommandAsync(
            new CommandPath(Endpoint, ClusterIds.NodeOperationalCredentials, NocCommands.AddTrustedRootCertificate), w.ToArray(), ct);
    }

    /// <summary>Install this controller's NOC on the device, completing the trust relationship.</summary>
    public async Task<NodeOperationalCertStatus> AddNocAsync(
        byte[] nocTlv, byte[]? icacTlv, byte[] ipk, ulong caseAdminSubject, ushort adminVendorId, CancellationToken ct = default)
    {
        if (ipk.Length != 16) throw new ArgumentException("IPK must be 16 bytes.", nameof(ipk));

        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(0), nocTlv);
        if (icacTlv is not null) w.WriteByteString(MatterTag.Context(1), icacTlv);
        w.WriteByteString(MatterTag.Context(2), ipk);
        w.WriteUnsignedInt(MatterTag.Context(3), caseAdminSubject);
        w.WriteUnsignedInt(MatterTag.Context(4), adminVendorId);
        w.EndContainer();

        byte[] response = await _client.InvokeCommandForDataAsync(
            new CommandPath(Endpoint, ClusterIds.NodeOperationalCredentials, NocCommands.AddNOC), w.ToArray(), ct);

        var r = new MatterTlvReader(response);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("NOCResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return (NodeOperationalCertStatus)r.GetUnsignedInt();
        }
        throw new FormatException("NOCResponse: missing StatusCode");
    }
}
