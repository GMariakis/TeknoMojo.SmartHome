using System.Net;
using System.Security.Cryptography;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Clusters;
using TeknoMojo.Matter.Core.Crypto;
using TeknoMojo.Matter.Core.Fabric;
using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Messaging;
using TeknoMojo.Matter.Core.Sessions;

namespace TeknoMojo.Matter.Core.Commissioning;

/// <summary>
/// The commissioning fabric context a caller supplies: our controller's own established
/// identity on the fabric the new device is joining, plus the root CA material needed to sign
/// the device's NOC.
/// </summary>
/// <remarks>
/// <paramref name="ControllerNocTlv"/> and <paramref name="ControllerPrivateKeyPkcs8"/> are our
/// own operational identity on this fabric. They are required because CommissioningComplete has
/// to be sent over CASE rather than PASE, so the commissioner must be able to authenticate as a
/// node once the new device is on the network.
/// </remarks>
public sealed record CommissionerFabricContext(
    ulong FabricId,
    byte[] RootCertificateDer,
    byte[] RootPrivateKeyPkcs8,
    ulong ControllerNodeId,
    byte[] IdentityProtectionKey,
    ushort AdminVendorId,
    byte[] ControllerNocTlv,
    byte[] ControllerPrivateKeyPkcs8);

/// <summary>Result of a successful commissioning run: what the caller needs to persist to talk to the device again later via CASE.</summary>
public sealed record CommissioningResult(ulong DeviceNodeId, byte[] DeviceNocDer, byte[] DevicePublicKeyUncompressed);

/// <summary>
/// M2f: end-to-end commissioner orchestration over an already BTP-handshaked transport — PASE,
/// then the commissioning cluster dance (ArmFailSafe → CSRRequest → issue NOC → install root +
/// NOC → CommissioningComplete), all over the encrypted PASE session itself (CASE is only used
/// for reconnecting afterward, over IP, not during initial commissioning).
/// </summary>
/// <remarks>
/// The flow follows the reference commissioner's stage order: read what the device needs, arm the
/// fail-safe, declare the regulatory regime, set the time if asked, attest the device, issue it
/// credentials, provision the network, then re-arm and complete over CASE.
///
/// Remaining deviations, stated rather than assumed:
/// <list type="bullet">
/// <item>Attestation is verified for signature, issuance and nonce freshness, but only anchors to
/// a certified root when the caller supplies one via <see cref="AttestationTrustStore"/>. The CSA's
/// PAA roots are deliberately not bundled — which roots to trust is the caller's policy.</item>
/// <item>Terms-and-conditions acceptance is relayed, never invented: a device that demands it and
/// is given no <see cref="TermsAcceptance"/> fails rather than having consent fabricated for it.</item>
/// <item>Single in-flight exchange. Chunked reads are reassembled, but batched invokes that span
/// messages are not.</item>
/// </list>
/// </remarks>
public sealed class MatterCommissioner
{
    /// <summary>
    /// Wi-Fi credentials to push to a device that has never joined any network. Omit entirely
    /// (pass null) for a device already on Wi-Fi/Ethernet — the common case for adding a
    /// second controller to an existing accessory.
    /// </summary>
    public sealed record WiFiCredentials(string Ssid, string Passphrase);

    /// <summary>
    /// A Thread network to join, as the operational dataset published by a border router. The
    /// commissioner obtains this from the Thread network; it is not something we can construct.
    /// </summary>
    public sealed record ThreadCredentials(byte[] OperationalDataset);

    /// <summary>
    /// Network credentials for a device that has never joined anything. Exactly one of the two
    /// applies, decided by which radio the device actually has.
    /// </summary>
    public sealed record NetworkCredentials
    {
        public WiFiCredentials? WiFi { get; init; }
        public ThreadCredentials? Thread { get; init; }

        public static NetworkCredentials ForWiFi(string ssid, string passphrase) =>
            new() { WiFi = new WiFiCredentials(ssid, passphrase) };

        public static NetworkCredentials ForThread(byte[] operationalDataset) =>
            new() { Thread = new ThreadCredentials(operationalDataset) };
    }

    /// <summary>
    /// Fail-safe window requested when arming, and again before the network is enabled. Generous
    /// on purpose: the second window has to cover the device joining Wi-Fi, reappearing on the
    /// operational network, and a CASE handshake.
    /// </summary>
    public static ushort FailSafeSeconds { get; set; } = 300;

    /// <summary>Regulatory regime declared to the device; the most restrictive unless told otherwise.</summary>
    public static RegulatoryLocation RegulatoryLocation { get; set; } = RegulatoryLocation.Outdoor;

    /// <summary>ISO 3166-1 alpha-2 country for the regulatory config; "XX" means unknown.</summary>
    public static string RegulatoryCountryCode { get; set; } = "XX";

    /// <summary>
    /// How long any single commissioning exchange may wait for its response. A peer that accepts a
    /// message and never answers it must surface as a named timeout, not as a hang.
    /// </summary>
    public static TimeSpan StepTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Opens a transport to the freshly-commissioned device on the operational network, so
    /// CommissioningComplete can be sent over CASE. Supply one to control how the device is
    /// reached (or to test without a network); omit it to discover the device over mDNS and
    /// connect by UDP.
    /// </summary>
    public delegate Task<IMatterTransport> OperationalTransportFactory(ulong deviceNodeId, CancellationToken ct);

    /// <summary>
    /// Run PASE against <paramref name="transport"/> using the device's 8-digit setup code, then
    /// perform the full commissioning cluster exchange to add the device to
    /// <paramref name="fabric"/>. On success the device holds our fabric's root cert and a NOC
    /// we issued; it is now reachable via CASE at its operational IP.
    /// </summary>
    /// <param name="network">
    /// Provide this for a factory-fresh device that has never joined a network — the credentials
    /// are pushed via the NetworkCommissioning cluster before CommissioningComplete. Leave null
    /// for a device already reachable on the network, such as one being added to a second fabric.
    /// </param>
    public static async Task<CommissioningResult> CommissionAsync(
        IMatterTransport transport,
        string setupCode,
        CommissionerFabricContext fabric,
        ulong newDeviceNodeId,
        NetworkCredentials? network = null,
        OperationalTransportFactory? operationalTransport = null,
        CancellationToken ct = default)
    {
        uint passcode = NormalizeSetupCode(setupCode);

        CommissioningResult result = await RunPasePhaseAsync(
            transport, passcode, fabric, newDeviceNodeId, network, ct);

        // CommissioningComplete SHALL travel over a CASE session established with the operational
        // certificate we just installed — a device rejects it over PASE with InvalidAuthentication.
        // The PASE session is finished with by this point and has been disposed.
        await CompleteOverCaseAsync(fabric, newDeviceNodeId, operationalTransport, ct);
        return result;
    }

    private static async Task<CommissioningResult> RunPasePhaseAsync(
        IMatterTransport transport,
        uint passcode,
        CommissionerFabricContext fabric,
        ulong newDeviceNodeId,
        NetworkCredentials? network,
        CancellationToken ct)
    {
        await using var channel = await RunPaseAsync(transport, passcode, ct);

        var interactionClient = new MatterInteractionClient(channel);

        var generalCommissioning = new GeneralCommissioningCluster(interactionClient);
        var noc = new NodeOperationalCredentialsCluster(interactionClient);

        // Everything up to and including CommissioningComplete has to happen inside this window,
        // and that includes the device joining Wi-Fi and reappearing on the operational network
        // before we can even open the CASE session. 120s leaves too little room for that.
        // Ask the device what it needs before doing anything to it, so the stages that follow are
        // driven by its own answers rather than our assumptions.
        var info = await MatterCommissioningInfo.ReadAsync(interactionClient, ct);

        // Honour the device's own recommended fail-safe when it exceeds ours; some devices ask for
        // a long window precisely because they are slow to join a network.
        ushort failSafe = Math.Max(FailSafeSeconds, info.RecommendedFailSafeSeconds ?? 0);

        var armResult = await generalCommissioning.ArmFailSafeAsync(failSafe, breadcrumb: 1, ct);
        if (armResult != CommissioningError.Ok)
            throw new InvalidOperationException($"ArmFailSafe failed: {armResult}");

        // Regulatory regime before anything touches the radio, bounded by what the device says it
        // can actually do — declaring a location beyond its capability is rejected.
        var location = info.LocationCapability switch
        {
            RegulatoryLocation.Indoor => RegulatoryLocation.Indoor,
            RegulatoryLocation.Outdoor => RegulatoryLocation.Outdoor,
            _ => RegulatoryLocation,
        };
        var regulatoryResult = await generalCommissioning.SetRegulatoryConfigAsync(
            location, RegulatoryCountryCode, breadcrumb: 2, ct);
        if (regulatoryResult != CommissioningError.Ok)
            throw new InvalidOperationException($"SetRegulatoryConfig failed: {regulatoryResult}");

        // Some devices refuse to finish commissioning until told the user accepted their terms.
        // We relay a decision the user made; we never invent one.
        if (info.RequiresTermsAcceptance)
        {
            if (TermsAcceptance is not { } terms)
                throw new InvalidOperationException(
                    "This device requires the user to accept its terms and conditions before it can be commissioned " +
                    $"(minimum version {info.MinimumTermsVersion?.ToString() ?? "unknown"}). Set " +
                    $"{nameof(MatterCommissioner)}.{nameof(TermsAcceptance)} to what the user actually agreed to.");

            ushort version = Math.Max(terms.Version, info.MinimumTermsVersion ?? 0);
            var tcResult = await generalCommissioning.SetTermsAndConditionsAsync(version, terms.UserResponse, ct);
            if (tcResult != CommissioningError.Ok)
                throw new InvalidOperationException($"SetTCAcknowledgements failed: {tcResult}");
        }

        await ConfigureTimeAsync(interactionClient, info, ct);

        // A sleepy device only talks to controllers it knows about. Registering here is what makes
        // us one of them; without it the device may go quiet the moment commissioning ends.
        if (info.IsIntermittentlyConnected)
        {
            byte[] checkInKey = RandomNumberGenerator.GetBytes(16);
            uint icdCounter = await new IcdManagementCluster(interactionClient).RegisterClientAsync(
                checkInNodeId: fabric.ControllerNodeId,
                monitoredSubject: fabric.ControllerNodeId,
                key: checkInKey, ct: ct);

            IcdRegistration = new IcdCheckInRegistration(fabric.ControllerNodeId, checkInKey, icdCounter);
        }

        // Attestation before we issue the device any credentials: establish that it is what it
        // says it is while we still have the option of walking away.
        Attestation = await AttestDeviceAsync(noc, ct);

        byte[] csrNonce = RandomNumberGenerator.GetBytes(32);
        var (devicePublicKey, _, _) = await noc.RequestCsrAsync(csrNonce, ct);

        byte[] deviceNocDer = MatterCertificateBuilder.IssueNocForDeviceCsr(
            fabric.RootCertificateDer, fabric.RootPrivateKeyPkcs8, devicePublicKey, newDeviceNodeId, fabric.FabricId);
        byte[] deviceNocTlv = MatterCertificateTlv.FromDer(deviceNocDer);
        byte[] rootTlv = MatterCertificateTlv.FromDer(fabric.RootCertificateDer);

        await noc.AddTrustedRootCertificateAsync(rootTlv, ct);

        var addResult = await noc.AddNocAsync(
            deviceNocTlv, icacTlv: null, fabric.IdentityProtectionKey,
            caseAdminSubject: fabric.ControllerNodeId, fabric.AdminVendorId, ct);
        if (addResult != NodeOperationalCertStatus.Ok)
            throw new InvalidOperationException($"AddNOC failed: {addResult}");

        if (network is not null)
        {
            var netComm = new NetworkCommissioningCluster(interactionClient);

            // The NetworkID a device connects by is the SSID for Wi-Fi, and the extended PAN ID
            // (the first 8 bytes the border router publishes) for Thread.
            byte[] networkId;
            if (network.WiFi is { } wifiCreds)
            {
                var addNetResult = await netComm.AddOrUpdateWiFiNetworkAsync(wifiCreds.Ssid, wifiCreds.Passphrase, breadcrumb: 3, ct);
                if (addNetResult != NetworkCommissioningStatus.Success)
                    throw new InvalidOperationException($"AddOrUpdateWiFiNetwork failed: {addNetResult}");
                networkId = System.Text.Encoding.UTF8.GetBytes(wifiCreds.Ssid);
            }
            else if (network.Thread is { } threadCreds)
            {
                var addNetResult = await netComm.AddOrUpdateThreadNetworkAsync(threadCreds.OperationalDataset, breadcrumb: 3, ct);
                if (addNetResult != NetworkCommissioningStatus.Success)
                    throw new InvalidOperationException($"AddOrUpdateThreadNetwork failed: {addNetResult}");
                networkId = ExtractThreadExtendedPanId(threadCreds.OperationalDataset);
            }
            else
            {
                throw new ArgumentException("Network credentials must carry either Wi-Fi or Thread details.", nameof(network));
            }

            // Re-arm before enabling the network. Everything still to come — associating with the
            // AP, obtaining an address, re-appearing on the operational network, and the CASE
            // handshake — has to complete before the fail-safe expires, and whatever remains of
            // the original window is not a safe budget for that.
            var rearmResult = await generalCommissioning.ArmFailSafeAsync(failSafe, breadcrumb: 4, ct);
            if (rearmResult != CommissioningError.Ok)
                throw new InvalidOperationException($"ArmFailSafe before network enable failed: {rearmResult}");

            // The device holds this response open until it has actually associated, so allow it
            // the time it said it might need rather than our generic step budget.
            var previousStepTimeout = StepTimeout;
            if (info.NetworkConnectMaxSeconds is { } connectMax)
                StepTimeout = TimeSpan.FromSeconds(Math.Max(previousStepTimeout.TotalSeconds, connectMax + 15));

            NetworkCommissioningStatus connectResult;
            try
            {
                connectResult = await netComm.ConnectNetworkAsync(networkId, breadcrumb: 5, ct);
            }
            finally
            {
                StepTimeout = previousStepTimeout;
            }
            if (connectResult != NetworkCommissioningStatus.Success)
                throw new InvalidOperationException($"ConnectNetwork failed: {connectResult}");
        }

        return new CommissioningResult(newDeviceNodeId, deviceNocDer, devicePublicKey);
    }

    /// <summary>
    /// Give the device the time, but only the parts it actually asked for. A node without a clock
    /// cannot judge certificate validity until an administrator tells it what time it is; a
    /// mains-powered plug with no Time Synchronization cluster needs none of this.
    /// </summary>
    private static async Task ConfigureTimeAsync(
        MatterInteractionClient client, MatterCommissioningInfo info, CancellationToken ct)
    {
        if (!info.RequiresUtcTime && !info.RequiresTimeZone && !info.RequiresDstOffset
            && !info.RequiresDefaultNtp && !info.RequiresTrustedTimeSource)
            return;

        var timeSync = new TimeSynchronizationCluster(client);
        var now = DateTimeOffset.UtcNow;

        if (info.RequiresUtcTime)
            await timeSync.SetUtcTimeAsync(now, ct: ct);

        if (info.RequiresTimeZone)
            await timeSync.SetTimeZoneAsync(TimeZoneInfo.Local.GetUtcOffset(now), ct: ct);

        // An empty DST list is the truthful answer when we have no transition schedule to give.
        if (info.RequiresDstOffset)
            await timeSync.SetDstOffsetAsync(offsets: null, ct);

        if (info.RequiresDefaultNtp && DefaultNtpServer is not null)
            await timeSync.SetDefaultNtpAsync(DefaultNtpServer, ct);

        // Point the device at us for time: we are on its fabric and already know the clock.
        if (info.RequiresTrustedTimeSource && TrustedTimeSourceNodeId is { } timeSourceNode)
            await timeSync.SetTrustedTimeSourceAsync(timeSourceNode, ct: ct);
    }

    /// <summary>NTP server handed to devices that ask for one; null leaves the device's own default alone.</summary>
    public static string? DefaultNtpServer { get; set; }

    /// <summary>Node whose clock a device should follow when it has none of its own; null leaves it unset.</summary>
    public static ulong? TrustedTimeSourceNodeId { get; set; }

    /// <summary>What the user agreed to, for devices that gate commissioning behind their terms.</summary>
    /// <param name="Version">The terms version the user was shown.</param>
    /// <param name="UserResponse">Bitmap of the individual terms the user accepted.</param>
    public sealed record TermsAndConditions(ushort Version, ushort UserResponse);

    /// <summary>
    /// The user's acceptance of a device's terms. Null by default and never defaulted to
    /// "accepted": consent is a human's to give, and a device that demands it will fail loudly
    /// rather than have it fabricated here.
    /// </summary>
    public static TermsAndConditions? TermsAcceptance { get; set; }

    /// <summary>
    /// Pull the Extended PAN ID out of a Thread operational dataset, which is what the device
    /// then uses as the NetworkID to connect by.
    /// </summary>
    /// <remarks>
    /// The dataset is Thread's own type-length-value encoding, not Matter TLV: a flat sequence of
    /// one-byte type, one-byte length, then value. Extended PAN ID is type 2 and always 8 bytes.
    /// </remarks>
    internal static byte[] ExtractThreadExtendedPanId(byte[] operationalDataset)
    {
        const byte ExtendedPanIdType = 2;
        int offset = 0;
        while (offset + 2 <= operationalDataset.Length)
        {
            byte type = operationalDataset[offset];
            byte length = operationalDataset[offset + 1];
            int valueStart = offset + 2;
            if (valueStart + length > operationalDataset.Length) break;

            if (type == ExtendedPanIdType && length == 8)
                return operationalDataset[valueStart..(valueStart + 8)];

            offset = valueStart + length;
        }
        throw new ArgumentException(
            "The Thread operational dataset contains no Extended PAN ID, so there is no NetworkID to connect by.",
            nameof(operationalDataset));
    }

    /// <summary>
    /// Roots that make an attestation chain trustworthy. Empty by default: which Product
    /// Attestation Authorities to accept is a policy decision for the caller, and shipping a
    /// guessed or stale list would be worse than shipping none.
    /// </summary>
    public static MatterAttestationTrustStore? AttestationTrustStore { get; set; }

    /// <summary>
    /// When true, a device whose attestation does not chain to a root in
    /// <see cref="AttestationTrustStore"/> is refused. Off by default, because with no trust store
    /// configured that would reject every device.
    /// </summary>
    public static bool RequireTrustedAttestation { get; set; }

    /// <summary>The attestation gathered during the most recent commissioning, for callers that want to inspect it.</summary>
    public static MatterDeviceAttestation? Attestation { get; private set; }

    /// <summary>
    /// What a controller must keep in order to receive a sleepy device's check-ins.
    /// </summary>
    /// <param name="CheckInKey">
    /// The shared secret the device authenticates its check-ins with. Losing it means losing
    /// contact with the device until it is re-registered, so persist it with the fabric credentials.
    /// </param>
    /// <param name="IcdCounter">The device's check-in counter at registration, used to spot missed check-ins.</param>
    public sealed record IcdCheckInRegistration(ulong CheckInNodeId, byte[] CheckInKey, uint IcdCounter);

    /// <summary>Set when the most recently commissioned device was an intermittently-connected one.</summary>
    public static IcdCheckInRegistration? IcdRegistration { get; private set; }

    /// <summary>
    /// Fetch and check the device's attestation chain. Signature and issuance are always
    /// verified; anchoring to a certified root additionally requires a trust store.
    /// </summary>
    private static async Task<MatterDeviceAttestation> AttestDeviceAsync(
        NodeOperationalCredentialsCluster noc, CancellationToken ct)
    {
        byte[] pai = await noc.GetCertificateChainAsync(CertificateChainType.ProductAttestationIntermediate, ct);
        byte[] dac = await noc.GetCertificateChainAsync(CertificateChainType.DeviceAttestation, ct);

        byte[] nonce = RandomNumberGenerator.GetBytes(32);
        var (elements, signature) = await noc.RequestAttestationAsync(nonce, ct);

        var attestation = MatterAttestationVerifier.Verify(elements, signature, nonce, dac, pai, AttestationTrustStore);

        if (RequireTrustedAttestation && !attestation.ChainsToTrustedRoot)
            throw new MatterAttestationException(
                "The device's attestation did not chain to any trusted Product Attestation Authority.");

        return attestation;
    }

    /// <summary>
    /// Reconnect to the device over the operational network via CASE and send
    /// CommissioningComplete there, which is what actually disarms the fail-safe and makes the
    /// commissioning permanent. Without this the device rolls everything back when the fail-safe
    /// expires.
    /// </summary>
    private static async Task CompleteOverCaseAsync(
        CommissionerFabricContext fabric,
        ulong deviceNodeId,
        OperationalTransportFactory? operationalTransport,
        CancellationToken ct)
    {
        byte[] rootPublicKey = MatterCertificateTlv.ExtractPublicKey(
                MatterCertificateTlv.FromDer(fabric.RootCertificateDer))
            ?? throw new InvalidOperationException("The fabric's root certificate carries no public key.");

        await using IMatterTransport opTransport = operationalTransport is not null
            ? await operationalTransport(deviceNodeId, ct)
            : await DiscoverOperationalTransportAsync(fabric, rootPublicKey, ct);

        var identity = new CaseIdentity(
            fabric.FabricId, rootPublicKey, fabric.IdentityProtectionKey,
            fabric.ControllerNodeId, fabric.ControllerNocTlv, fabric.ControllerPrivateKeyPkcs8);

        await using var caseChannel = await MatterCaseClient.ConnectAsync(opTransport, identity, deviceNodeId, ct);

        var completeResult = await new GeneralCommissioningCluster(new MatterInteractionClient(caseChannel))
            .CommissioningCompleteAsync(ct);
        if (completeResult != CommissioningError.Ok)
            throw new InvalidOperationException($"CommissioningComplete failed: {completeResult}");
    }

    /// <summary>
    /// Find the device on the operational network by its compressed fabric ID. It only starts
    /// advertising operationally once it has joined the network and installed our NOC, so this
    /// polls rather than expecting it to be there immediately.
    /// </summary>
    private static async Task<IMatterTransport> DiscoverOperationalTransportAsync(
        CommissionerFabricContext fabric, byte[] rootPublicKey, CancellationToken ct)
    {
        string wanted = Convert.ToHexString(
            MatterFabric.ComputeCompressedFabricId(fabric.FabricId, rootPublicKey));

        var discovery = new MatterDiscovery();
        var deadline = DateTime.UtcNow + OperationalDiscoveryTimeout;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var nodes = await discovery.DiscoverAsync(
                perTypeTimeout: TimeSpan.FromSeconds(2), includeCommissioning: false, rounds: 2, ct: ct);

            var node = nodes.FirstOrDefault(n =>
                string.Equals(n.CompressedFabricId, wanted, StringComparison.OrdinalIgnoreCase));
            if (node is not null)
                return await MatterUdpTransport.ConnectAsync(new IPEndPoint(node.Address, node.Port), ct: ct);
        }

        throw new TimeoutException(
            $"The device did not appear on the operational network as fabric {wanted} within " +
            $"{OperationalDiscoveryTimeout.TotalSeconds:0}s, so CommissioningComplete could not be sent.");
    }

    /// <summary>How long to wait for the device to show up operationally after it joins the network.</summary>
    public static TimeSpan OperationalDiscoveryTimeout { get; set; } = TimeSpan.FromSeconds(60);

    private static async Task<MatterSecureMessageChannel> RunPaseAsync(IMatterTransport transport, uint passcode, CancellationToken ct)
    {
        ushort initiatorSessionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);

        // Ephemeral identity for the unsecured session: we are not yet a node on any fabric, so
        // the source node ID and exchange ID are random and live only for this exchange. The
        // exchange itself owns message counters and, on transports that need it, MRP.
        var exchange = new MatterUnsecuredExchange(
            transport,
            sourceNodeId: BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8)),
            exchangeId: (ushort)Random.Shared.Next(1, ushort.MaxValue))
        {
            StepTimeout = StepTimeout,
        };

        byte[] initiatorRandom = RandomNumberGenerator.GetBytes(32);

        var pbkdfReq = new MatterPase.PbkdfParamRequest(initiatorRandom, initiatorSessionId, MatterPase.DefaultCommissioningPasscodeId, false);
        byte[] pbkdfReqTlv = MatterPase.EncodePbkdfParamRequest(pbkdfReq);
        await exchange.SendAsync(MatterSecureChannelOpcodes.PbkdfParamRequest, pbkdfReqTlv, ct);

        byte[] pbkdfRespTlv = await exchange.ReceiveAsync(MatterSecureChannelOpcodes.PbkdfParamResponse, "PBKDFParamResponse", ct);
        var pbkdfResp = MatterPase.DecodePbkdfParamResponse(pbkdfRespTlv);

        // Retransmit on the peer's own schedule rather than the spec defaults, now that it has
        // told us how slow it may be to answer.
        exchange.Mrp.ApplyPeerSessionParameters(pbkdfResp.PeerIdleIntervalMs, pbkdfResp.PeerActiveIntervalMs);

        byte[] context = MatterPase.ComputeContext(pbkdfReqTlv, pbkdfRespTlv);
        var (w0, w1) = MatterSpake2Plus.DeriveW0W1(passcode, pbkdfResp.Salt, (int)pbkdfResp.Iterations);

        var (pA, proverState) = MatterSpake2Plus.ProverStart(w0, w1);
        await exchange.SendAsync(MatterSecureChannelOpcodes.Pake1, MatterPase.EncodePake1(pA), ct);

        byte[] pake2Tlv = await exchange.ReceiveAsync(MatterSecureChannelOpcodes.Pake2, "Pake2", ct);
        var (pB, cB) = MatterPase.DecodePake2(pake2Tlv);

        var proverResult = MatterSpake2Plus.ProverFinish(proverState, pB, context);
        if (!CryptographicOperations.FixedTimeEquals(cB, proverResult.CB))
            throw new MatterCommissioningException("PASE: responder confirmation (cB) did not match — wrong setup code?");

        await exchange.SendAsync(MatterSecureChannelOpcodes.Pake3, MatterPase.EncodePake3(proverResult.CA), ct);

        byte[] statusTlv = await exchange.ReceiveAsync(MatterSecureChannelOpcodes.StatusReport, "PASE StatusReport", ct);

        // The unsecured exchange ends here, so the StatusReport has nothing left to piggyback on
        // and needs acknowledging on its own — otherwise the peer keeps retransmitting it into
        // the encrypted session that follows.
        await exchange.FlushAckAsync(ct);
        // Not decoded further: any response to Pake3 that reaches us as StatusReport signals the
        // responder considers pairing complete. A non-success StatusReport terminates PASE with
        // an exception at the transport/protocol layer already (see ReceiveUnsecuredAsync).
        _ = statusTlv;

        var (i2r, r2i, _) = MatterPase.DeriveSessionKeys(proverResult.Ke);
        var session = new MatterSecureSession(
            encrypt: new MatterSecureDirection(i2r, nonceSourceId: 0),
            decrypt: new MatterSecureDirection(r2i, nonceSourceId: 0),
            localSessionId: initiatorSessionId,
            peerSessionId: pbkdfResp.ResponderSessionId);

        var secureChannel = new MatterSecureMessageChannel(transport, session);
        secureChannel.Mrp.ApplyPeerSessionParameters(pbkdfResp.PeerIdleIntervalMs, pbkdfResp.PeerActiveIntervalMs);
        return secureChannel;
    }


    /// <summary>
    /// Accepts either a raw numeric PAKE passcode or the 11-/21-digit Matter Manual Pairing Code
    /// (e.g. "2033-022-0861", as shown when a commissioning window is opened) and returns the
    /// actual passcode to feed into PASE. A manual pairing code is NOT the passcode itself — it's
    /// a bit-packed encoding of the passcode, a short discriminator, and a check digit; see
    /// <see cref="MatterManualPairingCode"/>.
    /// </summary>
    private static uint NormalizeSetupCode(string code)
    {
        string digits = new string(code.Where(char.IsDigit).ToArray());
        return digits.Length switch
        {
            10 or 11 or 20 or 21 => MatterManualPairingCode.Decode(digits).SetupPinCode,
            _ => uint.Parse(digits),
        };
    }
}
