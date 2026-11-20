using System.Security.Cryptography;
using System.Threading.Channels;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using TeknoMojo.Matter.Core;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Clusters;
using TeknoMojo.Matter.Core.Commissioning;
using TeknoMojo.Matter.Core.Crypto;
using TeknoMojo.Matter.Core.InteractionModel;
using TeknoMojo.Matter.Core.Messaging;
using TeknoMojo.Matter.Core.Tlv;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Commissioning;

/// <summary>
/// End-to-end M2f test: a fake in-process "device" (PASE verifier + a minimal Interaction Model
/// server for the commissioning clusters) on one side of a loopback transport, and the real
/// <see cref="MatterCommissioner"/> on the other. If this passes, PASE, the IM codec, the
/// AES-CCM session, and the certificate issuance all interoperate correctly end to end — this
/// is the same style of test that caught the ref-struct aliasing bug in the IM codec earlier.
/// </summary>
public class MatterCommissionerTests
{
    private const string SetupCode = "20202021";

    [Fact]
    public async Task EndToEnd_Commissioning_Succeeds()
    {
        var (initiatorTransport, responderTransport) = LoopbackTransport.CreatePair();

        var fabricRoot = MatterCertificateBuilder.CreateRootCA(rootCaId: 1);
        var controllerNoc = MatterCertificateBuilder.IssueNoc(fabricRoot.CertificateDer, fabricRoot.PrivateKeyPkcs8, nodeId: 1, fabricId: 42);
        var fabric = new CommissionerFabricContext(
            FabricId: 42,
            RootCertificateDer: fabricRoot.CertificateDer,
            RootPrivateKeyPkcs8: fabricRoot.PrivateKeyPkcs8,
            ControllerNodeId: 1,
            IdentityProtectionKey: RandomNumberGenerator.GetBytes(16),
            AdminVendorId: 4933,
            ControllerNocTlv: MatterCertificateTlv.FromDer(controllerNoc.CertificateDer),
            ControllerPrivateKeyPkcs8: controllerNoc.PrivateKeyPkcs8);

        // CommissioningComplete is sent over CASE on the operational network, which a loopback
        // fake has no way to stand up. Assert that the PASE phase runs to completion and then
        // hands off to the operational reconnect with the right node id.
        var reachedCase = new TaskCompletionSource<ulong>();
        MatterCommissioner.OperationalTransportFactory operational = (nodeId, _) =>
        {
            reachedCase.TrySetResult(nodeId);
            throw new OperationalReconnectReached();
        };

        var deviceTask = Task.Run(() => new FakeMatterDevice(responderTransport).RunAsync(SetupCode));
        var commissionTask = MatterCommissioner.CommissionAsync(
            initiatorTransport, SetupCode, fabric, newDeviceNodeId: 100, operationalTransport: operational);

        await Assert.ThrowsAsync<OperationalReconnectReached>(() => commissionTask);
        Assert.Equal(100ul, await reachedCase.Task.WaitAsync(TimeSpan.FromSeconds(5)));

        var device = await deviceTask.WaitAsync(TimeSpan.FromSeconds(5));

        // The device accepted every PASE-phase command, and the NOC it was issued chains to our
        // root with the right node and fabric ids.
        byte[] nocTlv = device.InstalledNocTlv;
        Assert.Equal(100ul, MatterCertificateTlv.ExtractSubjectNodeId(nocTlv));
        Assert.Equal(42ul, MatterCertificateTlv.ExtractSubjectFabricId(nocTlv));
    }

    private sealed class OperationalReconnectReached : Exception;

    [Fact]
    public async Task WrongSetupCode_FailsPaseCleanly()
    {
        var (initiatorTransport, responderTransport) = LoopbackTransport.CreatePair();
        var fabricRoot = MatterCertificateBuilder.CreateRootCA(1);
        var controllerNoc = MatterCertificateBuilder.IssueNoc(fabricRoot.CertificateDer, fabricRoot.PrivateKeyPkcs8, nodeId: 1, fabricId: 42);
        var fabric = new CommissionerFabricContext(
            42, fabricRoot.CertificateDer, fabricRoot.PrivateKeyPkcs8, 1, RandomNumberGenerator.GetBytes(16), 4933,
            MatterCertificateTlv.FromDer(controllerNoc.CertificateDer), controllerNoc.PrivateKeyPkcs8);

        // The device stays blocked waiting for Pake3, which the initiator correctly never sends
        // once it detects the confirmation mismatch — real protocol behavior would follow up with
        // a PakeError, which isn't implemented yet. Disposing the transport after the assertion
        // unblocks the device's pending read so the background task doesn't leak past the test.
        var deviceTask = Task.Run(() => new FakeMatterDevice(responderTransport).RunAsync(SetupCode));

        var commissionTask = MatterCommissioner.CommissionAsync(initiatorTransport, "11111111", fabric, 100);
        await Assert.ThrowsAsync<MatterCommissioningException>(() => commissionTask);

        await initiatorTransport.DisposeAsync();
        await responderTransport.DisposeAsync();
        try { await deviceTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { /* expected: closed channel */ }
    }
}

/// <summary>In-memory duplex <see cref="IMatterTransport"/> pair, standing in for BLE/BTP in tests.</summary>
internal sealed class LoopbackTransport : IMatterTransport
{
    private readonly Channel<byte[]> _outbound;
    private readonly Channel<byte[]> _inbound;

    private LoopbackTransport(Channel<byte[]> outbound, Channel<byte[]> inbound)
    {
        _outbound = outbound;
        _inbound = inbound;
    }

    public static (LoopbackTransport a, LoopbackTransport b) CreatePair()
    {
        var ab = Channel.CreateUnbounded<byte[]>();
        var ba = Channel.CreateUnbounded<byte[]>();
        return (new LoopbackTransport(ab, ba), new LoopbackTransport(ba, ab));
    }

    public async Task SendMessageAsync(ReadOnlyMemory<byte> message, CancellationToken ct = default)
        => await _outbound.Writer.WriteAsync(message.ToArray(), ct);

    public async Task<byte[]> ReceiveMessageAsync(CancellationToken ct = default)
        => await _inbound.Reader.ReadAsync(ct);

    public ValueTask DisposeAsync()
    {
        _outbound.Writer.TryComplete();
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// A minimal fake Matter device: PASE verifier + just enough of an Interaction Model server to
/// answer the commissioning cluster calls our commissioner makes. Not a real device — no
/// attestation, no persistence — purely to give the real commissioner code something correct to
/// talk to for an in-process test.
/// </summary>
internal sealed class FakeMatterDevice
{
    private readonly IMatterTransport _transport;
    private readonly FakeAttestationChain _attestation = new();

    public FakeMatterDevice(IMatterTransport transport) => _transport = transport;

    public async Task<FakeDeviceResult> RunAsync(string setupCode)
    {
        uint passcode = uint.Parse(setupCode);
        var session = await RunPaseVerifierAsync(passcode);
        await using var channel = new MatterSecureMessageChannel(_transport, session);
        await RunCommissioningServerAsync(channel);
        return new FakeDeviceResult(_installedNocTlv);
    }

    internal sealed record FakeDeviceResult(byte[] InstalledNocTlv);

    private async Task<MatterSecureSession> RunPaseVerifierAsync(uint passcode)
    {
        byte[] pbkdfReqTlv = await ReceiveRawAsync();
        var (reqHeader, reqPayload) = DecodeUnsecured(pbkdfReqTlv);
        Assert.Equal(MatterSecureChannelOpcodes.PbkdfParamRequest, reqHeader.Opcode);
        var req = MatterPase.DecodePbkdfParamRequest(reqPayload);

        byte[] salt = RandomNumberGenerator.GetBytes(16);
        uint iterations = 1000;
        byte[] responderRandom = RandomNumberGenerator.GetBytes(32);
        ushort responderSessionId = 2000;
        var resp = new MatterPase.PbkdfParamResponse(req.InitiatorRandom, responderRandom, responderSessionId, iterations, salt);
        byte[] pbkdfRespTlv = MatterPase.EncodePbkdfParamResponse(resp);
        await SendUnsecuredAsync(MatterSecureChannelOpcodes.PbkdfParamResponse, pbkdfRespTlv);

        byte[] context = MatterPase.ComputeContext(pbkdfReqTlv.AsSpan(ExtractPayloadOffset(pbkdfReqTlv)).ToArray(), pbkdfRespTlv);
        // Recompute context using the exact same raw TLV bytes the initiator hashed (payload only).
        context = MatterPase.ComputeContext(reqPayload, pbkdfRespTlv);

        var (w0, w1) = MatterSpake2Plus.DeriveW0W1(passcode, salt, (int)iterations);
        byte[] verifierL = MatterSpake2Plus.ComputeL(w1);

        byte[] pake1Tlv = await ReceiveRawAsync();
        var (_, pake1Payload) = DecodeUnsecured(pake1Tlv);
        byte[] pA = MatterPase.DecodePake1(pake1Payload);

        var (pB, verifierResult) = MatterSpake2Plus.VerifierRespond(w0, verifierL, pA, context);
        await SendUnsecuredAsync(MatterSecureChannelOpcodes.Pake2, MatterPase.EncodePake2(pB, verifierResult.CB));

        byte[] pake3Tlv = await ReceiveRawAsync();
        var (_, pake3Payload) = DecodeUnsecured(pake3Tlv);
        byte[] cA = MatterPase.DecodePake3(pake3Payload);
        Assert.Equal(verifierResult.CA, cA); // fail loudly here, not silently, if the setup code was wrong

        await SendUnsecuredAsync(MatterSecureChannelOpcodes.StatusReport, Array.Empty<byte>());

        var (i2r, r2i, _) = MatterPase.DeriveSessionKeys(verifierResult.Ke);
        // Responder perspective: encrypts with R2I, decrypts with I2R (mirror of the initiator).
        return new MatterSecureSession(
            encrypt: new MatterSecureDirection(r2i, nonceSourceId: 0),
            decrypt: new MatterSecureDirection(i2r, nonceSourceId: 0),
            localSessionId: responderSessionId,
            peerSessionId: req.InitiatorSessionId);
    }

    private async Task RunCommissioningServerAsync(MatterSecureMessageChannel channel)
    {
        // ReadCommissioningInfo: answer with a plausible mains-powered plug — it has the General
        // Commissioning attributes, and nothing else the commissioner asked about.
        var (h0, _) = await channel.ReceiveAsync();
        await RespondCommissioningInfoAsync(channel, h0.ExchangeId);

        // ArmFailSafe
        var (h1, p1) = await channel.ReceiveAsync();
        var invoke1 = DecodeSingleInvoke(p1);
        Assert.Equal(ClusterIds.GeneralCommissioning, invoke1.Path.Cluster);
        Assert.Equal(GeneralCommissioningCommands.ArmFailSafe, invoke1.Path.Command);
        await RespondCommandDataAsync(channel, h1.ExchangeId, invoke1.Path,
            fields: w => { w.WriteUnsignedInt(MatterTag.Context(0), 0); w.WriteUtf8String(MatterTag.Context(1), ""); });

        // SetRegulatoryConfig
        var (hr, pr) = await channel.ReceiveAsync();
        var invokeReg = DecodeSingleInvoke(pr);
        Assert.Equal(ClusterIds.GeneralCommissioning, invokeReg.Path.Cluster);
        Assert.Equal(GeneralCommissioningCommands.SetRegulatoryConfig, invokeReg.Path.Command);
        await RespondCommandDataAsync(channel, hr.ExchangeId, invokeReg.Path,
            fields: w => { w.WriteUnsignedInt(MatterTag.Context(0), 0); w.WriteUtf8String(MatterTag.Context(1), ""); });

        // Attestation: PAI, then DAC, then a signature over the elements and our nonce.
        var (hPai, pPai) = await channel.ReceiveAsync();
        var invokePai = DecodeSingleInvoke(pPai);
        Assert.Equal(NocCommands.CertificateChainRequest, invokePai.Path.Command);
        await RespondCommandDataAsync(channel, hPai.ExchangeId, invokePai.Path,
            fields: w => w.WriteByteString(MatterTag.Context(0), _attestation.PaiDer));

        var (hDac, pDac) = await channel.ReceiveAsync();
        var invokeDac = DecodeSingleInvoke(pDac);
        Assert.Equal(NocCommands.CertificateChainRequest, invokeDac.Path.Command);
        await RespondCommandDataAsync(channel, hDac.ExchangeId, invokeDac.Path,
            fields: w => w.WriteByteString(MatterTag.Context(0), _attestation.DacDer));

        var (hAtt, pAtt) = await channel.ReceiveAsync();
        var invokeAtt = DecodeSingleInvoke(pAtt);
        Assert.Equal(NocCommands.AttestationRequest, invokeAtt.Path.Command);
        byte[] attNonce = ExtractCsrNonce(invokeAtt.FieldsTlv);   // same shape: a byte string at tag 0
        var (attElements, attSignature) = _attestation.Sign(attNonce);
        await RespondCommandDataAsync(channel, hAtt.ExchangeId, invokeAtt.Path, fields: w =>
        {
            w.WriteByteString(MatterTag.Context(0), attElements);
            w.WriteByteString(MatterTag.Context(1), attSignature);
        });

        // CSRRequest
        var (h2, p2) = await channel.ReceiveAsync();
        var invoke2 = DecodeSingleInvoke(p2);
        Assert.Equal(NocCommands.CSRRequest, invoke2.Path.Command);
        byte[] csrNonce = ExtractCsrNonce(invoke2.FieldsTlv);

        var (deviceKeyPair, _, _) = GenerateP256();
        byte[] csrDer = BuildSelfSignedCsr(deviceKeyPair);
        var nocsrWriter = new MatterTlvWriter();
        nocsrWriter.StartStructure(MatterTag.Anonymous);
        nocsrWriter.WriteByteString(MatterTag.Context(1), csrDer);
        nocsrWriter.WriteByteString(MatterTag.Context(2), csrNonce);
        nocsrWriter.EndContainer();
        byte[] nocsrElements = nocsrWriter.ToArray();

        await RespondCommandDataAsync(channel, h2.ExchangeId, invoke2.Path, fields: w =>
        {
            w.WriteByteString(MatterTag.Context(0), nocsrElements);
            w.WriteByteString(MatterTag.Context(1), new byte[64]); // fake attestation signature; not verified by the commissioner under test
        });

        // AddTrustedRootCertificate (no declared response payload -> we reply Status:Success)
        var (h3, p3) = await channel.ReceiveAsync();
        var invoke3 = DecodeSingleInvoke(p3);
        Assert.Equal(NocCommands.AddTrustedRootCertificate, invoke3.Path.Command);
        await RespondStatusAsync(channel, h3.ExchangeId, invoke3.Path, MatterStatus.Success);

        // AddNOC
        var (h4, p4) = await channel.ReceiveAsync();
        var invoke4 = DecodeSingleInvoke(p4);
        Assert.Equal(NocCommands.AddNOC, invoke4.Path.Command);
        _installedNocTlv = ReadFirstByteString(invoke4.FieldsTlv);
        await RespondCommandDataAsync(channel, h4.ExchangeId, invoke4.Path, fields: w =>
        {
            w.WriteUnsignedInt(MatterTag.Context(0), (byte)NodeOperationalCertStatus.Ok);
        });

        // No CommissioningComplete here: it is sent over CASE on the operational network, which
        // this loopback fake deliberately does not stand up.
    }

    /// <summary>The NOC the commissioner installed, so the test can verify what was issued.</summary>
    private byte[] _installedNocTlv = [];

    private static byte[] ReadFirstByteString(byte[] structureTlv)
    {
        var r = new MatterTlvReader(structureTlv);
        r.Read();
        r.EnterContainer();
        r.Read();
        return r.GetByteString();
    }

    // -------- helpers --------

    private async Task<byte[]> ReceiveRawAsync() => await _transport.ReceiveMessageAsync();

    private async Task SendUnsecuredAsync(byte opcode, byte[] payload)
    {
        var protoHeader = new MatterProtocolHeader
        {
            ExchangeFlags = MatterExchangeFlags.None,
            Opcode = opcode,
            ExchangeId = 0,
            ProtocolId = MatterProtocolIds.SecureChannel,
        };
        byte[] protoBytes = MatterProtocolHeaderCodec.Encode(protoHeader, payload);
        var msgHeader = new MatterMessageHeader { SessionId = 0, SecurityFlags = MatterSecurityFlags.SessionTypeUnicast, MessageCounter = 1 };
        byte[] headerBytes = MatterMessageCodec.EncodeHeader(msgHeader);
        byte[] frame = new byte[headerBytes.Length + protoBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, frame, 0, headerBytes.Length);
        Buffer.BlockCopy(protoBytes, 0, frame, headerBytes.Length, protoBytes.Length);
        await _transport.SendMessageAsync(frame);
    }

    private static (MatterProtocolHeader Header, byte[] Payload) DecodeUnsecured(byte[] frame)
    {
        MatterMessageCodec.DecodeHeader(frame, out int consumed);
        byte[] plaintext = frame.AsSpan(consumed).ToArray();
        var (header, offset) = MatterProtocolHeaderCodec.Decode(plaintext);
        return (header, plaintext.AsSpan(offset).ToArray());
    }

    private static int ExtractPayloadOffset(byte[] frame)
    {
        MatterMessageCodec.DecodeHeader(frame, out int consumed);
        var (_, offset) = MatterProtocolHeaderCodec.Decode(frame.AsSpan(consumed).ToArray());
        return consumed + offset;
    }

    private static (CommandPath Path, byte[] FieldsTlv) DecodeSingleInvoke(byte[] invokeRequestTlv)
    {
        var r = new MatterTlvReader(invokeRequestTlv);
        r.Read(); // Structure
        r.EnterContainer();
        CommandPath? path = null;
        byte[]? fields = null;
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) { if (IsContainer(r)) r.ExitContainer(); continue; }
            if (r.Tag.TagNumber == 2) // InvokeRequests array
            {
                r.EnterContainer();
                r.Read(); // one CommandDataIB
                r.EnterContainer();
                while (r.Read())
                {
                    if (r.Tag.TagNumber == 0) // Path
                    {
                        r.EnterContainer();
                        uint ep = 0, cl = 0, cmd = 0;
                        while (r.Read())
                        {
                            if (r.Tag.TagNumber == 0) ep = (uint)r.GetUnsignedInt();
                            else if (r.Tag.TagNumber == 1) cl = (uint)r.GetUnsignedInt();
                            else if (r.Tag.TagNumber == 2) cmd = (uint)r.GetUnsignedInt();
                        }
                        path = new CommandPath(ep, cl, cmd);
                    }
                    else if (r.Tag.TagNumber == 1) // Fields
                    {
                        fields = CaptureStructure(ref r);
                    }
                }
            }
            else if (IsContainer(r)) r.ExitContainer();
        }
        return (path ?? new CommandPath(0, 0, 0), fields ?? Array.Empty<byte>());
    }

    private static byte[] ExtractCsrNonce(byte[] fieldsTlv)
    {
        var r = new MatterTlvReader(fieldsTlv);
        r.Read();
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == 0)
                return r.GetByteString();
        }
        throw new FormatException("CSRRequest fields: missing CSRNonce");
    }

    private static byte[] CaptureStructure(ref MatterTlvReader r)
    {
        // r is positioned at a Structure; re-encode its raw bytes so the caller can decode it standalone.
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        r.EnterContainer();
        while (r.Read())
        {
            CopySimple(ref r, w);
        }
        w.EndContainer();
        return w.ToArray();
    }

    private static void CopySimple(ref MatterTlvReader r, MatterTlvWriter w)
    {
        switch (r.ElementType)
        {
            case MatterTlvElementType.UnsignedInt1 or MatterTlvElementType.UnsignedInt2 or MatterTlvElementType.UnsignedInt4 or MatterTlvElementType.UnsignedInt8:
                w.WriteUnsignedInt(r.Tag, r.GetUnsignedInt()); break;
            case MatterTlvElementType.ByteString1 or MatterTlvElementType.ByteString2 or MatterTlvElementType.ByteString4 or MatterTlvElementType.ByteString8:
                w.WriteByteString(r.Tag, r.GetByteStringSpan()); break;
            case MatterTlvElementType.BooleanTrue or MatterTlvElementType.BooleanFalse:
                w.WriteBool(r.Tag, r.GetBool()); break;
            default:
                if (IsContainer(r)) r.ExitContainer();
                break;
        }
    }

    private static bool IsContainer(MatterTlvReader r) =>
        r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List;

    /// <summary>
    /// A ReportData carrying the General Commissioning attributes a commissioner reads up front,
    /// and an UnsupportedCluster status for the Time Synchronization paths — the honest answer
    /// from a device that has no clock, and the case the commissioner must tolerate.
    /// </summary>
    private async Task RespondCommissioningInfoAsync(MatterSecureMessageChannel channel, ushort exchangeId)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.StartArray(MatterTag.Context(1));                     // AttributeReportIBs

        WriteAttributeData(w, ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.BasicCommissioningInfo, v =>
        {
            v.StartStructure(MatterTag.Context(2));
            v.WriteUnsignedInt(MatterTag.Context(0), 60);       // recommended fail-safe
            v.WriteUnsignedInt(MatterTag.Context(1), 900);      // max cumulative
            v.EndContainer();
        });
        WriteAttributeData(w, ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.LocationCapability,
            v => v.WriteUnsignedInt(MatterTag.Context(2), (byte)RegulatoryLocation.IndoorOutdoor));
        WriteAttributeData(w, ClusterIds.GeneralCommissioning, CommissioningInfoAttributes.SupportsConcurrentConnection,
            v => v.WriteBool(MatterTag.Context(2), true));
        WriteAttributeData(w, ClusterIds.NetworkCommissioning, CommissioningInfoAttributes.ConnectMaxTimeSeconds,
            v => v.WriteUnsignedInt(MatterTag.Context(2), 30));

        foreach (uint attribute in new[]
                 {
                     CommissioningInfoAttributes.UtcTime, CommissioningInfoAttributes.TimeZoneListMaxSize,
                     CommissioningInfoAttributes.DstOffsetListMaxSize, CommissioningInfoAttributes.DefaultNtp,
                 })
        {
            WriteAttributeStatus(w, ClusterIds.TimeSynchronization, attribute, MatterStatus.UnsupportedCluster);
        }

        w.EndContainer();                                       // AttributeReportIBs
        w.WriteUnsignedInt(MatterTag.Context(InteractionModelRevision.Tag), InteractionModelRevision.Revision);
        w.EndContainer();

        await channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.ReportData,
            exchangeId, w.ToArray(), isInitiator: false);
    }

    private static void WriteAttributeData(MatterTlvWriter w, uint cluster, uint attribute, Action<MatterTlvWriter> writeValue)
    {
        w.StartStructure(MatterTag.Anonymous);                  // AttributeReportIB
        w.StartStructure(MatterTag.Context(1));                 // AttributeDataIB
        w.WriteUnsignedInt(MatterTag.Context(0), 1);            // DataVersion
        WritePath(w, MatterTag.Context(1), cluster, attribute);
        writeValue(w);                                          // the value, at tag 2
        w.EndContainer();
        w.EndContainer();
    }

    private static void WriteAttributeStatus(MatterTlvWriter w, uint cluster, uint attribute, MatterStatus status)
    {
        w.StartStructure(MatterTag.Anonymous);                  // AttributeReportIB
        w.StartStructure(MatterTag.Context(0));                 // AttributeStatusIB
        WritePath(w, MatterTag.Context(0), cluster, attribute);
        w.StartStructure(MatterTag.Context(1));                 // StatusIB
        w.WriteUnsignedInt(MatterTag.Context(0), (byte)status);
        w.EndContainer();
        w.EndContainer();
        w.EndContainer();
    }

    private static void WritePath(MatterTlvWriter w, MatterTag tag, uint cluster, uint attribute)
    {
        w.StartList(tag);                                       // AttributePathIB is a List
        w.WriteUnsignedInt(MatterTag.Context(2), 0);            // Endpoint
        w.WriteUnsignedInt(MatterTag.Context(3), cluster);
        w.WriteUnsignedInt(MatterTag.Context(4), attribute);
        w.EndContainer();
    }

    private async Task RespondCommandDataAsync(MatterSecureMessageChannel channel, ushort exchangeId, CommandPath path, Action<MatterTlvWriter> fields)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteBool(MatterTag.Context(0), false);
        w.StartArray(MatterTag.Context(1));
        w.StartStructure(MatterTag.Anonymous);
        w.StartStructure(MatterTag.Context(0)); // Command (CommandDataIB)
        w.StartStructure(MatterTag.Context(0)); // Path
        w.WriteUnsignedInt(MatterTag.Context(0), path.Endpoint);
        w.WriteUnsignedInt(MatterTag.Context(1), path.Cluster);
        w.WriteUnsignedInt(MatterTag.Context(2), path.Command);
        w.EndContainer();
        w.StartStructure(MatterTag.Context(1)); // Fields
        fields(w);
        w.EndContainer();
        w.EndContainer(); // CommandDataIB
        w.EndContainer(); // InvokeResponseIB
        w.EndContainer(); // array
        w.EndContainer(); // top
        await channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.InvokeCommandResponse, exchangeId, w.ToArray(), isInitiator: false);
    }

    private async Task RespondStatusAsync(MatterSecureMessageChannel channel, ushort exchangeId, CommandPath path, MatterStatus status)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteBool(MatterTag.Context(0), false);
        w.StartArray(MatterTag.Context(1));
        w.StartStructure(MatterTag.Anonymous);
        w.StartStructure(MatterTag.Context(1)); // Status (CommandStatusIB)
        w.StartStructure(MatterTag.Context(0)); // Path
        w.WriteUnsignedInt(MatterTag.Context(0), path.Endpoint);
        w.WriteUnsignedInt(MatterTag.Context(1), path.Cluster);
        w.WriteUnsignedInt(MatterTag.Context(2), path.Command);
        w.EndContainer();
        w.StartStructure(MatterTag.Context(1)); // ErrorStatus
        w.WriteUnsignedInt(MatterTag.Context(0), (byte)status);
        w.EndContainer();
        w.EndContainer(); // CommandStatusIB
        w.EndContainer(); // InvokeResponseIB
        w.EndContainer(); // array
        w.EndContainer(); // top
        await channel.SendAsync(MatterProtocolIds.InteractionModel, InteractionModelOpcodes.InvokeCommandResponse, exchangeId, w.ToArray(), isInitiator: false);
    }

    private static (AsymmetricCipherKeyPair keyPair, byte[] pkcs8, byte[] pubUncompressed) GenerateP256()
    {
        var curve = NistNamedCurves.GetByName("P-256");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var gen = new ECKeyPairGenerator("ECDSA");
        gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        byte[] pkcs8 = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private).GetDerEncoded();
        byte[] pub = ((ECPublicKeyParameters)kp.Public).Q.GetEncoded(false);
        return (kp, pkcs8, pub);
    }

    private static byte[] BuildSelfSignedCsr(AsymmetricCipherKeyPair keyPair)
    {
        var subject = new X509Name("CN=Matter Device");
        var signer = new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private);
        var csr = new Pkcs10CertificationRequest(signer, subject, keyPair.Public, null);
        return csr.GetEncoded();
    }
}
