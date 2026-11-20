using System.Security.Cryptography;
using TeknoMojo.Matter.Core.Certificates;
using TeknoMojo.Matter.Core.Crypto;
using TeknoMojo.Matter.Core.Messaging;

namespace TeknoMojo.Matter.Core.Sessions;

/// <summary>
/// What a caller needs to open a CASE session as an already-commissioned controller: its own
/// operational identity on the fabric, plus the fabric's root (to compute the Destination ID
/// and, implicitly, to have already trusted whatever NOC the peer presents — this client
/// verifies the peer's CASE signature but does not re-walk the chain to the root; if you
/// commissioned the peer yourself against this exact root, that's sufficient).
/// </summary>
public sealed record CaseIdentity(
    ulong FabricId,
    byte[] RootPublicKeyUncompressed,
    byte[] IdentityProtectionKey,
    ulong ControllerNodeId,
    byte[] ControllerNocTlv,
    byte[] ControllerPrivateKeyPkcs8);

/// <summary>
/// Opens a CASE (Certificate-Authenticated Session Establishment) session to an operational
/// Matter node, using the SIGMA-I crypto in <see cref="MatterCase"/>. Transport-agnostic — pass
/// whichever <see cref="IMatterTransport"/> already reaches the device (UDP is the common case
/// for Matter's IP transport; a TCP-based one works identically if the device supports it).
/// This is the "reconnect to an already-commissioned device" path —
/// <see cref="Commissioning.MatterCommissioner"/> handles first-time PASE-based commissioning.
/// </summary>
public static class MatterCaseClient
{
    public static async Task<MatterSecureMessageChannel> ConnectAsync(
        IMatterTransport transport, CaseIdentity identity, ulong targetNodeId, CancellationToken ct = default)
    {
        ushort initiatorSessionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        // Session establishment predates any session, so this is an unsecured exchange; over
        // UDP it carries MRP, over BTP it does not.
        var exchange = new MatterUnsecuredExchange(
            transport, identity.ControllerNodeId, (ushort)Random.Shared.Next(1, ushort.MaxValue));
        byte[] initiatorRandom = RandomNumberGenerator.GetBytes(32);
        byte[] destinationId = MatterCase.ComputeDestinationId(
            identity.IdentityProtectionKey, initiatorRandom, identity.RootPublicKeyUncompressed, identity.FabricId, targetNodeId);

        var initiatorEph = MatterCase.GenerateEphemeralKey();
        var sigma1 = new MatterCase.Sigma1(initiatorRandom, initiatorSessionId, destinationId, initiatorEph.PublicKeyUncompressed);
        byte[] sigma1Wire = MatterCase.EncodeSigma1(sigma1);
        await exchange.SendAsync(MatterSecureChannelOpcodes.CaseSigma1, sigma1Wire, ct);

        byte[] sigma2Wire = await exchange.ReceiveAsync(MatterSecureChannelOpcodes.CaseSigma2, "CASE Sigma2", ct);
        var sigma2 = MatterCase.DecodeSigma2(sigma2Wire);

        byte[] z = MatterCase.Ecdh(initiatorEph.PrivateScalar, sigma2.ResponderEphPubKey);
        byte[] th1 = SHA256.HashData(sigma1Wire);
        byte[] s2k = MatterCase.DeriveS2K(identity.IdentityProtectionKey, z, th1);
        byte[] tbe2Plain = MatterCase.DecryptTbe(s2k, "NCASE_Sigma2", sigma2.Encrypted2);
        var parsed2 = MatterCase.ParseTbeData(tbe2Plain);

        byte[]? responderPubKey = MatterCertificateTlv.ExtractPublicKey(parsed2.SenderNocTlv);
        if (responderPubKey is null)
            throw new InvalidOperationException("CASE: could not extract the responder's public key from its NOC.");
        byte[] tbs2 = MatterCase.BuildTbsData(parsed2.SenderNocTlv, parsed2.SenderIcacTlv, sigma2.ResponderEphPubKey, initiatorEph.PublicKeyUncompressed);
        if (!MatterCase.VerifyTbs(responderPubKey, tbs2, parsed2.RawSignature))
            throw new InvalidOperationException("CASE: responder's Sigma2 signature failed to verify.");

        ulong? responderNodeId = MatterCertificateTlv.ExtractSubjectNodeId(parsed2.SenderNocTlv);
        if (responderNodeId != targetNodeId)
            throw new InvalidOperationException($"CASE: connected to node {responderNodeId}, expected {targetNodeId}.");

        byte[] tbs3 = MatterCase.BuildTbsData(identity.ControllerNocTlv, null, initiatorEph.PublicKeyUncompressed, sigma2.ResponderEphPubKey);
        byte[] sig3 = MatterCase.SignTbs(identity.ControllerPrivateKeyPkcs8, tbs3);
        byte[] tbe3Plain = MatterCase.BuildTbeData(identity.ControllerNocTlv, null, sig3);

        byte[] th12 = SHA256.HashData(Concat(sigma1Wire, sigma2Wire));
        byte[] s3k = MatterCase.DeriveS3K(identity.IdentityProtectionKey, z, th12);
        byte[] enc3 = MatterCase.EncryptTbe(s3k, "NCASE_Sigma3", tbe3Plain);
        var sigma3 = new MatterCase.Sigma3(enc3);
        byte[] sigma3Wire = MatterCase.EncodeSigma3(sigma3);
        await exchange.SendAsync(MatterSecureChannelOpcodes.CaseSigma3, sigma3Wire, ct);

        // A well-behaved responder confirms with a StatusReport (success); read and discard it.
        await exchange.ReceiveAsync(MatterSecureChannelOpcodes.StatusReport, "CASE StatusReport", ct);
        // The exchange ends on the peer's message, so acknowledge it explicitly.
        await exchange.FlushAckAsync(ct);

        byte[] th123 = SHA256.HashData(Concat(sigma1Wire, sigma2Wire, sigma3Wire));
        var (i2r, r2i, _) = MatterCase.DeriveSessionKeys(identity.IdentityProtectionKey, z, th123);

        var session = new MatterSecureSession(
            encrypt: new MatterSecureDirection(i2r, nonceSourceId: 0),
            decrypt: new MatterSecureDirection(r2i, nonceSourceId: 0),
            localSessionId: initiatorSessionId,
            peerSessionId: sigma2.ResponderSessionId);

        return new MatterSecureMessageChannel(transport, session);
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
