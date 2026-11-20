using System.Security.Cryptography;
using System.Text;
using TeknoMojo.Matter.Core.Tlv;

namespace TeknoMojo.Matter.Core.Crypto;

/// <summary>
/// PASE (Password-Authenticated Session Establishment) message flow: PBKDFParamRequest/Response
/// followed by the SPAKE2+ Pake1/Pake2/Pake3 exchange (Matter Core Spec §4.14, Secure Channel
/// protocol). Wraps the pure <see cref="MatterSpake2Plus"/> crypto with the actual TLV message
/// shapes and the commissioning "context" hash construction.
/// </summary>
/// <remarks>
/// Tag numbers and the context construction are verified against the Apache-2.0 reference
/// implementation (project-chip/connectedhomeip, src/protocols/secure_channel/PASESession.cpp),
/// not reconstructed from the prose spec.
/// </remarks>
public static class MatterPase
{
    /// <summary>Fixed ASCII string that seeds the commissioning transcript hash (verified against PASESession.cpp).</summary>
    private const string CommissioningContextSeed = "CHIP PAKE V1 Commissioning";

    /// <summary>The passcode id used for ordinary (non-resumption) commissioning PASE (verified: always 0).</summary>
    public const ushort DefaultCommissioningPasscodeId = 0;

    // ---------------------------------------------------------------- PBKDFParamRequest/Response

    public sealed record PbkdfParamRequest(byte[] InitiatorRandom, ushort InitiatorSessionId, ushort PasscodeId, bool HasPbkdfParameters);

    public static byte[] EncodePbkdfParamRequest(PbkdfParamRequest req)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), req.InitiatorRandom);
        w.WriteUnsignedInt(MatterTag.Context(2), req.InitiatorSessionId);
        w.WriteUnsignedInt(MatterTag.Context(3), req.PasscodeId);
        w.WriteBool(MatterTag.Context(4), req.HasPbkdfParameters);
        WriteSessionParameters(w, MatterTag.Context(5));
        w.EndContainer();
        return w.ToArray();
    }

    /// <summary>
    /// SessionParameters (Spec §4.12.8). Nominally optional, but a shipping accessory captured
    /// over the air was seen to BTP-ack a PBKDFParamRequest that omitted it and then never
    /// answer, so we always send it. Values mirror what a shipping commissioner advertises.
    /// </summary>
    private static void WriteSessionParameters(MatterTlvWriter w, MatterTag tag)
    {
        w.StartStructure(tag);
        w.WriteUnsignedInt(MatterTag.Context(1), 2000);  // SESSION_IDLE_INTERVAL (ms)
        w.WriteUnsignedInt(MatterTag.Context(2), 2000);  // SESSION_ACTIVE_INTERVAL (ms)
        w.WriteUnsignedInt(MatterTag.Context(3), 2000);  // SESSION_ACTIVE_THRESHOLD (ms)
        w.WriteUnsignedInt(MatterTag.Context(4), 19);    // DATA_MODEL_REVISION
        w.WriteUnsignedInt(MatterTag.Context(5), 12);    // INTERACTION_MODEL_REVISION
        w.WriteUnsignedInt(MatterTag.Context(6), 0x01050000); // SPECIFICATION_VERSION (1.5)
        w.WriteUnsignedInt(MatterTag.Context(7), 1);     // MAX_PATHS_PER_INVOKE
        w.EndContainer();
    }

    public static PbkdfParamRequest DecodePbkdfParamRequest(byte[] tlv)
    {
        byte[]? random = null; ushort sessionId = 0, passcodeId = 0; bool hasParams = false;
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("PBKDFParamRequest: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            switch (r.Tag.TagNumber)
            {
                case 1: random = r.GetByteString(); break;
                case 2: sessionId = (ushort)r.GetUnsignedInt(); break;
                case 3: passcodeId = (ushort)r.GetUnsignedInt(); break;
                case 4: hasParams = r.GetBool(); break;
                // Unknown fields must be skipped whole. A container skipped element-by-element
                // would leak its children into this loop and be misread as top-level fields —
                // e.g. SessionParameters (tag 5), whose children reuse context tags 1..7.
                default: SkipIfContainer(ref r); break;
            }
        }
        if (random is null) throw new FormatException("PBKDFParamRequest: missing InitiatorRandom");
        return new PbkdfParamRequest(random, sessionId, passcodeId, hasParams);
    }

    /// <param name="PeerIdleIntervalMs">
    /// The responder's SESSION_IDLE_INTERVAL from its SessionParameters, or 0 when it did not say.
    /// Feeds MRP's retransmission schedule, so the peer's own timing governs how long we wait.
    /// </param>
    /// <param name="PeerActiveIntervalMs">The responder's SESSION_ACTIVE_INTERVAL, or 0 when absent.</param>
    public sealed record PbkdfParamResponse(
        byte[] InitiatorRandom, byte[] ResponderRandom, ushort ResponderSessionId, uint Iterations, byte[] Salt,
        uint PeerIdleIntervalMs = 0, uint PeerActiveIntervalMs = 0);

    public static byte[] EncodePbkdfParamResponse(PbkdfParamResponse resp)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), resp.InitiatorRandom);
        w.WriteByteString(MatterTag.Context(2), resp.ResponderRandom);
        w.WriteUnsignedInt(MatterTag.Context(3), resp.ResponderSessionId);
        w.StartStructure(MatterTag.Context(4));
        w.WriteUnsignedInt(MatterTag.Context(1), resp.Iterations);
        w.WriteByteString(MatterTag.Context(2), resp.Salt);
        w.EndContainer();
        w.EndContainer();
        return w.ToArray();
    }

    public static PbkdfParamResponse DecodePbkdfParamResponse(byte[] tlv)
    {
        byte[]? initRandom = null, respRandom = null, salt = null;
        ushort respSessionId = 0;
        uint iterations = 0, idleIntervalMs = 0, activeIntervalMs = 0;
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("PBKDFParamResponse: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific)
            {
                if (r.ElementType == MatterTlvElementType.Structure) r.ExitContainer();
                continue;
            }
            switch (r.Tag.TagNumber)
            {
                case 1: initRandom = r.GetByteString(); break;
                case 2: respRandom = r.GetByteString(); break;
                case 3: respSessionId = (ushort)r.GetUnsignedInt(); break;
                case 4:
                    r.EnterContainer();
                    while (r.Read())
                    {
                        if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
                        if (r.Tag.TagNumber == 1) iterations = (uint)r.GetUnsignedInt();
                        else if (r.Tag.TagNumber == 2) salt = r.GetByteString();
                    }
                    break;
                case 5: // SessionParameters
                    r.EnterContainer();
                    while (r.Read())
                    {
                        if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
                        if (r.Tag.TagNumber == 1) idleIntervalMs = (uint)r.GetUnsignedInt();
                        else if (r.Tag.TagNumber == 2) activeIntervalMs = (uint)r.GetUnsignedInt();
                        else if (r.ElementType is MatterTlvElementType.Structure
                                 or MatterTlvElementType.Array or MatterTlvElementType.List) r.ExitContainer();
                    }
                    break;
                default:
                    if (r.ElementType is MatterTlvElementType.Structure
                        or MatterTlvElementType.Array or MatterTlvElementType.List) r.ExitContainer();
                    break;
            }
        }
        if (initRandom is null || respRandom is null || salt is null)
            throw new FormatException("PBKDFParamResponse: missing required field");
        return new PbkdfParamResponse(
            initRandom, respRandom, respSessionId, iterations, salt, idleIntervalMs, activeIntervalMs);
    }

    /// <summary>
    /// Commissioning transcript context: SHA-256("CHIP PAKE V1 Commissioning" || raw
    /// PBKDFParamRequest TLV bytes || raw PBKDFParamResponse TLV bytes). Plain concatenation,
    /// not length-prefixed — verified against PASESession.cpp's running SHA-256 usage.
    /// </summary>
    public static byte[] ComputeContext(byte[] pbkdfParamRequestTlv, byte[] pbkdfParamResponseTlv)
    {
        using var sha = SHA256.Create();
        byte[] seed = Encoding.ASCII.GetBytes(CommissioningContextSeed);
        sha.TransformBlock(seed, 0, seed.Length, null, 0);
        sha.TransformBlock(pbkdfParamRequestTlv, 0, pbkdfParamRequestTlv.Length, null, 0);
        sha.TransformFinalBlock(pbkdfParamResponseTlv, 0, pbkdfParamResponseTlv.Length);
        return sha.Hash!;
    }

    // ---------------------------------------------------------------- session keys

    /// <summary>
    /// Derive the final PASE session keys from the SPAKE2+ shared key Ke: HKDF-SHA-256 with an
    /// EMPTY salt (unlike CASE, which salts with IPK||transcript — there is no fabric/IPK yet
    /// during initial commissioning) and info "SessionKeys", producing I2RKey(16) || R2IKey(16)
    /// || AttestationChallenge(16). Verified against project-chip/connectedhomeip
    /// src/transport/CryptoContext.cpp (SEKeysInfo = "SessionKeys", salt = empty for PASE).
    /// </summary>
    public static (byte[] I2R, byte[] R2I, byte[] AttestationChallenge) DeriveSessionKeys(byte[] ke)
    {
        byte[] material = HKDF.DeriveKey(HashAlgorithmName.SHA256, ke, 48, salt: null, info: Encoding.UTF8.GetBytes("SessionKeys"));
        return (material.AsSpan(0, 16).ToArray(), material.AsSpan(16, 16).ToArray(), material.AsSpan(32, 16).ToArray());
    }

    // ---------------------------------------------------------------- Pake1/2/3

    public static byte[] EncodePake1(byte[] pA)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), pA);
        w.EndContainer();
        return w.ToArray();
    }

    public static byte[] DecodePake1(byte[] tlv) => DecodeSingleByteString(tlv, "Pake1", expectedTag: 1);

    public static byte[] EncodePake2(byte[] pB, byte[] cB)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), pB);
        w.WriteByteString(MatterTag.Context(2), cB);
        w.EndContainer();
        return w.ToArray();
    }

    public static (byte[] pB, byte[] cB) DecodePake2(byte[] tlv)
    {
        byte[]? pB = null, cB = null;
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException("Pake2: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control != MatterTlvTagControl.ContextSpecific) continue;
            if (r.Tag.TagNumber == 1) pB = r.GetByteString();
            else if (r.Tag.TagNumber == 2) cB = r.GetByteString();
        }
        if (pB is null || cB is null) throw new FormatException("Pake2: missing pB/cB");
        return (pB, cB);
    }

    public static byte[] EncodePake3(byte[] cA)
    {
        var w = new MatterTlvWriter();
        w.StartStructure(MatterTag.Anonymous);
        w.WriteByteString(MatterTag.Context(1), cA);
        w.EndContainer();
        return w.ToArray();
    }

    public static byte[] DecodePake3(byte[] tlv) => DecodeSingleByteString(tlv, "Pake3", expectedTag: 1);

    private static byte[] DecodeSingleByteString(byte[] tlv, string label, byte expectedTag)
    {
        var r = new MatterTlvReader(tlv);
        if (!r.Read() || r.ElementType != MatterTlvElementType.Structure) throw new FormatException($"{label}: missing structure");
        r.EnterContainer();
        while (r.Read())
        {
            if (r.Tag.Control == MatterTlvTagControl.ContextSpecific && r.Tag.TagNumber == expectedTag)
                return r.GetByteString();
        }
        throw new FormatException($"{label}: missing tag {expectedTag}");
    }

    private static void SkipIfContainer(ref MatterTlvReader r)
    {
        if (r.ElementType is MatterTlvElementType.Structure or MatterTlvElementType.Array or MatterTlvElementType.List)
            r.ExitContainer();
    }
}
