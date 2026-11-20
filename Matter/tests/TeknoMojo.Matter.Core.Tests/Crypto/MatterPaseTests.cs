using System.Security.Cryptography;
using System.Text;
using TeknoMojo.Matter.Core.Crypto;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Crypto;

public class MatterPaseTests
{
    [Fact]
    public void PbkdfParamRequest_RoundTrips()
    {
        var req = new MatterPase.PbkdfParamRequest(RandomNumberGenerator.GetBytes(32), 1234, MatterPase.DefaultCommissioningPasscodeId, false);
        var decoded = MatterPase.DecodePbkdfParamRequest(MatterPase.EncodePbkdfParamRequest(req));
        Assert.Equal(req.InitiatorRandom, decoded.InitiatorRandom);
        Assert.Equal(req.InitiatorSessionId, decoded.InitiatorSessionId);
        Assert.Equal(req.PasscodeId, decoded.PasscodeId);
        Assert.Equal(req.HasPbkdfParameters, decoded.HasPbkdfParameters);
    }

    [Fact]
    public void PbkdfParamResponse_RoundTrips()
    {
        var resp = new MatterPase.PbkdfParamResponse(
            RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), 5678, 1000, RandomNumberGenerator.GetBytes(16));
        var decoded = MatterPase.DecodePbkdfParamResponse(MatterPase.EncodePbkdfParamResponse(resp));
        Assert.Equal(resp.InitiatorRandom, decoded.InitiatorRandom);
        Assert.Equal(resp.ResponderRandom, decoded.ResponderRandom);
        Assert.Equal(resp.ResponderSessionId, decoded.ResponderSessionId);
        Assert.Equal(resp.Iterations, decoded.Iterations);
        Assert.Equal(resp.Salt, decoded.Salt);
    }

    [Fact]
    public void Pake1_2_3_RoundTrip()
    {
        byte[] pA = RandomNumberGenerator.GetBytes(65);
        Assert.Equal(pA, MatterPase.DecodePake1(MatterPase.EncodePake1(pA)));

        byte[] pB = RandomNumberGenerator.GetBytes(65);
        byte[] cB = RandomNumberGenerator.GetBytes(32);
        var (decPb, decCb) = MatterPase.DecodePake2(MatterPase.EncodePake2(pB, cB));
        Assert.Equal(pB, decPb);
        Assert.Equal(cB, decCb);

        byte[] cA = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(cA, MatterPase.DecodePake3(MatterPase.EncodePake3(cA)));
    }

    [Fact]
    public void ComputeContext_IsPlainConcatenation_NotLengthPrefixed()
    {
        byte[] req = Encoding.UTF8.GetBytes("REQ");
        byte[] resp = Encoding.UTF8.GetBytes("RESP");
        byte[] ctx = MatterPase.ComputeContext(req, resp);

        byte[] expected = SHA256.HashData(Encoding.ASCII.GetBytes("CHIP PAKE V1 Commissioning").Concat(req).Concat(resp).ToArray());
        Assert.Equal(expected, ctx);
    }

    /// <summary>
    /// Full PASE flow end-to-end: PBKDFParamRequest/Response negotiate salt+iterations, both
    /// sides compute the same commissioning context, and the SPAKE2+ crypto (already unit-tested
    /// in isolation) plugs in cleanly to produce matching Ke and confirmation tags.
    /// </summary>
    [Fact]
    public void EndToEnd_PaseFlow_DerivesMatchingKeys()
    {
        uint passcode = 20202021;

        // --- PBKDFParamRequest (initiator) ---
        byte[] initiatorRandom = RandomNumberGenerator.GetBytes(32);
        var pbkdfReq = new MatterPase.PbkdfParamRequest(initiatorRandom, 1000, MatterPase.DefaultCommissioningPasscodeId, false);
        byte[] pbkdfReqTlv = MatterPase.EncodePbkdfParamRequest(pbkdfReq);

        // --- PBKDFParamResponse (responder chooses salt/iterations) ---
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        uint iterations = 1000;
        byte[] responderRandom = RandomNumberGenerator.GetBytes(32);
        var pbkdfResp = new MatterPase.PbkdfParamResponse(initiatorRandom, responderRandom, 2000, iterations, salt);
        byte[] pbkdfRespTlv = MatterPase.EncodePbkdfParamResponse(pbkdfResp);

        // Both sides compute the same context from the two raw TLV payloads.
        byte[] contextInitiator = MatterPase.ComputeContext(pbkdfReqTlv, pbkdfRespTlv);
        byte[] contextResponder = MatterPase.ComputeContext(pbkdfReqTlv, pbkdfRespTlv);
        Assert.Equal(contextInitiator, contextResponder);

        // --- SPAKE2+ using the negotiated salt/iterations ---
        var (w0, w1) = MatterSpake2Plus.DeriveW0W1(passcode, salt, (int)iterations);
        byte[] verifierL = MatterSpake2Plus.ComputeL(w1);

        var (pA, proverState) = MatterSpake2Plus.ProverStart(w0, w1);
        byte[] pake1 = MatterPase.EncodePake1(pA);
        byte[] pADecoded = MatterPase.DecodePake1(pake1);

        var (pB, verifierResult) = MatterSpake2Plus.VerifierRespond(w0, verifierL, pADecoded, contextResponder);
        byte[] pake2 = MatterPase.EncodePake2(pB, verifierResult.CB);
        var (pBDecoded, cBDecoded) = MatterPase.DecodePake2(pake2);

        var proverResult = MatterSpake2Plus.ProverFinish(proverState, pBDecoded, contextInitiator);
        Assert.Equal(cBDecoded, proverResult.CB); // prover independently derives the same cB the verifier sent

        byte[] pake3 = MatterPase.EncodePake3(proverResult.CA);
        byte[] cADecoded = MatterPase.DecodePake3(pake3);
        Assert.Equal(verifierResult.CA, cADecoded); // verifier's expectation matches what prover sent

        Assert.Equal(verifierResult.Ke, proverResult.Ke);
    }
}
