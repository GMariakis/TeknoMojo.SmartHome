using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Math;
using TeknoMojo.Matter.Core.Crypto;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Crypto;

/// <summary>
/// SPAKE2+ conformance and round-trip tests. Wall-clock proof that the crypto is symmetric
/// (prover and verifier derive identical Ke / cA / cB from the same shared passcode), and
/// asymmetric (a wrong passcode diverges).
/// </summary>
public class MatterSpake2PlusTests
{
    // Matter test setup passcode from Spec §3.9 (all examples use it).
    private const uint TestPasscode = 20202021;
    private static readonly byte[] TestSalt = Encoding.UTF8.GetBytes("SPAKE2P Key Salt");
    private const int TestIterations = 1000;

    [Fact]
    public void DeriveW0W1_IsDeterministic_AndFits32Bytes()
    {
        var (w0a, w1a) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);
        var (w0b, w1b) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);

        Assert.Equal(32, w0a.Length);
        Assert.Equal(32, w1a.Length);
        Assert.Equal(w0a, w0b);
        Assert.Equal(w1a, w1b);

        // Different passcodes -> different derived scalars.
        var (w0c, w1c) = MatterSpake2Plus.DeriveW0W1(99999999, TestSalt, TestIterations);
        Assert.NotEqual(w0a, w0c);
        Assert.NotEqual(w1a, w1c);
    }

    [Fact]
    public void ComputeL_IsUncompressedP256Point()
    {
        var (_, w1) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);
        byte[] L = MatterSpake2Plus.ComputeL(w1);

        Assert.Equal(MatterSpake2Plus.PointSize, L.Length); // 65 bytes uncompressed
        Assert.Equal(0x04, L[0]);                            // uncompressed prefix
    }

    [Fact]
    public void ProverVerifierRoundTrip_ProducesSharedKeyAndMatchingConfirmations()
    {
        var (w0, w1) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);
        byte[] L = MatterSpake2Plus.ComputeL(w1);
        byte[] context = SHA256.HashData(Encoding.UTF8.GetBytes("CHIP PAKE V1 Commissioning-test-context"));

        // Prover step 1
        var (pA, proverState) = MatterSpake2Plus.ProverStart(w0, w1);

        // Verifier response
        var (pB, verifierResult) = MatterSpake2Plus.VerifierRespond(w0, L, pA, context);

        // Prover step 2
        var proverResult = MatterSpake2Plus.ProverFinish(proverState, pB, context);

        Assert.Equal(verifierResult.Ke, proverResult.Ke);
        Assert.Equal(MatterSpake2Plus.SharedKeySize, proverResult.Ke.Length);

        // The two sides swap roles for confirmation. cA is what the prover sends to the
        // verifier (as Pake3), cB is what the verifier sends to the prover (in Pake2).
        Assert.Equal(verifierResult.CA, proverResult.CA);
        Assert.Equal(verifierResult.CB, proverResult.CB);
    }

    [Fact]
    public void WrongPasscode_ProducesDifferentKe_AndConfirmationsDoNotMatch()
    {
        var (w0Right, w1Right) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);
        var (w0Wrong, w1Wrong) = MatterSpake2Plus.DeriveW0W1(11111111, TestSalt, TestIterations);
        byte[] LRight = MatterSpake2Plus.ComputeL(w1Right);
        byte[] context = SHA256.HashData(Encoding.UTF8.GetBytes("ctx"));

        // Prover uses the wrong passcode; verifier stores the correct verifier.
        var (pA, proverState) = MatterSpake2Plus.ProverStart(w0Wrong, w1Wrong);
        var (pB, verifierResult) = MatterSpake2Plus.VerifierRespond(w0Right, LRight, pA, context);
        var proverResult = MatterSpake2Plus.ProverFinish(proverState, pB, context);

        // Ke will diverge, and both confirmations will disagree — the security guarantee.
        Assert.NotEqual(verifierResult.Ke, proverResult.Ke);
        Assert.NotEqual(verifierResult.CA, proverResult.CA);
        Assert.NotEqual(verifierResult.CB, proverResult.CB);
    }

    [Fact]
    public void FixedRandomness_IsReproducible()
    {
        // With caller-supplied x and y the whole handshake is deterministic — no randomness left.
        var (w0, w1) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);
        byte[] L = MatterSpake2Plus.ComputeL(w1);
        byte[] context = SHA256.HashData(Encoding.UTF8.GetBytes("fixed-context"));

        BigInteger x = new(1, Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        BigInteger y = new(1, Enumerable.Range(33, 32).Select(i => (byte)i).ToArray());

        var (pA1, state1) = MatterSpake2Plus.ProverStart(w0, w1, x);
        var (pB1, vr1) = MatterSpake2Plus.VerifierRespond(w0, L, pA1, context, y);
        var pr1 = MatterSpake2Plus.ProverFinish(state1, pB1, context);

        // Run it again — same inputs → identical outputs.
        var (pA2, state2) = MatterSpake2Plus.ProverStart(w0, w1, x);
        var (pB2, vr2) = MatterSpake2Plus.VerifierRespond(w0, L, pA2, context, y);
        var pr2 = MatterSpake2Plus.ProverFinish(state2, pB2, context);

        Assert.Equal(pA1, pA2);
        Assert.Equal(pB1, pB2);
        Assert.Equal(pr1.Ke, pr2.Ke);
        Assert.Equal(vr1.CA, vr2.CA);
        Assert.Equal(vr1.CB, vr2.CB);
    }

    [Fact]
    public void ContextIsBoundIntoTheKey()
    {
        // Two runs with the same passcode but different context strings must diverge.
        var (w0, w1) = MatterSpake2Plus.DeriveW0W1(TestPasscode, TestSalt, TestIterations);
        byte[] L = MatterSpake2Plus.ComputeL(w1);
        BigInteger x = new(1, Enumerable.Repeat((byte)7, 32).ToArray());
        BigInteger y = new(1, Enumerable.Repeat((byte)9, 32).ToArray());

        byte[] ctxA = SHA256.HashData(Encoding.UTF8.GetBytes("session-A"));
        byte[] ctxB = SHA256.HashData(Encoding.UTF8.GetBytes("session-B"));

        var (pA, state) = MatterSpake2Plus.ProverStart(w0, w1, x);
        var (pB, _) = MatterSpake2Plus.VerifierRespond(w0, L, pA, ctxA, y);
        var withA = MatterSpake2Plus.ProverFinish(state, pB, ctxA);
        var withB = MatterSpake2Plus.ProverFinish(state, pB, ctxB);

        // Same pA/pB and passcode — but different transcript context → different Ke and tags.
        Assert.NotEqual(withA.Ke, withB.Ke);
        Assert.NotEqual(withA.CA, withB.CA);
        Assert.NotEqual(withA.CB, withB.CB);
    }
}
