using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace TeknoMojo.Matter.Core.Crypto;

/// <summary>
/// SPAKE2+ on NIST P-256 per RFC 9383, using the Matter setup-code binding described in the
/// Matter Core Specification §3.9–3.10. This is a Password-Authenticated Key Exchange: two
/// parties who share knowledge of an 8-digit setup code (plus salt/iterations known to both)
/// end up with a mutual shared secret and mutual confirmation values, without ever exposing
/// the passcode to observers or offline-guessing attackers.
/// </summary>
/// <remarks>
/// Matter uses SPAKE2+ as the "PASE" (Password-Authenticated Session Establishment) primitive
/// during commissioning. The commissioner is the SPAKE2+ <b>prover</b> (knows the passcode);
/// the commissionee is the <b>verifier</b> (stores derived <c>w0</c> and <c>L</c>).
///
/// This class provides:
///  - <see cref="DeriveW0W1"/> — PBKDF2 from (passcode, salt, iterations) → (w0, w1).
///  - <see cref="ComputeL"/> — verifier stored point L = w1·P (helper for tests and completeness).
///  - <see cref="ProverStart"/> — random ephemeral x → pA on the wire.
///  - <see cref="ProverFinish"/> — given pB and the transcript context, derive Ke + cA/cB.
///  - <see cref="VerifierRespond"/> — given pA, produce pB and derive the same Ke + cA/cB.
///    Exposed so callers can also build accessory-side SPAKE2+ (and to make tests self-contained).
///
/// Zero validation of ownership of P-256 point-on-curve / not-identity is skipped here — the
/// point decoders throw on invalid points, and successful key confirmation on both sides is
/// the mutual-authentication check.
/// </remarks>
public static class MatterSpake2Plus
{
    // NIST P-256 domain parameters.
    private static readonly X9ECParameters P256 = ECNamedCurveTable.GetByName("P-256");
    private static readonly ECDomainParameters Domain = new(P256.Curve, P256.G, P256.N, P256.H, P256.GetSeed());
    private static readonly ECCurve Curve = P256.Curve;
    private static readonly BigInteger N = P256.N;
    private static readonly ECPoint G = P256.G;

    // SPAKE2+ M and N constants for P-256 (RFC 9383 §4). Nothing-up-my-sleeve points chosen so
    // that their discrete logs w.r.t. the generator are unknown. Compressed form; the curve
    // decoder decompresses.
    private static readonly ECPoint M = DecodePoint(new byte[]
    {
        0x02, 0x88, 0x6E, 0x2F, 0x97, 0xAC, 0xE4, 0x6E, 0x55, 0xBA, 0x9D, 0xD7, 0x24, 0x25, 0x79,
        0xF2, 0x99, 0x3B, 0x64, 0xE1, 0x6E, 0xF3, 0xDC, 0xAB, 0x95, 0xAF, 0xD4, 0x97, 0x33, 0x3D,
        0x8F, 0xA1, 0x2F,
    });
    private static readonly ECPoint NPoint = DecodePoint(new byte[]
    {
        0x03, 0xD8, 0xBB, 0xD6, 0xC6, 0x39, 0xC6, 0x29, 0x37, 0xB0, 0x4D, 0x99, 0x7F, 0x38, 0xC3,
        0x77, 0x07, 0x19, 0xC6, 0x29, 0xD7, 0x01, 0x4D, 0x49, 0xA2, 0x4B, 0x4F, 0x98, 0xBA, 0xA1,
        0x29, 0x2B, 0x49,
    });

    /// <summary>Uncompressed encoding of a P-256 point: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes.</summary>
    public const int PointSize = 65;

    /// <summary>Number of bytes in the shared key <c>Ke</c> (half of SHA-256).</summary>
    public const int SharedKeySize = 16;

    /// <summary>Number of bytes in each confirmation tag (HMAC-SHA-256 output).</summary>
    public const int ConfirmationSize = 32;

    // ---------------------------------------------------------------- passcode → w0, w1

    /// <summary>
    /// Matter §3.9 Crypto_PBKDF: derive (w0, w1) from a numeric setup passcode plus salt and
    /// iteration count negotiated in the PBKDFParamRequest/Response exchange. The passcode is
    /// serialised as a 4-byte little-endian unsigned integer per spec, so leading zeros are
    /// preserved automatically (e.g. code "00012345" and code "12345" produce the same output).
    /// </summary>
    /// <param name="passcode">The numeric setup code, e.g. 20202021 for the spec test code "20202021".</param>
    /// <param name="salt">PBKDF salt (16–32 bytes) from PBKDFParamResponse.</param>
    /// <param name="iterations">PBKDF iteration count from PBKDFParamResponse (Matter minimum 1000, max 100000).</param>
    public static (byte[] w0, byte[] w1) DeriveW0W1(uint passcode, byte[] salt, int iterations)
    {
        // Passcode is a 4-byte little-endian input per Matter spec §3.9.
        Span<byte> pin = stackalloc byte[4];
        BitConverter.TryWriteBytes(pin, passcode);

        // Derive 80 raw bytes; first 40 → w0s, next 40 → w1s. Each reduced mod n gives w0/w1.
        byte[] pinArr = pin.ToArray();
        byte[] out80 = Rfc2898DeriveBytes.Pbkdf2(pinArr, salt, iterations, HashAlgorithmName.SHA256, 80);

        byte[] w0s = out80.AsSpan(0, 40).ToArray();
        byte[] w1s = out80.AsSpan(40, 40).ToArray();

        // Reduce mod n and re-emit as 32-byte big-endian scalars.
        byte[] w0 = ScalarToBytes(new BigInteger(1, w0s).Mod(N));
        byte[] w1 = ScalarToBytes(new BigInteger(1, w1s).Mod(N));
        return (w0, w1);
    }

    /// <summary>
    /// Compute the accessory's stored verifier point L = w1·P. The Matter commissionee stores
    /// this at manufacture time (encoded alongside w0 as the "SPAKE2+ verifier"), so it never
    /// has to know w1 — only L. Provided for callers building the verifier side.
    /// </summary>
    public static byte[] ComputeL(byte[] w1)
    {
        var l = G.Multiply(new BigInteger(1, w1)).Normalize();
        return l.GetEncoded(compressed: false);
    }

    // ---------------------------------------------------------------- prover

    /// <summary>State the prover keeps between its two messages.</summary>
    public sealed class ProverState
    {
        internal BigInteger X { get; init; } = null!;
        internal byte[] W0 { get; init; } = null!;
        internal byte[] W1 { get; init; } = null!;
        internal byte[] PA { get; init; } = null!;
    }

    /// <summary>
    /// Prover step 1: given (w0, w1) derived from the setup code, generate a random ephemeral
    /// scalar x, compute pA = x·P + w0·M, and return both the on-wire pA and the state to feed
    /// back into <see cref="ProverFinish"/>. Overload accepts a caller-supplied <c>x</c> for
    /// deterministic testing.
    /// </summary>
    public static (byte[] pA, ProverState state) ProverStart(byte[] w0, byte[] w1)
        => ProverStart(w0, w1, RandomScalar());

    /// <summary>Prover step 1 with a caller-provided <paramref name="x"/> (for tests).</summary>
    public static (byte[] pA, ProverState state) ProverStart(byte[] w0, byte[] w1, BigInteger x)
    {
        BigInteger w0Int = new(1, w0);
        // pA = x·P + w0·M
        ECPoint pA = G.Multiply(x).Add(M.Multiply(w0Int)).Normalize();
        byte[] pAEnc = pA.GetEncoded(compressed: false);
        return (pAEnc, new ProverState { X = x, W0 = w0, W1 = w1, PA = pAEnc });
    }

    /// <summary>
    /// Prover step 2: given the verifier's pB and the transcript context (typically
    /// SHA-256("CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse) —
    /// see Matter §3.10.3), derive shared key Ke and confirmation tags cA/cB.
    /// Verify that <paramref name="cBFromVerifier"/> equals the returned <c>cB</c> and send
    /// the returned <c>cA</c> to the verifier as Pake3.
    /// </summary>
    public static Spake2PlusResult ProverFinish(ProverState state, byte[] pB, byte[] context)
    {
        BigInteger w0 = new(1, state.W0);
        BigInteger w1 = new(1, state.W1);
        ECPoint pBPoint = DecodePoint(pB);

        // Y' = pB - w0·N
        ECPoint yPrime = pBPoint.Subtract(NPoint.Multiply(w0)).Normalize();
        // Z = h · x · (pB - w0·N)   (h = 1 for P-256)
        ECPoint z = yPrime.Multiply(state.X).Normalize();
        // V = h · w1 · (pB - w0·N)
        ECPoint v = yPrime.Multiply(w1).Normalize();

        return DeriveKeys(context, state.PA, pB, z.GetEncoded(false), v.GetEncoded(false), state.W0);
    }

    // ---------------------------------------------------------------- verifier

    /// <summary>State the verifier keeps between its two messages.</summary>
    public sealed class VerifierState
    {
        internal BigInteger Y { get; init; } = null!;
        internal byte[] W0 { get; init; } = null!;
        internal byte[] L { get; init; } = null!;
        internal byte[] PB { get; init; } = null!;
    }

    /// <summary>
    /// Verifier response: given the prover's pA plus stored (w0, L), pick random y, compute
    /// pB = y·P + w0·N, and derive the same Ke and confirmation tags as the prover will.
    /// Send pB and cB to the prover; keep cA to compare against Pake3.
    /// </summary>
    public static (byte[] pB, Spake2PlusResult result) VerifierRespond(byte[] w0, byte[] l, byte[] pA, byte[] context)
        => VerifierRespond(w0, l, pA, context, RandomScalar());

    /// <summary>Verifier response with caller-provided <paramref name="y"/> (for tests).</summary>
    public static (byte[] pB, Spake2PlusResult result) VerifierRespond(byte[] w0, byte[] l, byte[] pA, byte[] context, BigInteger y)
    {
        BigInteger w0Int = new(1, w0);
        ECPoint lPoint = DecodePoint(l);
        ECPoint pAPoint = DecodePoint(pA);

        // pB = y·P + w0·N
        ECPoint pB = G.Multiply(y).Add(NPoint.Multiply(w0Int)).Normalize();

        // Z = h · y · (pA - w0·M)
        ECPoint xPrime = pAPoint.Subtract(M.Multiply(w0Int)).Normalize();
        ECPoint z = xPrime.Multiply(y).Normalize();
        // V = h · y · L
        ECPoint v = lPoint.Multiply(y).Normalize();

        byte[] pBEnc = pB.GetEncoded(false);
        var result = DeriveKeys(context, pA, pBEnc, z.GetEncoded(false), v.GetEncoded(false), w0);
        return (pBEnc, result);
    }

    // ---------------------------------------------------------------- KDF / transcript

    /// <summary>
    /// Result of a SPAKE2+ session: the shared session key <see cref="Ke"/> and the two mutual
    /// confirmation tags. The prover sends <see cref="CA"/> and expects <see cref="CB"/>; the
    /// verifier does the reverse.
    /// </summary>
    public sealed record Spake2PlusResult(byte[] Ke, byte[] CA, byte[] CB);

    private static Spake2PlusResult DeriveKeys(byte[] context, byte[] pA, byte[] pB, byte[] z, byte[] v, byte[] w0)
    {
        byte[] tt = BuildTranscript(context, pA, pB, z, v, w0);

        // Matter §3.10.5.4: K_main = SHA-256(TT). Halves are Ka (first 16) and Ke (second 16).
        byte[] kMain = SHA256.HashData(tt);
        byte[] Ka = kMain.AsSpan(0, 16).ToArray();
        byte[] Ke = kMain.AsSpan(16, 16).ToArray();

        // HKDF-SHA-256 with salt=nil, info="ConfirmationKeys" gives 32 bytes = KcA (16) || KcB (16).
        byte[] confKeys = HKDF.DeriveKey(HashAlgorithmName.SHA256, Ka, 32, salt: null,
            info: Encoding.UTF8.GetBytes("ConfirmationKeys"));
        byte[] KcA = confKeys.AsSpan(0, 16).ToArray();
        byte[] KcB = confKeys.AsSpan(16, 16).ToArray();

        byte[] cA = HMACSHA256.HashData(KcA, pB);
        byte[] cB = HMACSHA256.HashData(KcB, pA);

        return new Spake2PlusResult(Ke, cA, cB);
    }

    /// <summary>
    /// SPAKE2+ transcript per RFC 9383 §3.3 / Matter §3.10.3: each of the seven inputs
    /// (context, idProver="", idVerifier="", M, N, pA, pB, Z, V, w0) is prefixed with its
    /// 8-byte little-endian length. Matter uses empty prover/verifier identity strings, so
    /// those slots emit only an 8-byte zero length. Fully-encoded M and N are the uncompressed
    /// point bytes; w0 is 32-byte big-endian.
    /// </summary>
    private static byte[] BuildTranscript(byte[] context, byte[] pA, byte[] pB, byte[] z, byte[] v, byte[] w0)
    {
        using var ms = new MemoryStream(256);
        WriteLv(ms, context);
        WriteLv(ms, Array.Empty<byte>());   // idProver A (empty in Matter)
        WriteLv(ms, Array.Empty<byte>());   // idVerifier B (empty in Matter)
        WriteLv(ms, M.GetEncoded(false));
        WriteLv(ms, NPoint.GetEncoded(false));
        WriteLv(ms, pA);
        WriteLv(ms, pB);
        WriteLv(ms, z);
        WriteLv(ms, v);
        WriteLv(ms, w0);
        return ms.ToArray();
    }

    private static void WriteLv(MemoryStream ms, byte[] value)
    {
        Span<byte> lenLe = stackalloc byte[8];
        BitConverter.TryWriteBytes(lenLe, (ulong)value.Length);
        ms.Write(lenLe);
        ms.Write(value);
    }

    // ---------------------------------------------------------------- helpers

    private static ECPoint DecodePoint(byte[] encoded) => Curve.DecodePoint(encoded).Normalize();

    private static BigInteger RandomScalar()
    {
        // Uniform in [1, n-1]; identical to how BC's ECKeyPairGenerator does it.
        int bytes = (N.BitLength + 7) / 8;
        byte[] buf = new byte[bytes];
        while (true)
        {
            RandomNumberGenerator.Fill(buf);
            var candidate = new BigInteger(1, buf);
            if (candidate.CompareTo(BigInteger.One) >= 0 && candidate.CompareTo(N) < 0)
                return candidate;
        }
    }

    private static byte[] ScalarToBytes(BigInteger v)
    {
        // Emit as 32-byte big-endian, left-padded with zeros.
        byte[] raw = v.ToByteArrayUnsigned();
        if (raw.Length == 32) return raw;
        if (raw.Length > 32) throw new InvalidOperationException("scalar larger than P-256 order");
        var padded = new byte[32];
        Buffer.BlockCopy(raw, 0, padded, 32 - raw.Length, raw.Length);
        return padded;
    }
}
