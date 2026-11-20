using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Agreement.Srp;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using TeknoMojo.HomeKit.Core;
using TeknoMojo.HomeKit.Hap.Http;
using TeknoMojo.HomeKit.Hap.Tlv;
using BCEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace TeknoMojo.HomeKit.Hap.Pairing;

/// <summary>
/// HAP pair-setup: SRP-6a (3072-bit, SHA-512) auth using the accessory's 8-digit setup code,
/// followed by a mutual Ed25519 long-term-key exchange under a HKDF-derived session key
/// (HAP §5.6). On success returns the persistable <see cref="HapPairing"/>.
/// </summary>
public static class PairSetup
{
    // ASCII content types HAP uses on the wire.
    private const string TlvContentType = "application/pairing+tlv8";

    /// <summary>
    /// Pair with <paramref name="accessory"/> using the 8-digit code printed on the device
    /// label (with or without the dash, e.g. "031-45-154" or "03145154"). This does one full
    /// pair-setup exchange over a fresh TCP connection.
    /// </summary>
    public static async Task<HapPairing> RunAsync(
        HapAccessory accessory,
        string setupCode,
        string? controllerIdOverride = null,
        CancellationToken ct = default)
    {
        if (accessory is null) throw new ArgumentNullException(nameof(accessory));
        if (accessory.Port <= 0) throw new ArgumentException("HapAccessory.Port not resolved from mDNS.", nameof(accessory));
        string code = NormalizeSetupCode(setupCode);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(new IPEndPoint(accessory.Address, accessory.Port), ct);
        using var net = tcp.GetStream();

        // --- M1: request pair-setup ---
        var m1 = Tlv8.Encode(
            Tlv8.Byte(HapTlvType.State, HapPairingState.M1),
            Tlv8.Byte(HapTlvType.Method, HapPairingMethod.PairSetup));
        await HapHttp.WriteRequestAsync(net, "POST", "/pair-setup", TlvContentType, m1, ct);
        var m2 = await ReadTlvAsync(net, ct);
        EnsureState(m2, HapPairingState.M2);

        byte[] salt = m2.Get(HapTlvType.Salt);
        byte[] accessoryPubB = m2.Get(HapTlvType.PublicKey);

        // --- Client SRP-6a (username "Pair-Setup", password = setup code) ---
        var group = Srp6StandardGroups.rfc5054_3072;
        var digest = new Sha512Digest();
        var client = new Srp6Client();
        client.Init(group, digest, new SecureRandom());
        var clientPubA = client.GenerateClientCredentials(salt, Encoding.UTF8.GetBytes("Pair-Setup"), Encoding.UTF8.GetBytes(code));
        var sharedS = client.CalculateSecret(new Org.BouncyCastle.Math.BigInteger(1, accessoryPubB));

        // K = H(S); the proof helper uses SHA-512(padded_S).
        byte[] sBytes = BigIntegerToUnsigned(sharedS);
        byte[] kHash = Sha512(sBytes);

        // Compute M1 (client proof) per SRP-6a with the HAP-defined layout.
        byte[] clientProof = ComputeClientProof(group, digest, salt, "Pair-Setup",
            BigIntegerToUnsigned(clientPubA), accessoryPubB, kHash);

        // --- M3: send A + client proof ---
        var m3 = Tlv8.Encode(
            Tlv8.Byte(HapTlvType.State, HapPairingState.M3),
            Tlv8.Bytes(HapTlvType.PublicKey, BigIntegerToUnsigned(clientPubA)),
            Tlv8.Bytes(HapTlvType.Proof, clientProof));
        await HapHttp.WriteRequestAsync(net, "POST", "/pair-setup", TlvContentType, m3, ct);
        var m4 = await ReadTlvAsync(net, ct);
        EnsureState(m4, HapPairingState.M4);

        byte[] serverProof = m4.Get(HapTlvType.Proof);
        byte[] expectedServerProof = ComputeServerProof(BigIntegerToUnsigned(clientPubA), clientProof, kHash);
        if (!CryptographicOperations.FixedTimeEquals(serverProof, expectedServerProof))
            throw new HapAuthenticationException("SRP server proof mismatch — wrong setup code?");

        // --- M5: send our identity (encrypted) ---
        byte[] sessionKey = HapCrypto.HkdfSha512(kHash,
            salt: "Pair-Setup-Encrypt-Salt", info: "Pair-Setup-Encrypt-Info", length: 32);
        byte[] iOSDeviceX = HapCrypto.HkdfSha512(kHash,
            salt: "Pair-Setup-Controller-Sign-Salt", info: "Pair-Setup-Controller-Sign-Info", length: 32);

        string controllerId = controllerIdOverride ?? Guid.NewGuid().ToString();

        // Fresh Ed25519 long-term keypair for this pairing.
        byte[] controllerLtsk = RandomBytes(BCEd25519.SecretKeySize);
        byte[] controllerLtpk = new byte[BCEd25519.PublicKeySize];
        BCEd25519.GeneratePublicKey(controllerLtsk, 0, controllerLtpk, 0);

        byte[] iOSDeviceInfo = Concat(iOSDeviceX, Encoding.UTF8.GetBytes(controllerId), controllerLtpk);
        byte[] iOSDeviceSignature = new byte[BCEd25519.SignatureSize];
        BCEd25519.Sign(controllerLtsk, 0, iOSDeviceInfo, 0, iOSDeviceInfo.Length, iOSDeviceSignature, 0);

        byte[] subTlv = Tlv8.Encode(
            Tlv8.String(HapTlvType.Identifier, controllerId),
            Tlv8.Bytes(HapTlvType.PublicKey, controllerLtpk),
            Tlv8.Bytes(HapTlvType.Signature, iOSDeviceSignature));

        byte[] encrypted = EncryptPairing(sessionKey, "PS-Msg05", subTlv);

        var m5 = Tlv8.Encode(
            Tlv8.Byte(HapTlvType.State, HapPairingState.M5),
            Tlv8.Bytes(HapTlvType.EncryptedData, encrypted));
        await HapHttp.WriteRequestAsync(net, "POST", "/pair-setup", TlvContentType, m5, ct);

        // --- M6: verify accessory identity ---
        var m6 = await ReadTlvAsync(net, ct);
        EnsureState(m6, HapPairingState.M6);

        byte[] m6Encrypted = m6.Get(HapTlvType.EncryptedData);
        byte[] m6Plain = DecryptPairing(sessionKey, "PS-Msg06", m6Encrypted);
        var m6Sub = Tlv8.Decode(m6Plain);
        string accessoryId = Encoding.UTF8.GetString(m6Sub.Get(HapTlvType.Identifier));
        byte[] accessoryLtpk = m6Sub.Get(HapTlvType.PublicKey);
        byte[] accessorySig = m6Sub.Get(HapTlvType.Signature);

        byte[] accessoryX = HapCrypto.HkdfSha512(kHash,
            salt: "Pair-Setup-Accessory-Sign-Salt", info: "Pair-Setup-Accessory-Sign-Info", length: 32);
        byte[] accessoryInfo = Concat(accessoryX, Encoding.UTF8.GetBytes(accessoryId), accessoryLtpk);
        if (!BCEd25519.Verify(accessorySig, 0, accessoryLtpk, 0, accessoryInfo, 0, accessoryInfo.Length))
            throw new HapAuthenticationException("Accessory identity signature failed to verify.");

        return new HapPairing
        {
            AccessoryId = accessoryId,
            AccessoryLtpk = accessoryLtpk,
            ControllerId = controllerId,
            ControllerLtpk = controllerLtpk,
            ControllerLtsk = controllerLtsk,
        };
    }

    // -------- helpers --------

    private static async Task<List<TlvItem>> ReadTlvAsync(Stream s, CancellationToken ct)
    {
        var resp = await HapHttp.ReadResponseAsync(s, ct);
        if (resp.Status != 200) throw new HapProtocolException($"HAP pair-setup HTTP {resp.Status}");
        var tlv = Tlv8.Decode(resp.Body);
        if (tlv.TryGet(HapTlvType.Error, out var err) && err.Length == 1)
            throw new HapProtocolException($"HAP pair-setup error 0x{err[0]:X2} ({(HapTlvError)err[0]})");
        return tlv;
    }

    private static void EnsureState(List<TlvItem> tlv, byte expected)
    {
        byte? state = tlv.GetByteOrNull(HapTlvType.State);
        if (state != expected)
            throw new HapProtocolException($"HAP pair-setup: expected M{expected} got {(state.HasValue ? "M" + state : "no-state")}");
    }

    private static string NormalizeSetupCode(string code)
    {
        string digits = new string(code.Where(char.IsDigit).ToArray());
        if (digits.Length != 8) throw new ArgumentException("HomeKit setup code must be 8 digits (e.g. 031-45-154).", nameof(code));
        return digits.Insert(3, "-").Insert(6, "-");
    }

    private static byte[] Sha512(byte[] input)
    {
        var d = new Sha512Digest();
        d.BlockUpdate(input, 0, input.Length);
        var o = new byte[d.GetDigestSize()];
        d.DoFinal(o, 0);
        return o;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = parts.Sum(p => p.Length);
        var buf = new byte[total];
        int pos = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, buf, pos, p.Length); pos += p.Length; }
        return buf;
    }

    private static byte[] BigIntegerToUnsigned(Org.BouncyCastle.Math.BigInteger v)
    {
        // BouncyCastle emits a leading zero byte for values with the high bit set; HAP wants the
        // unsigned magnitude, padded to the group modulus length (384 bytes for 3072-bit).
        byte[] raw = v.ToByteArrayUnsigned();
        const int len = 3072 / 8;
        if (raw.Length == len) return raw;
        if (raw.Length > len) throw new InvalidOperationException("SRP value larger than group modulus");
        var padded = new byte[len];
        Buffer.BlockCopy(raw, 0, padded, len - raw.Length, raw.Length);
        return padded;
    }

    private static byte[] RandomBytes(int length)
    {
        var b = new byte[length];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    /// <summary>
    /// SRP-6a client proof M1 = H( H(N) XOR H(g) || H(username) || salt || A || B || K ).
    /// This is the SRP-6a "M1" (not to be confused with HAP's pair-setup step number M1).
    /// </summary>
    private static byte[] ComputeClientProof(
        Srp6GroupParameters group,
        Sha512Digest digest,
        byte[] salt,
        string username,
        byte[] aPadded,
        byte[] bPadded,
        byte[] kHash)
    {
        byte[] hN = Sha512(BigIntegerToUnsigned(group.N));
        byte[] hG = Sha512(BigIntegerToUnsigned(group.G));
        byte[] hNxorG = new byte[hN.Length];
        for (int i = 0; i < hN.Length; i++) hNxorG[i] = (byte)(hN[i] ^ hG[i]);
        byte[] hU = Sha512(Encoding.UTF8.GetBytes(username));
        return Sha512(Concat(hNxorG, hU, salt, aPadded, bPadded, kHash));
    }

    /// <summary>SRP-6a server proof M2 = H(A || M1 || K).</summary>
    private static byte[] ComputeServerProof(byte[] aPadded, byte[] m1, byte[] kHash)
        => Sha512(Concat(aPadded, m1, kHash));

    private static byte[] EncryptPairing(byte[] key, string nonceLabel, byte[] plaintext)
    {
        using var cha = new ChaCha20Poly1305(key);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        cha.Encrypt(HapCrypto.PairingNonce(nonceLabel), plaintext, cipher, tag);
        var output = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, output, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, output, cipher.Length, tag.Length);
        return output;
    }

    private static byte[] DecryptPairing(byte[] key, string nonceLabel, byte[] ciphertextAndTag)
    {
        if (ciphertextAndTag.Length < 16)
            throw new HapProtocolException("Encrypted pairing payload smaller than a tag.");
        int cipherLen = ciphertextAndTag.Length - 16;
        var cipher = ciphertextAndTag.AsSpan(0, cipherLen);
        var tag = ciphertextAndTag.AsSpan(cipherLen, 16);
        using var cha = new ChaCha20Poly1305(key);
        var plaintext = new byte[cipherLen];
        cha.Decrypt(HapCrypto.PairingNonce(nonceLabel), cipher, tag, plaintext);
        return plaintext;
    }
}

