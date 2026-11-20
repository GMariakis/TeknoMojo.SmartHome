using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TeknoMojo.Matter.Core.Messaging;

/// <summary>
/// A one-direction Matter secure-session cipher: AES-CCM with 16-byte MIC, keyed with the
/// direction's 16-byte key. Matter uses a 13-byte nonce constructed as:
///   <c>Nonce = SecurityFlags(1) || MessageCounter(4 LE) || SourceNodeId(8 LE, zeros if none)</c>
/// The message-header bytes (up to and including source/destination ids, before ciphertext)
/// are passed as AAD (Spec §4.4.1.9). Each direction of a session has its own instance.
/// </summary>
public sealed class MatterSecureDirection : IDisposable
{
    private readonly AesCcm _cipher;

    /// <summary>The 8-byte identifier baked into the nonce for this direction (source Node ID or 0 for unsecured/PASE).</summary>
    public ulong NonceSourceId { get; }

    public MatterSecureDirection(byte[] key, ulong nonceSourceId)
    {
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (key.Length != 16) throw new ArgumentException("Matter session key must be 16 bytes.", nameof(key));
        _cipher = new AesCcm(key);
        NonceSourceId = nonceSourceId;
    }

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> using the nonce derived from
    /// (<paramref name="securityFlags"/>, <paramref name="messageCounter"/>, <see cref="NonceSourceId"/>)
    /// with <paramref name="header"/> (the encoded outer message header) as AAD. Returns
    /// ciphertext || tag; tag length is 16 bytes.
    /// </summary>
    public byte[] Encrypt(MatterSecurityFlags securityFlags, uint messageCounter, ReadOnlySpan<byte> header, ReadOnlySpan<byte> plaintext)
    {
        byte[] nonce = BuildNonce((byte)securityFlags, messageCounter, NonceSourceId);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        _cipher.Encrypt(nonce, plaintext, cipher, tag, header);
        var output = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, output, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, output, cipher.Length, tag.Length);
        return output;
    }

    /// <summary>
    /// Decrypt <paramref name="ciphertextAndTag"/> (the encrypted payload + 16-byte trailing tag)
    /// with <paramref name="header"/> as AAD. Throws <see cref="CryptographicException"/> on tag
    /// mismatch (wrong key, wrong counter, wrong header, or tampered ciphertext).
    /// </summary>
    public byte[] Decrypt(MatterSecurityFlags securityFlags, uint messageCounter, ReadOnlySpan<byte> header, ReadOnlySpan<byte> ciphertextAndTag)
    {
        if (ciphertextAndTag.Length < 16)
            throw new CryptographicException("Matter payload shorter than MIC.");
        int cipherLen = ciphertextAndTag.Length - 16;
        var cipher = ciphertextAndTag.Slice(0, cipherLen);
        var tag = ciphertextAndTag.Slice(cipherLen, 16);

        byte[] nonce = BuildNonce((byte)securityFlags, messageCounter, NonceSourceId);
        var plain = new byte[cipherLen];
        _cipher.Decrypt(nonce, cipher, tag, plain, header);
        return plain;
    }

    private static byte[] BuildNonce(byte securityFlags, uint messageCounter, ulong nonceSourceId)
    {
        var nonce = new byte[13];
        nonce[0] = securityFlags;
        BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(1, 4), messageCounter);
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(5, 8), nonceSourceId);
        return nonce;
    }

    public void Dispose() => _cipher.Dispose();
}

/// <summary>
/// Both directions of a Matter secure session (Spec §4.5) — the pair of AES-CCM keys derived
/// after PASE or CASE, one for the initiator-to-responder direction and one for the reverse,
/// plus their independent monotonic message counters.
/// </summary>
public sealed class MatterSecureSession : IDisposable
{
    /// <summary>Cipher for messages we send.</summary>
    public MatterSecureDirection Encrypt { get; }

    /// <summary>Cipher for messages we receive.</summary>
    public MatterSecureDirection Decrypt { get; }

    /// <summary>Session ID assigned by the peer (used as SessionId in the outbound message header).</summary>
    public ushort PeerSessionId { get; }

    /// <summary>Session ID we allocated (goes into inbound headers).</summary>
    public ushort LocalSessionId { get; }

    private uint _outboundCounter;

    public MatterSecureSession(
        MatterSecureDirection encrypt,
        MatterSecureDirection decrypt,
        ushort localSessionId,
        ushort peerSessionId,
        uint initialOutboundCounter = 1)
    {
        Encrypt = encrypt;
        Decrypt = decrypt;
        LocalSessionId = localSessionId;
        PeerSessionId = peerSessionId;
        _outboundCounter = initialOutboundCounter;
    }

    /// <summary>Pick and consume the next outbound message counter.</summary>
    public uint NextOutboundCounter() => Interlocked.Increment(ref _outboundCounter) - 1;

    public void Dispose()
    {
        Encrypt.Dispose();
        Decrypt.Dispose();
    }
}
