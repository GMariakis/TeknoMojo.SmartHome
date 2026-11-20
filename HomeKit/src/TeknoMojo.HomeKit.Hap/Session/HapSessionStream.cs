using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TeknoMojo.HomeKit.Hap.Session;

/// <summary>
/// Wraps a duplex <see cref="Stream"/> (typically the accessory TCP socket after pair-verify)
/// with HAP's ChaCha20-Poly1305 record framing (HAP §5.5.2):
///   Each record on the wire = 2-byte little-endian plaintext length (AAD)
///                            || ciphertext || 16-byte tag.
/// Maximum plaintext per record is 1024 bytes; writes larger than that are split. Each direction
/// has its own key and independent 64-bit nonce counter that starts at zero and increments per
/// record. Reading returns exactly what one record contained.
/// </summary>
internal sealed class HapSessionStream : Stream
{
    private const int MaxRecord = 1024;
    private const int TagSize = 16;

    private readonly Stream _inner;
    private readonly ChaCha20Poly1305 _readCipher;
    private readonly ChaCha20Poly1305 _writeCipher;
    private ulong _readCounter;
    private ulong _writeCounter;

    // Leftover plaintext from a previous record when the caller reads smaller chunks than the record size.
    private byte[]? _readBuffer;
    private int _readBufferOffset;
    private int _readBufferLength;

    public HapSessionStream(Stream inner, byte[] readKey, byte[] writeKey)
    {
        _inner = inner;
        _readCipher = new ChaCha20Poly1305(readKey);
        _writeCipher = new ChaCha20Poly1305(writeKey);
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken ct = default)
    {
        if (_readBuffer is null || _readBufferOffset >= _readBufferLength)
        {
            if (!await ReadOneRecordAsync(ct)) return 0;
        }

        int available = _readBufferLength - _readBufferOffset;
        int take = Math.Min(destination.Length, available);
        _readBuffer!.AsSpan(_readBufferOffset, take).CopyTo(destination.Span);
        _readBufferOffset += take;
        return take;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();

    private async Task<bool> ReadOneRecordAsync(CancellationToken ct)
    {
        var lenAad = new byte[2];
        int n = await ReadExactAsync(lenAad, throwOnShort: false, ct);
        if (n == 0) return false;
        if (n < 2) throw new EndOfStreamException("HAP: truncated record length");
        int payloadLen = BinaryPrimitives.ReadUInt16LittleEndian(lenAad);

        var cipher = new byte[payloadLen];
        var tag = new byte[TagSize];
        await ReadExactAsync(cipher, throwOnShort: true, ct);
        await ReadExactAsync(tag, throwOnShort: true, ct);

        var plaintext = new byte[payloadLen];
        _readCipher.Decrypt(HapCrypto.SessionNonce(_readCounter++), cipher, tag, plaintext, lenAad);

        _readBuffer = plaintext;
        _readBufferOffset = 0;
        _readBufferLength = plaintext.Length;
        return true;
    }

    private async Task<int> ReadExactAsync(byte[] dest, bool throwOnShort, CancellationToken ct)
    {
        int total = 0;
        while (total < dest.Length)
        {
            int n = await _inner.ReadAsync(dest.AsMemory(total), ct);
            if (n <= 0) break;
            total += n;
        }
        if (throwOnShort && total < dest.Length)
            throw new EndOfStreamException("HAP: encrypted record truncated");
        return total;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> source, CancellationToken ct = default)
    {
        int offset = 0;
        while (offset < source.Length)
        {
            int chunk = Math.Min(MaxRecord, source.Length - offset);
            var aad = new byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(aad, (ushort)chunk);

            var cipher = new byte[chunk];
            var tag = new byte[TagSize];
            _writeCipher.Encrypt(HapCrypto.SessionNonce(_writeCounter++), source.Span.Slice(offset, chunk), cipher, tag, aad);

            await _inner.WriteAsync(aad, ct);
            await _inner.WriteAsync(cipher, ct);
            await _inner.WriteAsync(tag, ct);
            offset += chunk;
        }
        await _inner.FlushAsync(ct);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _readCipher.Dispose();
            _writeCipher.Dispose();
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }
}
