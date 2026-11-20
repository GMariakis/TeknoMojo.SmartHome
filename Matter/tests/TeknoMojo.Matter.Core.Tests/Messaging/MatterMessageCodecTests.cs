using System.Security.Cryptography;
using TeknoMojo.Matter.Core.Messaging;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Messaging;

/// <summary>
/// Round-trip and byte-exact tests for the Matter outer message header, the inner protocol
/// header, and the AES-CCM secure-session cipher.
/// </summary>
public class MatterMessageCodecTests
{
    [Fact]
    public void MessageHeader_MinimalRoundTrip()
    {
        var h = new MatterMessageHeader
        {
            Flags = MatterMessageFlags.None,
            SessionId = 0x1234,
            SecurityFlags = MatterSecurityFlags.None,
            MessageCounter = 0xDEADBEEF,
        };
        byte[] bytes = MatterMessageCodec.EncodeHeader(h);
        Assert.Equal(8, bytes.Length);
        // Expected: flags=00, sess=34 12, sec=00, counter=EF BE AD DE
        Assert.Equal(new byte[] { 0x00, 0x34, 0x12, 0x00, 0xEF, 0xBE, 0xAD, 0xDE }, bytes);

        var decoded = MatterMessageCodec.DecodeHeader(bytes, out int consumed);
        Assert.Equal(bytes.Length, consumed);
        Assert.Equal(h.SessionId, decoded.SessionId);
        Assert.Equal(h.MessageCounter, decoded.MessageCounter);
        Assert.Null(decoded.SourceNodeId);
        Assert.Null(decoded.DestinationNodeId);
    }

    [Fact]
    public void MessageHeader_WithSourceAndDestNodeId()
    {
        var h = new MatterMessageHeader
        {
            Flags = MatterMessageFlags.SourceNodeIdPresent | MatterMessageFlags.DestNodeId,
            SessionId = 0xABCD,
            SecurityFlags = MatterSecurityFlags.SessionTypeUnicast,
            MessageCounter = 42,
            SourceNodeId = 0x0011223344556677,
            DestinationNodeId = 0xFFEEDDCCBBAA9988,
        };
        byte[] bytes = MatterMessageCodec.EncodeHeader(h);
        var decoded = MatterMessageCodec.DecodeHeader(bytes, out int consumed);
        Assert.Equal(bytes.Length, consumed);
        Assert.Equal(h.SourceNodeId, decoded.SourceNodeId);
        Assert.Equal(h.DestinationNodeId, decoded.DestinationNodeId);
    }

    [Fact]
    public void MessageHeader_WithDestGroupId()
    {
        var h = new MatterMessageHeader
        {
            Flags = MatterMessageFlags.DestGroupId,
            SessionId = 1,
            SecurityFlags = MatterSecurityFlags.SessionTypeGroup,
            MessageCounter = 99,
            DestinationGroupId = 0x1234,
        };
        byte[] bytes = MatterMessageCodec.EncodeHeader(h);
        var decoded = MatterMessageCodec.DecodeHeader(bytes, out int consumed);
        Assert.Equal(bytes.Length, consumed);
        Assert.Equal((ushort)0x1234, decoded.DestinationGroupId);
        Assert.Null(decoded.DestinationNodeId);
    }

    [Fact]
    public void MessageHeader_MissingSourceThrows()
    {
        var h = new MatterMessageHeader
        {
            Flags = MatterMessageFlags.SourceNodeIdPresent,
            SessionId = 1,
            MessageCounter = 1,
        };
        Assert.Throws<InvalidOperationException>(() => MatterMessageCodec.EncodeHeader(h));
    }

    [Fact]
    public void ProtocolHeader_MinimalRoundTrip()
    {
        var h = new MatterProtocolHeader
        {
            ExchangeFlags = MatterExchangeFlags.Initiator | MatterExchangeFlags.ReliabilityRequested,
            Opcode = MatterSecureChannelOpcodes.PbkdfParamRequest,
            ExchangeId = 0x1000,
            ProtocolId = MatterProtocolIds.SecureChannel,
        };
        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        byte[] wire = MatterProtocolHeaderCodec.Encode(h, payload);
        Assert.Equal(MatterProtocolHeaderCodec.MinHeaderSize + payload.Length, wire.Length);

        var (decoded, offset) = MatterProtocolHeaderCodec.Decode(wire);
        Assert.Equal(h.Opcode, decoded.Opcode);
        Assert.Equal(h.ExchangeId, decoded.ExchangeId);
        Assert.Equal(h.ProtocolId, decoded.ProtocolId);
        Assert.Null(decoded.VendorId);
        Assert.Null(decoded.AckMessageCounter);
        Assert.Equal(payload, wire.AsSpan(offset).ToArray());
    }

    [Fact]
    public void ProtocolHeader_WithVendorAndAck()
    {
        var h = new MatterProtocolHeader
        {
            ExchangeFlags = MatterExchangeFlags.Initiator | MatterExchangeFlags.AckPresent | MatterExchangeFlags.VendorPresent,
            Opcode = 0x99,
            ExchangeId = 7,
            VendorId = 4933,
            ProtocolId = 0xBEEF,
            AckMessageCounter = 12345,
        };
        byte[] wire = MatterProtocolHeaderCodec.Encode(h, ReadOnlySpan<byte>.Empty);
        var (decoded, offset) = MatterProtocolHeaderCodec.Decode(wire);
        Assert.Equal(wire.Length, offset);
        Assert.Equal((ushort)4933, decoded.VendorId);
        Assert.Equal((uint)12345, decoded.AckMessageCounter);
        Assert.Equal((ushort)0xBEEF, decoded.ProtocolId);
    }

    [Fact]
    public void Secure_EncryptDecryptRoundTrip_ValidatesAad()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        using var direction = new MatterSecureDirection(key, nonceSourceId: 0x0011223344556677);

        byte[] header = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("hello matter world");
        byte[] enc = direction.Encrypt(MatterSecurityFlags.SessionTypeUnicast, 42, header, plaintext);

        Assert.Equal(plaintext.Length + 16, enc.Length); // ciphertext + 16-byte tag

        byte[] decrypted = direction.Decrypt(MatterSecurityFlags.SessionTypeUnicast, 42, header, enc);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Secure_TamperedHeader_FailsDecryption()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        using var d = new MatterSecureDirection(key, 0);
        byte[] header = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] plaintext = new byte[] { 1, 2, 3 };
        byte[] enc = d.Encrypt(MatterSecurityFlags.None, 1, header, plaintext);

        byte[] tampered = header.ToArray();
        tampered[0] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() =>
            d.Decrypt(MatterSecurityFlags.None, 1, tampered, enc));
    }

    [Fact]
    public void Secure_WrongCounter_FailsDecryption()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        using var d = new MatterSecureDirection(key, 0);
        byte[] header = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] enc = d.Encrypt(MatterSecurityFlags.None, 100, header, new byte[] { 42 });
        Assert.ThrowsAny<CryptographicException>(() =>
            d.Decrypt(MatterSecurityFlags.None, 101, header, enc));
    }

    [Fact]
    public void OutboundCounter_IsMonotonicFromInitial()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        using var session = new MatterSecureSession(
            new MatterSecureDirection(key, 1),
            new MatterSecureDirection(key, 2),
            localSessionId: 1000, peerSessionId: 2000,
            initialOutboundCounter: 5);

        Assert.Equal(5u, session.NextOutboundCounter());
        Assert.Equal(6u, session.NextOutboundCounter());
        Assert.Equal(7u, session.NextOutboundCounter());
    }
}
