using System.Buffers.Binary;

namespace TeknoMojo.Matter.Core.Ble;

/// <summary>
/// BTP (Bluetooth Transport Protocol) capabilities handshake — the messages exchanged once
/// over GATT before any Matter payload flows, to negotiate protocol version, fragment size,
/// and receive-window size (Matter Core Spec §4.19.5 / "CHIPoBLE Transport Protocol").
/// </summary>
/// <remarks>
/// Magic bytes 0x65 0x6C are the fixed "check bytes" both messages start with. The supported
/// version list packs 2 versions per byte, slot 0 in the LOW nibble of the first byte. Both
/// the nibble order and the advertised ATT MTU were verified by capturing a shipping
/// commissioner's handshake over the air with a BLE sniffer — a mistake in either compiles
/// fine and only shows up as an accessory that never answers.
/// </remarks>
public static class BtpHandshake
{
    public const byte CheckByte1 = 0x65;
    public const byte CheckByte2 = 0x6C;

    /// <summary>The only BTP protocol version this stack (and current Matter 1.x devices) supports.</summary>
    public const byte ProtocolVersion = 4;

    /// <summary>
    /// Upper bound on the ATT MTU we advertise in the capabilities request, and therefore on our
    /// BTP fragment size. Windows negotiates 247 with these accessories, but at least one
    /// shipping Matter accessory silently ignores a handshake advertising 247 while answering an
    /// otherwise byte-identical one advertising 185 — the MTU iOS negotiates, and so the value
    /// accessories are in practice tested against. This only bounds commissioning-time framing.
    /// </summary>
    public const ushort MaxAdvertisedAttMtu = 185;

    /// <summary>Number of 4-bit version slots packed 2-per-byte in the capabilities request (spec: 8 slots).</summary>
    public const int SupportedVersionSlots = 8;

    private const int SupportedVersionsBytes = (SupportedVersionSlots / 2) + (SupportedVersionSlots % 2); // = 4

    public const int RequestLength = 2 /*magic*/ + SupportedVersionsBytes /*versions*/ + 2 /*mtu*/ + 1 /*window*/; // 9
    public const int ResponseLength = 2 /*magic*/ + 1 /*selected version*/ + 2 /*fragment size*/ + 1 /*window*/;   // 6

    /// <summary>What the initiator (central/commissioner) sends first.</summary>
    public sealed record CapabilitiesRequest(byte[] SupportedProtocolVersions, ushort Mtu, byte WindowSize)
    {
        /// <summary>Build a request advertising only <see cref="ProtocolVersion"/> (the only version we implement).</summary>
        public static CapabilitiesRequest ForCurrentVersion(ushort mtu, byte windowSize)
        {
            var versions = new byte[SupportedVersionsBytes];
            SetVersionSlot(versions, 0, ProtocolVersion);
            return new CapabilitiesRequest(versions, mtu, windowSize);
        }

        private static void SetVersionSlot(byte[] versions, int index, byte version)
        {
            // Slot 0 is the LOW nibble of the first byte. Confirmed by sniffing a shipping
            // commissioner's handshake off the air: it advertises protocol version 4 as
            // 65 6C 04 00 00 00 ..., not 65 6C 40 ....
            int byteIndex = index / 2;
            bool highNibble = index % 2 != 0;
            byte v = (byte)(version & 0x0F);
            if (highNibble)
            {
                versions[byteIndex] = (byte)((versions[byteIndex] & 0x0F) | (v << 4));
            }
            else
            {
                versions[byteIndex] = (byte)((versions[byteIndex] & 0xF0) | v);
            }
        }
    }

    /// <summary>What the responder (peripheral/accessory) sends back.</summary>
    public sealed record CapabilitiesResponse(byte SelectedProtocolVersion, ushort FragmentSize, byte WindowSize)
    {
        /// <summary>True when the responder found a version it supports (0 = "no compatible version").</summary>
        public bool IsAccepted => SelectedProtocolVersion != 0;
    }

    public static byte[] EncodeRequest(CapabilitiesRequest req)
    {
        if (req.SupportedProtocolVersions.Length != SupportedVersionsBytes)
            throw new ArgumentException($"SupportedProtocolVersions must be {SupportedVersionsBytes} bytes.", nameof(req));

        var buf = new byte[RequestLength];
        int pos = 0;
        buf[pos++] = CheckByte1;
        buf[pos++] = CheckByte2;
        req.SupportedProtocolVersions.CopyTo(buf.AsSpan(pos)); pos += SupportedVersionsBytes;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), req.Mtu); pos += 2;
        buf[pos] = req.WindowSize;
        return buf;
    }

    public static CapabilitiesRequest DecodeRequest(ReadOnlySpan<byte> data)
    {
        if (data.Length < RequestLength) throw new FormatException("BTP capabilities request too short.");
        ValidateMagic(data);
        int pos = 2;
        byte[] versions = data.Slice(pos, SupportedVersionsBytes).ToArray(); pos += SupportedVersionsBytes;
        ushort mtu = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos, 2)); pos += 2;
        byte window = data[pos];
        return new CapabilitiesRequest(versions, mtu, window);
    }

    public static byte[] EncodeResponse(CapabilitiesResponse resp)
    {
        var buf = new byte[ResponseLength];
        int pos = 0;
        buf[pos++] = CheckByte1;
        buf[pos++] = CheckByte2;
        buf[pos++] = resp.SelectedProtocolVersion;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(pos, 2), resp.FragmentSize); pos += 2;
        buf[pos] = resp.WindowSize;
        return buf;
    }

    public static CapabilitiesResponse DecodeResponse(ReadOnlySpan<byte> data)
    {
        if (data.Length < ResponseLength) throw new FormatException("BTP capabilities response too short.");
        ValidateMagic(data);
        int pos = 2;
        byte selected = data[pos++];
        ushort fragSize = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(pos, 2)); pos += 2;
        byte window = data[pos];
        return new CapabilitiesResponse(selected, fragSize, window);
    }

    private static void ValidateMagic(ReadOnlySpan<byte> data)
    {
        if (data[0] != CheckByte1 || data[1] != CheckByte2)
            throw new FormatException("BTP handshake magic bytes mismatch — not a BTP capabilities message.");
    }
}
