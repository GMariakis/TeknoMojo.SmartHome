using System.Buffers.Binary;

namespace TeknoMojo.Matter.Core.Ble;

/// <summary>
/// The Matter/CHIPoBLE "Device Identification Info" block carried as GATT Service Data
/// (against <see cref="MatterBleUuids.ServiceUuid16"/>) in a commissionable device's BLE
/// advertisement. This is how a commissioner finds and identifies a specific device (by
/// discriminator) among many advertising nearby, before ever opening a GATT connection.
/// </summary>
/// <remarks>
/// Byte layout verified against the Apache-2.0 reference implementation
/// (project-chip/connectedhomeip, src/ble/CHIPBleServiceData.h) — an 8-byte little-endian
/// packed structure:
/// <code>
///   [0]    OpCode (implementation-defined; not validated here — devices vary)
///   [1-2]  Discriminator (12 bits) packed with Advertisement Version (4 bits) in byte[2]'s high nibble
///   [3-4]  Vendor ID (uint16 LE)
///   [5-6]  Product ID (uint16 LE)
///   [7]    Additional Data Flag (bit0 = additional data present, bit1 = extended announcement)
/// </code>
/// </remarks>
public sealed record MatterBleAdvertisement(
    byte OpCode,
    ushort Discriminator,
    byte AdvertisementVersion,
    ushort VendorId,
    ushort ProductId,
    bool HasAdditionalData,
    bool IsExtendedAnnouncement)
{
    /// <summary>Fixed size of the identification block, in bytes.</summary>
    public const int Size = 8;

    private const ushort DiscriminatorMask = 0x0FFF;
    private const byte AdditionalDataFlagMask = 0x01;
    private const byte ExtendedAnnouncementFlagMask = 0x02;
    private const byte AdvertisementVersionMask = 0xF0;
    private const int AdvertisementVersionShift = 4;

    /// <summary>Parse the 8-byte service-data payload from a BLE advertisement.</summary>
    public static MatterBleAdvertisement Parse(ReadOnlySpan<byte> serviceData)
    {
        if (serviceData.Length < Size)
            throw new FormatException($"Matter BLE service data must be {Size} bytes, got {serviceData.Length}.");

        byte opCode = serviceData[0];
        ushort discAndVersion = BinaryPrimitives.ReadUInt16LittleEndian(serviceData.Slice(1, 2));
        ushort discriminator = (ushort)(discAndVersion & DiscriminatorMask);
        byte advVersion = (byte)((serviceData[2] & AdvertisementVersionMask) >> AdvertisementVersionShift);
        ushort vendorId = BinaryPrimitives.ReadUInt16LittleEndian(serviceData.Slice(3, 2));
        ushort productId = BinaryPrimitives.ReadUInt16LittleEndian(serviceData.Slice(5, 2));
        byte flags = serviceData[7];

        return new MatterBleAdvertisement(
            opCode, discriminator, advVersion, vendorId, productId,
            HasAdditionalData: (flags & AdditionalDataFlagMask) != 0,
            IsExtendedAnnouncement: (flags & ExtendedAnnouncementFlagMask) != 0);
    }

    /// <summary>Encode back to the 8-byte wire form (mainly useful for tests).</summary>
    public byte[] ToBytes()
    {
        var buf = new byte[Size];
        buf[0] = OpCode;

        byte lowByte = (byte)(Discriminator & 0xFF);
        byte highNibbleOfDisc = (byte)((Discriminator >> 8) & 0x0F);
        byte highByte = (byte)(highNibbleOfDisc | ((AdvertisementVersion << AdvertisementVersionShift) & AdvertisementVersionMask));
        buf[1] = lowByte;
        buf[2] = highByte;

        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(3, 2), VendorId);
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(5, 2), ProductId);

        byte flags = 0;
        if (HasAdditionalData) flags |= AdditionalDataFlagMask;
        if (IsExtendedAnnouncement) flags |= ExtendedAnnouncementFlagMask;
        buf[7] = flags;

        return buf;
    }
}
