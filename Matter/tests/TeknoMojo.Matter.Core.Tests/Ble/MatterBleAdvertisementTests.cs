using TeknoMojo.Matter.Core.Ble;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Ble;

public class MatterBleAdvertisementTests
{
    [Fact]
    public void Parse_KnownBytes_ExtractsFields()
    {
        // Discriminator 3520 (0xDC0), advVersion 0, vendor 4933 (0x1345), product 40970 (0xA00A), no flags.
        // discAndVersion low byte = 0xC0, high byte = 0x0D (low nibble of disc high byte = 0xD, adv version 0 in high nibble)
        byte[] data =
        {
            0x00,             // OpCode
            0xC0, 0x0D,       // discriminator 0xDC0, advVersion 0
            0x45, 0x13,       // vendorId 0x1345 = 4933 LE
            0x0A, 0xA0,       // productId 0xA00A = 40970 LE
            0x00,             // flags
        };
        var adv = MatterBleAdvertisement.Parse(data);
        Assert.Equal((ushort)0xDC0, adv.Discriminator);
        Assert.Equal(0, adv.AdvertisementVersion);
        Assert.Equal((ushort)4933, adv.VendorId);
        Assert.Equal((ushort)40970, adv.ProductId);
        Assert.False(adv.HasAdditionalData);
        Assert.False(adv.IsExtendedAnnouncement);
    }

    [Fact]
    public void RoundTrip_AllFieldsIncludingFlags()
    {
        var adv = new MatterBleAdvertisement(
            OpCode: 0,
            Discriminator: 0xABC,
            AdvertisementVersion: 0,
            VendorId: 4933,
            ProductId: 40970,
            HasAdditionalData: true,
            IsExtendedAnnouncement: true);

        byte[] bytes = adv.ToBytes();
        Assert.Equal(MatterBleAdvertisement.Size, bytes.Length);

        var decoded = MatterBleAdvertisement.Parse(bytes);
        Assert.Equal(adv, decoded);
    }

    [Fact]
    public void Discriminator_Is12BitMasked()
    {
        // Max 12-bit value is 0xFFF; ensure it round-trips without bleeding into the version nibble.
        var adv = new MatterBleAdvertisement(0, 0xFFF, AdvertisementVersion: 0, 1, 1, false, false);
        var decoded = MatterBleAdvertisement.Parse(adv.ToBytes());
        Assert.Equal((ushort)0xFFF, decoded.Discriminator);
    }

    [Fact]
    public void TooShort_Throws()
    {
        Assert.Throws<FormatException>(() => MatterBleAdvertisement.Parse(new byte[5]));
    }

    [Theory]
    [InlineData("0000fff6-0000-1000-8000-00805f9b34fb")]
    public void ServiceUuid_MatchesReference(string expected)
    {
        Assert.Equal(Guid.Parse(expected), MatterBleUuids.Service);
    }

    [Fact]
    public void CharacteristicUuids_MatchReference()
    {
        Assert.Equal(Guid.Parse("18ee2ef5-263d-4559-959f-4f9c429f9d11"), MatterBleUuids.CharacteristicC1Write);
        Assert.Equal(Guid.Parse("18ee2ef5-263d-4559-959f-4f9c429f9d12"), MatterBleUuids.CharacteristicC2Indicate);
        Assert.Equal(Guid.Parse("64630238-8772-45f2-b87d-748a83218f04"), MatterBleUuids.CharacteristicC3AdditionalData);
    }
}
