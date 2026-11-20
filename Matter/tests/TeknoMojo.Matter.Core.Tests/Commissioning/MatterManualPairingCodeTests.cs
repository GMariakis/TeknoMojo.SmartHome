using TeknoMojo.Matter.Core.Commissioning;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Commissioning;

public class MatterManualPairingCodeTests
{
    [Fact]
    public void Decode_RealDeviceCode_MatchesHandComputedBitLayout()
    {
        var decoded = MatterManualPairingCode.Decode("2033-022-0861");
        Assert.False(decoded.IsLongCode);
        Assert.Equal(8, decoded.ShortDiscriminator);
        Assert.Equal(34180326u, decoded.SetupPinCode);
        Assert.Null(decoded.VendorId);
        Assert.Null(decoded.ProductId);
    }

    [Fact]
    public void Decode_BadCheckDigit_Throws()
    {
        Assert.Throws<FormatException>(() => MatterManualPairingCode.Decode("2033-022-0862"));
    }

    [Fact]
    public void Decode_DashesAreCosmetic()
    {
        var a = MatterManualPairingCode.Decode("2033-022-0861");
        var b = MatterManualPairingCode.Decode("20330220861");
        Assert.Equal(a, b);
    }
}
