using TeknoMojo.Matter.Core.Clusters;
using TeknoMojo.Matter.Core.Commissioning;
using Xunit;

namespace TeknoMojo.Matter.Core.Tests.Commissioning;

/// <summary>
/// The NetworkID a device connects by differs per radio: for Wi-Fi it is the SSID, for Thread the
/// Extended PAN ID buried in the operational dataset.
/// </summary>
public class NetworkProvisioningTests
{
    /// <summary>Thread datasets are a flat type-length-value sequence; Extended PAN ID is type 2, 8 bytes.</summary>
    private static byte[] Dataset(params (byte Type, byte[] Value)[] entries)
    {
        var bytes = new List<byte>();
        foreach (var (type, value) in entries)
        {
            bytes.Add(type);
            bytes.Add((byte)value.Length);
            bytes.AddRange(value);
        }
        return [.. bytes];
    }

    [Fact]
    public void ExtendedPanIdIsFoundRegardlessOfPositionInTheDataset()
    {
        byte[] expected = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        byte[] dataset = Dataset(
            (0, [15]),                                   // channel
            (3, "my-thread-net"u8.ToArray()),            // network name
            (2, expected),                               // extended PAN ID
            (5, new byte[16]));                          // network key

        Assert.Equal(expected, MatterCommissioner.ExtractThreadExtendedPanId(dataset));
    }

    [Fact]
    public void DatasetWithoutAnExtendedPanIdIsRejectedClearly()
    {
        byte[] dataset = Dataset((0, [15]), (3, "no-pan-id"u8.ToArray()));

        var ex = Assert.Throws<ArgumentException>(() => MatterCommissioner.ExtractThreadExtendedPanId(dataset));
        Assert.Contains("Extended PAN ID", ex.Message);
    }

    [Fact]
    public void TruncatedDatasetDoesNotReadPastItsEnd()
    {
        // A length byte claiming more data than is present must not walk off the array.
        byte[] truncated = [2, 8, 0xDE, 0xAD];

        Assert.Throws<ArgumentException>(() => MatterCommissioner.ExtractThreadExtendedPanId(truncated));
    }

    [Fact]
    public void MatterEpochIsCountedFromTheYear2000InMicroseconds()
    {
        // One full day after the Matter epoch.
        var oneDayIn = new DateTimeOffset(2000, 1, 2, 0, 0, 0, TimeSpan.Zero);

        Assert.Equal(86_400_000_000UL, TimeSynchronizationCluster.ToMatterEpochMicroseconds(oneDayIn));
    }

    [Fact]
    public void MatterEpochIsNotTheUnixEpoch()
    {
        // Confusing the two is a 30-year error, so pin the distinction.
        var unixEpoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var matterEpoch = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

        Assert.Equal(0UL, TimeSynchronizationCluster.ToMatterEpochMicroseconds(matterEpoch));
        Assert.True(TimeSynchronizationCluster.ToMatterEpochMicroseconds(unixEpoch) > long.MaxValue / 2,
            "times before the Matter epoch wrap, which is why callers must not pass them");
    }
}
