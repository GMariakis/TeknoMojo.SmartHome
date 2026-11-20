namespace TeknoMojo.Matter.Core.Ble;

/// <summary>
/// GATT UUIDs for Matter-over-BLE commissioning ("CHIPoBLE"). Verified against the Apache-2.0
/// reference implementation (project-chip/connectedhomeip, src/ble/BleUUID.h) rather than
/// reconstructed from memory.
/// </summary>
public static class MatterBleUuids
{
    /// <summary>16-bit short form of the CHIPoBLE service UUID, as it appears in advertisement data.</summary>
    public const ushort ServiceUuid16 = 0xFFF6;

    /// <summary>128-bit CHIPoBLE service UUID.</summary>
    public static readonly Guid Service = Guid.Parse("0000fff6-0000-1000-8000-00805f9b34fb");

    /// <summary>C1: central writes Matter/BTP data to the accessory (Write / Write-Without-Response).</summary>
    public static readonly Guid CharacteristicC1Write = Guid.Parse("18ee2ef5-263d-4559-959f-4f9c429f9d11");

    /// <summary>C2: accessory sends Matter/BTP data to the central (Indicate).</summary>
    public static readonly Guid CharacteristicC2Indicate = Guid.Parse("18ee2ef5-263d-4559-959f-4f9c429f9d12");

    /// <summary>C3: optional additional-data characteristic (Read) — device software version, rotating id, etc.</summary>
    public static readonly Guid CharacteristicC3AdditionalData = Guid.Parse("64630238-8772-45f2-b87d-748a83218f04");
}
