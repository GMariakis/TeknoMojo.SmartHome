using TeknoMojo.Matter.Ble.Linux.DBus;

namespace TeknoMojo.Matter.Ble.Linux.BlueZ;

/// <summary>
/// Helpers for walking the org.freedesktop.DBus.ObjectManager.GetManagedObjects() reply, whose
/// signature is <c>a{oa{sa{sv}}}</c>: a dict from object path to a dict of interface name to
/// property dict. BlueZ organizes its entire object tree (adapters, devices, GATT
/// services/characteristics) under this one call.
/// </summary>
internal static class BlueZObjects
{
    public const string Service = "org.bluez";
    public const string RootPath = "/";

    public const string ObjectManagerInterface = "org.freedesktop.DBus.ObjectManager";
    public const string PropertiesInterface = "org.freedesktop.DBus.Properties";
    public const string AdapterInterface = "org.bluez.Adapter1";
    public const string DeviceInterface = "org.bluez.Device1";
    public const string GattServiceInterface = "org.bluez.GattService1";
    public const string GattCharacteristicInterface = "org.bluez.GattCharacteristic1";

    /// <summary>Parsed managed-objects reply: object path -> (interface name -> property dict).</summary>
    public sealed record ManagedObject(string Path, IReadOnlyDictionary<string, IReadOnlyDictionary<string, DBusValue>> Interfaces)
    {
        public bool Implements(string iface) => Interfaces.ContainsKey(iface);
        public IReadOnlyDictionary<string, DBusValue>? Properties(string iface) => Interfaces.GetValueOrDefault(iface);
    }

    public static async Task<List<ManagedObject>> GetManagedObjectsAsync(DBusConnection conn, CancellationToken ct)
    {
        List<DBusValue> reply = await conn.CallAsync(Service, RootPath, ObjectManagerInterface, "GetManagedObjects", "", null, ct);
        var outer = (DBusValue.Arr)reply[0]; // a{oa{sa{sv}}}
        var result = new List<ManagedObject>();

        foreach (DBusValue item in outer.Items)
        {
            var entry = (DBusValue.DictEntry)item;
            string path = entry.Key.AsString();
            var ifacesDict = (DBusValue.Arr)entry.Value;

            var ifaces = new Dictionary<string, IReadOnlyDictionary<string, DBusValue>>();
            foreach (DBusValue ifaceItem in ifacesDict.Items)
            {
                var ifaceEntry = (DBusValue.DictEntry)ifaceItem;
                string ifaceName = ifaceEntry.Key.AsString();
                var propsDict = (DBusValue.Arr)ifaceEntry.Value;

                var props = new Dictionary<string, DBusValue>();
                foreach (DBusValue propItem in propsDict.Items)
                {
                    var propEntry = (DBusValue.DictEntry)propItem;
                    props[propEntry.Key.AsString()] = propEntry.Value.Unwrap();
                }
                ifaces[ifaceName] = props;
            }
            result.Add(new ManagedObject(path, ifaces));
        }
        return result;
    }

    /// <summary>Find the first adapter object (implements org.bluez.Adapter1), e.g. "/org/bluez/hci0".</summary>
    public static async Task<string> FindFirstAdapterAsync(DBusConnection conn, CancellationToken ct)
    {
        var objects = await GetManagedObjectsAsync(conn, ct);
        var adapter = objects.FirstOrDefault(o => o.Implements(AdapterInterface));
        if (adapter is null) throw new InvalidOperationException("No Bluetooth adapter found via BlueZ (org.bluez.Adapter1).");
        return adapter.Path;
    }
}
