namespace TeknoMojo.Matter.Ble.Linux.DBus;

/// <summary>D-Bus type codes we actually marshal (a small subset of the full spec — enough for BlueZ).</summary>
public enum DBusType : byte
{
    Byte = (byte)'y',
    Boolean = (byte)'b',
    Int16 = (byte)'n',
    UInt16 = (byte)'q',
    Int32 = (byte)'i',
    UInt32 = (byte)'u',
    Int64 = (byte)'x',
    UInt64 = (byte)'t',
    Double = (byte)'d',
    String = (byte)'s',
    ObjectPath = (byte)'o',
    Signature = (byte)'g',
    Array = (byte)'a',
    Struct = (byte)'r',      // signature uses '(' ')'; 'r' is the internal type-code marker
    DictEntry = (byte)'e',   // signature uses '{' '}'
    Variant = (byte)'v',
}

/// <summary>
/// A single D-Bus value: either a scalar, a string-like value, an array (including the
/// dict/a{sv} shape used everywhere in BlueZ), a struct, or a variant wrapping another value.
/// This is the generic model our marshaler reads/writes; BlueZ-specific code translates to/from
/// this rather than working with raw bytes directly.
/// </summary>
public abstract record DBusValue
{
    public sealed record Byte(byte Value) : DBusValue;
    public sealed record Bool(bool Value) : DBusValue;
    public sealed record Int16(short Value) : DBusValue;
    public sealed record UInt16(ushort Value) : DBusValue;
    public sealed record Int32(int Value) : DBusValue;
    public sealed record UInt32(uint Value) : DBusValue;
    public sealed record Int64(long Value) : DBusValue;
    public sealed record UInt64(ulong Value) : DBusValue;
    public sealed record Double(double Value) : DBusValue;
    public sealed record Str(string Value) : DBusValue;
    public sealed record ObjectPath(string Value) : DBusValue;
    public sealed record Signature(string Value) : DBusValue;

    /// <summary>An array of values, all sharing <see cref="ElementSignature"/>.</summary>
    public sealed record Arr(string ElementSignature, IReadOnlyList<DBusValue> Items) : DBusValue;

    /// <summary>A struct: an ordered, heterogeneous tuple.</summary>
    public sealed record Struct(IReadOnlyList<DBusValue> Fields) : DBusValue;

    /// <summary>A dict entry: exactly one key + one value (only meaningful inside an Arr of dict entries).</summary>
    public sealed record DictEntry(DBusValue Key, DBusValue Value) : DBusValue;

    /// <summary>A variant: a value tagged with its own signature, used pervasively by BlueZ (a{sv}).</summary>
    public sealed record Variant(string TypeSignature, DBusValue Value) : DBusValue;

    // ---- convenience constructors/accessors ----

    public static DBusValue.Str S(string v) => new(v);
    public static DBusValue.ObjectPath O(string v) => new(v);
    public static DBusValue.UInt32 U32(uint v) => new(v);
    public static DBusValue.Arr EmptyArray(string elementSig) => new(elementSig, Array.Empty<DBusValue>());
    public static DBusValue.Arr ByteArray(byte[] bytes) => new("y", bytes.Select(b => (DBusValue)new Byte(b)).ToList());

    /// <summary>Build an a{sv} dict from key/value pairs, wrapping each value as a Variant.</summary>
    public static DBusValue.Arr Dict(params (string Key, DBusValue Value)[] entries) =>
        new("{sv}", entries.Select(e => (DBusValue)new DictEntry(new Str(e.Key), new Variant(SignatureOf(e.Value), e.Value))).ToList());

    /// <summary>Best-effort signature inference for values built with the convenience constructors above.</summary>
    public static string SignatureOf(DBusValue v) => v switch
    {
        Byte => "y",
        Bool => "b",
        Int16 => "n",
        UInt16 => "q",
        Int32 => "i",
        UInt32 => "u",
        Int64 => "x",
        UInt64 => "t",
        Double => "d",
        Str => "s",
        ObjectPath => "o",
        Signature => "g",
        Arr a => "a" + a.ElementSignature,
        Struct st => "(" + string.Concat(st.Fields.Select(SignatureOf)) + ")",
        DictEntry de => "{" + SignatureOf(de.Key) + SignatureOf(de.Value) + "}",
        Variant => "v",
        _ => throw new NotSupportedException($"Cannot infer signature for {v.GetType().Name}"),
    };

    // ---- extraction helpers for reading BlueZ replies ----

    public byte[] AsByteArray() => this is Arr { ElementSignature: "y" } a
        ? a.Items.Select(i => ((Byte)i).Value).ToArray()
        : throw new InvalidCastException($"{GetType().Name} is not a byte array");

    public string AsString() => this switch
    {
        Str s => s.Value,
        ObjectPath o => o.Value,
        _ => throw new InvalidCastException($"{GetType().Name} is not a string/object-path"),
    };

    public DBusValue Unwrap() => this is Variant v ? v.Value.Unwrap() : this;
}
