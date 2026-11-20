using System.Buffers.Binary;
using System.Text;

namespace TeknoMojo.HomeKit.Hap.Tlv;

/// <summary>
/// TLV8 codec for HAP payloads (HAP R2 §5.6.1).
/// Each item is a 1-byte type, 1-byte length, then that many bytes of value. Values longer than
/// 255 bytes are split into consecutive items of the same type; on decode, consecutive same-type
/// items are joined back into one value. A zero-length <see cref="HapTlvType.Separator"/> (0xFF)
/// delimits list entries (used in ListPairings responses).
/// </summary>
public static class Tlv8
{
    private const int MaxItemLength = 255;

    /// <summary>Decodes a TLV8 blob into an ordered list of items, joining fragmented values.</summary>
    public static List<TlvItem> Decode(ReadOnlySpan<byte> data)
    {
        var items = new List<TlvItem>();
        int pos = 0;
        while (pos < data.Length)
        {
            byte type = data[pos++];
            if (pos >= data.Length) throw new FormatException("TLV8: truncated length");
            int len = data[pos++];
            if (pos + len > data.Length) throw new FormatException("TLV8: truncated value");

            // Join adjacent 255-byte fragments of the same type into one logical value.
            if (items.Count > 0 && items[^1].Type == type && items[^1].Value.Length % MaxItemLength == 0
                && items[^1].Value.Length > 0)
            {
                var prev = items[^1];
                var merged = new byte[prev.Value.Length + len];
                prev.Value.CopyTo(merged, 0);
                data.Slice(pos, len).CopyTo(merged.AsSpan(prev.Value.Length));
                items[^1] = new TlvItem(type, merged);
            }
            else
            {
                items.Add(new TlvItem(type, data.Slice(pos, len).ToArray()));
            }
            pos += len;
        }
        return items;
    }

    /// <summary>Encodes items into TLV8, splitting long values into 255-byte fragments.</summary>
    public static byte[] Encode(params TlvItem[] items) => Encode((IReadOnlyList<TlvItem>)items);

    /// <inheritdoc cref="Encode(TlvItem[])"/>
    public static byte[] Encode(IReadOnlyList<TlvItem> items)
    {
        int total = 0;
        foreach (var it in items)
        {
            int len = it.Value.Length;
            // Every 255-byte fragment carries its own 2-byte header; a 0-length item still has a header.
            int fragments = len == 0 ? 1 : (len + MaxItemLength - 1) / MaxItemLength;
            total += fragments * 2 + len;
        }

        var buf = new byte[total];
        int pos = 0;
        foreach (var it in items)
        {
            int remaining = it.Value.Length;
            int offset = 0;
            do
            {
                int chunk = Math.Min(remaining, MaxItemLength);
                buf[pos++] = it.Type;
                buf[pos++] = (byte)chunk;
                if (chunk > 0)
                {
                    it.Value.AsSpan(offset, chunk).CopyTo(buf.AsSpan(pos));
                    pos += chunk;
                    offset += chunk;
                    remaining -= chunk;
                }
                else
                {
                    remaining = -1; // written the empty item
                }
            } while (remaining > 0);
        }
        return buf;
    }

    // Convenience constructors -----------------------------------------------------------------

    public static TlvItem Byte(byte type, byte value) => new(type, new[] { value });
    public static TlvItem Bytes(byte type, byte[] value) => new(type, value);
    public static TlvItem String(byte type, string value) => new(type, Encoding.UTF8.GetBytes(value));

    // Convenience readers ----------------------------------------------------------------------

    public static bool TryGet(this IReadOnlyList<TlvItem> items, byte type, out byte[] value)
    {
        foreach (var it in items)
        {
            if (it.Type == type) { value = it.Value; return true; }
        }
        value = Array.Empty<byte>();
        return false;
    }

    public static byte[] Get(this IReadOnlyList<TlvItem> items, byte type) =>
        items.TryGet(type, out var v) ? v : throw new KeyNotFoundException($"TLV8: missing tag 0x{type:X2}");

    public static byte? GetByteOrNull(this IReadOnlyList<TlvItem> items, byte type) =>
        items.TryGet(type, out var v) && v.Length == 1 ? v[0] : null;
}

/// <summary>A single TLV8 item after fragment merging.</summary>
public readonly record struct TlvItem(byte Type, byte[] Value);
