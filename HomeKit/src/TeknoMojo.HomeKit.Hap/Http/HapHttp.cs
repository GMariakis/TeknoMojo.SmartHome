using System.Buffers;
using System.Text;

namespace TeknoMojo.HomeKit.Hap.Http;

/// <summary>
/// Minimal HTTP/1.1 request/response codec over a <see cref="Stream"/>. HAP uses HTTP/1.1 as
/// its wire format for both the plain pair-setup/verify phase and, after key derivation, over
/// the ChaCha20-Poly1305 record layer. We roll our own because <see cref="System.Net.Http.HttpClient"/>
/// can't be plugged into an arbitrary bidirectional record stream.
/// </summary>
internal static class HapHttp
{
    public static async Task WriteRequestAsync(
        Stream s,
        string method,
        string path,
        string contentType,
        byte[]? body,
        CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");
        sb.Append("Host: hap\r\n");
        if (body is not null)
        {
            sb.Append("Content-Type: ").Append(contentType).Append("\r\n");
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
        }
        sb.Append("\r\n");

        byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
        await s.WriteAsync(head, ct);
        if (body is { Length: > 0 })
            await s.WriteAsync(body, ct);
        await s.FlushAsync(ct);
    }

    public static async Task<HapHttpResponse> ReadResponseAsync(Stream s, CancellationToken ct)
    {
        // Read headers until CRLFCRLF. HAP responses are small; a simple line reader is fine.
        var headerBytes = new List<byte>(256);
        int consecutive = 0;
        while (consecutive < 4)
        {
            int b = await ReadByteAsync(s, ct);
            if (b < 0) throw new EndOfStreamException("HAP: connection closed while reading headers");
            headerBytes.Add((byte)b);
            consecutive = (b, consecutive) switch
            {
                ('\r', 0 or 2) => consecutive + 1,
                ('\n', 1 or 3) => consecutive + 1,
                _ => 0,
            };
        }

        string headerText = Encoding.ASCII.GetString(headerBytes.ToArray());
        string[] lines = headerText.Split("\r\n");

        // Status line: "HTTP/1.1 200 OK" (or "EVENT/1.0 200 OK" for HAP events, which we treat the same here).
        string[] statusParts = lines[0].Split(' ', 3);
        if (statusParts.Length < 2) throw new FormatException("HAP: malformed status line: " + lines[0]);
        int status = int.Parse(statusParts[1]);

        int contentLength = 0;
        string contentType = "";
        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0) continue;
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string name = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();
            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                contentLength = int.Parse(value);
            else if (name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                contentType = value;
        }

        byte[] body = Array.Empty<byte>();
        if (contentLength > 0)
        {
            body = new byte[contentLength];
            int read = 0;
            while (read < contentLength)
            {
                int n = await s.ReadAsync(body.AsMemory(read, contentLength - read), ct);
                if (n <= 0) throw new EndOfStreamException("HAP: connection closed while reading body");
                read += n;
            }
        }

        return new HapHttpResponse(status, contentType, body);
    }

    private static async Task<int> ReadByteAsync(Stream s, CancellationToken ct)
    {
        var buf = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            int n = await s.ReadAsync(buf.AsMemory(0, 1), ct);
            return n == 0 ? -1 : buf[0];
        }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }
}

internal readonly record struct HapHttpResponse(int Status, string ContentType, byte[] Body);
