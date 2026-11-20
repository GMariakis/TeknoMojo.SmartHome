using System.Text;

namespace TeknoMojo.HomeKit.Meross;

/// <summary>HTTP transport: POST http://&lt;host&gt;/config with the JSON envelope.</summary>
public sealed class MerossHttpTransport : IMerossTransport, IDisposable
{
    private readonly HttpClient _http;
    private readonly Uri _endpoint;

    public MerossHttpTransport(string host, TimeSpan? timeout = null)
    {
        _endpoint = new Uri($"http://{host}/config");
        _http = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(10) };
    }

    public async Task<string> SendAsync(string envelopeJson, CancellationToken ct = default)
    {
        using var content = new StringContent(envelopeJson, Encoding.UTF8, "application/json");
        using HttpResponseMessage resp = await _http.PostAsync(_endpoint, content, ct);
        string body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new MerossException($"HTTP {(int)resp.StatusCode} from {_endpoint}: {body}");
        return body;
    }

    public void Dispose() => _http.Dispose();
}
