using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TeknoMojo.HomeKit.Meross;

/// <summary>
/// One-shot login to the Meross cloud purely to retrieve the account device key. The password is
/// MD5-hashed and sent only to Meross's own HTTPS auth endpoint — the same call the Meross app
/// makes — and is never stored or logged here. The returned key is account-wide (one key controls
/// every device you own).
/// </summary>
public sealed class MerossCloud
{
    // Shared secret baked into every Meross client; used only to sign the login request.
    private const string Secret = "23x17ahWarFH6w29";
    private const string SignInPath = "/v1/Auth/signIn";

    // Modern Meross is region-sharded. Start with these; a wrong-region reply (apiStatus 1030)
    // carries the correct domain in data.domain and we retry against it.
    private static readonly string[] BaseDomains =
    {
        "https://iotx-us.meross.com",
        "https://iotx-eu.meross.com",
        "https://iotx-ap.meross.com",
    };

    private const int CodeNoError = 0;
    private const int CodeRedirectRegion = 1030;

    public sealed record CloudCredentials(string Key, string UserId, string Token, string Email, string Domain);

    public async Task<CloudCredentials> LoginAsync(string email, string password, string? mfaCode = null,
        string countryCode = "us", CancellationToken ct = default)
    {
        string passwordMd5 = Md5Hex(password);
        var errors = new List<string>();

        foreach (string start in BaseDomains)
        {
            string domain = start;
            for (int redirects = 0; redirects < 2; redirects++)
            {
                (int apiStatus, string info, JsonNode? data, string raw, int http) =
                    await AttemptAsync(domain, email, passwordMd5, mfaCode, countryCode, ct);

                if (apiStatus == CodeNoError && data is not null)
                {
                    string key = data["key"]?.GetValue<string>() ?? throw new MerossException("Login OK but no key in response.");
                    return new CloudCredentials(
                        key,
                        data["userid"]?.GetValue<string>() ?? data["userId"]?.GetValue<string>() ?? "",
                        data["token"]?.GetValue<string>() ?? "",
                        data["email"]?.GetValue<string>() ?? email,
                        domain);
                }

                if (apiStatus == CodeRedirectRegion && data?["domain"]?.GetValue<string>() is string redirect && redirect.Length > 0)
                {
                    domain = redirect.StartsWith("http") ? redirect : $"https://{redirect}";
                    continue; // retry against the region the account actually lives in
                }

                if (apiStatus == int.MinValue) // transport/parse failure — try the next base domain
                {
                    errors.Add($"{domain}: HTTP {http} — {Truncate(raw)}");
                    break;
                }

                // A real, actionable API error (wrong password, MFA, etc.) — stop and report it.
                throw new MerossException($"Cloud login failed (apiStatus {apiStatus}): {info}. {DescribeStatus(apiStatus)}", apiStatus);
            }
        }

        throw new MerossException("Could not reach a working Meross login endpoint on any region domain.\n  " + string.Join("\n  ", errors));
    }

    private static async Task<(int apiStatus, string info, JsonNode? data, string raw, int http)> AttemptAsync(
        string baseDomain, string email, string passwordMd5, string? mfaCode, string countryCode, CancellationToken ct)
    {
        var pars = new JsonObject
        {
            ["email"] = email,
            ["password"] = passwordMd5,
            ["accountCountryCode"] = countryCode,
            ["encryption"] = 1,
            ["agree"] = 1,
            ["mobileInfo"] = new JsonObject
            {
                ["deviceModel"] = "TeknoMojo.HomeKit",
                ["mobileOsVersion"] = Environment.OSVersion.VersionString,
                ["mobileOs"] = "windows",
                ["uuid"] = "teknomojo-homekit",
                ["carrier"] = "",
            },
        };
        if (!string.IsNullOrEmpty(mfaCode)) pars["mfaCode"] = mfaCode;

        string paramsB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pars.ToJsonString()));
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string nonce = NewNonce();
        string sign = Md5Hex(Secret + timestamp + nonce + paramsB64);

        var body = new JsonObject
        {
            ["params"] = paramsB64,
            ["sign"] = sign,
            ["timestamp"] = timestamp,
            ["nonce"] = nonce,
        };

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        content.Headers.TryAddWithoutValidation("Authorization", "Basic");
        http.DefaultRequestHeaders.TryAddWithoutValidation("AppVersion", "4.4.4");
        http.DefaultRequestHeaders.TryAddWithoutValidation("AppType", "MerossApp");
        http.DefaultRequestHeaders.TryAddWithoutValidation("AppLanguage", "EN");
        http.DefaultRequestHeaders.TryAddWithoutValidation("vender", "meross"); // Meross spells it this way
        http.DefaultRequestHeaders.TryAddWithoutValidation("vendor", "meross");
        http.DefaultRequestHeaders.UserAgent.ParseAdd("TeknoMojo.HomeKit.Meross");

        string url = baseDomain.TrimEnd('/') + SignInPath;
        string raw;
        int httpCode;
        try
        {
            using HttpResponseMessage resp = await http.PostAsync(url, content, ct);
            raw = await resp.Content.ReadAsStringAsync(ct);
            httpCode = (int)resp.StatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return (int.MinValue, ex.Message, null, ex.Message, 0);
        }

        JsonNode? root = TryParse(raw);
        if (root is null || root["apiStatus"] is null)
            return (int.MinValue, "unparseable", null, raw, httpCode);

        int apiStatus = ReadInt(root["apiStatus"]!);
        string info = root["info"]?.GetValue<string>() ?? "(no info)";
        return (apiStatus, info, root["data"], raw, httpCode);
    }

    private static string DescribeStatus(int apiStatus) => apiStatus switch
    {
        1004 => "Wrong password.",
        1005 or 1008 => "This email is not registered on this region. Try --country eu (or ap), or check the email.",
        1022 or 1032 or 1033 => "MFA appears required - re-run with --mfa <code> from your email/authenticator app.",
        _ => "See Meross apiStatus codes.",
    };

    private static int ReadInt(JsonNode n) =>
        n.GetValueKind() == JsonValueKind.String ? int.Parse(n.GetValue<string>()) : n.GetValue<int>();

    private static JsonNode? TryParse(string s)
    {
        try { return JsonNode.Parse(s); } catch { return null; }
    }

    private static string Truncate(string s) => s.Length > 200 ? s[..200] + "..." : s;

    private static string Md5Hex(string s) =>
        Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static string NewNonce()
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Span<char> chars = stackalloc char[16];
        for (int i = 0; i < chars.Length; i++)
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return new string(chars);
    }
}
