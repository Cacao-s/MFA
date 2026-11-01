using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace MFA.Conformance;

/// <summary>
/// An <see cref="HttpMessageHandler"/> that answers from a script and records
/// what it was asked, so a case can assert on both halves of the exchange.
/// </summary>
/// <remarks>
/// A fake transport rather than a local server: the GitHub and GitLab URLs are
/// hard-coded in the implementation, which is correct, and a transport can
/// still intercept them.
/// </remarks>
internal sealed class ScriptedTransport(JsonArray exchanges) : HttpMessageHandler
{
    private int next;

    internal List<Recorded> Seen { get; } = [];

    internal sealed record Recorded(
        string Method,
        string Url,
        Dictionary<string, string> Headers,
        byte[] Body);

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, values) in request.Headers)
        {
            headers[name] = string.Join(", ", values);
        }
        if (request.Content is not null)
        {
            foreach (var (name, values) in request.Content.Headers)
            {
                headers[name] = string.Join(", ", values);
            }
        }

        var body = request.Content is null
            ? []
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);

        Seen.Add(new Recorded(
            request.Method.Method,
            request.RequestUri?.ToString() ?? string.Empty,
            headers,
            body));

        if (next >= exchanges.Count)
        {
            throw new InvalidOperationException(
                $"the implementation made {Seen.Count} requests; the case scripts {exchanges.Count}");
        }

        return Respond(exchanges[next++]!["response"]!);
    }

    private static HttpResponseMessage Respond(JsonNode scripted)
    {
        var response = new HttpResponseMessage(
            (HttpStatusCode)scripted["status"]!.GetValue<int>());

        if (scripted["body_json"] is JsonNode json)
        {
            response.Content = new StringContent(
                json.ToJsonString(), Encoding.UTF8, "application/json");
        }
        else
        {
            var encoded = scripted["body_base64"]?.GetValue<string>() ?? string.Empty;
            response.Content = new ByteArrayContent(
                encoded.Length == 0 ? [] : Convert.FromBase64String(encoded));
        }

        foreach (var (name, value) in Headers(scripted))
        {
            // The ETag is a typed header; everything else goes on as-is.
            if (name.Equals("etag", StringComparison.OrdinalIgnoreCase))
            {
                response.Headers.ETag = new EntityTagHeaderValue(value);
            }
            else if (!response.Headers.TryAddWithoutValidation(name, value))
            {
                response.Content.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return response;
    }

    private static IEnumerable<(string Name, string Value)> Headers(JsonNode scripted)
    {
        if (scripted["headers"] is not JsonObject headers) yield break;
        foreach (var (name, value) in headers)
        {
            yield return (name, value!.GetValue<string>());
        }
    }

    /// <summary>How many requests the script still expects.</summary>
    internal int Unused => exchanges.Count - next;
}
