using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MFA.Sync;

/// <summary>
/// GitHub, GitLab and the self-hosted server.
/// </summary>
/// <remarks>
/// All three are "a file with a revision" over HTTP, differing only in the
/// shape of the request and in what they call the revision:
/// <list type="table">
/// <item><term>self-hosted</term><description>ETag; <c>If-Match</c>, 412 when stale</description></item>
/// <item><term>GitHub</term><description>blob <c>sha</c> in the body, 409 when stale</description></item>
/// <item><term>GitLab</term><description><c>last_commit_id</c> in the body, 400 or 409</description></item>
/// </list>
/// The token is passed in and never stored in the vault, because the vault's
/// settings travel to the other devices.
/// </remarks>
internal sealed class HttpProvider(
    HttpProvider.Flavour flavour,
    string location,
    string token) : ISyncProvider
{
    internal enum Flavour { SelfHosted, GitHub, GitLab }

    /// <summary>
    /// One client for the process. A new <see cref="HttpClient"/> per request
    /// exhausts sockets under any load, and this one is never reconfigured.
    /// </summary>
    private static readonly HttpClient Client = new()
    {
        Timeout = TimeSpan.FromSeconds(30),
    };

    public Task<Fetched?> FetchAsync(string name) => flavour switch
    {
        Flavour.SelfHosted => FetchSelfHostedAsync(name),
        Flavour.GitHub => FetchGitHubAsync(name),
        _ => FetchGitLabAsync(name),
    };

    public Task<string?> PutAsync(string name, byte[] bytes, string? expected) => flavour switch
    {
        Flavour.SelfHosted => PutSelfHostedAsync(name, bytes, expected),
        Flavour.GitHub => PutGitHubAsync(name, bytes, expected),
        _ => PutGitLabAsync(name, bytes, expected),
    };

    // --- self-hosted -----------------------------------------------------

    private async Task<Fetched?> FetchSelfHostedAsync(string name)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, SelfHostedUri(name));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await Client.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureAsync(response);

        var etag = response.Headers.ETag?.Tag?.Trim('"')
            ?? throw new SyncProblem("the server's response had no ETag");
        return new Fetched(await response.Content.ReadAsByteArrayAsync(), etag);
    }

    private async Task<string?> PutSelfHostedAsync(string name, byte[] bytes, string? expected)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, SelfHostedUri(name))
        {
            Content = new ByteArrayContent(bytes),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        if (expected is not null)
        {
            request.Headers.IfMatch.Add(new EntityTagHeaderValue($"\"{expected}\""));
        }
        else
        {
            request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
        }

        using var response = await Client.SendAsync(request);
        // 412 is the server saying somebody wrote first: a retry, not an error
        // to show the user.
        if (response.StatusCode == HttpStatusCode.PreconditionFailed) return null;
        await EnsureAsync(response);

        return response.Headers.ETag?.Tag?.Trim('"') ?? Hash(bytes);
    }

    private Uri SelfHostedUri(string name) =>
        Uri.TryCreate($"{location.TrimEnd('/')}/v1/files/{name}", UriKind.Absolute, out var uri)
            ? uri
            : throw new SyncProblem($"“{location}” is not a URL");

    // --- GitHub ----------------------------------------------------------

    private async Task<Fetched?> FetchGitHubAsync(string name)
    {
        var (owner, repo, branch) = GitHubLocation();
        using var request = GitHubRequest(
            HttpMethod.Get,
            $"https://api.github.com/repos/{owner}/{repo}/contents/{name}?ref={branch}");

        using var response = await Client.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureAsync(response);

        var contents = await response.Content.ReadFromJsonAsync<GitHubContents>()
            ?? throw new SyncProblem("the file came back empty");
        if (contents.Encoding != "base64")
        {
            throw new SyncProblem("the file came back in an unexpected encoding");
        }
        return new Fetched(Convert.FromBase64String(contents.Content.Replace("\n", "")), contents.Sha);
    }

    private async Task<string?> PutGitHubAsync(string name, byte[] bytes, string? expected)
    {
        var (owner, repo, branch) = GitHubLocation();
        var body = new Dictionary<string, string>
        {
            ["message"] = "MFA sync",
            ["content"] = Convert.ToBase64String(bytes),
            ["branch"] = branch,
        };
        // Without `sha` GitHub refuses to overwrite, which is the guard we
        // want on a first write.
        if (expected is not null) body["sha"] = expected;

        using var request = GitHubRequest(
            HttpMethod.Put,
            $"https://api.github.com/repos/{owner}/{repo}/contents/{name}");
        request.Content = JsonContent.Create(body);

        using var response = await Client.SendAsync(request);
        // 409 is a stale sha; 422 is "already exists" on a create.
        if (response.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.UnprocessableEntity)
        {
            return null;
        }
        await EnsureAsync(response);

        var written = await response.Content.ReadFromJsonAsync<GitHubWritten>();
        return written?.Content.Sha;
    }

    private HttpRequestMessage GitHubRequest(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        // GitHub rejects requests with no user agent.
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("MFA", "0.1"));
        return request;
    }

    private (string Owner, string Repo, string Branch) GitHubLocation()
    {
        var parts = location.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) throw new SyncProblem("expected owner/repo or owner/repo/branch");
        return (parts[0], parts[1], parts.Length > 2 ? parts[2] : "main");
    }

    private sealed record GitHubContents(
        [property: JsonPropertyName("sha")] string Sha,
        [property: JsonPropertyName("content")] string Content,
        [property: JsonPropertyName("encoding")] string Encoding);

    private sealed record GitHubWritten(
        [property: JsonPropertyName("content")] GitHubContents Content);

    // --- GitLab ----------------------------------------------------------

    private async Task<Fetched?> FetchGitLabAsync(string name)
    {
        var (project, branch) = GitLabLocation();
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://gitlab.com/api/v4/projects/{Uri.EscapeDataString(project)}" +
            $"/repository/files/{Uri.EscapeDataString(name)}?ref={branch}");
        request.Headers.Add("PRIVATE-TOKEN", token);

        using var response = await Client.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await EnsureAsync(response);

        var file = await response.Content.ReadFromJsonAsync<GitLabFile>()
            ?? throw new SyncProblem("the file came back empty");
        if (file.Encoding != "base64")
        {
            throw new SyncProblem("the file came back in an unexpected encoding");
        }
        return new Fetched(Convert.FromBase64String(file.Content), file.LastCommitId);
    }

    private async Task<string?> PutGitLabAsync(string name, byte[] bytes, string? expected)
    {
        var (project, branch) = GitLabLocation();
        var body = new Dictionary<string, string>
        {
            ["branch"] = branch,
            ["content"] = Convert.ToBase64String(bytes),
            ["encoding"] = "base64",
            ["commit_message"] = "MFA sync",
        };
        if (expected is not null) body["last_commit_id"] = expected;

        // GitLab is strict: POST creates, PUT updates.
        using var request = new HttpRequestMessage(
            expected is null ? HttpMethod.Post : HttpMethod.Put,
            $"https://gitlab.com/api/v4/projects/{Uri.EscapeDataString(project)}" +
            $"/repository/files/{Uri.EscapeDataString(name)}")
        {
            Content = JsonContent.Create(body),
        };
        request.Headers.Add("PRIVATE-TOKEN", token);

        using var response = await Client.SendAsync(request);
        // 400 covers a stale last_commit_id and "already exists".
        if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Conflict)
        {
            return null;
        }
        await EnsureAsync(response);

        // The write response has no commit id, so read it back.
        return (await FetchGitLabAsync(name))?.Revision;
    }

    private (string Project, string Branch) GitLabLocation()
    {
        var parts = location.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) throw new SyncProblem("expected a project id, optionally /branch");
        return (parts[0], parts.Length > 1 ? parts[1] : "main");
    }

    private sealed record GitLabFile(
        [property: JsonPropertyName("content")] string Content,
        [property: JsonPropertyName("encoding")] string Encoding,
        [property: JsonPropertyName("last_commit_id")] string LastCommitId);

    // --- shared ----------------------------------------------------------

    /// <summary>
    /// Throws with something showable.
    /// </summary>
    /// <remarks>
    /// Only the first line of the body, and never the request: an error body
    /// can echo headers, and the token is in one of them.
    /// </remarks>
    private static async Task EnsureAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;

        var body = await response.Content.ReadAsStringAsync();
        var detail = body.Length > 200 ? body[..200] : body;
        detail = detail.Split('\n').FirstOrDefault()?.Trim() ?? "";

        throw new SyncProblem(detail.Length == 0
            ? $"the server answered {(int)response.StatusCode}"
            : $"{(int)response.StatusCode}: {detail}");
    }

    private static string Hash(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
