using System.Text.Json.Nodes;
using MFA.Sync;
using Xunit;

namespace MFA.Conformance;

/// <summary>
/// Drives every case in conformance/vectors/sync-provider.json against the
/// real <see cref="HttpProvider"/>.
/// </summary>
/// <remarks>
/// The same decision table is written once per platform. What makes the three
/// agree is not that they were written together — they were — but that each
/// one is checked against the same file. This is that check for the Windows
/// copy; the Kotlin and Swift copies have their own, reading the same JSON.
/// </remarks>
public sealed class SyncProviderConformance
{
    private static readonly JsonNode Vectors = LoadVectors();

    private static string Token => Vectors["token"]!.GetValue<string>();

    public static TheoryData<string> Cases()
    {
        var data = new TheoryData<string>();
        foreach (var id in CaseIds())
        {
            data.Add(id);
        }
        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task MatchesTheSharedVector(string id)
    {
        var vector = Case(id);
        var exchanges = vector["exchanges"]!.AsArray();
        var transport = new ScriptedTransport(exchanges);
        var provider = new HttpProvider(
            Flavour(vector["flavour"]!.GetValue<string>()),
            vector["location"]!.GetValue<string>(),
            Token,
            new HttpClient(transport));

        var name = vector["name"]!.GetValue<string>();
        var expected = vector["expect"]!;
        var outcome = expected["outcome"]!.GetValue<string>();
        var operation = vector["operation"]!.GetValue<string>();

        if (outcome == "error")
        {
            var problem = await Assert.ThrowsAnyAsync<Exception>(() =>
                operation == "fetch"
                    ? provider.FetchAsync(name)
                    : (Task)provider.PutAsync(name, Body(vector), Expected(vector)));

            // Not part of the outcome, but worth asserting wherever an error
            // message is built: the token travels in a header, and an error
            // body can echo the request back.
            Assert.DoesNotContain(Token, problem.Message, StringComparison.Ordinal);
        }
        else if (operation == "fetch")
        {
            var fetched = await provider.FetchAsync(name);
            if (outcome == "absent")
            {
                Assert.Null(fetched);
            }
            else
            {
                Assert.NotNull(fetched);
                Assert.Equal(expected["revision"]!.GetValue<string>(), fetched!.Revision);
                Assert.Equal(Base64(expected["body_base64"]!.GetValue<string>()), fetched.Bytes);
            }
        }
        else
        {
            var revision = await provider.PutAsync(name, Body(vector), Expected(vector));
            if (outcome == "lost_race")
            {
                Assert.Null(revision);
            }
            else
            {
                Assert.Equal(expected["revision"]!.GetValue<string>(), revision);
            }
        }

        AssertRequests(id, exchanges, transport);
    }

    /// <summary>
    /// Checks that the implementation sent what the case says it should.
    /// </summary>
    /// <remarks>
    /// Half the table is about the request, not the response: whether a write
    /// carried its guard, and which verb GitLab was given. A client that gets
    /// the response handling right and the request wrong fails in production
    /// and nowhere else.
    /// </remarks>
    private static void AssertRequests(string id, JsonArray exchanges, ScriptedTransport transport)
    {
        var sent = transport.Seen;
        Assert.Equal(exchanges.Count - transport.Unused, sent.Count);

        for (var index = 0; index < sent.Count; index++)
        {
            var specification = exchanges[index]!["request"]!;
            var actual = sent[index];
            var where = $"{id} request {index}";

            Assert.Equal(specification["method"]!.GetValue<string>(), actual.Method);
            Assert.Equal(specification["url"]!.GetValue<string>(), actual.Url);

            if (specification["headers"] is JsonObject required)
            {
                foreach (var (header, value) in required)
                {
                    Assert.True(
                        actual.Headers.TryGetValue(header, out var presented),
                        $"{where}: no {header} header");
                    Assert.Equal(value!.GetValue<string>(), presented);
                }
            }

            foreach (var header in Strings(specification["headers_absent"]))
            {
                Assert.False(
                    actual.Headers.ContainsKey(header),
                    $"{where}: {header} should not have been sent");
            }

            if (specification["body_base64"] is JsonNode body)
            {
                Assert.Equal(Base64(body.GetValue<string>()), actual.Body);
            }

            if (specification["body_json_has"] is JsonObject fields)
            {
                var parsed = JsonNode.Parse(actual.Body)!;
                foreach (var (field, value) in fields)
                {
                    Assert.Equal(
                        value!.GetValue<string>(),
                        parsed[field]?.GetValue<string>());
                }
            }

            foreach (var field in Strings(specification["body_json_lacks"]))
            {
                var parsed = JsonNode.Parse(actual.Body)!;
                Assert.True(
                    parsed[field] is null,
                    $"{where}: the body carries {field}, which is the guard being tested");
            }
        }
    }

    /// <summary>
    /// Fails if the vectors describe a flavour or an outcome this suite does
    /// not handle, so an addition cannot pass by being ignored.
    /// </summary>
    [Fact]
    public void EveryCaseIsUnderstood()
    {
        Assert.NotEmpty(CaseIds());

        foreach (var id in CaseIds())
        {
            var vector = Case(id);
            Flavour(vector["flavour"]!.GetValue<string>());

            var operation = vector["operation"]!.GetValue<string>();
            Assert.Contains(operation, new[] { "fetch", "put" });

            var outcome = vector["expect"]!["outcome"]!.GetValue<string>();
            string[] allowed = operation == "fetch"
                ? ["fetched", "absent", "error"]
                : ["written", "lost_race", "error"];
            Assert.Contains(outcome, allowed);
        }
    }

    private static HttpProvider.Flavour Flavour(string name) => name switch
    {
        "self_hosted" => HttpProvider.Flavour.SelfHosted,
        "github" => HttpProvider.Flavour.GitHub,
        "gitlab" => HttpProvider.Flavour.GitLab,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "unknown flavour"),
    };

    private static byte[] Body(JsonNode vector) =>
        Base64(vector["body_base64"]!.GetValue<string>());

    private static string? Expected(JsonNode vector) =>
        vector["expected_revision"]?.GetValue<string>();

    private static byte[] Base64(string encoded) =>
        encoded.Length == 0 ? [] : Convert.FromBase64String(encoded);

    private static IEnumerable<string> Strings(JsonNode? node) =>
        node is JsonArray array
            ? array.Select(item => item!.GetValue<string>())
            : [];

    private static List<string> CaseIds() =>
        Vectors["cases"]!.AsArray()
            .Select(vector => vector!["id"]!.GetValue<string>())
            .ToList();

    private static JsonNode Case(string id) =>
        Vectors["cases"]!.AsArray()
            .First(vector => vector!["id"]!.GetValue<string>() == id)!;

    private static JsonNode LoadVectors()
    {
        // Walk up to the repository root, so the suite runs from wherever the
        // runner happens to put the assembly.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "conformance", "vectors", "sync-provider.json");
            if (File.Exists(candidate))
            {
                return JsonNode.Parse(File.ReadAllText(candidate))!;
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException(
            "conformance/vectors/sync-provider.json was not found above " + AppContext.BaseDirectory);
    }
}
