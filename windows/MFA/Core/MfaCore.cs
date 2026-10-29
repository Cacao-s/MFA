using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MFA.Core;

/// <summary>
/// The bridge to the Rust core.
/// </summary>
/// <remarks>
/// Two exported functions carrying JSON, rather than generated bindings:
/// UniFFI has no first-party C# generator, and a third-party one has to track
/// UniFFI's internal ABI, where a mismatch shows up as memory corruption
/// rather than a compile error. This is the whole surface, and it is
/// reviewable in one sitting.
/// <para/>
/// Every call is synchronous and fast — the core does no I/O — except the ones
/// that derive a key from a password, which take a second or so on purpose.
/// Those are wrapped in <c>Task.Run</c> by the callers so the UI thread is not
/// the one waiting.
/// </remarks>
internal static partial class MfaCore
{
    private const string Library = "mfa_ffi";

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr mfa_call(string requestJson);

    [LibraryImport(Library)]
    private static partial void mfa_string_free(IntPtr responseJson);

    internal static readonly JsonSerializerOptions Json = new()
    {
        // The Rust side is snake_case for fields and the enum member's own
        // name for variants, so the enum converter gets no naming policy.
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Calls a method that returns nothing.</summary>
    internal static void Invoke(string method, object? parameters = null, ulong? handle = null) =>
        Call<JsonElement>(method, parameters, handle);

    /// <summary>Calls a method and deserialises its result.</summary>
    internal static T Call<T>(string method, object? parameters = null, ulong? handle = null)
    {
        var request = JsonSerializer.Serialize(
            new Request(method, handle, parameters), Json);

        var pointer = mfa_call(request);
        if (pointer == IntPtr.Zero)
        {
            throw new MfaException(ErrorKind.Other, "The core returned nothing.");
        }

        string response;
        try
        {
            response = Marshal.PtrToStringUTF8(pointer)
                ?? throw new MfaException(ErrorKind.Other, "The core's answer was not text.");
        }
        finally
        {
            // The caller always owns the result, including on the failure
            // paths above.
            mfa_string_free(pointer);
        }

        var envelope = JsonSerializer.Deserialize<Response<T>>(response, Json);
        if (envelope?.Error is { } error)
        {
            throw new MfaException(error.Kind, error.Message);
        }
        if (envelope is null)
        {
            throw new MfaException(ErrorKind.Other, "The core's answer could not be read.");
        }
        return envelope.Ok!;
    }

    private sealed record Request(
        [property: JsonPropertyName("method")] string Method,
        [property: JsonPropertyName("handle")] ulong? Handle,
        [property: JsonPropertyName("params")] object? Params);

    private sealed record Response<T>(
        [property: JsonPropertyName("ok")] T? Ok,
        [property: JsonPropertyName("error")] ErrorBody? Error);

    private sealed record ErrorBody(
        [property: JsonPropertyName("kind")] ErrorKind Kind,
        [property: JsonPropertyName("message")] string Message);
}

/// <summary>What kind of failure it was, for the UI to branch on.</summary>
internal enum ErrorKind
{
    BadUri,
    BadAccount,
    WrongPassword,
    CannotDecrypt,
    BadFile,
    TooNew,
    IncompleteImport,
    NotFound,
    Unsupported,
    NoQrCode,
    Other,
}

/// <summary>
/// A failure from the core.
/// </summary>
/// <remarks>
/// <see cref="Kind"/> is for deciding what to do — a wrong backup password
/// means ask again, a corrupt file means do not — and
/// <see cref="Exception.Message"/> is already written to be shown.
/// </remarks>
internal sealed class MfaException(ErrorKind kind, string message) : Exception(message)
{
    internal ErrorKind Kind { get; } = kind;
}
