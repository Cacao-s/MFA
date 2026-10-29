using MFA.Core;

namespace MFA.Views;

/// <summary>
/// One row, with the two things the list needs that the core does not provide:
/// a progress value for the ring and a grouped code.
/// </summary>
/// <remarks>
/// A wrapper rather than XAML converters: two converters for two fields is
/// more moving parts than one record, and the grouping rule is easier to read
/// here than in a converter.
/// </remarks>
internal sealed record AccountRow(AccountView Account)
{
    internal string Id => Account.Id;
    internal string Title => Account.Issuer ?? Account.Account;

    /// <summary>Blank rather than repeated when there is no issuer.</summary>
    internal string Subtitle =>
        Account.Issuer is not null && Account.Account.Length > 0 ? Account.Account : "";

    /// <summary><c>123 456</c>, which is how people read a code while typing it.</summary>
    internal string Code =>
        Account.Code.Length % 2 != 0
            ? Account.Code
            : $"{Account.Code[..(Account.Code.Length / 2)]} {Account.Code[(Account.Code.Length / 2)..]}";

    internal string Remaining => Account.RemainingSecs.ToString();

    /// <summary>0 to 100, for the ring.</summary>
    internal double Progress =>
        Account.Period == 0 ? 0 : 100.0 * Account.RemainingSecs / Account.Period;

    /// <summary>Digits read one at a time, so a screen reader does not say
    /// "one hundred and twenty-three thousand".</summary>
    internal string Spoken => $"{Account.DisplayName}, code {string.Join(' ', Account.Code)}";
}
