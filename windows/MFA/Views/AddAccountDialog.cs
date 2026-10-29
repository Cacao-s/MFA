using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MFA.Core;
using Windows.Storage.Pickers;

namespace MFA.Views;

/// <summary>
/// The ways an account can get in on Windows (spec §1).
/// </summary>
/// <remarks>
/// No camera flow: a desktop with a webcam pointed at a screen is a worse
/// experience than reading the picture, and it would mean asking for the
/// webcam capability. So: paste the link, read a picture of the QR code, or
/// type the key.
/// <para/>
/// Built in code rather than XAML because it is one dialog with three sections
/// and no reusable parts; a XAML pair for it would be two files to keep in
/// step for no gain.
/// </remarks>
internal sealed class AddAccountDialog : ContentDialog
{
    private readonly AppModel _model;

    private readonly TextBox _pasted = new()
    {
        PlaceholderText = "otpauth://totp/…",
        AcceptsReturn = true,
        Height = 64,
    };

    private readonly TextBox _issuer = new() { Header = "Service", PlaceholderText = "GitHub" };
    private readonly TextBox _account = new() { Header = "Account", PlaceholderText = "you@example.com" };
    private readonly TextBox _secret = new() { Header = "Setup key", PlaceholderText = "JBSW Y3DP EHPK 3PXP" };
    private readonly ComboBox _algorithm = new() { Header = "Algorithm", SelectedIndex = 0 };
    private readonly ComboBox _digits = new() { Header = "Digits", SelectedIndex = 0 };
    private readonly ComboBox _period = new() { Header = "Changes every", SelectedIndex = 0 };
    private readonly TextBlock _problem = new()
    {
        Visibility = Visibility.Collapsed,
        TextWrapping = TextWrapping.Wrap,
    };

    internal AddAccountDialog(AppModel model)
    {
        _model = model;

        Title = "Add account";
        CloseButtonText = "Cancel";
        PrimaryButtonText = "Add";
        DefaultButton = ContentDialogButton.Primary;

        foreach (var name in new[] { "SHA1", "SHA256", "SHA512" }) _algorithm.Items.Add(name);
        foreach (var count in new[] { "6", "7", "8" }) _digits.Items.Add(count);
        foreach (var seconds in new[] { "30 seconds", "60 seconds" }) _period.Items.Add(seconds);

        var fromPicture = new Button { Content = "Read a QR code from a picture…" };
        fromPicture.Click += async (_, _) => await ReadPictureAsync();

        var addLink = new Button { Content = "Add from link" };
        addLink.Click += (_, _) => AddFromLink();

        Content = new ScrollViewer
        {
            Content = new StackPanel
            {
                Spacing = 12,
                Width = 400,
                Children =
                {
                    fromPicture,
                    new TextBlock { Text = "Or paste the setup link:" },
                    _pasted,
                    addLink,
                    new TextBlock
                    {
                        Text = "Or type the key by hand. Almost every site uses SHA1, " +
                               "6 digits and 30 seconds — only change those if told to.",
                        TextWrapping = TextWrapping.Wrap,
                        Style = (Style)Application.Current.Resources["CaptionTextBlockStyle"],
                    },
                    _issuer, _account, _secret, _algorithm, _digits, _period,
                    _problem,
                },
            },
        };

        PrimaryButtonClick += (_, args) =>
        {
            // Keeping the dialog open on a failure means the user does not
            // retype everything.
            if (!AddTyped()) args.Cancel = true;
        };
    }

    private void AddFromLink()
    {
        var uri = _pasted.Text.Trim();
        if (uri.Length == 0) return;

        if (_model.Add(uri))
        {
            Hide();
        }
        else
        {
            // Add() has already reported why; this is the nudge that it was
            // not a new account.
            _pasted.Text = "";
        }
    }

    private bool AddTyped()
    {
        if (_secret.Text.Trim().Length == 0) return false;
        if (_issuer.Text.Length == 0 && _account.Text.Length == 0)
        {
            Fail("Give the account a service name or an account name, so you can tell it apart later.");
            return false;
        }

        _model.Add(new AccountDraft(
            Issuer: _issuer.Text.Length == 0 ? null : _issuer.Text,
            Account: _account.Text,
            Secret: _secret.Text,
            Algorithm: (string)(_algorithm.SelectedItem ?? "SHA1"),
            Digits: byte.Parse((string)(_digits.SelectedItem ?? "6")),
            Period: _period.SelectedIndex == 1 ? 60u : 30u));

        return true;
    }

    private async Task ReadPictureAsync()
    {
        var picker = new FileOpenPicker();
        foreach (var extension in new[] { ".png", ".jpg", ".jpeg", ".bmp" })
        {
            picker.FileTypeFilter.Add(extension);
        }

        // An unpackaged WinUI app has to be told which window owns the picker,
        // or it throws instead of opening.
        if (App.MainWindow is { } window)
        {
            var handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
            WinRT.Interop.InitializeWithWindow.Initialize(picker, handle);
        }

        var file = await picker.PickSingleFileAsync();
        if (file is null) return;

        var bytes = (await Windows.Storage.FileIO.ReadBufferAsync(file)).ToArray();
        try
        {
            var uris = Mfa.DecodeQrImage(bytes);

            // A picture can hold a migration export; those go through the
            // import, not the one-account path.
            var migrations = uris
                .Where(uri => uri.StartsWith("otpauth-migration://", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (migrations.Count > 0)
            {
                _model.ImportMigration(migrations);
                Hide();
                return;
            }

            if (uris.Any(_model.Add)) Hide();
        }
        catch (MfaException exception)
        {
            Fail(exception.Kind == ErrorKind.NoQrCode
                ? "That picture does not contain a QR code MFA can read."
                : exception.Message);
        }
    }

    private void Fail(string message)
    {
        _problem.Text = message;
        _problem.Visibility = Visibility.Visible;
    }
}
