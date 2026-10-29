using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using MFA.Core;
using Windows.Storage.Pickers;

namespace MFA.Views;

/// <summary>
/// Settings. Everything here lives in the vault, so it travels to the other
/// devices, except the tokens, which are named as staying put.
/// </summary>
public sealed partial class SettingsPage : Page
{
    private MainWindow _window = null!;
    private AppModel Model => _window.Model;
    private bool _isLoading;

    private static readonly uint[] Timeouts = [0, 30, 60, 300];
    private static readonly uint[] ClipboardSeconds = [15, 30, 60];

    public SettingsPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs args)
    {
        _window = (MainWindow)args.Parameter;
        Load();
    }

    private void Load()
    {
        // Setting a control's value raises its changed event, which would save
        // what we have just read back over the top of it.
        _isLoading = true;

        if (Model.LockConfig() is { } lock_)
        {
            LockToggle.IsOn = lock_.BiometricEnabled;
            TimeoutBox.SelectedIndex = Math.Max(0, Array.IndexOf(Timeouts, lock_.BackgroundTimeoutSecs));
            TimeoutBox.IsEnabled = lock_.BiometricEnabled;
            PinButton.Content = lock_.HasPin ? "Change PIN…" : "Set a PIN…";
            RemovePinButton.Visibility = lock_.HasPin ? Visibility.Visible : Visibility.Collapsed;
        }

        if (Model.Preferences() is { } preferences)
        {
            ClipboardBox.SelectedIndex =
                Math.Max(0, Array.IndexOf(ClipboardSeconds, preferences.ClipboardClearSecs));
            SortBox.SelectedIndex = preferences.Sort == SortMode.Manual ? 0 : 1;
        }

        LockNote.Text = "MFA asks Windows Hello, which falls back to your account password, " +
                        "so you always have a way in.";
        VersionLabel.Text = $"MFA {Mfa.LibraryVersion()}";

        ShowTargets();
        _isLoading = false;
    }

    private void ShowTargets()
    {
        var targets = Model.SyncTargets();
        Targets.ItemsSource = targets
            .Select(target => new
            {
                target.Id,
                Display = $"{target.Label} — {target.Kind} — {target.Location}" +
                          (target.Enabled ? "" : " (off)"),
            })
            .ToList();
        Targets.DisplayMemberPath = "Display";

        SyncSetup.Visibility = Model.HasSyncKey ? Visibility.Collapsed : Visibility.Visible;
        PublishButton.IsEnabled = Model.HasSyncKey && targets.Length > 0;
    }

    private void OnBackClick(object sender, RoutedEventArgs args) => Frame.GoBack();

    // --- lock ------------------------------------------------------------

    private void OnLockToggled(object sender, RoutedEventArgs args)
    {
        if (_isLoading || Model.LockConfig() is not { } current) return;
        Model.SetLockConfig(current with { BiometricEnabled = LockToggle.IsOn });
        TimeoutBox.IsEnabled = LockToggle.IsOn;
    }

    private void OnTimeoutChanged(object sender, SelectionChangedEventArgs args)
    {
        if (_isLoading || Model.LockConfig() is not { } current) return;
        Model.SetLockConfig(current with
        {
            BackgroundTimeoutSecs = Timeouts[Math.Max(0, TimeoutBox.SelectedIndex)],
        });
    }

    private async void OnPinClick(object sender, RoutedEventArgs args)
    {
        var first = new PasswordBox { Header = "PIN" };
        var again = new PasswordBox { Header = "PIN again" };
        var problem = new TextBlock { Visibility = Visibility.Collapsed, TextWrapping = TextWrapping.Wrap };

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Set a PIN",
            Content = new StackPanel { Spacing = 8, Children = { first, again, problem } },
            PrimaryButtonText = "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };

        dialog.PrimaryButtonClick += (_, buttonArgs) =>
        {
            if (first.Password.Length < 4)
            {
                problem.Text = "At least 4 digits.";
                problem.Visibility = Visibility.Visible;
                buttonArgs.Cancel = true;
            }
            else if (first.Password != again.Password)
            {
                problem.Text = "The two do not match.";
                problem.Visibility = Visibility.Visible;
                buttonArgs.Cancel = true;
            }
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            Model.SetPin(first.Password);
            Load();
        }
    }

    private void OnRemovePinClick(object sender, RoutedEventArgs args)
    {
        Model.ClearPin();
        Load();
    }

    // --- list ------------------------------------------------------------

    private void OnClipboardChanged(object sender, SelectionChangedEventArgs args)
    {
        if (_isLoading || Model.Preferences() is not { } current) return;
        Model.SetPreferences(current with
        {
            ClipboardClearSecs = ClipboardSeconds[Math.Max(0, ClipboardBox.SelectedIndex)],
        });
    }

    private void OnSortChanged(object sender, SelectionChangedEventArgs args)
    {
        if (_isLoading || Model.Preferences() is not { } current) return;
        Model.SetPreferences(current with
        {
            Sort = SortBox.SelectedIndex == 0 ? SortMode.Manual : SortMode.IssuerAsc,
        });
    }

    // --- sync ------------------------------------------------------------

    private void OnCreateSyncSetClick(object sender, RoutedEventArgs args)
    {
        Model.CreateSyncSet();
        ShowTargets();
    }

    private async void OnJoinClick(object sender, RoutedEventArgs args)
    {
        var password = await AskPasswordAsync(
            "Join a sync set",
            "The same password you use for encrypted backups. MFA will look for the key file " +
            "on the targets you have set up.");
        if (password is null) return;

        var failure = await Model.JoinSyncSetAsync(password);
        if (failure is not null) Model.PendingNotice = new AppModel.Notice("Could not join", failure);
        ShowTargets();
    }

    private async void OnPublishClick(object sender, RoutedEventArgs args)
    {
        var password = await AskPasswordAsync(
            "Publish the key file",
            "Choose a long one: this single password protects your backups and the key file " +
            "on every sync target.");
        if (password is null) return;

        var failure = await Model.PublishKeyFileAsync(password);
        if (failure is not null) Model.PendingNotice = new AppModel.Notice("Could not publish", failure);
    }

    private async void OnAddTargetClick(object sender, RoutedEventArgs args) =>
        await EditTargetAsync(null);

    private async void OnTargetClick(object sender, ItemClickEventArgs args)
    {
        var id = args.ClickedItem?.GetType().GetProperty("Id")?.GetValue(args.ClickedItem) as string;
        var target = Model.SyncTargets().FirstOrDefault(candidate => candidate.Id == id);
        if (target is not null) await EditTargetAsync(target);
    }

    private async Task EditTargetAsync(SyncTargetView? existing)
    {
        var kind = new ComboBox { Header = "Kind" };
        foreach (var name in new[] { "Folder", "GitHub", "GitLab", "Server" }) kind.Items.Add(name);
        kind.SelectedIndex = existing is null ? 3 : (int)existing.Kind;
        kind.IsEnabled = existing is null;

        var label = new TextBox { Header = "Name", Text = existing?.Label ?? "" };
        var location = new TextBox
        {
            Header = "Where",
            Text = existing?.Location ?? "",
            PlaceholderText = "https://mfa.example.com, owner/repo/branch, project-id/branch, or a folder path",
        };
        var token = new PasswordBox { Header = "Token (left blank to keep the saved one)" };
        var enabled = new ToggleSwitch { Header = "Use this target", IsOn = existing?.Enabled ?? true };

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = existing is null ? "Add a target" : existing.Label,
            Content = new StackPanel
            {
                Spacing = 8,
                Width = 420,
                Children = { kind, label, location, token, enabled },
            },
            PrimaryButtonText = "Save",
            SecondaryButtonText = existing is null ? "" : "Remove",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };

        switch (await dialog.ShowAsync())
        {
            case ContentDialogResult.Primary:
                var chosen = (SyncKind)Math.Max(0, kind.SelectedIndex);
                Model.UpsertSyncTarget(
                    new SyncTargetView(
                        existing?.Id ?? "",
                        chosen,
                        label.Text.Length == 0 ? chosen.ToString() : label.Text,
                        location.Text,
                        enabled.IsOn),
                    token.Password.Length == 0 ? null : token.Password);
                break;

            case ContentDialogResult.Secondary when existing is not null:
                Model.RemoveSyncTarget(existing.Id);
                break;
        }
        ShowTargets();
    }

    // --- backup ----------------------------------------------------------

    private async void OnExportClick(object sender, RoutedEventArgs args)
    {
        var password = await AskPasswordAsync(
            "Export a backup",
            "At least 8 characters, and worth making longer. MFA cannot recover it for you.",
            minimumLength: 8,
            confirm: true);
        if (password is null) return;

        var bytes = Model.ExportBackup(password);
        if (bytes is null) return;

        var picker = new FileSavePicker { SuggestedFileName = "mfa-backup" };
        picker.FileTypeChoices.Add("MFA backup", [".mfabackup"]);
        Attach(picker);

        var file = await picker.PickSaveFileAsync();
        if (file is not null) await Windows.Storage.FileIO.WriteBytesAsync(file, bytes);
    }

    private async void OnImportClick(object sender, RoutedEventArgs args)
    {
        var picker = new FileOpenPicker();
        picker.FileTypeFilter.Add(".mfabackup");
        picker.FileTypeFilter.Add("*");
        Attach(picker);

        var file = await picker.PickSingleFileAsync();
        if (file is null) return;

        var bytes = (await Windows.Storage.FileIO.ReadBufferAsync(file)).ToArray();
        var password = await AskPasswordAsync(
            "Import a backup",
            "Importing merges: accounts already here are kept, and a wrong password changes nothing.");
        if (password is null) return;

        Model.ImportBackup(bytes, password);
    }

    // --- reset -----------------------------------------------------------

    private async void OnResetClick(object sender, RoutedEventArgs args)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Delete everything on this machine?",
            Content = new TextBlock
            {
                Text = "Your accounts will be gone from this machine and cannot be recovered " +
                       "from it. Make sure you have a backup, or that another device has them.",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Delete",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary) Model.ResetEverything();
    }

    // --- shared ----------------------------------------------------------

    /// <summary>Asks for a password, or null if the user backed out.</summary>
    private async Task<string?> AskPasswordAsync(
        string title,
        string explanation,
        int minimumLength = 1,
        bool confirm = false)
    {
        var first = new PasswordBox { Header = "Password" };
        var again = new PasswordBox { Header = "Password again" };
        var problem = new TextBlock { Visibility = Visibility.Collapsed, TextWrapping = TextWrapping.Wrap };

        var panel = new StackPanel
        {
            Spacing = 8,
            Width = 380,
            Children = { new TextBlock { Text = explanation, TextWrapping = TextWrapping.Wrap }, first },
        };
        if (confirm) panel.Children.Add(again);
        panel.Children.Add(problem);

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = title,
            Content = panel,
            PrimaryButtonText = "Continue",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };

        dialog.PrimaryButtonClick += (_, buttonArgs) =>
        {
            if (first.Password.Length < minimumLength)
            {
                problem.Text = $"At least {minimumLength} characters.";
                problem.Visibility = Visibility.Visible;
                buttonArgs.Cancel = true;
            }
            else if (confirm && first.Password != again.Password)
            {
                problem.Text = "The two do not match.";
                problem.Visibility = Visibility.Visible;
                buttonArgs.Cancel = true;
            }
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary ? first.Password : null;
    }

    /// <summary>
    /// Tells a picker which window owns it. An unpackaged WinUI app throws
    /// without this instead of opening the picker.
    /// </summary>
    private static void Attach(object picker)
    {
        if (App.MainWindow is not { } window) return;
        var handle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, handle);
    }
}
