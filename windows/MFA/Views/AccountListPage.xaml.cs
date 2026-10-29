using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using MFA.Core;

namespace MFA.Views;

/// <summary>The main screen: every account, its code, and how long it has left.</summary>
public sealed partial class AccountListPage : Page
{
    private MainWindow _window = null!;
    private AppModel Model => _window.Model;

    public AccountListPage() => InitializeComponent();

    protected override void OnNavigatedTo(NavigationEventArgs args)
    {
        _window = (MainWindow)args.Parameter;
        Model.PropertyChanged += (_, changed) =>
        {
            switch (changed.PropertyName)
            {
                case nameof(AppModel.Accounts): ShowAccounts(); break;
                case nameof(AppModel.Status):
                case nameof(AppModel.IsSyncing): ShowStatus(); break;
            }
        };
        ShowAccounts();
        ShowStatus();
    }

    private void ShowAccounts()
    {
        Accounts.ItemsSource = Model.Accounts.Select(account => new AccountRow(account)).ToList();

        var isEmpty = Model.Accounts.Count == 0;
        Accounts.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
        EmptyState.Visibility = isEmpty ? Visibility.Visible : Visibility.Collapsed;

        if (!isEmpty) return;
        var searching = !string.IsNullOrWhiteSpace(Model.Query);
        EmptyTitle.Text = searching ? "Nothing matches" : "No accounts yet";
        EmptyBody.Text = searching
            ? "Try a different search."
            : "Add your first account by pasting the setup link, or reading the QR code from a picture.";
    }

    private void ShowStatus()
    {
        SyncButton.IsEnabled = Model.HasSyncKey && !Model.IsSyncing;

        var text = Model.IsSyncing ? "Syncing…" : Model.Status;
        StatusBar.Message = text ?? "";
        StatusBar.IsOpen = text is not null;
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs args) =>
        Model.Query = SearchBox.Text;

    private void OnAccountClick(object sender, ItemClickEventArgs args)
    {
        if (args.ClickedItem is AccountRow row) Model.Copy(row.Account);
    }

    private async void OnMoreClick(object sender, RoutedEventArgs args)
    {
        if (sender is not Button { Tag: string id }) return;
        var account = Model.Accounts.FirstOrDefault(candidate => candidate.Id == id);
        if (account is null) return;

        var menu = new MenuFlyout();

        var copy = new MenuFlyoutItem { Text = "Copy code" };
        copy.Click += (_, _) => Model.Copy(account);
        menu.Items.Add(copy);

        var showQr = new MenuFlyoutItem { Text = "Show the setup link…" };
        showQr.Click += async (_, _) => await ShowUriAsync(account);
        menu.Items.Add(showQr);

        menu.Items.Add(new MenuFlyoutSeparator());

        var delete = new MenuFlyoutItem { Text = "Delete…" };
        delete.Click += async (_, _) => await ConfirmDeleteAsync(account);
        menu.Items.Add(delete);

        menu.ShowAt((Button)sender);
        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows the account's <c>otpauth://</c> URI.
    /// </summary>
    /// <remarks>
    /// <b>This contains the secret</b>, so it is behind a deliberate choice
    /// and the dialog says what it is. There is no QR image here yet: the core
    /// can read one but not draw one, and the link is enough to move an
    /// account to another app on the same machine.
    /// </remarks>
    private async Task ShowUriAsync(AccountView account)
    {
        var uri = Model.ExportUri(account.Id);
        if (uri is null) return;

        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Move “{account.DisplayName}”",
            Content = new StackPanel
            {
                Spacing = 12,
                Children =
                {
                    new TextBlock
                    {
                        Text = "This link contains the secret key for this account. Anyone who " +
                               "reads it can generate your codes.",
                        TextWrapping = TextWrapping.Wrap,
                    },
                    new TextBox { Text = uri, IsReadOnly = true, TextWrapping = TextWrapping.Wrap },
                },
            },
            CloseButtonText = "Done",
        };
        await dialog.ShowAsync();
    }

    private async Task ConfirmDeleteAsync(AccountView account)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = $"Delete “{account.DisplayName}”?",
            Content = new TextBlock
            {
                Text = "You will not be able to sign in to this account with MFA again unless " +
                       "you add it back. Check you can still get in another way first.",
                TextWrapping = TextWrapping.Wrap,
            },
            PrimaryButtonText = "Delete",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            Model.Delete(account.Id);
        }
    }

    private async void OnAddClick(object sender, RoutedEventArgs args) =>
        await new AddAccountDialog(Model) { XamlRoot = XamlRoot }.ShowAsync();

    private void OnSyncClick(object sender, RoutedEventArgs args) => _ = Model.SyncNowAsync();

    private void OnSettingsClick(object sender, RoutedEventArgs args) =>
        Frame.Navigate(typeof(SettingsPage), _window);

    private void OnLockClick(object sender, RoutedEventArgs args) => Model.Lock();
}
