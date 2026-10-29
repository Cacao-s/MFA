using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using MFA.Platform;
using MFA.Views;

namespace MFA;

/// <summary>
/// The window, and the only place that owns the once-a-second tick.
/// </summary>
/// <remarks>
/// One timer for the whole app, rather than one per row: the list is a pure
/// function of the vault and the time, so re-reading it is all that is needed
/// and the countdown rings cannot drift away from the codes they describe.
/// </remarks>
public sealed partial class MainWindow : Window
{
    internal AppModel Model { get; } = new();

    private readonly DispatcherQueueTimer _ticker;

    public MainWindow()
    {
        InitializeComponent();

        _ticker = DispatcherQueue.CreateTimer();
        _ticker.Interval = TimeSpan.FromSeconds(1);
        _ticker.Tick += (_, _) => Model.Refresh();

        Model.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(AppModel.Current)) ShowCurrentPhase();
            if (args.PropertyName == nameof(AppModel.PendingNotice)) _ = ShowNoticeAsync();
        };

        // Activated covers both directions, which is what the background
        // timeout needs.
        Activated += (_, args) =>
        {
            if (args.WindowActivationState == WindowActivationState.Deactivated)
            {
                Model.EnteredBackground();
            }
            else
            {
                Model.EnteredForeground();
            }
        };

        Closed += (_, _) => _ticker.Stop();

        Model.Start();
        ShowCurrentPhase();
    }

    private void ShowCurrentPhase()
    {
        LockPanel.Visibility = Visibility.Collapsed;
        SetupPanel.Visibility = Visibility.Collapsed;
        Content.Visibility = Visibility.Collapsed;

        switch (Model.Current)
        {
            case AppModel.Phase.NeedsSetup:
                _ticker.Stop();
                SetupPanel.Visibility = Visibility.Visible;
                break;

            case AppModel.Phase.Locked:
                _ticker.Stop();
                LockPanel.Visibility = Visibility.Visible;
                _ = PromptAsync();
                break;

            case AppModel.Phase.Unlocked:
                Content.Visibility = Visibility.Visible;
                if (Content.Content is null) Content.Navigate(typeof(AccountListPage), this);
                _ticker.Start();
                break;
        }
    }

    private async Task PromptAsync()
    {
        UnlockButton.IsEnabled = false;
        LockProblem.Visibility = Visibility.Collapsed;

        switch (await WindowsHello.AuthenticateAsync("Unlock your verification codes"))
        {
            case WindowsHello.Outcome.Succeeded:
                Model.OnUnlocked();
                break;

            case WindowsHello.Outcome.Cancelled:
                break;

            case WindowsHello.Outcome.Failed:
                LockProblem.Text = await WindowsHello.CheckAsync() == WindowsHello.Capability.Unavailable
                    ? "Windows Hello is not set up on this machine, so MFA cannot verify who you are. " +
                      "Set up Hello, or turn the lock off from another device that syncs."
                    : "Windows could not verify you. Try again.";
                LockProblem.Visibility = Visibility.Visible;
                break;
        }

        UnlockButton.IsEnabled = true;
    }

    private void OnUnlockClick(object sender, RoutedEventArgs args) => _ = PromptAsync();

    private void OnStartFreshClick(object sender, RoutedEventArgs args) => Model.CreateVault();

    private void OnRestoreClick(object sender, RoutedEventArgs args)
    {
        // Restoring needs a vault to merge into, so make one first.
        Model.CreateVault();
        if (Model.Current == AppModel.Phase.Unlocked)
        {
            Content.Navigate(typeof(SettingsPage), this);
        }
    }

    private async Task ShowNoticeAsync()
    {
        if (Model.PendingNotice is not { } notice) return;
        Model.PendingNotice = null;

        var dialog = new Microsoft.UI.Xaml.Controls.ContentDialog
        {
            XamlRoot = Root.XamlRoot,
            Title = notice.Title,
            Content = new Microsoft.UI.Xaml.Controls.TextBlock
            {
                Text = notice.Body,
                TextWrapping = TextWrapping.Wrap,
            },
            CloseButtonText = "OK",
        };
        await dialog.ShowAsync();
    }
}
