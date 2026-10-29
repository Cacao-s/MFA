using Microsoft.UI.Xaml;

namespace MFA;

public partial class App : Application
{
    /// <summary>
    /// The main window.
    /// </summary>
    /// <remarks>
    /// Exposed because an unpackaged WinUI app has to tell a file picker which
    /// window owns it, or the picker throws instead of opening.
    /// </remarks>
    internal static Window? MainWindow { get; private set; }

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        MainWindow = new MainWindow();
        MainWindow.Activate();
    }
}
