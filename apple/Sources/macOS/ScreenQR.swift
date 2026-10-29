import AppKit
import Foundation

/// Reading a QR code on the Mac, where there is no camera flow worth building.
///
/// Two ways in, both ending at the core's image decoder: an image file the user
/// picks, or a screen grab. The grab shells out to `screencapture`, the same
/// tool Shift-Cmd-4 uses, because it gives the user the familiar crosshair and
/// keeps us out of the screen-recording permission prompt.
enum ScreenQR {
    /// Asks for an image file and returns its bytes.
    static func pickImage() -> Data? {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.png, .jpeg, .heic, .tiff, .gif, .bmp]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose a picture of the QR code"

        guard panel.runModal() == .OK, let url = panel.url else { return nil }
        return try? Data(contentsOf: url)
    }

    /// Lets the user drag a rectangle on screen and returns the grab.
    ///
    /// Returns `nil` if they press Escape.
    static func captureScreenArea() -> Data? {
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("mfa-grab-\(UUID().uuidString).png")

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        // -i interactive, -s selection, -x no shutter sound.
        task.arguments = ["-i", "-s", "-x", destination.path]

        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            return nil
        }

        defer { try? FileManager.default.removeItem(at: destination) }
        guard task.terminationStatus == 0,
              FileManager.default.fileExists(atPath: destination.path)
        else { return nil }

        // The grab holds a secret, so it is read once and deleted straight
        // away rather than left in the temporary directory.
        return try? Data(contentsOf: destination)
    }
}
