import Foundation
#if canImport(UIKit)
import UIKit
import UniformTypeIdentifiers
#else
import AppKit
#endif

/// Copying a code, and clearing it again (spec §4).
///
/// This is `mfa_core::platform::Clipboard` on Apple platforms. The two
/// platforms differ in a way worth knowing: iOS can hand the expiry to the OS,
/// so the code disappears even if the app is killed, while macOS has no such
/// facility and the best available is a timer that checks the pasteboard still
/// holds our code before clearing it.
enum Clipboard {
    /// Copies `code`, arranging for it to be cleared after `seconds`.
    ///
    /// Returns whether the clearing can actually be promised, so the UI does
    /// not tell the user something the platform will not do.
    @discardableResult
    @MainActor
    static func copy(code: String, clearAfter seconds: UInt32) -> Bool {
        #if canImport(UIKit)
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: code]],
            options: [.expirationDate: Date().addingTimeInterval(TimeInterval(seconds))]
        )
        // The OS owns the expiry from here, so this holds even if the app dies.
        return true
        #else
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(code, forType: .string)
        let writtenChange = pasteboard.changeCount

        Task { @MainActor in
            try? await Task.sleep(for: .seconds(Double(seconds)))
            // Only clear if nothing else has written since: wiping something
            // the user copied afterwards would be worse than leaving the code.
            guard NSPasteboard.general.changeCount == writtenChange else { return }
            NSPasteboard.general.clearContents()
        }
        // The timer dies with the app, so this is a best effort and the UI
        // should say "about 30 seconds" rather than promise it.
        return false
        #endif
    }
}
