import CryptoKit
import Foundation

/// A content-derived revision, for targets that do not hand one out.
///
/// Content rather than a timestamp, so two devices looking at the same bytes
/// agree, and a file restored from a backup cannot reuse a revision for
/// different content.
enum Revision {
    static func of(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}
