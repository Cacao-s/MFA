import SwiftUI

/// One account in the list.
struct AccountRow: View {
    let account: AccountView
    let onCopy: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(account.issuer ?? account.account)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)

                if account.issuer != nil, !account.account.isEmpty {
                    Text(account.account)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Text(grouped(account.code))
                    .font(.system(size: 26, weight: .regular, design: .rounded))
                    .monospacedDigit()
                    // Selectable so a user can copy by hand if they would
                    // rather not trust the clipboard timer.
                    .textSelection(.enabled)
            }

            Spacer(minLength: 8)

            CountdownRing(remaining: account.remainingSecs, period: account.period)
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .onTapGesture(perform: onCopy)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(account.displayName), code \(spelled(account.code))")
        .accessibilityHint("Double tap to copy")
    }

    /// `123 456`, which is how people read a code aloud while typing it.
    private func grouped(_ code: String) -> String {
        guard code.count % 2 == 0 else { return code }
        let middle = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[code.startIndex..<middle]) \(code[middle...])"
    }

    /// Digits read one at a time, so VoiceOver does not say "one hundred and
    /// twenty-three thousand".
    private func spelled(_ code: String) -> String {
        code.map(String.init).joined(separator: " ")
    }
}
