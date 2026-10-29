import SwiftUI

/// Typing a key in by hand, for sites that print the secret instead of showing
/// a QR code.
struct ManualEntryView: View {
    @EnvironmentObject private var model: AppModel
    let onAdded: () -> Void

    @State private var issuer = ""
    @State private var account = ""
    @State private var secret = ""
    @State private var algorithm = "SHA1"
    @State private var digits = 6
    @State private var period = 30
    @State private var isShowingAdvanced = false

    private var canAdd: Bool {
        !secret.trimmingCharacters(in: .whitespaces).isEmpty
            && !(issuer.isEmpty && account.isEmpty)
    }

    var body: some View {
        Form {
            Section {
                TextField("Service", text: $issuer, prompt: Text("GitHub"))
                TextField("Account", text: $account, prompt: Text("you@example.com"))
            } footer: {
                Text("At least one of these, so you can tell the account apart later.")
            }

            Section {
                TextField("Setup key", text: $secret, prompt: Text("JBSW Y3DP EHPK 3PXP"), axis: .vertical)
                    .font(.body.monospaced())
                    #if os(iOS)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    #endif
            } footer: {
                Text("Spaces and capitals do not matter.")
            }

            Section(isExpanded: $isShowingAdvanced) {
                Picker("Algorithm", selection: $algorithm) {
                    ForEach(["SHA1", "SHA256", "SHA512"], id: \.self) { Text($0) }
                }
                Picker("Digits", selection: $digits) {
                    ForEach([6, 7, 8], id: \.self) { Text("\($0)") }
                }
                Picker("Changes every", selection: $period) {
                    Text("30 seconds").tag(30)
                    Text("60 seconds").tag(60)
                }
            } header: {
                Text("Advanced")
            } footer: {
                Text("""
                Almost every site uses SHA1, 6 digits and 30 seconds. Only change \
                these if the site told you to.
                """)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Enter a key")
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Add") {
                    model.add(draft: AccountDraft(
                        issuer: issuer.isEmpty ? nil : issuer,
                        account: account,
                        secret: secret,
                        algorithm: algorithm,
                        digits: UInt8(digits),
                        period: UInt32(period)
                    ))
                    onAdded()
                }
                .disabled(!canAdd)
            }
        }
    }
}
