import SwiftUI

/// Renaming an account and giving it a note.
///
/// The secret is deliberately not editable: a typo there turns a working
/// account into one that produces plausible-looking wrong codes, which is far
/// harder to diagnose than a missing account. Re-add it instead.
struct EditAccountView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let account: AccountView
    @State private var issuer: String
    @State private var name: String
    @State private var note: String

    init(account: AccountView) {
        self.account = account
        _issuer = State(initialValue: account.issuer ?? "")
        _name = State(initialValue: account.account)
        _note = State(initialValue: account.note ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Service", text: $issuer)
                    TextField("Account", text: $name)
                }
                Section {
                    TextField("Note", text: $note, axis: .vertical)
                } footer: {
                    Text("Notes are searchable. They are stored in the vault, encrypted like everything else.")
                }
                Section {
                    LabeledContent("Algorithm", value: account.algorithm)
                    LabeledContent("Digits", value: "\(account.digits)")
                    LabeledContent("Changes every", value: "\(account.period) seconds")
                } footer: {
                    Text("These came from the site and cannot be changed. Re-add the account if they are wrong.")
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Edit")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.rename(id: account.id,
                                     issuer: issuer.isEmpty ? nil : issuer,
                                     account: name)
                        model.setNote(id: account.id, note: note.isEmpty ? nil : note)
                        dismiss()
                    }
                }
            }
        }
    }
}
