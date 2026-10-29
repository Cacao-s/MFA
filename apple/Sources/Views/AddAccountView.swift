import SwiftUI

/// The ways an account can get in (spec §1).
struct AddAccountView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var route: Route?
    @State private var pasted = ""

    private enum Route: Hashable, Identifiable {
        case scan, manual, migration
        var id: Self { self }
    }

    var body: some View {
        NavigationStack {
            List {
                #if os(iOS)
                Button { route = .scan } label: {
                    Label("Scan a QR code", systemImage: "qrcode.viewfinder")
                }
                #else
                Button { pickImage() } label: {
                    Label("Read a QR code from an image", systemImage: "photo")
                }
                #endif

                Section("Paste a setup link") {
                    TextField("otpauth://totp/…", text: $pasted, axis: .vertical)
                        .textFieldStyle(.plain)
                        .font(.footnote.monospaced())
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        #endif

                    Button("Add from link") {
                        if model.add(uri: pasted.trimmingCharacters(in: .whitespacesAndNewlines)) {
                            dismiss()
                        }
                    }
                    .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }

                Section {
                    Button { route = .manual } label: {
                        Label("Enter a key by hand", systemImage: "keyboard")
                    }
                    Button { route = .migration } label: {
                        Label("Import from Google Authenticator", systemImage: "square.and.arrow.down")
                    }
                } footer: {
                    Text("""
                    Authy cannot be imported: it has no export. You will need to \
                    turn two-factor authentication off and on again at each site.
                    """)
                }
            }
            .navigationTitle("Add account")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .navigationDestination(item: $route) { route in
                switch route {
                #if os(iOS)
                case .scan:
                    CameraScannerView { uri in
                        if model.add(uri: uri) { dismiss() }
                    }
                #else
                case .scan: EmptyView()
                #endif
                case .manual:
                    ManualEntryView { dismiss() }
                case .migration:
                    MigrationImportView { dismiss() }
                }
            }
        }
    }

    #if os(macOS)
    private func pickImage() {
        guard let data = ScreenQR.pickImage() else { return }
        do {
            let uris = try decodeQrImage(image: data)
            // A screen grab can hold several codes; a migration export is a
            // different flow, so hand those over whole.
            if uris.contains(where: { $0.lowercased().hasPrefix("otpauth-migration://") }) {
                model.importMigration(uris: uris.filter {
                    $0.lowercased().hasPrefix("otpauth-migration://")
                })
                dismiss()
                return
            }
            var added = 0
            for uri in uris where model.add(uri: uri) { added += 1 }
            if added > 0 { dismiss() }
        } catch {
            model.alert = AppModel.Alert(
                title: "No code found",
                message: "That image does not contain a QR code MFA can read."
            )
        }
    }
    #endif
}
