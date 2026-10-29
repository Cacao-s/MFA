import SwiftUI
import UniformTypeIdentifiers

/// Encrypted backup export and import (spec §1, §5).
struct BackupView: View {
    enum Mode { case both, importOnly }

    @EnvironmentObject private var model: AppModel
    let mode: Mode
    let onFinished: () -> Void

    @State private var exportPassword = ""
    @State private var exportAgain = ""
    @State private var importPassword = ""
    @State private var exported: ExportedBackup?
    @State private var isPickingFile = false
    @State private var pickedFile: Data?

    var body: some View {
        Form {
            if mode == .both {
                Section {
                    SecureField("Backup password", text: $exportPassword)
                    SecureField("Password again", text: $exportAgain)
                    Button("Export…") { export() }
                        .disabled(exportPassword.count < 8 || exportPassword != exportAgain)
                } header: {
                    Text("Export")
                } footer: {
                    Text("""
                    At least 8 characters, and worth making longer: this one password \
                    protects the backup file wherever it ends up, and the key file on \
                    every sync target. MFA cannot recover it for you.
                    """)
                }
            }

            Section {
                Button(pickedFile == nil ? "Choose a backup file…" : "Choose a different file…") {
                    isPickingFile = true
                }
                if pickedFile != nil {
                    SecureField("Backup password", text: $importPassword)
                    Button("Import") {
                        if let file = pickedFile {
                            model.importBackup(file, password: importPassword)
                            onFinished()
                        }
                    }
                    .disabled(importPassword.isEmpty)
                }
            } header: {
                Text("Import")
            } footer: {
                Text("""
                Importing merges: accounts already on this device are kept, and a \
                wrong password changes nothing.
                """)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Backup")
        .fileImporter(isPresented: $isPickingFile,
                      allowedContentTypes: [.data]) { result in
            if case let .success(url) = result {
                // A sandboxed read of a user-chosen file needs the scope held
                // for the length of the read.
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                pickedFile = try? Data(contentsOf: url)
            }
        }
        .fileExporter(isPresented: Binding(get: { exported != nil },
                                           set: { if !$0 { exported = nil } }),
                      document: exported,
                      contentType: .data,
                      defaultFilename: defaultFilename) { _ in
            exported = nil
            exportPassword = ""
            exportAgain = ""
        }
    }

    private var defaultFilename: String {
        let date = Date().formatted(.iso8601.year().month().day())
        return "mfa-backup-\(date).mfabackup"
    }

    private func export() {
        guard let data = model.exportBackup(password: exportPassword) else { return }
        exported = ExportedBackup(data: data)
    }
}

/// Wraps the backup bytes so `fileExporter` can write them.
struct ExportedBackup: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    let data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
