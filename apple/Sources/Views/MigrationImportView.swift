import SwiftUI

/// Importing a Google Authenticator export.
///
/// A large export is split over several QR codes, and the whole set has to be
/// scanned before anything is imported — a partial import that looks finished
/// is the failure mode worth designing against here.
struct MigrationImportView: View {
    @EnvironmentObject private var model: AppModel
    let onFinished: () -> Void

    @State private var scanned: [String] = []
    @State private var progress: MigrationProgress?
    @State private var problem: String?

    var body: some View {
        VStack(spacing: 16) {
            #if os(iOS)
            CameraScannerView(expecting: .migration) { uri in
                add(uri)
            }
            .frame(maxHeight: 380)
            #else
            Button {
                if let data = ScreenQR.pickImage(),
                   let uris = try? decodeQrImage(image: data) {
                    uris.forEach(add)
                }
            } label: {
                Label("Read a QR code from an image", systemImage: "photo")
            }
            .buttonStyle(.borderedProminent)
            #endif

            if let progress {
                VStack(spacing: 6) {
                    Text("Scanned \(progress.scanned) of \(progress.expected)")
                        .font(.headline)
                    if !progress.complete {
                        Text(missingLine(progress))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("In Google Authenticator, choose Transfer accounts → Export.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            if let problem {
                Text(problem).font(.footnote).foregroundStyle(.red)
            }

            Button("Import \(countLabel)") {
                model.importMigration(uris: scanned)
                onFinished()
            }
            .buttonStyle(.borderedProminent)
            .disabled(progress?.complete != true)
        }
        .padding()
        .navigationTitle("Import from Google Authenticator")
    }

    private var countLabel: String {
        guard let progress, progress.complete else { return "" }
        return "(\(progress.scanned) code\(progress.scanned == 1 ? "" : "s"))"
    }

    private func missingLine(_ progress: MigrationProgress) -> String {
        let next = progress.missing.first.map { $0 + 1 }
        return next.map { "Scan code \($0) next." } ?? "Keep scanning."
    }

    private func add(_ uri: String) {
        guard uri.lowercased().hasPrefix("otpauth-migration://") else {
            problem = "That is a normal QR code, not an export. Add it from the previous screen."
            return
        }
        guard !scanned.contains(uri) else { return }

        var candidate = scanned
        candidate.append(uri)
        do {
            // Ask the core: it rejects codes from a different export, which
            // would otherwise silently lose accounts.
            progress = try migrationProgress(uris: candidate)
            scanned = candidate
            problem = nil
        } catch let MfaError.Failed(_, message) {
            problem = message
        } catch {
            problem = error.localizedDescription
        }
    }
}
