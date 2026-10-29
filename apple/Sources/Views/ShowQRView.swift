import CoreImage.CIFilterBuiltins
import SwiftUI

/// Shows an account as a QR code, for moving it to another app or another
/// authenticator.
///
/// **This puts the secret on screen**, so it is behind a deliberate tap, it
/// says so, and the code is only generated while the sheet is open.
struct ShowQRView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let account: AccountView
    @State private var isRevealed = false
    @State private var image: CGImage?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Text(account.displayName).font(.headline)

                if isRevealed, let image {
                    Image(decorative: image, scale: 1)
                        .interpolation(.none)
                        .resizable()
                        .aspectRatio(1, contentMode: .fit)
                        .frame(maxWidth: 260)
                        .padding(8)
                        .background(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                } else {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(.quaternary)
                        .aspectRatio(1, contentMode: .fit)
                        .frame(maxWidth: 260)
                        .overlay {
                            VStack(spacing: 12) {
                                Image(systemName: "eye.slash").font(.largeTitle)
                                Text("Hidden").foregroundStyle(.secondary)
                            }
                        }
                }

                Text("""
                This QR code contains the secret key for this account. Anyone who \
                photographs it can generate your codes. Make sure nobody is \
                looking, and that you are not sharing your screen.
                """)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

                Button(isRevealed ? "Hide" : "Show the code") {
                    if isRevealed {
                        isRevealed = false
                        image = nil
                    } else {
                        generate()
                    }
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(24)
            .navigationTitle("Move this account")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func generate() {
        guard let uri = model.exportURI(id: account.id) else { return }

        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(uri.utf8)
        // Medium: enough redundancy for a camera to read off a screen without
        // making the modules too small to resolve.
        filter.correctionLevel = "M"

        guard let output = filter.outputImage else { return }
        // Nearest-neighbour scale: a blurred QR code is an unreadable one.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        image = CIContext().createCGImage(scaled, from: scaled.extent)
        isRevealed = image != nil
    }
}
