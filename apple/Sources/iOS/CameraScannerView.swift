import AVFoundation
import SwiftUI

/// The camera scanner (spec §1).
///
/// `AVCaptureMetadataOutput` rather than Vision: the capture pipeline does the
/// detection itself, so there is no frame buffer passing through our code and
/// nothing to leak. Frames are never written anywhere.
struct CameraScannerView: View {
    enum Expecting {
        case account
        /// A Google Authenticator export, which needs several codes.
        case migration
    }

    var expecting: Expecting = .account
    let onFound: (String) -> Void

    @State private var permission: Permission = .unknown
    @State private var lastFound: String?

    private enum Permission { case unknown, granted, denied }

    var body: some View {
        ZStack {
            switch permission {
            case .granted:
                CameraPreview { payload in
                    // The camera reports the same code many times a second.
                    guard payload != lastFound else { return }
                    lastFound = payload
                    onFound(payload)
                    // Allow the same code again after a moment, so a second
                    // deliberate scan still works.
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        lastFound = nil
                    }
                }
                .overlay(alignment: .bottom) { hint }

            case .denied:
                ContentUnavailableView {
                    Label("No camera access", systemImage: "camera.slash")
                } description: {
                    Text("Allow camera access in Settings to scan a QR code, or paste the setup link instead.")
                }

            case .unknown:
                ProgressView()
            }
        }
        .background(.black)
        .task { await requestAccess() }
    }

    private var hint: some View {
        Text(expecting == .migration
             ? "Point at each export code in turn"
             : "Point at the QR code the website is showing")
            .font(.footnote)
            .padding(10)
            .background(.black.opacity(0.6), in: Capsule())
            .foregroundStyle(.white)
            .padding(.bottom, 24)
    }

    private func requestAccess() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            permission = .granted
        case .notDetermined:
            permission = await AVCaptureDevice.requestAccess(for: .video) ? .granted : .denied
        default:
            permission = .denied
        }
    }
}

/// The capture session, wrapped for SwiftUI.
private struct CameraPreview: UIViewControllerRepresentable {
    let onPayload: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onPayload = onPayload
        return controller
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {
        controller.onPayload = onPayload
    }
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onPayload: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        // Set after adding the output, or the available types are empty.
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        self.preview = preview
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        guard !session.isRunning else { return }
        // Starting the session blocks; off the main thread it is.
        Task.detached { [session] in session.startRunning() }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        session.stopRunning()
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        for object in objects {
            guard let code = object as? AVMetadataMachineReadableCodeObject,
                  let payload = code.stringValue
            else { continue }
            onPayload?(payload)
        }
    }
}
