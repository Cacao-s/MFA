import SwiftUI

@main
struct MFAApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .task { model.start() }
        }
        #if os(macOS)
        .defaultSize(width: 420, height: 620)
        .windowResizability(.contentSize)
        #endif
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active: model.enteredForeground()
            case .inactive, .background: model.enteredBackground()
            @unknown default: break
            }
        }

        #if os(macOS)
        Settings {
            SettingsView()
                .environmentObject(model)
                .frame(width: 460)
        }
        #endif
    }
}

/// Chooses the screen for whatever state the app is in.
struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Group {
            switch model.phase {
            case .loading:
                ProgressView()
            case .needsSetup:
                SetupView()
            case .locked:
                LockView()
            case .unlocked:
                AccountListView()
            }
        }
        .animation(.default, value: model.phase)
        .alert(item: $model.alert)
        #if os(iOS)
        // Keeps the codes out of the app switcher snapshot (spec §4).
        .sceneBlanking(isActive: model.phase == .unlocked)
        #endif
    }
}

extension View {
    /// One place for the app's alerts, so every screen reports the same way.
    func alert(item: Binding<AppModel.Alert?>) -> some View {
        alert(item.wrappedValue?.title ?? "",
              isPresented: Binding(get: { item.wrappedValue != nil },
                                   set: { if !$0 { item.wrappedValue = nil } })) {
            Button("OK", role: .cancel) { item.wrappedValue = nil }
        } message: {
            Text(item.wrappedValue?.message ?? "")
        }
    }
}
