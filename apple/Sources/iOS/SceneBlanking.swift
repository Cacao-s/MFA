import SwiftUI
import UIKit

/// Keeps the codes out of the app switcher thumbnail (spec §4).
///
/// iOS takes that snapshot when the app stops being frontmost, so the cover has
/// to be up before then. `willResignActiveNotification` fires early enough; a
/// scene-phase change does not reliably.
struct SceneBlanking: ViewModifier {
    let isActive: Bool
    @State private var isCovered = false

    private let willResign = NotificationCenter.default
        .publisher(for: UIApplication.willResignActiveNotification)
    private let didBecomeActive = NotificationCenter.default
        .publisher(for: UIApplication.didBecomeActiveNotification)

    func body(content: Content) -> some View {
        content
            .overlay {
                if isActive, isCovered {
                    ZStack {
                        Rectangle().fill(.background)
                        Image(systemName: "lock.shield")
                            .font(.system(size: 48))
                            .foregroundStyle(.tint)
                    }
                    .ignoresSafeArea()
                }
            }
            .onReceive(willResign) { _ in isCovered = true }
            .onReceive(didBecomeActive) { _ in isCovered = false }
    }
}

extension View {
    func sceneBlanking(isActive: Bool) -> some View {
        modifier(SceneBlanking(isActive: isActive))
    }
}
