import SwiftUI

/// The ring that empties as the code expires.
///
/// Driven by the seconds the core reports rather than by its own animation
/// clock, so it cannot drift away from the code it is describing. It turns
/// amber near the end, because the useful question is "do I have time to type
/// this?" and a colour answers it faster than a number.
struct CountdownRing: View {
    let remaining: UInt32
    let period: UInt32

    private var fraction: Double {
        guard period > 0 else { return 0 }
        return Double(remaining) / Double(period)
    }

    private var isRunningOut: Bool { remaining <= 5 }

    var body: some View {
        ZStack {
            Circle()
                .stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(isRunningOut ? Color.orange : Color.accentColor,
                        style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 0.9), value: fraction)

            Text("\(remaining)")
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(isRunningOut ? Color.orange : .secondary)
        }
        .frame(width: 30, height: 30)
        .accessibilityLabel("\(remaining) seconds left")
    }
}
