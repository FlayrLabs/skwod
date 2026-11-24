import SwiftUI
#if os(iOS)
import UIKit

/// The on-screen keyboard's frame, in window coordinates (SwiftUI's `.global`), as the system
/// announces it. `.zero` while it is hidden.
///
/// Why the chat measures the keyboard itself instead of trusting the keyboard safe area alone: on
/// iPhone the chat page lives inside the drawer's horizontal paging `ScrollView` (`DrawerPager`).
/// Whether SwiftUI hands the keyboard safe area down to a page inside a scroll view is up to the
/// scroll view (it may turn the keyboard into a content inset of its own instead), and a build
/// shipped where the composer — send button included — sat behind the keyboard on a real tap.
/// Measuring the overlap between the keyboard and the chat's own frame lifts the composer by
/// exactly what is covered, whichever way the system lays the page out: if the safe area did
/// shrink the page, the overlap is zero and nothing is added twice.
@MainActor @Observable
final class KeyboardFrame {
    static let shared = KeyboardFrame()

    private(set) var frame: CGRect = .zero
    /// The keyboard's own curve and duration, so the composer moves with it.
    private(set) var animation: Animation = .easeOut(duration: 0.25)

    @ObservationIgnored private var observers: [NSObjectProtocol] = []

    private init() {
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: UIResponder.keyboardWillChangeFrameNotification, object: nil, queue: .main) { note in
            let info = Self.read(note)
            MainActor.assumeIsolated { KeyboardFrame.shared.update(info) }
        })
        observers.append(center.addObserver(forName: UIResponder.keyboardWillHideNotification, object: nil, queue: .main) { note in
            var info = Self.read(note)
            info.frame = .zero
            MainActor.assumeIsolated { KeyboardFrame.shared.update(info) }
        })
    }

    private struct Info: Sendable { var frame: CGRect; var duration: Double }

    nonisolated private static func read(_ note: Notification) -> Info {
        let end = (note.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? NSValue)?.cgRectValue ?? .zero
        let duration = (note.userInfo?[UIResponder.keyboardAnimationDurationUserInfoKey] as? NSNumber)?.doubleValue ?? 0.25
        return Info(frame: end, duration: duration)
    }

    private func update(_ info: Info) {
        animation = .easeOut(duration: max(0.1, info.duration))
        guard info.frame != .zero, let window = Self.keyWindow else { frame = .zero; return }
        // Screen coordinates → this window's (they differ for an iPad window that isn't full screen).
        let inWindow = window.convert(info.frame, from: window.screen.coordinateSpace)
        // Off-screen (a hardware keyboard: only the shortcut bar, or nothing) counts as hidden.
        frame = inWindow.minY >= window.bounds.maxY ? .zero : inWindow
    }

    private static var keyWindow: UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow)
    }

    /// How much of a view whose bottom edge sits at `bottomY` (global) the keyboard covers.
    static func overlap(keyboard: CGRect, viewBottom bottomY: CGFloat) -> CGFloat {
        guard keyboard != .zero else { return 0 }
        return max(0, bottomY - keyboard.minY)
    }
}

extension View {
    /// Lifts this content by the part of `container`'s bottom the keyboard covers (iOS).
    /// `containerBottom` is the global maxY of the view the content sits at the bottom of.
    func keyboardLift(containerBottom: CGFloat) -> some View {
        modifier(KeyboardLiftModifier(containerBottom: containerBottom))
    }
}

private struct KeyboardLiftModifier: ViewModifier {
    let containerBottom: CGFloat
    private var keyboard: KeyboardFrame { .shared }

    func body(content: Content) -> some View {
        let lift = KeyboardFrame.overlap(keyboard: keyboard.frame, viewBottom: containerBottom)
        content
            .padding(.bottom, lift)
            .animation(keyboard.animation, value: lift)
    }
}
#endif
