import SwiftUI

/// Who is typing in the open conversation, for the bar above the composer (build 46).
@MainActor
final class TypingCenter: ObservableObject {
    @Published private(set) var state = TypingState()
    private var throttle = TypingSendThrottle()
    private weak var app: AppState?
    private var sweep: Task<Void, Never>?
    /// Who may show as typing in the conversation on screen (set by its chat surface).
    @Published private var audience: TypingAudience?

    func attach(_ app: AppState) {
        self.app = app
        app.realtime.onTyping = { [weak self] topic, uid in
            Task { @MainActor in self?.received(topic: topic, userId: uid) }
        }
        app.realtime.onPosted = { [weak self] _, author in
            Task { @MainActor in self?.state.messageArrived(from: author) }
        }
    }

    var enabled: Bool { TypingSetting.isOn() }

    private func received(topic: String, userId: String) {
        guard let app else { return }
        state.focus(app.realtime.focusedTopic)
        state.received(userId: userId, topic: topic, me: app.realtime.currentUserId,
                       blocked: BlockList.shared.ids, audience: audience, enabled: enabled, now: Date())
        scheduleSweep()
    }

    /// Drop typers whose last event is older than the lifetime, so the bar clears by itself.
    private func scheduleSweep() {
        sweep?.cancel()
        sweep = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self else { return }
                self.state.expire(now: Date())
                if self.state.typers.isEmpty { return }
            }
        }
    }

    /// The composer changed in the open conversation.
    func draftChanged(_ draft: String) {
        guard let app, let topic = app.realtime.focusedTopic else { return }
        if throttle.shouldSend(draft: draft, enabled: enabled, now: Date()) { app.realtime.sendTyping(topic: topic) }
    }

    /// Sent, or the conversation changed: stop saying "typing" and start fresh.
    func stoppedTyping() { throttle.reset() }

    func focus(_ topic: String?) { state.focus(topic) }

    /// The conversation on screen and its people: nobody else is shown as typing there.
    func setAudience(_ audience: TypingAudience) { self.audience = audience }

    /// The names to show, through the contact book's trust rules (never a claimed name as is).
    func labels(now: Date) -> [String] {
        // Only for the conversation they were typing in, and only with the setting on.
        guard let app, enabled, state.topic != nil, state.topic == app.realtime.focusedTopic else { return [] }
        return state.names(now: now, audience: audience) { app.contacts.display($0, claimedName: $1).label(for: .typing) }
    }
}

private struct TypingCenterKey: EnvironmentKey {
    static let defaultValue: TypingCenter? = nil
}

extension EnvironmentValues {
    var typingCenter: TypingCenter? {
        get { self[TypingCenterKey.self] }
        set { self[TypingCenterKey.self] = newValue }
    }
}

/// "Sam is typing…" with three small pulsing dots, just above the composer. Takes its line
/// of space only while someone is typing.
struct TypingIndicatorBar: View {
    @ObservedObject var center: TypingCenter

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if let text = TypingState.text(center.labels(now: context.date)) {
                HStack(spacing: 6) {
                    TypingDots()
                    Text(text).font(.system(size: 12, weight: .medium)).foregroundStyle(.white.opacity(0.6))
                        .lineLimit(1)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 20).padding(.top, 2)
                .transition(.opacity)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("chat.typing")
            }
        }
    }
}

private struct TypingDots: View {
    var body: some View {
        TimelineView(.animation(minimumInterval: 0.15)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            HStack(spacing: 3) {
                ForEach(0..<3, id: \.self) { i in
                    Circle().fill(.white.opacity(0.65)).frame(width: 4, height: 4)
                        .opacity(0.35 + 0.65 * max(0, sin((t * 4) - Double(i) * 0.8)))
                }
            }
        }
    }
}
