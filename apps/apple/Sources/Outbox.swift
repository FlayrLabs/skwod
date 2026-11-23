import SwiftUI

/// Where a message of mine stands on its way out (the core's outbox, `queue…` + `flushOutbox`).
/// A delivered message has no state.
enum SendState: Hashable {
    case sending
    /// The server refused it (or it cannot be delivered as it is): shown with the reason and
    /// Retry / Discard.
    case failed(localId: String, reason: String)
}

extension Notification.Name {
    /// The outbox changed (something was queued, delivered or failed): open conversations redraw.
    static let skwodOutboxChanged = Notification.Name("skwod.outboxChanged")
}

/// Everything a person sends — chat, posts, stories, comments, game moves, forwards, edits,
/// deletes, reactions, and the DM counterparts — is queued in the core and delivered when the
/// network allows, once. This is the app's thin side of it: kick a flush, read the states.
@MainActor
enum Outbox {
    private static var running = false
    private static var again = false
    /// Messages the user composed that are waiting to be accepted (for the sent sound).
    private static var composedWaiting = 0

    /// Deliver what is queued (coalesced: a burst of sends makes one pass, then one more).
    /// Call after queueing, when the live connection comes up, and on the slow safety timers.
    static func flush(_ app: AppState) async {
        guard let client = app.client else { return }
        if running { again = true; return }
        running = true
        defer { running = false }
        repeat {
            again = false
            let report = await client.flushOutbox()
            #if DEBUG
            E2E.sawOutbox(sent: Int(report.sent), pending: Int(report.pending), failed: Int(report.failed))
            #endif
            // The sent sound: when the server took something the user wrote — not on tap.
            if MessageAlert.sentSound(composedWaiting: composedWaiting, accepted: Int(report.sent), soundOn: SoundSettings.sent) {
                SoundPlayer.play(.sent)
            }
            if report.sent > 0 || report.pending == 0 { composedWaiting = 0 }
            NotificationCenter.default.post(name: .skwodOutboxChanged, object: nil)
        } while again
    }

    /// Queue-and-go: flush in the background.
    /// `composed`: the user wrote and sent this (a message, an edit) — as opposed to what the
    /// app queues by itself (likes, comments, game moves), which makes no sound.
    static func kick(_ app: AppState, composed: Bool = false) {
        if composed { composedWaiting += 1 }
        NotificationCenter.default.post(name: .skwodOutboxChanged, object: nil)
        Task { await flush(app) }
    }

    /// The send state of every queued message of `scope` (`channel:<id>` / `dm:<id>`), by
    /// message id — and the first sentence to show for an edit, delete or reaction that failed
    /// (those have no row to hang a state on; they are dropped once reported).
    static func states(_ client: SkwodClient, scope: String) async -> (byMessage: [String: SendState], problem: String?) {
        var out: [String: SendState] = [:]
        var problem: String?
        for p in await client.pendingSends(scope: scope) {
            if p.kind == "send" {
                out[p.messageId] = p.state == "failed" ? .failed(localId: p.localId, reason: p.error ?? "This message wasn't sent.") : .sending
            } else if p.state == "failed" {
                if problem == nil { problem = p.error ?? "That change could not be made." }
                await client.discardSend(localId: p.localId)
            }
        }
        return (out, problem)
    }

    static func retry(_ app: AppState, localId: String) {
        Task {
            await app.client?.retrySend(localId: localId)
            await flush(app)
        }
    }

    static func discard(_ app: AppState, localId: String) {
        Task {
            await app.client?.discardSend(localId: localId)
            NotificationCenter.default.post(name: .skwodOutboxChanged, object: nil)
        }
    }
}

/// "Sending…" / "Not delivered — reason · Retry · Discard" under a message of mine. A send
/// that reached nobody (every device of the contact held, say) is a failure here, never "sent".
struct SendStateLine: View {
    let state: SendState
    var onRetry: ((String) -> Void)?
    var onDiscard: ((String) -> Void)?

    var body: some View {
        switch state {
        case .sending:
            HStack(spacing: 5) {
                Image(systemName: "clock").font(.system(size: 9))
                Text("Sending…").font(.system(size: 10))
            }
            .foregroundStyle(.white.opacity(0.4))
            .accessibilityLabel("Sending")
        case .failed(let localId, let reason):
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.circle.fill").font(.system(size: 11)).foregroundStyle(.orange)
                Text("Not delivered — \(IdentityHold.isIdentityFailure(reason) ? "on hold until you accept or verify their new security key" : reason)")
                    .font(.system(size: 11)).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                if let onRetry {
                    Button("Retry") { onRetry(localId) }.buttonStyle(.plain)
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(Color.skAccent)
                }
                if let onDiscard {
                    Button("Discard") { onDiscard(localId) }.buttonStyle(.plain)
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(.white.opacity(0.6))
                }
            }
        }
    }
}
