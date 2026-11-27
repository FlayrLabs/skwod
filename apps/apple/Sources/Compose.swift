import Foundation

// What a person sends goes where they sent it (build 51). Foundation only.

/// One thing someone sent, as it was at the tap: from which skwod, to which conversation and whom,
/// and what. Taken in one step — nothing is read again after it, so a conversation or a skwod opened
/// a moment later changes nothing about it.
struct SendOrder: Equatable {
    enum Place: Equatable {
        case channel(String)
        case direct(conversationId: String, peers: [String])
    }
    let workspaceId: String
    let place: Place
    let text: String
    var replyTo: String?
    var editing: String?
}

enum Compose {
    enum Taken: Equatable {
        case send(SendOrder)
        /// There is no open cache of that skwod right now (the app is opening it): nothing is taken,
        /// the text stays where it is, and the composer says so. Never another skwod's cache.
        case opening
        case nothing
    }

    static let opening = "Opening… Your message is still here — send it again in a moment."

    /// `home`: the skwod the conversation on screen belongs to. `bound`: the one whose cache is open.
    static func take(text: String, home: String?, bound: String?, place: SendOrder.Place, replyTo: String? = nil, editing: String? = nil) -> Taken {
        let text = text.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return .nothing }
        guard let home, !home.isEmpty, home == bound else { return .opening }
        return .send(SendOrder(workspaceId: home, place: place, text: text, replyTo: replyTo, editing: editing))
    }

    /// Text that could not be queued comes back to its own composer, before whatever was typed since.
    static func givenBack(_ text: String, to draft: String) -> String {
        draft.isEmpty ? text : "\(text)\n\(draft)"
    }

    /// A direct conversation's key: its view's identity, and what its draft is kept under.
    static func directKey(workspaceId: String?, conversationId: String) -> String { "\(workspaceId ?? "")|dm|\(conversationId)" }
}

/// Has THIS client's server pin been applied? Only such a client is ever given a way to its host.
enum PinState: Equatable {
    /// Not looked at yet.
    case unchecked
    /// The saved key could not be applied: nothing of it goes to any host.
    case failed
    /// Applied — this key (nil: the skwod has none saved, and what the host says first is trusted).
    case applied(key: String?)
}

/// A client that was put up offline goes online — if its pin was applied, is the one saved NOW, and
/// can be applied again; and only while it is still the one that is up.
@MainActor
struct GoOnline<Client: AnyObject> {
    let up: BoundClient<Client>
    /// The key saved for the skwod right now.
    let pinned: String?
    var isCurrent: () -> Bool
    /// The core: the pin, then the way to the host, then the session — or an error and no change.
    var goOnline: (_ client: Client, _ pinned: String?) async throws -> Void
    /// An error that says the pin itself could not be applied.
    var isPinError: (Error) -> Bool
    var renew: () -> Int?
    /// The client that is up is marked: its pin could not be applied.
    var failPin: () -> Void

    enum Outcome: Equatable {
        /// Online, as this turn.
        case online(turn: Int)
        /// Not a client to take online (or the core could not take it online): it is bound anew.
        case notThisOne
        case superseded
        /// The pin could not be applied: it stays without a way to any host.
        case pinFailed
    }

    func run() async -> Outcome {
        guard up.cacheOpen else { return .notThisOne }
        switch up.pin {
        case .failed: return .pinFailed
        case .unchecked: return .notThisOne
        case .applied(let key) where key != pinned: return .notThisOne
        case .applied: break
        }
        do { try await goOnline(up.client, pinned) } catch {
            if isPinError(error) {
                guard isCurrent() else { return .superseded }
                failPin()
                return .pinFailed
            }
            // Anything else (the host not reached, this install superseded): the core kept the
            // client's old way, so it is still offline — it is bound anew, on the host, whose own
            // bind retries and routes a superseded or removed device.
            guard isCurrent() else { return .superseded }
            return .notThisOne
        }
        guard isCurrent(), let turn = renew() else { return .superseded }
        return .online(turn: turn)
    }
}
