import Foundation

/// Why joining a call failed, stage by stage, and the one fixed sentence for it (build 51; Foundation
/// only, hostless-tested). Same rule and words as Android's `VoiceFailure.kt`
/// (`shared-test-vectors/voice-failures.json`). Nothing a host or the media engine said is ever shown:
/// their errors can carry an address.
enum VoiceFailure: String, CaseIterable {
    case off
    case starting
    case unreachable
    case noAccess = "no_access"
    case unavailable
    case portTaken = "port_taken"
    case mediaBlocked = "media_blocked"
    case mediaSilent = "media_silent"
    case other

    /// The core's `CoreError.Voice` code. What happened to the media is never a code: that is
    /// worked out here, from the tunnel's counters.
    init(code: String) {
        switch VoiceFailure(rawValue: code) {
        case .none, .mediaBlocked, .mediaSilent: self = .other
        case .some(let known): self = known
        }
    }

    var message: String {
        switch self {
        case .off: return "Voice is off on this Skwod right now. Ask the host to check it."
        case .starting: return "Voice is starting on this Skwod. Try again in a moment."
        case .unreachable: return "Couldn't reach the host. Check your connection and try again."
        case .noAccess: return "You can't join this channel. Ask the host to let you in."
        case .unavailable: return "The host didn't open the call. Try again in a moment."
        case .portTaken: return "Another call is using this device's sound and video path. End it, then try again."
        case .mediaBlocked: return "Reached the call, but this device's connection blocked its sound and video. Joining on Wi-Fi may work."
        case .mediaSilent: return "Reached the call, but sound and video didn't get through. Try again in a moment."
        case .other: return "Couldn't join the call. Try again."
        }
    }

    /// Tried once more by itself: nothing was joined yet, and waiting may be all it takes.
    var retriesOnce: Bool { self == .starting || self == .unreachable }

    /// The voice tunnel's counters (`SkwodClient.voiceTunnel`).
    struct Counters: Equatable {
        /// Signaling sockets the call server accepted.
        var accepted: UInt64
        var up: UInt64
        var down: UInt64
        /// Answers this device could not hand to the call.
        var undelivered: UInt64
    }

    /// The media engine gave up: where? This device's own network is only ever suspected when the
    /// call server accepted the signaling socket during THIS attempt, and either nothing the engine
    /// sent reached the tunnel or none of the host's answers could be handed back to it. (A socket on
    /// a point-to-point interface — cellular, some VPNs — can send to 127.0.0.1 and not be answered.)
    static func media(before: Counters?, after: Counters?) -> VoiceFailure {
        guard let before, let after else { return .other }
        guard after.accepted >= before.accepted, after.up >= before.up, after.down >= before.down,
              after.undelivered >= before.undelivered else { return .other }
        guard after.accepted > before.accepted else { return .unreachable }
        let (up, down, undelivered) = (after.up - before.up, after.down - before.down, after.undelivered - before.undelivered)
        if up == 0 { return .mediaBlocked }
        if down > 0, undelivered >= down { return .mediaBlocked }
        return .mediaSilent
    }
}

/// What the Voice row does, from the host's live status (`SkwodClient.voiceConfig`).
enum VoiceGate: Equatable {
    case join
    /// The owner's panel for a call server of their own. Never where the skwod has one built in:
    /// saving another there kept the built-in one off on every start.
    case setUp
    case say(String)

    static let notSetUp = "Voice & video isn't set up on this Skwod yet. Ask the host to turn it on."

    static func decide(configured: Bool, status: String, bundled: Bool, owner: Bool) -> VoiceGate {
        if configured { return .join }
        if status == "starting" { return .say(VoiceFailure.starting.message) }
        if bundled { return .say(VoiceFailure.off.message) }
        return owner ? .setUp : .say(notSetUp)
    }
}
