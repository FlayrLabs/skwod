import Foundation

/// What to do when a skwod refuses this app's session. Foundation only (the logic tests compile
/// it). The rule the apps follow: **a refusal never silently signs the user out and never wipes
/// anything.** Only a real 401 from `/api/auth/me` ends the session — and even then the keys, the
/// cache and the workspace stay, and the log-in screen says what happened.
///
/// Server side (build 45, `server/src/auth.rs`): an UNBOUND session gets 403 "device bind
/// required" on nearly every route once the account has a device and the host requires bound
/// sessions. A build-45+ app binds before its first request; a freshly logged-in second device is
/// legitimately unbound until it is linked (that is the link flow, not an error).
enum SessionRefusal: Equatable {
    /// The session is over (401 on `/api/auth/me`): show "Log in again" for THIS skwod only.
    case signedOut
    /// The host speaks a newer protocol than this app: show "This Skwod's host is newer —
    /// update Skwod" with the update action. The session and everything else stay.
    case updateApp
    /// Bind this session to this install (`bindSession`) and try again.
    case bindThenRetry
    /// This install is not a device of the account yet: the "Set up this device → Link from
    /// another device" flow.
    case linkDevice
    /// Removed / superseded / a restore waiting: the existing device-state screens.
    case deviceStopped
    /// Anything else (offline, host asleep, a 5xx, a refusal of one request): keep the session,
    /// retry later.
    case transient

    /// Facts about the failure, from the error text the core gives and what the app knows.
    struct Facts: Equatable {
        /// The failure's description, as `String(describing: error)` gives it.
        var errorText: String
        /// The core's typed `UpdateRequired`.
        var updateRequired = false
        /// `sessionState()` said `.signedOut` (a 401 on `/api/auth/me`).
        var sessionSignedOut = false
        /// This install is a registered device of the account (has a device id).
        var isRegisteredDevice = true
        /// `bindSession()` was already tried for THIS client and reported success.
        var bindSucceeded = false
    }

    static func decide(_ f: Facts) -> SessionRefusal {
        let d = f.errorText.lowercased()
        // Only the typed error, or the HTTP status the core reports (the core already turns
        // every 426 into `UpdateRequired`). Never a "426" or "upgrade required" anywhere in the
        // text: the rest of it is the server's words.
        if f.updateRequired || httpStatus(d) == 426 {
            return .updateApp
        }
        if d.contains("device removed") || d.contains("device superseded") || d.contains("recovery pending") {
            return .deviceStopped
        }
        if d.contains("device bind required") {
            // Not a device yet (a second device right after log-in): link it — never "update".
            guard f.isRegisteredDevice else { return .linkDevice }
            // A device whose session is still unbound: bind it. If the server STILL demands a
            // bind after one succeeded, it wants something this app cannot give: the host is
            // newer than the app.
            return f.bindSucceeded ? .updateApp : .bindThenRetry
        }
        if d.contains("device link required") { return .linkDevice }
        // 401 on a single request is not proof: only `/api/auth/me` decides "signed out".
        if f.sessionSignedOut { return .signedOut }
        return .transient
    }

    /// The status of a core `ClientError::Status`, which the core writes as
    /// `http status <NNN>: <body>`: the FIRST "http status " (the body only comes after it),
    /// followed by exactly three digits and then ":" or the end. Nil for anything else.
    static func httpStatus(_ text: String) -> Int? {
        guard let r = text.range(of: "http status ", options: .caseInsensitive) else { return nil }
        let rest = text[r.upperBound...]
        let digits = rest.prefix(3)
        guard digits.count == 3, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        let after = rest.dropFirst(3).first
        guard after == nil || after == ":" else { return nil }
        return Int(digits)
    }

    /// The banner's words for `.updateApp`.
    static let hostNewerTitle = "This Skwod's host is newer — update Skwod"
    static let hostNewerMessage = "The host runs a newer version of Skwod than this app, so it can't open your chats until you update. Nothing was deleted: your account, keys and messages are still here."
}
