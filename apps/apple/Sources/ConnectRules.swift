import Foundation

/// Build 48: connecting to a p2p host always ends — in a connection or in an error the person can
/// act on — and never in an endless "Finding your host…". Foundation only (logic-tested).
enum ConnectDeadline {
    /// The app's backstop: a little after the core's own budget (`p2pConnectTimeoutSecs()`), so
    /// the core's clearer error normally arrives first.
    static func backstop(coreSeconds: UInt32) -> Duration { .seconds(Int(coreSeconds) + 5) }

    /// Run `body`, or throw `P2PConnectTimeout` once `limit` has passed. Returns on time even if
    /// `body` ignores cancellation (a stalled core call): it is raced, not awaited — a task group
    /// would wait for every child to finish, which is exactly the hang this guards against.
    static func run<T: Sendable>(_ limit: Duration, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        let gate = OneShot<T>()
        return try await withCheckedThrowingContinuation { continuation in
            gate.arm(continuation)
            let work = Task { do { gate.resume(.success(try await body())) } catch { gate.resume(.failure(error)) } }
            Task {
                try? await Task.sleep(for: limit)
                if gate.resume(.failure(P2PConnectTimeout())) { work.cancel() }
            }
        }
    }
}

/// Resumes a continuation exactly once, whoever gets there first.
final class OneShot<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    private var pending: Result<T, Error>?

    func arm(_ c: CheckedContinuation<T, Error>) {
        lock.lock()
        if let pending { lock.unlock(); c.resume(with: pending); return }
        continuation = c
        lock.unlock()
    }

    /// True if this call was the one that resumed it.
    @discardableResult
    func resume(_ result: Result<T, Error>) -> Bool {
        lock.lock()
        if let c = continuation {
            continuation = nil
            pending = result   // marks it done
            lock.unlock()
            c.resume(with: result)
            return true
        }
        if pending == nil { pending = result; lock.unlock(); return true }
        lock.unlock()
        return false
    }
}

/// The host could not be reached in time (the app-side backstop; the core normally fails first).
struct P2PConnectTimeout: Error, CustomStringConvertible {
    var description: String { "could not reach the host: timed out" }
}

/// What the login screen says when a p2p host can't be reached, and what to try.
enum HostUnreachableHint {
    static let message = "Couldn't reach your host. Their computer may be off, asleep or offline — or this network may block the connection."
    static let tips = "Try again, or switch between Wi-Fi and cellular. On Wi-Fi, check Settings › Privacy & Security › Local Network allows Skwod."
    /// Shown only while relays are off: most networks can't reach a home computer without one.
    static let relaysOff = "Relays are off on this device, so only a direct connection can work — and most networks don't allow one to a home computer."
}

