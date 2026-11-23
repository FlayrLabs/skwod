import Foundation

/// How large one file may be on the skwod this device is talking to.
///
/// The host chooses it (`SKWOD_MAX_UPLOAD_MB`, or the Mac app's host settings) and the server
/// reports it (`GET /api/instance/limits`). This app checks a file against it BEFORE encrypting
/// and shows the real number — a courtesy to the user; the server refuses an oversized upload
/// whatever this app believes. Foundation only (compiled into the logic tests as it is).
enum UploadLimit {
    static let mib: Int64 = 1024 * 1024
    /// What every host allowed before the limit was a setting, and what a host that does not
    /// answer the question (a server older than build 45) still allows.
    static let defaultBytes: Int64 = 100 * mib
    /// The server's own bounds; an answer outside them is brought inside.
    static let minBytes: Int64 = 1 * mib
    static let maxBytes: Int64 = 1900 * mib
    /// A file that is encrypted in memory (a feed or story photo) is never larger than this,
    /// whatever the host allows: the core's single-shot encryption stops there.
    static let inMemoryBytes: Int64 = 100 * mib
    /// What the Mac app's host settings offer (megabytes).
    static let hostChoicesMB = [25, 50, 100, 250, 500, 1000, 1900]

    static func clamped(_ bytes: Int64) -> Int64 { min(max(bytes, minBytes), maxBytes) }

    /// `max_upload_bytes` from the server's answer (also carried by its 413), bounded. nil when
    /// the body is not that answer — the caller keeps what it had.
    static func parse(_ body: Data) -> Int64? {
        guard let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
              let number = object["max_upload_bytes"] as? NSNumber else { return nil }
        // A JSON `true` is an NSNumber too.
        guard CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let value = number.doubleValue
        guard value.isFinite, value >= 1 else { return nil }
        return clamped(Int64(min(value, Double(maxBytes))))
    }

    /// May a file of `size` bytes be sent? `inMemory`: it will be encrypted in one piece.
    static func allowsUpload(size: Int64, limit: Int64, inMemory: Bool = false) -> Bool {
        size >= 0 && size <= (inMemory ? min(limit, inMemoryBytes) : limit)
    }

    /// The most this app will DOWNLOAD for one attachment. Never less than the old 100 MB: a
    /// host that lowers its limit must not make files that are already there unopenable.
    static func downloadCap(limit: Int64) -> Int64 { max(clamped(limit), defaultBytes) }

    /// The most that is ever downloaded INTO MEMORY (an attachment from a build ≤ 40, which
    /// cannot be decrypted file to file). A fixed bound: whatever limit a server reports — a
    /// generous host or a hostile one — it never grows, so a claimed limit cannot be used to
    /// make this app buffer gigabytes. Larger files only ever take the streamed path.
    static func inMemoryDownloadCap(limit: Int64) -> Int64 { min(downloadCap(limit: limit), inMemoryBytes) }

    /// "100 MB", "1.5 GB" — binary units, as the host set it.
    static func label(_ bytes: Int64) -> String {
        let mb = Double(bytes) / Double(mib)
        if mb >= 1024 {
            let gb = mb / 1024
            return gb == gb.rounded() ? "\(Int(gb)) GB" : String(format: "%.1f GB", gb)
        }
        return "\(Int(mb.rounded())) MB"
    }

    static func tooLargeSentence(limit: Int64) -> String {
        "That file is too large — this Skwod's host allows up to \(label(limit)) per file."
    }

    // MARK: the limit in force

    private static let lock = NSLock()
    private static var active: (workspace: String, bytes: Int64) = ("", defaultBytes)
    private static func key(_ workspace: String) -> String { WorkspaceItems.uploadLimitPrefix + workspace }

    /// The limit of the skwod in front, as last learned (100 MB until it has been asked).
    static var current: Int64 {
        lock.lock(); defer { lock.unlock() }
        return active.bytes
    }

    /// A skwod came to the front: use what was last learned about it, until it is asked again.
    static func activate(workspace: String, defaults: UserDefaults = .standard) {
        let stored = (defaults.object(forKey: key(workspace)) as? NSNumber)?.int64Value
        lock.lock(); defer { lock.unlock() }
        guard active.workspace != workspace else { return }
        active = (workspace, stored.map(clamped) ?? defaultBytes)
    }

    /// The server answered (`bytes` nil: it does not know the question — keep the default).
    /// A skwod's local data was deleted (its stored limit goes with `WorkspaceItems.wipe`):
    /// what this run remembers of it goes too.
    static func forget(workspace: String) {
        lock.lock(); defer { lock.unlock() }
        if active.workspace == workspace { active = ("", defaultBytes) }
    }

    static func learned(_ bytes: Int64?, workspace: String, defaults: UserDefaults = .standard) {
        let value = bytes.map(clamped) ?? defaultBytes
        defaults.set(NSNumber(value: value), forKey: key(workspace))
        lock.lock(); defer { lock.unlock() }
        if active.workspace == workspace || active.workspace.isEmpty { active = (workspace, value) }
    }
}
