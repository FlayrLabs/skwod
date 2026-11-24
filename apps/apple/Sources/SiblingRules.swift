import Foundation

/// Build 49: what this device takes from the state one of its OWN other devices hands over
/// (`share_with_siblings` / `take_sibling_payloads`; sealed between our verified devices, the
/// host relays ciphertext only). The core already merged the safety-number verifications under
/// its own rules and lists the contacts whose devices it sees differently (`mismatched`): those
/// are skipped here entirely. Foundation only: the logic tests compile it.
enum SiblingRules {
    /// One synced contact against what this device has (`book`: the book as merged so far,
    /// local entries first). A name the user set here (known or verified) always wins; a synced
    /// name never counts for more than KNOWN here — VERIFIED comes only from the core's own
    /// verification state for exactly the devices this device holds (`noteVerification`) — and
    /// only UNVERIFIED when it looks like someone the user knows or has characters no Skwod name
    /// has. Only users the sender's identity snapshot vouches for (`vouched`) and that it does
    /// not hold under other keys are taken. Nil = leave the book as it is.
    static func mergedContact(userId: String, local: Contact?, synced: Contact, vouched: Bool, mismatched: Bool,
                              book: [String: Contact], roster: [String: String] = [:]) -> Contact? {
        if mismatched || !vouched { return nil }
        if let local, local.level >= .known { return nil }
        guard !synced.name.isEmpty else { return nil }
        let suspicious = ContactTrust.collides(userId: userId, name: synced.name, book: book, roster: roster)
            || WaitingTrust.hasUnusualCharacters(synced.name)
        // KNOWN only for someone the sibling's user made known themself; a verified-only entry
        // (known == false) stays UNVERIFIED — the core decides VERIFIED, and un-verifying then
        // returns it to UNVERIFIED.
        let known = !suspicious && synced.explicitlyKnown
        let level: TrustLevel = known ? .known : .unverified
        let merged = Contact(name: synced.name, level: max(local?.level ?? .unverified, level), known: known || local?.known == true)
        return merged == local ? nil : merged
    }

    /// Merge a whole synced book into `local`, entry by entry against the growing result (so a
    /// synced name can never collide its way past a name pinned here, nor past one taken a
    /// moment earlier). Returns the merged book.
    static func mergedBook(local: [String: Contact], synced: [String: Contact], vouched: Set<String>, mismatched: Set<String>,
                           roster: [String: String] = [:]) -> [String: Contact] {
        var book = local
        for userId in synced.keys.sorted().prefix(2000) where !userId.isEmpty && userId.count <= 128 {
            guard let contact = synced[userId] else { continue }
            if let merged = mergedContact(userId: userId, local: book[userId], synced: contact,
                                          vouched: vouched.contains(userId), mismatched: mismatched.contains(userId),
                                          book: book, roster: roster) {
                book[userId] = merged
            }
        }
        return book
    }

    /// One avatar entry as a sibling sends it (the same shape as an avatar pointer).
    struct AvatarEntry: Codable, Equatable {
        var key: String
        var img: String?
        var ts: Int64
    }

    /// Per picture and per batch, at most (an avatar is a 256 px JPEG of a few tens of kB).
    static let maxAvatarBytes = 96 * 1024
    /// Decoded picture bytes taken from one payload.
    static let maxBatchBytes = 120 * 1024
    /// Base64 characters put in one payload when sending (the core takes 120 KiB per payload,
    /// JSON included).
    static let sendBudget = 110_000

    /// The avatar entries to take: well-formed keys; a `user:` key only for a user the sender's
    /// snapshot vouches for and not held under other keys here; newer than what is held or
    /// cleared here; a picture decodable as a small image (`acceptable`) within the per-picture
    /// and per-batch caps — or `img == nil`, a clear (tombstone), which also wins when newer.
    /// Returns key → (bytes or nil for a clear, ts).
    static func acceptedAvatars(_ entries: [AvatarEntry], vouched: Set<String>, mismatched: Set<String>, heldTs: [String: Int64], now: Int64,
                                acceptable: (Data) -> Bool) -> [String: (data: Data?, ts: Int64)] {
        var out: [String: (data: Data?, ts: Int64)] = [:]
        var total = 0
        for e in entries.prefix(64) {
            guard e.key.hasPrefix("user:") || e.key.hasPrefix("server:") || e.key.hasPrefix("skwod:"), e.key.count <= 200 else { continue }
            if e.key.hasPrefix("user:") {
                let user = String(e.key.dropFirst(5))
                if mismatched.contains(user) || !vouched.contains(user) { continue }
            }
            guard e.ts > 0, e.ts <= now + 5 * 60 * 1000, (heldTs[e.key] ?? 0) < e.ts, (out[e.key]?.ts ?? 0) < e.ts else { continue }
            guard let img = e.img, !img.isEmpty else {
                out[e.key] = (nil, e.ts)   // cleared on the sibling after what is held here
                continue
            }
            guard img.utf8.count <= maxAvatarBytes * 4 / 3 + 4,
                  let bytes = Data(base64Encoded: img), bytes.count <= maxAvatarBytes,
                  total + bytes.count <= maxBatchBytes, acceptable(bytes) else { continue }
            total += bytes.count
            out[e.key] = (bytes, e.ts)
        }
        return out
    }

    /// Split avatar entries into batches that each fit one sibling payload (own first: `first`).
    static func batches(_ entries: [AvatarEntry], first: String?, limit: Int = sendBudget, maxBatches: Int = 8) -> [[AvatarEntry]] {
        let ordered = entries.sorted { a, b in
            if a.key == first { return true }
            if b.key == first { return false }
            return a.ts > b.ts
        }
        var out: [[AvatarEntry]] = []
        var current: [AvatarEntry] = []
        var size = 0
        for e in ordered {
            let n = (e.img?.utf8.count ?? 0) + e.key.utf8.count + 32
            // A clear (no picture) travels too: it must win over an older picture elsewhere.
            guard (e.img?.utf8.count ?? 0) * 3 / 4 <= maxAvatarBytes, n <= limit else { continue }
            if size + n > limit, !current.isEmpty {
                out.append(current)
                if out.count == maxBatches { return out }
                current = []; size = 0
            }
            current.append(e); size += n
        }
        if !current.isEmpty, out.count < maxBatches { out.append(current) }
        return out
    }
}
