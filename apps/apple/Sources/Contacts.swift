import SwiftUI

// `ContactTrust` — the one rule set for showing a person's name — is in `NameTrust.swift`.

/// The local contact book of the active skwod: user id → the name this device uses and how far
/// it trusts it. Kept apart from the DM list (a conversation is not a statement of trust) and
/// stored in the workspace's encrypted cache.
@MainActor
final class ContactBook: ObservableObject {
    @Published private(set) var entries: [String: Contact] = [:]
    /// Accepted members of the servers the user shares (user id → the server's name for them):
    /// listed, not held by the core, not waiting to be let in. The collision set for the
    /// impersonation warning, together with known/verified contacts. Not persisted.
    @Published private(set) var roster: [String: String] = [:]
    private var rosterByServer: [String: [String: String]] = [:]
    /// "user id|name" → whether the directory lookup of that name led to that account.
    @Published private(set) var lookups: [String: Bool] = [:]
    private var lookingUp: Set<String> = []
    private weak var app: AppState?
    private var loadedFor: String?
    /// The last write of the book did not go through.
    private var unsaved = false
    /// Write the book again if its last write failed (called once a client is bound).
    func retrySave() { if unsaved, loadedFor != nil { save() } }
    /// Was the book READ for this workspace? Until then nobody's name counts as trusted.
    func isLoaded(for workspaceId: String) -> Bool { !workspaceId.isEmpty && loadedFor == workspaceId }

    func bind(_ app: AppState) { self.app = app }

    private var key: String? { app?.current.map { "\($0.id)|contacts.v1" } }

    /// Load the active workspace's book (once per workspace) — only through a client that has
    /// that workspace's cache OPEN. Without it there is nothing to read: the book is not marked
    /// loaded (an empty book would later be written over the real one) and the next bind loads it.
    func loadIfNeeded() async {
        guard let app, let wid = app.current?.id, loadedFor != wid,
              let bound = app.bound, bound.workspaceId == wid, bound.cacheOpen, let key else { return }
        let client = bound.client
        // STRICT (`kv_read`): the book holds who the user verified and who they know. A read
        // that fails is not an empty book — nothing is marked loaded, nothing is written, and
        // the next call reads again.
        let json: String?
        do { json = try await client.kvRead(key: key) } catch { return }
        guard app.bound?.workspaceId == wid, app.bound?.turn == bound.turn, app.current?.id == wid, loadedFor != wid else { return }
        var stored: [String: Contact] = [:]
        var keptAs: String?
        if let json, !json.isEmpty {
            if let decoded = try? JSONDecoder().decode([String: Contact].self, from: Data(json.utf8)) {
                stored = decoded
            } else {
                // Read, but not decodable: the bytes are kept under a key of their own (read
                // back) BEFORE the book continues with what can be salvaged. An entry that
                // cannot be read comes back as unverified at most — never as trusted.
                let side = "\(key).unreadable.\(Int64(Date().timeIntervalSince1970 * 1000))"
                do {
                    try await client.kvWrite(key: side, value: json)
                    guard try await client.kvRead(key: side) == json else { return }
                } catch { return }
                guard app.bound?.workspaceId == wid, app.bound?.turn == bound.turn, loadedFor != wid else { return }
                stored = Self.salvage(json)
                keptAs = side
            }
        }
        loadedFor = wid
        entries = stored
        if let keptAs {
            save()
            await app.logSecurity(kind: "contacts_unreadable", title: "Your contact list could not be read",
                                  message: "The list of people you know and have verified, which Skwod keeps on this device, could not be fully read. Skwod kept what it could read; anyone it could not read is shown as unverified again until you confirm them. Nothing was deleted: the data as it was is kept on this device (as “\(keptAs)”).",
                                  atMs: Int64(Date().timeIntervalSince1970 * 1000))
        }
    }

    /// The entries of a stored book that does not decode as a whole, one by one.
    static func salvage(_ json: String) -> [String: Contact] {
        guard let top = try? JSONSerialization.jsonObject(with: Data(json.utf8)), let all = top as? [String: Any] else { return [:] }
        var out: [String: Contact] = [:]
        for (userId, value) in all {
            guard JSONSerialization.isValidJSONObject(value), let data = try? JSONSerialization.data(withJSONObject: value),
                  let contact = try? JSONDecoder().decode(Contact.self, from: data) else { continue }
            out[userId] = contact
        }
        return out
    }

    func reset() { saving = nil; entries = [:]; loadedFor = nil; unsaved = false; roster = [:]; rosterByServer = [:]; lookups = [:]; lookingUp = [] }

    /// Replace one server's accepted members.
    func setRoster(serverId: String, members: [String: String]) {
        guard rosterByServer[serverId] != members else { return }
        rosterByServer[serverId] = members
        roster = rosterByServer.values.reduce(into: [:]) { $0.merge($1) { first, _ in first } }
    }

    /// Cross-check a server-claimed name with the directory (once per name per launch): does
    /// looking it up lead to exactly this account? The answer only decides between the quiet
    /// "unverified" marker and a flag — it never makes a name trusted.
    func check(_ userId: String, name: String) async {
        let key = "\(userId)|\(name)"
        guard !name.isEmpty, lookups[key] == nil, level(userId) < .known, let bound = app?.bound, lookingUp.insert(key).inserted else { return }
        defer { lookingUp.remove(key) }
        // The answer is the directory of the workspace that was ASKED: if the user is in
        // another one when it comes (a server can hold it), it says nothing about this book.
        var answer: Bool?
        do { answer = try await bound.client.findUser(username: name).userId == userId }
        catch CoreError.Engine(let detail) where detail.contains("404") || detail.contains("user not found") { answer = false }
        catch {}   // no answer: stays unconfirmed, asked again next time
        guard app?.bound?.workspaceId == bound.workspaceId, app?.bound?.turn == bound.turn else { return }
        if let answer { lookups[key] = answer }
    }

    private func save() {
        // Never before the book was read: what is in memory then is not the book.
        guard let wid = loadedFor, wid == app?.current?.id, let client = app?.client, let key else { return }
        // STRICT write. One that fails is retried with the next change (the whole book is
        // written each time) and by `retrySave` on the next bind.
        // IN ORDER: each write waits for the one before it and writes the book as it is THEN,
        // so two changes in quick succession can never land oldest-last.
        let previous = saving
        saving = Task { [weak self] in
            await previous?.value
            guard let self, self.loadedFor == wid, self.app?.current?.id == wid,
                  let data = try? JSONEncoder().encode(self.entries), let json = String(data: data, encoding: .utf8) else { return }
            do { try await client.kvWrite(key: key, value: json); self.unsaved = false } catch { self.unsaved = true }
        }
    }
    private var saving: Task<Void, Never>?

    func level(_ userId: String) -> TrustLevel { entries[userId]?.level ?? .unverified }

    /// Record a name at a level (see `ContactTrust.merged`).
    func note(_ userId: String, name: String, level: TrustLevel) {
        guard !userId.isEmpty else { return }
        let merged = ContactTrust.merged(existing: entries[userId], name: name, level: level)
        guard merged != entries[userId] else { return }
        entries[userId] = merged
        save()
    }

    /// The user opened a conversation (see `ContactTrust.afterOpening`).
    func opened(_ userId: String, name: String, isNewConversation: Bool) {
        let badge = display(userId, claimedName: name).badge
        guard let updated = ContactTrust.afterOpening(existing: entries[userId], isNewConversation: isNewConversation, name: name, badge: badge),
              updated != entries[userId] else { return }
        entries[userId] = updated
        save()
    }

    /// "I know them — accept". Returns false (and changes nothing) while a strong flag stands.
    @discardableResult
    func accept(_ userId: String, name: String) -> Bool {
        guard ContactTrust.mayAccept(shown: display(userId, claimedName: name), name: name) else { return false }
        note(userId, name: name, level: .known)
        return true
    }

    /// Build 49: the contact book one of our own devices handed over, for `workspaceId`
    /// (`SiblingRules.mergedBook`): a name the user set here wins, nothing is raised above KNOWN
    /// (a colliding or odd name stays UNVERIFIED), and only users the sender's snapshot vouches
    /// for and that agree with this device are taken. Blocks live elsewhere and are never touched.
    /// Returns the users that sibling had VERIFIED (the caller asks the core); nil when another
    /// skwod's book is loaded.
    @discardableResult
    func mergeFromSibling(_ synced: [String: Contact], workspaceId: String, vouched: Set<String>, mismatched: Set<String>) -> [String]? {
        guard !workspaceId.isEmpty, loadedFor == workspaceId, app?.current?.id == workspaceId else { return nil }
        let merged = SiblingRules.mergedBook(local: entries, synced: synced, vouched: vouched, mismatched: mismatched, roster: roster)
        if merged != entries { entries = merged; save() }
        return synced.filter { $0.value.level == .verified && vouched.contains($0.key) && !mismatched.contains($0.key) }.map(\.key)
    }

    /// The book of `workspaceId` as a sibling payload (nil when another skwod's book is loaded).
    func siblingPayload(workspaceId: String) -> Data? {
        guard !workspaceId.isEmpty, loadedFor == workspaceId else { return nil }
        return try? JSONEncoder().encode(entries)
    }

    /// Follow the core's verification state for a contact.
    ///
    /// The ONE raise path, gated here (not by callers): a verification pins only a name that is
    /// clean right now against this book and the roster — not a look-alike, not unusual
    /// characters, not unconfirmed (`ContactTrust.mayPinOnVerify` on `display`). Callers:
    /// `SafetyNumberView.reconcile(after: .verified)` and `SiblingSync.drain` (see Build49Tests).
    @discardableResult
    func noteVerification(_ userId: String, name: String, verified: Bool) -> Bool {
        if verified {
            let shown = display(userId, claimedName: name)
            guard ContactTrust.mayPinOnVerify(shown.badge) else { return false }
            guard let updated = ContactTrust.withVerification(entries[userId], name: shown.text, verified: true),
                  updated != entries[userId] else { return true }
            entries[userId] = updated
            save()
            return true
        }
        guard let updated = ContactTrust.withVerification(entries[userId], name: name, verified: false),
              updated != entries[userId] else { return true }
        entries[userId] = updated
        save()
        return true
    }

    /// A read of the core's verification state: may only demote (`ContactTrust.afterStatusRead`).
    func noteStatusRead(_ userId: String, verified: Bool) {
        guard let updated = ContactTrust.afterStatusRead(entries[userId], verified: verified), updated != entries[userId] else { return }
        entries[userId] = updated
        save()
    }

    /// The label for the author of a channel message, feed post, comment or call
    /// (`ContactTrust.authorLabel`): never the server's name for them as given.
    func authorLabel(_ userId: String?, claimedName: String?) -> String {
        guard let userId, !userId.isEmpty else { return ContactTrust.authorLabel(userId: nil, claimedName: nil, book: [:]) }
        let name = (claimedName?.isEmpty == false ? claimedName : entries[userId]?.name) ?? ""
        return ContactTrust.authorLabel(userId: userId, claimedName: claimedName, book: entries, roster: roster,
                                        lookup: lookups["\(userId)|\(name)"])
    }

    func display(_ userId: String, claimedName: String?) -> ContactTrust.Display {
        let name = (claimedName?.isEmpty == false ? claimedName : entries[userId]?.name) ?? ""
        return ContactTrust.display(userId: userId, claimedName: claimedName, book: entries, roster: roster,
                                    lookup: lookups["\(userId)|\(name)"])
    }
}

/// The marker beside a name: a shield for a verified contact, a quiet "unverified" for a name
/// only the server vouches for, a red warning for a look-alike. Nothing for a known contact.
struct TrustBadge: View {
    let badge: ContactTrust.Badge
    var compact = false

    var body: some View {
        switch badge {
        case .none:
            EmptyView()
        case .verified:
            Image(systemName: "checkmark.shield.fill").font(.system(size: compact ? 9 : 11)).foregroundStyle(.green)
                .accessibilityLabel("Verified")
        case .unconfirmed:
            Text("unconfirmed name").font(.system(size: compact ? 8.5 : 9.5, weight: .semibold)).foregroundStyle(.orange)
                .padding(.horizontal, 4).padding(.vertical, 1)
                .overlay(Capsule().strokeBorder(.orange.opacity(0.5), lineWidth: 1))
                .accessibilityLabel("Name could not be confirmed")
        case .unverified where compact:
            // Rows (build 49): a small mark, not a word after every name.
            Image(systemName: "questionmark.circle").font(.system(size: 10)).foregroundStyle(.white.opacity(0.4))
                .accessibilityLabel("Name not verified")
        case .unverified:
            Text("unverified").font(.system(size: compact ? 8.5 : 9.5, weight: .medium)).foregroundStyle(.white.opacity(0.45))
                .padding(.horizontal, 4).padding(.vertical, 1)
                .overlay(Capsule().strokeBorder(.white.opacity(0.18), lineWidth: 1))
                .accessibilityLabel("Name not verified")
        case .impersonation:
            Label("possible impersonation", systemImage: "exclamationmark.octagon.fill")
                .font(.system(size: compact ? 9 : 10, weight: .semibold)).foregroundStyle(.red)
                .labelStyle(.titleAndIcon)
                .accessibilityLabel("Possible impersonation")
        }
    }
}
