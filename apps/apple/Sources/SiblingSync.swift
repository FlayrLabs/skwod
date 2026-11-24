import Foundation

/// Build 49: hand the state a newly linked device of ours is missing — the contact book (with the
/// core's verifications) and the avatar cache — over the core's sealed channel between our own
/// verified devices, and take what our other devices hand us. Rules: `SiblingRules` (app) and
/// `b49.rs` (core: who may send, verifications, limits).
///
/// Every step is bound to the skwod it started for (`BindTicket` plus the same client): after each
/// await it checks that the same skwod and client are still the active ones, and the stores
/// refuse anything for another workspace — nothing from one skwod is ever shared from, or merged
/// into, another.
@MainActor
enum SiblingSync {
    private static var sharing = false

    /// Send the contact book and the avatars to our other devices (after one was linked, or
    /// when one asks). The core rate-limits; a refusal just waits for the next occasion.
    static func share(_ app: AppState) async {
        guard !sharing, let client = app.client, let asked = app.bindTicket(), case let wid = asked.workspaceId, !wid.isEmpty else { return }
        sharing = true
        defer { sharing = false }
        func still() -> Bool { app.holds(asked) && app.client === client && app.current?.id == wid }
        await app.contacts.loadIfNeeded()
        await app.avatars.loadIfNeeded()
        guard still() else { return }
        if let book = app.contacts.siblingPayload(workspaceId: wid) {
            _ = try? await client.shareWithSiblings(kind: "contacts.v1", body: book)
        }
        guard still(), let entries = app.avatars.siblingEntries(workspaceId: wid) else { return }
        let mine = app.session.map { AvatarStore.userKey($0.userId) }
        for batch in SiblingRules.batches(entries, first: mine) {
            guard still(), let body = try? JSONEncoder().encode(batch) else { return }
            do { _ = try await client.shareWithSiblings(kind: "avatars.v1", body: body) } catch { return }
        }
    }

    /// A newly linked device asks its siblings once per skwod for their state.
    static func requestIfNeeded(_ app: AppState) async {
        guard let client = app.client, let asked = app.bindTicket(), case let wid = asked.workspaceId, !wid.isEmpty else { return }
        let key = "skwod.siblingStateRequested.\(wid)"
        guard !UserDefaults.standard.bool(forKey: key) else { return }
        if let sent = try? await client.requestSiblingState(), sent > 0, app.holds(asked) {
            UserDefaults.standard.set(true, forKey: key)
        }
    }

    /// Take and merge what our other devices handed over — into the skwod they were taken for.
    static func drain(_ app: AppState) async {
        guard let client = app.client, let asked = app.bindTicket(), case let wid = asked.workspaceId, !wid.isEmpty else { return }
        func still() -> Bool { app.holds(asked) && app.client === client && app.current?.id == wid }
        // The stores of THIS skwod first: payloads are only taken once they can be merged.
        await app.contacts.loadIfNeeded()
        await app.avatars.loadIfNeeded()
        guard still(), app.contacts.isLoaded(for: wid) else { return }
        let payloads = await client.takeSiblingPayloads()
        guard still(), !payloads.isEmpty else { return }
        for p in payloads {
            // Our own account is ours: its avatar comes from our own device (no snapshot entry).
            var vouched = Set(p.vouchedUsers)
            if let me = app.session?.userId { vouched.insert(me) }
            let mismatched = Set(p.mismatchedUsers)
            switch p.kind {
            case "contacts.v1":
                guard let book = try? JSONDecoder().decode([String: Contact].self, from: p.body),
                      let verified = app.contacts.mergeFromSibling(book, workspaceId: wid, vouched: vouched, mismatched: mismatched) else { continue }
                // VERIFIED only where the core now says so (it merged the sibling's verification
                // for exactly the devices this device holds — or not at all).
                for userId in verified.prefix(500) {
                    let status = await client.contactStatus(userId: userId)
                    guard still() else { return }
                    guard status.verified, app.contacts.isLoaded(for: wid),
                          app.contacts.noteVerification(userId, name: book[userId]?.name ?? "", verified: true) else { continue }
                    // Read again: an un-verify that happened meanwhile wins.
                    let again = await client.contactStatus(userId: userId)
                    guard still() else { return }
                    app.contacts.noteStatusRead(userId, verified: again.verified)
                }
            case "avatars.v1":
                guard let entries = try? JSONDecoder().decode([SiblingRules.AvatarEntry].self, from: p.body) else { continue }
                app.avatars.mergeFromSibling(entries, workspaceId: wid, vouched: vouched, mismatched: mismatched)
            default:
                continue
            }
        }
    }
}
