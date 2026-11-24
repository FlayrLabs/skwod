#if DEBUG
import Foundation
import ImageIO
import CoreGraphics
import UserNotifications
import CryptoKit
#if os(macOS)
import AppKit
#else
import UIKit
#endif
import LiveKit

/// DEBUG-only automation hooks for the end-to-end checks in docs/APPLE.md ("Proving it").
///
/// The simulator has no scriptable taps without a UI-test bundle, so a Debug build can be driven
/// by environment variables instead (`SIMCTL_CHILD_<NAME>` for the simulator). The real paths are
/// still exercised — the invite arrives through the `skwod://` URL handler, sign-up goes through
/// `AuthView.authenticate()`, messages go through the same client calls the UI makes. Everything
/// here is compiled out of Release builds.
///
/// | Variable | Effect |
/// |---|---|
/// | `SKWOD_E2E_USER`, `SKWOD_E2E_PASSWORD` | once an invite is in the connect form, fill these in and submit (after `SKWOD_E2E_DELAY` s, default 4) |
/// | `SKWOD_E2E_INVITE` | adopt this invite at launch (same code path as a pasted link) |
/// | `SKWOD_E2E_PAIR_QR` | adopt this "Add a device" QR text at launch, as if scanned (the Simulator has no camera), answer "Continue" on the "Join … as …?" and "Approved on your other device" screens a second after each appears; the pairing's phases (`join`, `connecting`, `waiting`, `confirm` + `emoji`, `approved`, `finishing`, `done`, `failed`) go to `<out>/pair.json` |
/// | `SKWOD_E2E_SPACE` | after sign-in, create a server with this name if there is none |
/// | `SKWOD_E2E_MINT` | `token` or `code`: mint an invite and write the link to `SKWOD_E2E_OUT`/invite.txt |
/// | `SKWOD_E2E_AUTOAPPROVE` | `1`: approve + provision every pending join request |
/// | `SKWOD_E2E_SEND` | send this text to the first channel, once |
/// | `SKWOD_E2E_OUT` | directory for `invite.txt`, `messages.json` (decrypted first-channel history) and `call.json`; default: Documents |
/// | `SKWOD_E2E_CMD` | comma-separated commands to run once a server exists (see below) |
/// | `SKWOD_E2E_RTC_LOG` | `1`: the media engine's own log goes to the unified log (names local addresses — troubleshooting only) |
/// | `SKWOD_E2E_LOOPBACK_ICE` | `1`: the media engine also offers this device's loopback address as a candidate — needed to reach a loopback SFU from a Simulator whose Mac routes everything through a VPN |
/// | `SKWOD_E2E_AUTOANSWER` | `1` (iOS): answer an incoming call through CallKit the moment it is reported (the Simulator has no call screen and ends the call a second later) |
/// | `SKWOD_E2E_SYNTHETIC_MEDIA` | `1`: calls publish a generated picture and tone instead of opening the camera/microphone (the Simulator always uses the generated picture) |
///
/// Commands can also be dropped, one per line, into `<out>/cmd.txt` while the app runs; the file
/// is consumed. They call the same functions the buttons do:
/// `call` (open the first server's call), `camera`, `mute`, `switch`, `speaker`, `ring`
/// ("Ring everyone"), `answer` / `decline` (the ringing call — on iOS through a CallKit
/// transaction), `hangup`, `notif` (ask for provisional notification permission, which needs no
/// prompt), `shot` (macOS: save a picture of the app's own windows). `call.json` reports what the call sees: tracks, their encryption, decode counters.
///
/// Trust and messaging commands (same file / variable; each calls what the matching button calls,
/// and its outcome is recorded under `results` in `<out>/e2e.json`):
/// `send:<text>` · `edit:<text>` (my newest message in the first channel) · `react:<emoji>` (the
/// newest message from someone else) · `letin` / `decline` (everyone in "Waiting to join") ·
/// `safety:<username>` (compute the account safety number) · `verify:<username>` (confirm the
/// number last computed) · `verifynumber:<username>:<digits>` · `safetyqr:<username>` (this
/// device's QR payload) · `scanqr:<username>:<payload>` (what scanning that payload concludes) ·
/// `dm:<username>:<text>` (send a DM; `held` when a verified contact's devices changed) ·
/// `accept:<username>` ("Accept & send": accept the changed devices) · `approvelink:<code>`
/// (approve a device link for this account) · `open:dm:<username>` / `open:channel` (show that
/// conversation) · `mint:<kind>` (one more invite code, appended to `invites.txt`) · `showsafety` (open the safety-number screen of the DM on screen) · `showmembers` (open the member list of the channel on screen) ·
/// `selfcheck` (run the content-privacy checks: metadata stripping, decode bounds, link policy, avatar authority, quarantine, "Waiting to join" name checks).
///
/// Build 43b ("the basics") commands — each goes through the same service calls the buttons use:
/// `photo` (a generated photo into the first channel, as an attachment) · `dmphoto:<username>` ·
/// `openatt` / `opendmatt:<username>` (download + decrypt the newest attachment from someone
/// else; reports its size) · `open:feed` · `feedpost:<text>` / `feedphoto:<text>` (through the
/// Feed screen's own model; the Feed must be open) · `flood:<n>` (n numbered messages) ·
/// `loadolder` (the channel on screen pages one step back) · `listdms` · `rings` (ask every
/// signed-in skwod what is ringing) · `background` / `foreground` (what the scene-phase observer
/// calls) · `join:<code>` (join one more server with a code).
/// `e2e.json` → `live` reports what the live connection did: events seen by name, DMs that
/// arrived (and whether each was a copy of our own), every local notification the app asked
/// for, how many announced channel messages turned out to deserve one, join requests, the
/// invite pre-check, the session (signed out / token rotated), the sidebar's DM list, the join
/// status and what the Feed shows. `SKWOD_E2E_ROTATE=1` treats the stored token as a week old.
/// `e2e.json` also reports who is waiting to join, the pinned owners, each named contact's
/// status, and `messages.json` lists reactions, edits and system rows.
enum E2E {
    static func env(_ name: String) -> String? {
        let v = ProcessInfo.processInfo.environment[name]
        return (v?.isEmpty == false) ? v : nil
    }

    static var active: Bool {
        env("SKWOD_E2E_USER") != nil || env("SKWOD_E2E_SEND") != nil || env("SKWOD_E2E_MINT") != nil
            || env("SKWOD_E2E_CMD") != nil || env("SKWOD_E2E_OUT") != nil
    }

    static var outDir: URL {
        if let p = env("SKWOD_E2E_OUT") { return URL(fileURLWithPath: p, isDirectory: true) }
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    static var submitDelay: Double { env("SKWOD_E2E_DELAY").flatMap(Double.init) ?? 4 }

    // MARK: What the live connection did (reported under `live` in e2e.json)

    @MainActor static var rotatedOnce = false
    @MainActor private static var events: [String: Int] = [:]
    @MainActor private static var dmEvents: [[String: Any]] = []
    @MainActor private static var channelFetches: [[String: Any]] = []
    @MainActor private static var joinRequests: [[String: Any]] = []
    @MainActor private static var inviteCheck: [String: Any]?
    @MainActor private static var feedPhotos: [String: [String: Any]] = [:]
    @MainActor private static var feedResult: [String: Any]?
    @MainActor private static weak var feedApp: AppState?

    @MainActor static func sawEvent(_ name: String) { events[name, default: 0] += 1 }

    // ---- build 44: outbox, reports, blocks ----
    @MainActor private static var outbox: [String: Any] = [:]
    @MainActor private static var reports: [[String: Any]] = []
    /// Totals over the run: how many operations the outbox delivered, and what is left.
    @MainActor static func sawOutbox(sent: Int, pending: Int, failed: Int) {
        outbox = ["sent": (outbox["sent"] as? Int ?? 0) + sent, "pending": pending, "failed": failed, "flushes": (outbox["flushes"] as? Int ?? 0) + 1]
    }
    @MainActor static func sawReport(id: String, sealed: Bool) {
        reports.append(["report_id": id, "sealed_to_owner": sealed])
    }

    // ---- build 44: uploads, groups ----
    @MainActor private static var uploads: [[String: Any]] = []
    @MainActor private static var uploadPeak: [String: UInt64] = [:]
    /// What `pendingUploads()` last said, and the furthest each upload has been seen.
    @MainActor static func sawUploads(_ pending: [UploadProgress]) {
        uploads = pending.map { ["upload_id": $0.uploadId, "blob_id": $0.blobId ?? "", "sent": $0.sent, "total": $0.total, "done": $0.done] }
        for p in pending { uploadPeak[p.uploadId] = max(uploadPeak[p.uploadId] ?? 0, p.sent) }
    }

    @MainActor static func sawDm(_ e: DmEvent, name: String?) {
        dmEvents.append(["conversation_id": e.conversationId, "peer": name ?? e.peerUserId, "from_self": e.fromSelf,
                         "text": e.text.hasPrefix("\u{2}") ? "(tagged: \(e.text.dropFirst().prefix(12)))" : e.text, "message_id": e.messageId])
        if dmEvents.count > 100 { dmEvents.removeFirst(dmEvents.count - 100) }
    }

    @MainActor static func sawChannelFetch(channelId: String, announced: Int, notifying: Int) {
        channelFetches.append(["channel_id": channelId, "announced": announced, "notifying": notifying])
        if channelFetches.count > 100 { channelFetches.removeFirst(channelFetches.count - 100) }
    }

    @MainActor static func sawJoinRequest(serverId: String, waiting: Int) {
        joinRequests.append(["server_id": serverId, "waiting": waiting, "at": Int(Date().timeIntervalSince1970 * 1000)])
    }

    /// The raw error behind the last failed pairing, for `pair.json` (the screen shows friendly text).
    @MainActor static var pairingErrorDetail: String?

    /// Where the new device's QR pairing stands (`<out>/pair.json`).
    @MainActor static func notePairing(_ phase: NewDevicePairing.Phase) {
        var state: [String: Any] = ["at": Int(Date().timeIntervalSince1970 * 1000)]
        if let detail = pairingErrorDetail { state["detail"] = detail }
        switch phase {
        case .join: state["phase"] = "join"
        case .connecting: state["phase"] = "connecting"
        case .waiting: state["phase"] = "waiting"
        case .confirm(let emoji): state["phase"] = "confirm"; state["emoji"] = emoji
        case .approved: state["phase"] = "approved"
        case .finishing: state["phase"] = "finishing"
        case .done: state["phase"] = "done"
        case .failed(let why): state["phase"] = "failed"; state["error"] = why
        }
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        if let data = try? JSONSerialization.data(withJSONObject: state, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: outDir.appendingPathComponent("pair.json"), options: .atomic)
        }
    }

    @MainActor static func noteInviteCheck(valid: Bool, reason: String?, requiresApproval: Bool) {
        let state: [String: Any] = ["valid": valid, "reason": reason ?? "", "requires_approval": requiresApproval,
                                    "at": Int(Date().timeIntervalSince1970 * 1000)]
        inviteCheck = state
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        if let data = try? JSONSerialization.data(withJSONObject: state, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: outDir.appendingPathComponent("invite-check.json"), options: .atomic)
        }
    }

    @MainActor static func sawFeedPhoto(blobId: String, opened: Bool, error: String?) {
        feedPhotos[blobId] = ["opened": opened, "error": error ?? ""]
    }

    @MainActor static func feedPosted(ok: Bool, error: String?) {
        feedResult = ["ok": ok, "error": error ?? ""]
        // What the status row went through: the phases in order, and how far the upload's
        // progress was reported (1.0 = the host confirmed the last piece).
        let fractions = feedPhases.compactMap { phase -> Double? in if case .uploading(let f) = phase { return f } else { return nil } }
        let kinds = feedPhases.map { phase -> String in
            switch phase { case .encrypting: return "encrypting"; case .uploading: return "uploading"; case .sending: return "sending" }
        }
        let order = kinds.reduce(into: [String]()) { if $0.last != $1 { $0.append($1) } }
        let forwards = zip(fractions, fractions.dropFirst()).allSatisfy { $0 <= $1 }
        let progress = "phases=\(order.joined(separator: ">")) upload_reports=\(fractions.count) upload_max=\(fractions.max() ?? 0) forwards=\(forwards)"
        feedPhases = []
        note("feedpost", ok ? "ok \(progress)" : "error: \(error ?? "?") \(progress)")
    }

    @MainActor private static var feedPhases: [FeedSendPhase] = []
    @MainActor static func sawFeedPhase(_ phase: FeedSendPhase?) { if let phase { feedPhases.append(phase) } }

    /// Every alert decision made for an incoming message (`AppState.incomingAlert`), newest last.
    @MainActor private static var alerts: [String] = []
    @MainActor static func sawAlert(topic: String, muted: Bool, outcome: MessageAlert.Outcome, mention: Bool = false) {
        alerts.append("\(topic.prefix(11)) mention=\(mention) muted=\(muted) banner=\(outcome.banner) banner_sound=\(outcome.bannerSound) app_sound=\(outcome.inAppSound)")
        if alerts.count > 50 { alerts.removeFirst(alerts.count - 50) }
    }

    // ---- build 46: paste, typing, mentions, server menus, the skwod's host name ----
    /// How many attachments the composer on screen has staged (set by the composer itself).
    @MainActor static var stagedCount = 0
    #if os(iOS)
    /// The composer field on screen: `pasteimage` calls its own `paste(_:)`, as the Paste menu does.
    @MainActor static weak var composerField: UITextView?
    #endif

    /// A small photo with a GPS tag, as a phone would hand over (the upload path strips it).
    static func samplePhoto(seed: Int = 0) -> Data {
        let cs = CGColorSpaceCreateDeviceRGB()
        let w = 640, h = 480
        let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                            bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
        let hue = CGFloat((seed * 37) % 100) / 100
        for band in 0..<8 {
            ctx?.setFillColor(red: hue, green: CGFloat(band) / 8, blue: 1 - CGFloat(band) / 8, alpha: 1)
            ctx?.fill(CGRect(x: band * w / 8, y: 0, width: w / 8, height: h))
        }
        ctx?.setFillColor(red: 1, green: 1, blue: 1, alpha: 1)
        ctx?.fillEllipse(in: CGRect(x: 220, y: 140, width: 200, height: 200))
        let out = NSMutableData()
        if let cg = ctx?.makeImage(), let dest = CGImageDestinationCreateWithData(out, "public.jpeg" as CFString, 1, nil) {
            let props: [CFString: Any] = [kCGImagePropertyGPSDictionary: [kCGImagePropertyGPSLatitude: 38.7, kCGImagePropertyGPSLatitudeRef: "N",
                                                                           kCGImagePropertyGPSLongitude: 77.6, kCGImagePropertyGPSLongitudeRef: "W"]]
            CGImageDestinationAddImage(dest, cg, props as CFDictionary)
            CGImageDestinationFinalize(dest)
        }
        return out as Data
    }

    /// The `live` section of e2e.json.
    @MainActor
    private static func liveState(app: AppState, chat: ChatModel) async -> [String: Any] {
        // What the SYSTEM holds as delivered — not just what the app asked for.
        let delivered = await UNUserNotificationCenter.current().deliveredNotifications()
            .map { ["title": $0.request.content.title, "body": $0.request.content.body, "thread": $0.request.content.threadIdentifier] }
        var state: [String: Any] = [
            "delivered": delivered,
            "events": events,
            "socket_live": app.realtime.isLive,
            "dm_events": dmEvents,
            "outbox": outbox,
            "uploads": uploads,
            "group_invitations": chat.pendingGroups.map { ["conversation_id": $0.conversationId, "members": $0.memberUserIds] as [String: Any] },
            "groups": chat.groups.map { ["conversation_id": $0.conversationId, "members": $0.memberUserIds, "title": chat.title(of: $0)] as [String: Any] },
            "reports_sent": reports,
            "blocked": Array(BlockList.shared.ids).sorted(),
            "notifications": Realtime.posted,
            "channel_fetches": channelFetches,
            "join_requests": joinRequests,
            "dms": chat.dms.map { d -> [String: Any] in
                let shown = app.contacts.display(d.peerUserId, claimedName: d.name)
                return ["name": d.name, "conversation_id": d.conversationId, "shown": shown.text, "badge": "\(shown.badge)",
                        "level": app.contacts.level(d.peerUserId).rawValue, "peer": d.peerUserId,
                        "started_here": d.startedHere ?? false, "claimed": d.isClaimed]
            },
            // How the lists were READ for the workspace on screen (the bind and load path).
            "store": ["workspace": chat.store.workspaceId, "current": app.current?.id ?? "", "bound": app.bound?.workspaceId ?? "",
                      "cache_open": app.bound?.cacheOpen ?? false, "ready": chat.store.ready, "load_failures": chat.store.loadFailures,
                      "review_direct": Array(chat.store.review.direct).sorted(), "review_group": Array(chat.store.review.group).sorted(),
                      "review_all": chat.store.review.all, "unreadable": chat.conversationsUnreadable, "review_pending": chat.reviewPending,
                      "problem": chat.conversationProblem.map { "\($0)" } ?? "", "ignored": chat.store.declined.sorted(),
                      "servers": Array(Set(chat.spaces.map(\.serverId))).sorted()] as [String: Any],
            "feed_channels": chat.feedChannels,
            "feed_photos": feedPhotos,
            "link_requests": app.linkRequests,
            "session": ["signed_out": app.signedOut != nil, "rotated": rotatedOnce,
                        "token_issued_at": app.current?.tokenIssuedAt ?? 0],
            "text_channels": chat.spaces.map(\.channelName),
        ]
        if let inviteCheck { state["invite_check"] = inviteCheck }
        if let feedResult { state["feed_result"] = feedResult }
        if let status = chat.joinStatus { state["join_status"] = "\(status)" }
        if let join = app.current.flatMap({ PendingJoinStore.get(address: $0.server) }) {
            state["pending_join"] = ["server_id": join.serverId ?? "", "awaiting_approval": join.awaitingApproval]
        }
        return state
    }

    /// Runs for the life of the main shell: creates/mints/approves/sends as configured and keeps
    /// `messages.json` current with what this device can DECRYPT in its first channel.
    @MainActor
    static func drive(app: AppState, chat: ChatModel) async {
        guard active else { return }
        try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
        var sent = false
        var minted = false
        var names: [String: String] = [:]
        var pending = (env("SKWOD_E2E_CMD") ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(2))
            guard let client = app.client, app.deviceId != nil, let me = app.session?.userId else { continue }

            if let name = env("SKWOD_E2E_SPACE"), chat.spaces.isEmpty,
               let s = try? await client.createSpace(name: name, channelName: "general") {
                chat.addSpace(RealSpace(name: name, channelName: "general", serverId: s.serverId,
                                        channelId: s.channelId, inviteCode: s.inviteCode, spaceKeyHex: s.spaceKeyHex))
            }
            // What the live connection has done so far — also before there is any server (a
            // joiner waiting to be let in has no channel yet).
            if let data = try? JSONSerialization.data(withJSONObject: await liveState(app: app, chat: chat), options: [.prettyPrinted, .sortedKeys]) {
                try? data.write(to: outDir.appendingPathComponent("live.json"), options: .atomic)
            }
            guard let space = chat.spaces.first else { continue }

            if !minted, let kind = env("SKWOD_E2E_MINT"),
               let code = try? await client.inviteToSpace(serverId: space.serverId, kind: kind, reservedUsername: nil) {
                var nodeId = app.current?.nodeId
                #if os(macOS)
                if nodeId == nil { nodeId = HostManager.shared.nodeId }
                #endif
                var link = nodeId.flatMap { InviteLink.format(nodeId: $0, joinCode: code) }
                // A classic (https, or this machine's loopback) skwod: `<address>#<code>`.
                if link == nil, nodeId == nil, let server = app.current?.server { link = "\(server)#\(code)" }
                if let link {
                    try? link.write(to: outDir.appendingPathComponent("invite.txt"), atomically: true, encoding: .utf8)
                    minted = true
                }
            }

            if env("SKWOD_E2E_AUTOAPPROVE") == "1",
               let pending = try? await client.listJoinRequests(serverId: space.serverId) {
                for req in pending {
                    if (try? await client.approveJoinRequest(serverId: space.serverId, userId: req.userId)) != nil {
                        await app.waiting.handOver(serverId: space.serverId, userId: req.userId, username: req.username)
                    }
                }
            }
            // Keys for whoever is in the channel now (what opening the channel in the UI does).
            _ = try? await client.syncChannelMembership(channelId: space.channelId, serverId: space.serverId, myUserId: me)

            if !sent, let text = env("SKWOD_E2E_SEND"),
               (try? await client.sendChannelMessage(channelId: space.channelId, text: text)) != nil {
                sent = true
            }

            // Commands: the launch list first, then whatever was dropped into cmd.txt.
            let cmdFile = outDir.appendingPathComponent("cmd.txt")
            if let text = try? String(contentsOf: cmdFile, encoding: .utf8) {
                try? FileManager.default.removeItem(at: cmdFile)
                pending += text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            }
            for command in pending where !command.isEmpty {
                if await trust(command, app: app, chat: chat, space: space, me: me) { continue }
                run(command, app: app, serverId: space.serverId)
            }
            pending = []
            await app.waiting.refresh(serverId: space.serverId)
            await dumpTrust(app: app, chat: chat, client: client, space: space, me: me)
            CallDebug.saveRemoteFrames(to: outDir)
            if let data = try? JSONSerialization.data(withJSONObject: CallDebug.snapshot(app: app), options: [.prettyPrinted, .sortedKeys]) {
                try? data.write(to: outDir.appendingPathComponent("call.json"), options: .atomic)
            }

            if let members = try? await client.listMembers(serverId: space.serverId) {
                for m in members { names[m.userId] = m.username }
            }
            if let rows = try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me) {
                await app.drainDmEvents()
                let reactions = Dictionary(grouping: await client.channelReactions(channelId: space.channelId), by: \.messageId)
                var dump: [[String: Any]] = []
                for m in rows {
                    guard let text = m.content else { continue }
                    if m.isSystem {
                        // Persistent security / membership rows, as the conversation words them.
                        if let row = SecurityAlert.systemMessage(m, name: { $0 == me ? "You" : (names[$0] ?? String($0.prefix(6))) }) {
                            dump.append(["system": row.system?.kind ?? "", "text": row.body, "at": m.createdAt])
                        }
                        continue
                    }
                    if let a = ChatTags.parse(text).attachment {
                        dump.append(["id": m.messageId, "mine": m.authorId == me || m.authorId == "__me__", "at": m.createdAt,
                                     "attachment": a.name, "blob_id": a.blobId, "size": a.size, "has_token": a.token != nil])
                        continue
                    }
                    guard !text.hasPrefix("\u{2}skwod/") else { continue }
                    var entry: [String: Any] = ["id": m.messageId, "mine": m.authorId == me || m.authorId == "__me__",
                                                "text": text, "at": m.createdAt, "edited": m.isEdited]
                    if let mine = reactions[m.messageId], !mine.isEmpty {
                        entry["reactions"] = mine.map { ["by_me": $0.userId == me, "emoji": $0.emoji ?? "?"] }
                    }
                    dump.append(entry)
                }
                let state: [String: Any] = [
                    "connection": app.connection.title,
                    "p2p": app.current?.isP2P ?? false,
                    "channel": space.channelName,
                    "count": dump.count,
                    "cached_window": rows.count,
                    "messages": dump,
                ]
                if let data = try? JSONSerialization.data(withJSONObject: state, options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: outDir.appendingPathComponent("messages.json"), options: .atomic)
                }
            }
        }
    }

    // MARK: Trust + messaging commands

    /// Outcome of each trust/messaging command, newest last (`e2e.json` → `results`).
    @MainActor private static var results: [[String: String]] = []
    /// Contacts a command named (username → user id), reported in `e2e.json`.
    @MainActor private static var contacts: [String: String] = [:]
    @MainActor private static var safety: [String: String] = [:]

    @MainActor
    private static func note(_ command: String, _ outcome: String) { results.append(["command": command, "result": outcome]) }

    /// Runs `command` if it is one of the trust/messaging commands; false = not one of them.
    @MainActor
    private static func trust(_ command: String, app: AppState, chat: ChatModel, space: RealSpace, me: String) async -> Bool {
        guard let client = app.client else { return false }
        let parts = command.split(separator: ":", maxSplits: 1).map(String.init)
        let arg = parts.count > 1 ? parts[1] : ""
        func user(_ name: String) async -> FoundUser? {
            guard let found = try? await client.findUser(username: name) else { return nil }
            contacts[name] = found.userId
            return found
        }
        func outcome(_ work: () async throws -> Void) async -> String {
            do { try await work(); return "ok" }
            catch CoreError.IdentityChanged { return "held" }
            catch let error as AttachmentError { return "error: \(error.errorDescription ?? "attachment") [\(error)]" }
            catch { return "error: \(coreErrorText(error))" }
        }
        /// The DM conversation with `name` and the id of the newest message in it (mine or any).
        func dm(_ name: String, mine: Bool) async -> (convo: String, peer: String, last: Message?)? {
            guard let found = await user(name), let convo = try? await client.openDm(peerUserId: found.userId) else { return nil }
            _ = try? await client.syncDms()
            let rows = await client.history(scope: "dm:\(convo)").filter { !$0.isDeleted && !$0.isSystem }
            let last = rows.last { !mine || $0.authorId == "__me__" || $0.authorId == me }
            return (convo, found.userId, last)
        }
        switch parts[0] {
        // ---- build 45: held sends after a contact's key changed, bound sessions ----
        case "dmq":
            // dmq:<user>:<text> — what the DM composer does: queue, then deliver (`Outbox`).
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard bits.count == 2, let found = await user(bits[0]),
                  let convo = try? await client.openDm(peerUserId: found.userId) else { note(command, "error: no such user"); return true }
            if !chat.dms.contains(where: { $0.conversationId == convo }) {
                chat.addDM(DMConversation(name: bits[0], peerUserId: found.userId, peerDeviceId: found.deviceId, conversationId: convo))
            }
            note(command, await outcome { _ = try await client.queueDm(conversationId: convo, peerUserIds: [found.userId], text: bits[1], replyToId: nil, uploadIds: []) })
            await Outbox.flush(app)
            await app.surfaceSecurityNotices()
        case "hold":
            // hold:<user> — the conversation banner as `DMChatView` decides it, and the states of
            // my queued sends there ("sending" / "failed: <reason>").
            guard let found = await user(arg), let convo = try? await client.openDm(peerUserId: found.userId) else { note(command, "error: no such user"); return true }
            let status = await client.contactStatus(userId: found.userId)
            let pending = await client.pendingSends(scope: "dm:\(convo)").filter { $0.kind == "send" }
            let failedOnIdentity = pending.contains { $0.state == "failed" && IdentityHold.isIdentityFailure($0.error ?? "") }
            let hold = IdentityHold.decide(sendsHeld: status.sendsHeld, devices: status.devices, unvouchedDevices: status.unvouchedDevices, failedOnIdentity: failedOnIdentity)
            note(command, "hold=\(hold) held=\(status.sendsHeld) devices=\(status.devices) unvouched=\(status.unvouchedDevices) verified=\(status.verified) sends=[\(pending.map { $0.state == "failed" ? "failed: \($0.error ?? "")" : $0.state }.joined(separator: " | "))]")
        case "retryheld":
            // retryheld:<user> — what Accept on the banner does after `accept_identity_change`.
            guard let found = await user(arg), let convo = try? await client.openDm(peerUserId: found.userId) else { note(command, "error: no such user"); return true }
            var n = 0
            for p in await client.pendingSends(scope: "dm:\(convo)") where p.kind == "send" && p.state == "failed" && IdentityHold.isIdentityFailure(p.error ?? "") {
                await client.retrySend(localId: p.localId); n += 1
            }
            await Outbox.flush(app)
            note(command, "retried=\(n)")
        case "bind":
            note(command, await outcome { _ = try await client.bindSession() })
        case "notices":
            // The Security activity rows, newest first (kinds only).
            note(command, app.securityActivity.prefix(12).map(\.kind).joined(separator: ","))
        // ---- build 44: groups, streamed uploads, placeholders, the reports inbox ----
        case "groupdm":
            // groupdm:<user1>+<user2>[+…]:<text> — what "New group" then the composer do.
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            var members: [(userId: String, name: String)] = []
            for name in (bits.first ?? "").split(separator: "+").map(String.init) {
                guard let found = await user(name) else { note(command, "error: no such user \(name)"); return true }
                members.append((found.userId, name))
            }
            if let problem = GroupDM.sizeProblem(others: members.count) { note(command, "error: \(problem)"); return true }
            do {
                try await chat.startGroup(with: members)
                guard case .group(let g)? = chat.selection else { note(command, "error: group not opened"); return true }
                if bits.count > 1 {
                    _ = try await client.queueDm(conversationId: g.conversationId, peerUserIds: g.memberUserIds, text: bits[1], replyToId: nil, uploadIds: [])
                    await Outbox.flush(app)
                }
                note(command, "ok conversation=\(g.conversationId) title=\(chat.title(of: g))")
            } catch { note(command, "error: \(coreErrorText(error))") }
        case "acceptgroup":
            // What "Join group" on an invitation does (after its members were shown).
            await app.syncMailbox()
            await chat.refreshGroups()
            guard let invitation = chat.pendingGroups.first else { note(command, "error: no invitation (accepted=\(chat.groups.count))"); return true }
            let members = invitation.memberUserIds.map { app.contacts.display($0, claimedName: invitation.claimedNames[$0]).spoken }
            await chat.accept(invitation)
            note(command, "ok members=\(members.joined(separator: ",")) accepted=\(chat.groups.count)")
        case "groups":
            await app.syncMailbox()
            await chat.refreshGroups()
            var out: [String] = []
            for g in chat.groups {
                let rows = await client.history(scope: "dm:\(g.conversationId)").filter { !$0.isDeleted && !$0.isSystem }
                out.append("\(chat.title(of: g)){\(rows.map { ($0.authorId == "__me__" || $0.authorId == me ? "me" : String(($0.authorId ?? "?").prefix(6))) + ":" + ($0.content ?? "") }.joined(separator: " | "))}")
            }
            // A group must never have produced a 1:1 row for a member who only wrote in the group.
            note(command, "count=\(chat.groups.count) invitations=\(chat.pendingGroups.count) disagree=\(chat.groups.filter { $0.serverDisagrees == true }.count) dms=\(chat.dms.count) \(out.joined(separator: " ; "))")
        case "groupsend":
            guard let g = chat.groups.first else { note(command, "error: no group"); return true }
            note(command, await outcome { _ = try await client.queueDm(conversationId: g.conversationId, peerUserIds: g.memberUserIds, text: arg, replyToId: nil, uploadIds: []) })
            await Outbox.flush(app)
        case "upload", "dmupload":
            // upload:<path> · dmupload:<user>:<path> — a file through the composer's own path:
            // encrypted file-to-file, queued, uploaded in resumable chunks.
            var path = arg
            var target = StreamedUpload.Target.channel(channelId: space.channelId)
            if parts[0] == "dmupload" {
                let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
                guard bits.count == 2, let d = await dm(bits[0], mine: false) else { note(command, "error: no such user"); return true }
                path = bits[1]
                target = .dm(conversationId: d.convo, peers: [d.peer])
            }
            let before = Self.residentMemory()
            note(command, await outcome { try await StreamedUpload.queue(.file(URL(fileURLWithPath: path)), to: target, app: app) }
                 + " memory_delta_mb=\((Int64(Self.residentMemory()) - Int64(before)) / 1_048_576)")
        case "uploads":
            let pending = await client.pendingUploads()
            sawUploads(pending)
            let queued = await client.pendingSends(scope: nil)
            note(command, "pending=\(pending.map { "\($0.sent)/\($0.total)\($0.done ? " done" : "")" }.joined(separator: ",")) peak=\(uploadPeak.values.map(String.init).joined(separator: ",")) queued_sends=\(queued.count)")
        case "resumeuploads":
            let done = await client.resumeUploads()
            await Outbox.flush(app)
            note(command, "done=\(done) left=\(await client.pendingUploads().filter { !$0.done }.count)")
        case "fetchatt":
            // The newest attachment of anyone in the first channel: download + decrypt to a
            // file (streamed) and report its size and SHA-256.
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            guard let a = rows.reversed().compactMap({ ChatTags.parse($0.content ?? "").attachment }).first(where: { StreamedUpload.uploadId(forPlaceholder: $0.blobId) == nil }),
                  let store = BlobStore(app: app) else { note(command, "error: no attachment"); return true }
            do {
                let url = try await AttachmentService.localFile(for: a, store: store)
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
                note(command, "ok name=\(a.name) size=\(size) sha256=\(Self.sha256(of: url))")
            } catch { note(command, "error: \((error as? AttachmentError)?.errorDescription ?? "\(error)")") }
        case "placeholders":
            // What the channel on screen shows for rows this device could not decrypt.
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            let members = (try? await client.listMembers(serverId: space.serverId)) ?? []
            let shown = rows.compactMap { SecurityAlert.placeholderMessage($0, name: { id in members.first(where: { $0.userId == id })?.username ?? String(id.prefix(6)) })?.body }
            let lookalikes = rows.filter { !$0.isUndecryptable && !$0.isSystem && ($0.content ?? "").hasPrefix("skwod/") }.count
            note(command, "count=\(shown.count) rows=\(rows.count) lookalike_plain=\(lookalikes) \(shown.joined(separator: " | "))")
        case "reportat":
            // reportat:<user>[:note] — "Report…" on their newest message in the first channel,
            // quoted, with where it is (what the message menu sends).
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard let found = await user(bits.first ?? "") else { note(command, "error: no such user"); return true }
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            guard let target = rows.last(where: { $0.authorId == found.userId && !$0.isDeleted && !$0.isSystem }) else { note(command, "error: nothing of theirs"); return true }
            do {
                let receipt = try await client.reportMessageAt(category: "harassment", note: bits.count > 1 ? bits[1] : nil, messageText: target.content,
                                                               subjectUserId: found.userId, serverId: space.serverId,
                                                               channelId: space.channelId, messageId: target.messageId)
                sawReport(id: receipt.reportId, sealed: receipt.sealedToOwner)
                note(command, "ok sealed=\(receipt.sealedToOwner)")
            } catch { note(command, "error: \(coreErrorText(error))") }
        case "inbox":
            // The owner's reports inbox, as the screen builds it.
            await app.syncMailbox()
            await app.refreshReports()
            var lines: [String] = []
            for r in app.reports {
                let item = await app.reportItem(r)
                let res = item.resolution
                lines.append("\(r.category) note=\(r.note ?? "-") excerpt=\(r.excerpt ?? "-") resolved=\(res.target != nil) author_is_subject=\(res.target?.authorId == r.subjectUserId) quote=\(res.quote) warnings=\(res.warnings.count) may_remove=\(res.mayRemove) caption=\(ReportResolution.quoteCaption(res.quote))")
            }
            note(command, "count=\(app.reports.count) \(lines.joined(separator: " ; "))")
        case "reportaction":
            // reportaction:<remove|kick|ban|dismiss> — on the newest report, against what THIS
            // device resolved (never the report's own subject / server).
            await app.refreshReports()
            guard let newest = app.reports.last else { note(command, "error: no report"); return true }
            let item = await app.reportItem(newest)
            var problem: String?
            switch arg {
            case "remove": problem = await app.removeReportedMessage(item)
            case "dismiss": await app.dismiss(item)
            case "kick", "ban":
                if item.resolution.mayModerate, let t = item.resolution.target {
                    problem = await app.moderate(ban: arg == "ban", userId: t.authorId, serverId: t.serverId, reason: "reported: \(newest.category)")
                } else { problem = "not resolved to a message on this device (the owner must pick by hand)" }
            default: problem = "unknown action"
            }
            note(command, problem.map { "error: \($0)" } ?? "ok left=\(app.reports.count)")
        case "reportforged":
            // reportforged:<victim>:<author> — a report that points at <author>'s newest message
            // but names <victim> as its subject (what a malicious reporter would craft).
            let bits = arg.split(separator: ":").map(String.init)
            guard bits.count == 2, let victim = await user(bits[0]), let author = await user(bits[1]) else { note(command, "error: users"); return true }
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            guard let target = rows.last(where: { $0.authorId == author.userId && !$0.isDeleted && !$0.isSystem }) else { note(command, "error: nothing of theirs"); return true }
            do {
                _ = try await client.reportMessageAt(category: "harassment", note: "ban them", messageText: target.content,
                                                     subjectUserId: victim.userId, serverId: space.serverId,
                                                     channelId: space.channelId, messageId: target.messageId)
                note(command, "ok")
            } catch { note(command, "error: \(coreErrorText(error))") }
        case "queue":
            // What the composer does: queue (works offline), then try to deliver.
            note(command, await outcome { _ = try await client.queueChannelMessage(channelId: space.channelId, text: arg, replyToId: nil, blobIds: [], uploadIds: []) })
            Outbox.kick(app)
        case "flush":
            await Outbox.flush(app)
            let left = await client.pendingSends(scope: nil)
            note(command, "pending=\(left.filter { $0.state == "sending" }.count) failed=\(left.filter { $0.state == "failed" }.count)")
        case "block", "unblock":
            guard let found = await user(arg) else { note(command, "error: no such user"); return true }
            let failure = await BlockList.shared.setBlocked(app, userId: found.userId, name: arg, blocked: parts[0] == "block")
            note(command, failure.map { "error: \($0)" } ?? "ok")
        case "blocks":
            await BlockList.shared.refresh(app)
            note(command, "blocked=\(BlockList.shared.ids.count)")
        case "report":
            // report:<user>[:note] — the newest message of theirs in the first channel, quoted,
            // as "Report…" on that message with "Include this message" switched on does.
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard let found = await user(bits.first ?? "") else { note(command, "error: no such user"); return true }
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            let quoted = rows.last { $0.authorId == found.userId && !$0.isDeleted }.flatMap(\.content)
            do {
                let receipt = try await client.reportMessage(category: "harassment", note: bits.count > 1 ? bits[1] : nil, messageText: quoted,
                                                             subjectUserId: found.userId, serverId: space.serverId)
                sawReport(id: receipt.reportId, sealed: receipt.sealedToOwner)
                note(command, "ok sealed=\(receipt.sealedToOwner) quoted=\(quoted != nil)")
            } catch { note(command, "error: \(coreErrorText(error))") }
        case "reports":
            // The owner's side: what reached this device, sealed.
            _ = try? await client.syncDms()
            let got = await client.receivedReports()
            note(command, "count=\(got.count)" + (got.last.map { " last=\($0.category) note=\($0.note ?? "-") excerpt=\($0.excerpt ?? "-")" } ?? ""))
        case "dmreply", "dmedit", "dmreact":
            // dmreply:<user>:<text> · dmedit:<user>:<text> · dmreact:<user>:<emoji>
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard bits.count == 2, let d = await dm(bits[0], mine: parts[0] == "dmedit"), let last = d.last else { note(command, "error: no message to act on"); return true }
            note(command, await outcome {
                switch parts[0] {
                case "dmreply": _ = try await client.queueDm(conversationId: d.convo, peerUserIds: [d.peer], text: bits[1], replyToId: last.messageId, uploadIds: [])
                case "dmedit": try await client.queueDmEdit(conversationId: d.convo, peerUserIds: [d.peer], messageId: last.messageId, text: bits[1])
                default: try await client.queueDmReaction(conversationId: d.convo, peerUserIds: [d.peer], messageId: last.messageId, emoji: bits[1], remove: false)
                }
            })
            await Outbox.flush(app)
        case "dmdelete":
            guard let d = await dm(arg, mine: true), let last = d.last else { note(command, "error: nothing of mine to delete"); return true }
            note(command, await outcome { try await client.queueDmDelete(conversationId: d.convo, peerUserIds: [d.peer], messageId: last.messageId) })
            await Outbox.flush(app)
        case "dmstate":
            // What this device shows for the conversation with <user>.
            guard let d = await dm(arg, mine: false) else { note(command, "error: no such user"); return true }
            let rows = await client.history(scope: "dm:\(d.convo)").filter { !$0.isSystem }
            let reactions = await client.dmReactions(conversationId: d.convo).compactMap(\.emoji).sorted().joined()
            let shown = rows.map { $0.isDeleted ? "(deleted)" : (($0.content ?? "") + ($0.isEdited ? " (edited)" : "") + ($0.replyToId != nil ? " (reply)" : "")) }
            note(command, "rows=[\(shown.joined(separator: " | "))] reactions=\(reactions)")
        case "clear":
            note(command, await outcome { try await client.clearChannelMessages(channelId: space.channelId) })
            NotificationCenter.default.post(name: .skwodChannelChanged, object: space.channelId)
        case "story":
            // A text story in this server's feed, queued like the composer's.
            note(command, await outcome {
                let feed = try await client.feedChannel(serverId: space.serverId)
                _ = try await client.queueChannelMessage(channelId: feed, text: STORY_TAG + "{\"text\":\"\(arg)\",\"ts\":0}", replyToId: nil, blobIds: [], uploadIds: [])
            })
            await Outbox.flush(app)
        case "expire":
            // expire:<ttl ms> — end stories older than that (the app uses 24 h).
            guard let feed = try? await client.feedChannel(serverId: space.serverId) else { note(command, "error: no feed"); return true }
            _ = try? await client.fetchChannelMessages(channelId: feed, myUserId: me)
            let ended = await client.expireStories(channelId: feed, storyTag: STORY_TAG, ttlMs: Int64(arg) ?? STORY_TTL_MS)
            let left = ((try? await client.fetchChannelMessages(channelId: feed, myUserId: me)) ?? []).filter { !$0.isDeleted && ($0.content ?? "").hasPrefix(STORY_TAG) }.count
            note(command, "ended=\(ended) stories_left=\(left)")
        case "send":
            note(command, await outcome { _ = try await client.sendChannelMessage(channelId: space.channelId, text: arg) })
        case "edit":
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            guard let last = rows.last(where: { ($0.authorId == me || $0.authorId == "__me__") && !$0.isDeleted
                && !($0.content ?? "\u{2}").hasPrefix("\u{2}") }) else { note(command, "error: nothing of mine to edit"); return true }
            note(command, await outcome { try await client.editChannelMessage(channelId: space.channelId, messageId: last.messageId, text: arg) })
        case "react":
            let rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            guard let last = rows.last(where: { $0.authorId != me && $0.authorId != "__me__" && !$0.isSystem
                && !$0.isDeleted && !($0.content ?? "\u{2}").hasPrefix("\u{2}") }) else { note(command, "error: nothing to react to"); return true }
            note(command, await outcome { try await client.addReaction(channelId: space.channelId, messageId: last.messageId, emoji: arg) })
        case "letin", "decline":
            await app.waiting.refresh(serverId: space.serverId)
            let people = app.waiting.waiting(in: space.serverId)
            for w in people {
                if parts[0] == "letin" { await app.waiting.letIn(w, serverId: space.serverId) }
                else { await app.waiting.decline(w, serverId: space.serverId) }
            }
            note(command, people.isEmpty ? "nobody waiting" : "\(people.map(\.username).joined(separator: ",")): \(app.waiting.problem ?? "ok")")
        case "safety":
            guard let found = await user(arg) else { note(command, "error: no such user"); return true }
            if let n = try? await client.safetyNumber(myUserId: me, userId: found.userId, deviceId: "") {
                safety[arg] = n
                note(command, n)
            } else { note(command, "error: no safety number") }
        case "verify":
            guard let found = await user(arg) else { note(command, "error: no such user"); return true }
            // `verify:<user>` confirms the number last computed with `safety:<user>`;
            // `verify:<user>:<digits>` confirms exactly those digits (e.g. a stale number).
            let shown = safety[arg] ?? ""
            note(command, await outcome { try await client.verifyContact(userId: found.userId, safetyNumber: shown) })
        case "verifynumber":
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard bits.count == 2, let found = await user(bits[0]) else { note(command, "error: no such user"); return true }
            note(command, await outcome { try await client.verifyContact(userId: found.userId, safetyNumber: bits[1]) })
        case "safetyqr":
            guard let found = await user(arg) else { note(command, "error: no such user"); return true }
            note(command, (try? await client.safetyQr(userId: found.userId)) ?? "error: no code")
        case "scanqr":
            // What a live scan of `<payload>` on <user>'s screen would conclude.
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard bits.count == 2, let found = await user(bits[0]) else { note(command, "error: no such user"); return true }
            do {
                let matched = try await client.checkSafetyQr(userId: found.userId, scanned: bits[1])
                note(command, matched.map { "match \($0)" } ?? "not a safety code")
            } catch CoreError.IdentityChanged { note(command, "MISMATCH") }
            catch { note(command, "error: \(coreErrorText(error))") }
        case "accept":
            guard let found = await user(arg) else { note(command, "error: no such user"); return true }
            let shown = await client.contactStatus(userId: found.userId).acceptFingerprint
            note(command, await outcome { try await client.acceptIdentityChange(userId: found.userId, deviceId: "", shown: shown) })
        case "dm":
            let bits = arg.split(separator: ":", maxSplits: 1).map(String.init)
            guard bits.count == 2, let found = await user(bits[0]),
                  let convo = try? await client.openDm(peerUserId: found.userId) else { note(command, "error: no such user"); return true }
            if !chat.dms.contains(where: { $0.conversationId == convo }) {
                chat.addDM(DMConversation(name: bits[0], peerUserId: found.userId, peerDeviceId: found.deviceId, conversationId: convo))
            }
            note(command, await outcome {
                _ = try await client.sendDm(conversationId: convo, userId: found.userId, deviceId: found.deviceId, text: bits[1])
            })
            await app.surfaceSecurityNotices()
        case "approvelink":
            note(command, await outcome { if !(try await client.approveDeviceLink(code: arg)) { throw CoreError.Invalid(detail: "link not approved") } })
        case "mint":
            // One more invite code (bare), appended to invites.txt — e.g. for a second joiner.
            if let code = try? await client.inviteToSpace(serverId: space.serverId, kind: arg.isEmpty ? "token" : arg, reservedUsername: nil) {
                let file = outDir.appendingPathComponent("invites.txt")
                let existing = (try? String(contentsOf: file, encoding: .utf8)) ?? ""
                try? (existing + code + "\n").write(to: file, atomically: true, encoding: .utf8)
                note(command, "ok")
            } else { note(command, "error: could not mint") }
        case "photo":
            // A photo into the first channel, exactly as the composer sends one: sealed,
            // uploaded, and sent WITH its blob id so the server links it to the message.
            guard let store = BlobStore(app: app) else { note(command, "error: not connected"); return true }
            note(command, await outcome {
                let out = try await AttachmentService.uploadImage(samplePhoto(seed: results.count), to: .channel, store: store)
                _ = try await client.sendChannelMessageWith(channelId: space.channelId, text: out.body, replyToId: nil, blobIds: out.blobIds)
            })
        case "dmphoto":
            guard let store = BlobStore(app: app), let found = await user(arg),
                  let convo = try? await client.openDm(peerUserId: found.userId) else { note(command, "error: no such user"); return true }
            await chat.upsertDM(conversationId: convo, peerUserId: found.userId)
            note(command, await outcome {
                let out = try await AttachmentService.uploadImage(samplePhoto(seed: results.count), to: .directMessage, store: store)
                _ = try await client.sendDm(conversationId: convo, userId: found.userId, deviceId: found.deviceId, text: out.body)
            })
        case "openatt", "opendmatt":
            // Download + decrypt the newest attachment someone ELSE sent — the thing that used
            // to work for the uploader only.
            guard let store = BlobStore(app: app) else { note(command, "error: not connected"); return true }
            var rows: [Message] = []
            if parts[0] == "openatt" {
                rows = (try? await client.fetchChannelMessages(channelId: space.channelId, myUserId: me)) ?? []
            } else if let found = await user(arg), let convo = try? await client.openDm(peerUserId: found.userId) {
                rows = (try? await client.fetchDm(conversationId: convo, userId: found.userId, deviceId: found.deviceId, myUserId: me)) ?? []
            }
            await app.drainDmEvents()
            guard let a = rows.last(where: { $0.authorId != me && $0.authorId != "__me__" && ChatTags.parse($0.content ?? "").attachment != nil })
                .flatMap({ ChatTags.parse($0.content ?? "").attachment }) else { note(command, "error: no attachment from someone else"); return true }
            do {
                let file = try await AttachmentService.localFile(for: a, store: store)
                let bytes = (try? Data(contentsOf: file)) ?? Data()
                let image = SafeImage.decode(bytes) != nil
                note(command, "ok: \(bytes.count) bytes, declared \(a.size), image=\(image), token=\(a.token != nil)")
            } catch { note(command, "error: \((error as? AttachmentError)?.errorDescription ?? "\(error)")") }
        // ---- build 45: mutes, the alert decisions, the host's upload limit, a photo story ----
        case "pasteimage":
            // A picture on the clipboard, then the composer's own Paste (what the edit menu calls).
            #if os(iOS)
            guard let field = composerField else { note(command, "error: no composer on screen"); return true }
            UIPasteboard.general.image = UIImage(data: samplePhoto(seed: 46))
            let before = stagedCount
            field.paste(nil)
            for _ in 0..<20 where stagedCount == before { try? await Task.sleep(for: .milliseconds(250)) }
            note(command, stagedCount > before ? "ok staged=\(stagedCount)" : "error: nothing staged (\(stagedCount))")
            #else
            note(command, "error: iOS only")
            #endif
        case "typing":
            // Who shows as typing in the conversation on screen now.
            let now = Date()
            note(command, "topic=\(app.typing.state.topic ?? "-") typers=\(app.typing.state.active(now: now).count) line=\(TypingState.text(app.typing.labels(now: now)) ?? "-")")
        case "mutechannel":
            guard let workspace = app.current?.id else { note(command, "error: no skwod"); return true }
            MuteCenter.shared.mute(workspaceId: workspace, key: "channel:\(space.channelId)", for: .forever)
            note(command, "ok muted=\(MuteCenter.shared.isMuted(workspaceId: workspace, scope: "channel:\(space.channelId)"))")
        case "mentions":
            // The red "@ n" of every channel of this skwod, and whose @everyone counts here.
            guard let workspace = app.current?.id else { note(command, "error: no skwod"); return true }
            MentionBadges.reload()
            let counts = MentionBadges.shared.counts[workspace] ?? [:]
            note(command, "badges=\(counts.values.reduce(0, +)) channel=\(MentionBadges.shared.count("channel:\(space.channelId)", workspaceId: workspace)) everyone=\(chat.everyoneSenders[space.serverId]?.count ?? -1)")
        case "servers":
            let before = chat.serverGroups.count
            await chat.refreshServerList()
            note(command, "n=\(chat.serverGroups.count) [\(chat.serverGroups.map(\.name).joined(separator: ", "))] before=\(before)")
        case "leaveserver", "deleteserver":
            // leaveserver[:<name>] / deleteserver[:<name>] — what the server menu's items call.
            let target = arg.isEmpty ? space.serverId : (chat.serverGroups.first { $0.name == arg }?.serverId ?? "")
            guard !target.isEmpty else { note(command, "error: no such server"); return true }
            let problem = parts[0] == "leaveserver" ? await chat.leaveServer(target) : await chat.deleteServer(target)
            note(command, problem.map { "error: \($0)" } ?? "ok servers=\(chat.serverGroups.count)")
        case "setavatar":
            // What "Change profile picture" does: my avatar to every channel I am in.
            await app.avatars.setUserAvatar(E2E.samplePhoto(seed: 7))
            note(command, "ok has=\(app.avatars.data(for: AvatarStore.userKey(me)) != nil)")
        case "avatars":
            // The avatars this device holds (keys), e.g. after a sibling handed its cache over.
            let keys = (app.avatars.siblingEntries(workspaceId: app.current?.id ?? "") ?? []).filter { $0.img != nil }.map(\.key).sorted()
            note(command, "n=\(keys.count) [\(keys.joined(separator: ", "))]")
        case "trust":
            // trust:<username> — how this device shows them, and what the core says.
            guard let found = await user(arg) else { note(command, "error: no such user"); return true }
            let shown = app.contacts.display(found.userId, claimedName: arg)
            let status = await client.contactStatus(userId: found.userId)
            note(command, "label=\(shown.spoken) badge=\(shown.badge) level=\(app.contacts.level(found.userId)) core_verified=\(status.verified)")
        case "sharesiblings":
            await SiblingSync.share(app)
            note(command, "ok")
        case "renameserver":
            // What "Rename server…" calls (owners and admins).
            let problem = await chat.renameServer(space.serverId, to: arg)
            note(command, problem.map { "error: \($0)" } ?? "ok name=\(chat.serverGroups.first { $0.serverId == space.serverId }?.name ?? "-")")
        case "servername":
            // The name this device shows for the first server, after asking the host again.
            await chat.refreshServerList()
            note(command, "name=\(chat.serverGroups.first { $0.serverId == space.serverId }?.name ?? "-")")
        case "renamehost":
            // What "Rename on host…" calls (the instance owner).
            let problem = await app.setInstanceName(arg)
            note(command, problem.map { "error: \($0)" } ?? "ok")
        case "skwodname":
            // The name this entry shows, after asking the host again.
            await app.refreshInstanceName()
            note(command, "name=\(app.current?.displayName ?? "-") from_host=\(app.current?.nameFromHost == true)")
        case "mute", "unmute":
            // mute:<user> — the conversation with them; mute:skwod — the whole skwod (until unmuted).
            guard let workspace = app.current?.id else { note(command, "error: no skwod"); return true }
            var key = MuteList.skwod
            if arg != "skwod" {
                guard let d = await dm(arg, mine: false) else { note(command, "error: no such user"); return true }
                key = "dm:\(d.convo)"
            }
            if parts[0] == "mute" { MuteCenter.shared.mute(workspaceId: workspace, key: key, for: .forever) }
            else { MuteCenter.shared.unmute(workspaceId: workspace, key: key) }
            let stored = MuteStore.load(workspaceId: workspace)
            let now = Date().timeIntervalSince1970
            note(command, "ok held=\(MuteCenter.shared.holds(workspaceId: workspace, key: key)) stored=\(stored.holds(key, now: now)) calls_ring=\(stored.callsRing(now: now))")
        case "alerts":
            // Every alert decision so far; `alerts:clear` starts over.
            if arg == "clear" { alerts = []; note(command, "ok") } else { note(command, "n=\(alerts.count) [\(alerts.joined(separator: " | "))]") }
        case "limit":
            // What the host says one file may be, asked now.
            await UploadLimitSync.refresh(app, force: true)
            note(command, "bytes=\(UploadLimit.current) label=\(UploadLimit.label(UploadLimit.current))")
        case "feedpost", "feedphoto", "storyphoto":
            // Through the Feed screen's own model (it must be on screen: `open:feed`).
            feedResult = nil
            var info: [String: Any] = ["text": arg]
            if parts[0] != "feedpost" { info["photo"] = samplePhoto(seed: results.count) }
            if parts[0] == "storyphoto" { info["story"] = true }
            NotificationCenter.default.post(name: .skwodE2EFeedPost, object: info)
        case "flood":
            let n = Int(arg) ?? 150
            var sent = 0
            var failure = ""
            for i in 1...max(1, n) {
                do { _ = try await client.sendChannelMessage(channelId: space.channelId, text: "flood \(i) of \(n)"); sent += 1 }
                catch { failure = coreErrorText(error); try? await Task.sleep(for: .seconds(2)) }
            }
            note(command, "sent \(sent) of \(n)\(failure.isEmpty ? "" : " (last error: \(failure))")")
        case "showatt":
            // Open the newest picture from someone else full-size, as a tap on it does.
            let rows = await client.history(scope: {
                if case .dm(let d) = chat.selection { return "dm:\(d.conversationId)" }
                return "channel:\(space.channelId)"
            }())
            let blob = rows.last(where: { $0.authorId != me && $0.authorId != "__me__" && ChatTags.parse($0.content ?? "").attachment?.kind == .image })
                .flatMap { ChatTags.parse($0.content ?? "").attachment?.blobId }
            NotificationCenter.default.post(name: .skwodE2EShowAttachment, object: blob)
            note(command, blob == nil ? "error: no picture from someone else" : "ok")
        case "closeatt":
            NotificationCenter.default.post(name: .skwodE2EShowAttachment, object: "close")
            note(command, "ok")
        case "loadolder":
            NotificationCenter.default.post(name: .skwodE2ELoadOlder, object: nil)
            note(command, "ok")
        case "listdms":
            await chat.refreshDMList()
            note(command, chat.dms.map(\.name).sorted().joined(separator: ","))
        case "rings":
            let rings = await app.pendingRingsEverywhere()
            note(command, rings.isEmpty ? "none" : rings.map { "\($0.workspace.displayName):\($0.ring.channelId):expires_in=\(($0.ring.expiresAt - Int64(Date().timeIntervalSince1970 * 1000)) / 1000)s" }.joined(separator: ","))
        case "background":
            app.enterBackground(); app.setActive(false)
            note(command, "socket_live=\(app.realtime.isLive)")
        case "foreground":
            app.setActive(true)
            await app.enterForeground()
            note(command, "ok")
        case "join":
            note(command, await chat.joinByCode(arg) ?? "ok")
        case "open":
            if arg == "feed" { chat.homeMode = false; chat.selection = .feed; note(command, "ok"); return true }
            if arg == "home" { chat.showHome(); note(command, "ok"); return true }
            if arg == "channel" { chat.selection = .space(space) }
            else if arg.hasPrefix("dm:"), let d = chat.dms.first(where: { $0.name == String(arg.dropFirst(3)) }) {
                // Shown without `addDM`: looking at a conversation is not vouching for its name.
                chat.homeMode = true
                chat.selection = .dm(d)
            }
            note(command, "ok")
        case "showsafety":
            NotificationCenter.default.post(name: .skwodE2EShowSafety, object: nil)
            note(command, "ok")
        case "selfcheck":
            boundedReadOutcome = await checkBoundedRead()
            var report = contentPrivacyCheck()
            #if os(macOS)
            // The Mac host's decisions (restart, port, proof, quit, updates): Sources/HostReliability.swift.
            report += " " + HostReliabilityChecks.run()
                .map { "\($0.0.replacingOccurrences(of: " ", with: "_"))=\($0.1 ? "ok" : "FAIL")" }.joined(separator: " ")
            #endif
            note(command, report)
        case "showmembers":
            NotificationCenter.default.post(name: .skwodE2EShowMembers, object: nil)
            note(command, "ok")
        default:
            return false
        }
        return true
    }

    /// Set by `selfcheck` (the read is async): a stream LONGER than the limit is cut off, one at
    /// the limit is read whole.
    @MainActor static var boundedReadOutcome: Bool?

    static func checkBoundedRead() async -> Bool {
        let endless = AsyncStream<UInt8> { c in for i in 0..<200_000 { c.yield(UInt8(truncatingIfNeeded: i)) }; c.finish() }
        var cutOff = false
        do { _ = try await AttachmentLimits.read(endless, limit: 100_000) }
        catch AttachmentError.oversized { cutOff = true }
        catch {}
        let exact = AsyncStream<UInt8> { c in for i in 0..<100_000 { c.yield(UInt8(truncatingIfNeeded: i)) }; c.finish() }
        let whole = (try? await AttachmentLimits.read(exact, limit: 100_000))?.count == 100_000
        return cutOff && whole
    }

    /// Exercises the content-privacy code paths on this device and reports each as ok/FAIL:
    /// metadata stripping, decode bounds, link policy, avatar authority and (macOS) quarantine.
    @MainActor
    private static func contentPrivacyCheck() -> String {
        var out: [String] = []
        func check(_ name: String, _ ok: Bool) { out.append("\(name)=\(ok ? "ok" : "FAIL")") }

        // A DM reply preview quotes only what the conversation's two participants wrote: a
        // row a third account got filed under the conversation id never shows through one.
        let dmRows: [(id: String, authorId: String?, deleted: Bool, content: String)] = [
            ("m1", "__me__", false, "mine"), ("m2", "peer", false, "theirs"), ("m3", "ghost", false, "planted"),
            ("m4", "__system__", false, "notice"), ("m5", "peer", true, "deleted"), ("m6", "me-id", false, "my other device"),
            ("m7", nil, false, "no author"),
        ]
        let quotable = DMReplySources.quotable(dmRows, me: "me-id", peer: "peer")
        check("dm-reply-quotes-participants-only", Set(quotable.keys) == ["m1", "m2", "m6"])
        check("dm-reply-never-quotes-a-third-account", quotable["m3"] == nil && quotable["m4"] == nil && quotable["m7"] == nil)
        check("dm-reply-attribution", quotable["m1"]?.mine == true && quotable["m6"]?.mine == true && quotable["m2"]?.mine == false)
        check("dm-reply-skips-deleted", quotable["m5"] == nil)

        // A JPEG that carries a GPS position and a camera model, as a phone photo does.
        let cs = CGColorSpaceCreateDeviceRGB()
        let ctx = CGContext(data: nil, width: 64, height: 48, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                            bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
        ctx?.setFillColor(red: 0.2, green: 0.5, blue: 0.8, alpha: 1)
        ctx?.fill(CGRect(x: 0, y: 0, width: 64, height: 48))
        let tagged = NSMutableData()
        if let cg = ctx?.makeImage(),
           let dest = CGImageDestinationCreateWithData(tagged, "public.jpeg" as CFString, 1, nil) {
            let props: [CFString: Any] = [
                kCGImagePropertyGPSDictionary: [kCGImagePropertyGPSLatitude: 38.7, kCGImagePropertyGPSLatitudeRef: "N",
                                                kCGImagePropertyGPSLongitude: 77.6, kCGImagePropertyGPSLongitudeRef: "W"],
                kCGImagePropertyTIFFDictionary: [kCGImagePropertyTIFFMake: "Apple", kCGImagePropertyTIFFModel: "iPhone"],
                kCGImagePropertyExifDictionary: [kCGImagePropertyExifDateTimeOriginal: "2026:11:18 10:00:00"],
            ]
            CGImageDestinationAddImage(dest, cg, props as CFDictionary)
            CGImageDestinationFinalize(dest)
        }
        let photo = tagged as Data
        check("fixture_has_gps", SafeImage.hasPrivateMetadata(photo))
        let clean = SafeImage.stripped(photo)
        check("stripped_has_no_gps", clean.map { !SafeImage.hasPrivateMetadata($0.data) } ?? false)
        check("stripped_decodes", clean.flatMap { SafeImage.decode($0.data) } != nil)
        check("bounds_refuse_bomb", !SafeImage.plausible(width: 60_000, height: 60_000) && SafeImage.plausible(width: 8064, height: 6048))
        check("garbage_is_not_an_image", SafeImage.decode(Data(repeating: 0x41, count: 4096)) == nil)

        let honest = String(LinkSafety.attributed("see [skwod.io/reset](https://evil.example/x) now").characters)
        check("link_shows_target", honest.contains("(https://evil.example/x)"))
        check("link_same_label_untouched", String(LinkSafety.attributed("[https://skwod.io](https://skwod.io)").characters) == "https://skwod.io")
        check("link_schemes", LinkSafety.isOpenable(URL(string: "https://a.example")!) && !LinkSafety.isOpenable(URL(string: "file:///etc/passwd")!)
              && !LinkSafety.isOpenable(URL(string: "skwod://join/x")!) && !LinkSafety.isOpenable(URL(string: "javascript:alert(1)")!))

        let a = AvatarStore.Authority(serverId: "A", serverOwner: "ownerA", instanceId: "I", instanceOwner: "host")
        check("avatar_user_own_only", AvatarStore.mayWrite(key: "user:u1", authorId: "u1", me: nil, authority: a)
              && !AvatarStore.mayWrite(key: "user:u1", authorId: "u2", me: nil, authority: a))
        check("avatar_server_bound_to_carrier", AvatarStore.mayWrite(key: "server:A", authorId: "ownerA", me: nil, authority: a)
              && !AvatarStore.mayWrite(key: "server:B", authorId: "ownerA", me: nil, authority: a))
        check("avatar_skwod_instance_owner_only", AvatarStore.mayWrite(key: "skwod:I", authorId: "host", me: nil, authority: a)
              && !AvatarStore.mayWrite(key: "skwod:I", authorId: "ownerA", me: nil, authority: a)
              && !AvatarStore.mayWrite(key: "skwod:J", authorId: "host", me: nil, authority: a))
        check("avatar_unpinned_authorizes_nobody", !AvatarStore.mayWrite(key: "server:A", authorId: "ownerA", me: nil, authority: .init(serverId: "A"))
              && !AvatarStore.mayWrite(key: "skwod:I", authorId: "host", me: nil, authority: .init(instanceId: "I")))

        // "Waiting to join" labels: a name is only a name when it resolves to that account
        // and is not the name of someone else the user already knows.
        let friends = [(userId: "u-merhan", name: "Merhan")]
        check("waiting_name_ok", WaitingTrust.assess(userId: "u-new", username: "sam", lookup: .some("u-new"), known: friends) == .ok)
        check("waiting_name_other_account", WaitingTrust.assess(userId: "u-ghost", username: "sam", lookup: .some("u-sam"), known: friends) == .nameMismatch)
        check("waiting_name_nobody", WaitingTrust.assess(userId: "u-ghost", username: "sam", lookup: .some(nil), known: friends) == .nameMismatch
              && WaitingTrust.assess(userId: "u-ghost", username: "", lookup: .some("u-ghost"), known: friends) == .nameMismatch)
        check("waiting_lookup_failed_is_unchecked", WaitingTrust.assess(userId: "u-new", username: "sam", lookup: nil, known: friends) == .unchecked)
        check("waiting_impersonation", WaitingTrust.assess(userId: "u-ghost", username: " merhan ", lookup: .some("u-ghost"), known: friends) == .impersonation
              && WaitingTrust.assess(userId: "u-merhan", username: "Merhan", lookup: .some("u-merhan"), known: friends) == .ok)
        // Look-alike names: invisible characters, another script, full-width forms. None may
        // ever read as "ok", and next to the real Merhan each is an impersonation.
        check("waiting_zero_width", WaitingTrust.assess(userId: "u-ghost", username: "mer\u{200B}han", lookup: .some("u-ghost"), known: friends) == .impersonation
              && WaitingTrust.assess(userId: "u-new", username: "sa\u{200D}m", lookup: .some("u-new"), known: friends) == .unusualCharacters
              && WaitingTrust.assess(userId: "u-new", username: "sam\u{FEFF}", lookup: .some("u-new"), known: friends) == .unusualCharacters)
        check("waiting_cyrillic_lookalike", WaitingTrust.assess(userId: "u-ghost", username: "m\u{0435}rhan", lookup: .some("u-ghost"), known: friends) == .impersonation
              && WaitingTrust.assess(userId: "u-new", username: "s\u{0430}m", lookup: .some("u-new"), known: friends) == .unusualCharacters)
        check("waiting_full_width", WaitingTrust.assess(userId: "u-ghost", username: "\u{FF4D}\u{FF45}\u{FF52}\u{FF48}\u{FF41}\u{FF4E}", lookup: .some("u-ghost"), known: friends) == .impersonation
              && WaitingTrust.assess(userId: "u-new", username: "\u{FF53}\u{FF41}\u{FF4D}", lookup: .some("u-new"), known: friends) == .unusualCharacters)
        check("waiting_ascii_lookalike", WaitingTrust.assess(userId: "u-ghost", username: "rnerhan", lookup: .some("u-ghost"), known: friends) == .impersonation
              && WaitingTrust.assess(userId: "u-ghost", username: "merhan", lookup: .some("u-ghost"), known: [(userId: "u-m", name: "MERHAN")]) == .impersonation)
        check("waiting_plain_ascii_different_name", WaitingTrust.assess(userId: "u-new", username: "morgan", lookup: .some("u-new"), known: friends) == .ok
              && WaitingTrust.assess(userId: "u-new", username: "sam_2", lookup: .some("u-new"), known: friends) == .ok)
        check("waiting_only_ok_can_be_let_in", [WaitingTrust.Verdict.unchecked, .nameMismatch, .impersonation, .unusualCharacters].allSatisfy {
            !WaitingMember(userId: "u", username: "n", source: .held, trust: $0).canLetIn
        } && WaitingMember(userId: "u", username: "n", source: .held, trust: .ok).canLetIn)
        // One name-trust model (`ContactTrust`): only something the USER did raises a name
        // above "unverified"; the server's word never does.
        let book: [String: Contact] = ["u-merhan": Contact(name: "merhan", level: .known),
                                       "u-vera": Contact(name: "vera", level: .verified)]
        check("contact_rekey_refused",
              ContactTrust.conversationIndex(for: "u-ghost", conversationId: "c1", in: [(conversationId: "c1", peerUserId: "u-merhan")]) == nil
              && ContactTrust.conversationIndex(for: "u-merhan", conversationId: "c1", in: [(conversationId: "c1", peerUserId: "u-merhan")]) == 0)
        let legacy = (try? JSONDecoder().decode([String: Contact].self, from: Data(#"{"u-old":{"name":"olga"}}"#.utf8))) ?? [:]
        check("contact_old_entries_unverified", legacy["u-old"]?.level == .unverified && legacy["u-old"]?.name == "olga"
              && ContactTrust.migratedLevel(startedHere: false) == .unverified && ContactTrust.migratedLevel(startedHere: true) == .known)
        // A name seen in a member list AND confirmed by findUser was recorded as unverified —
        // twice — and is still shown as unverified; server data cannot touch a pinned contact.
        let serverOnly = ContactTrust.merged(existing: ContactTrust.merged(existing: nil, name: "sam", level: .unverified), name: "sam", level: .unverified)
        check("contact_server_name_never_trusted", serverOnly.level == .unverified
              // member list + a matching findUser: still only the quiet "unverified" marker…
              && ContactTrust.display(userId: "u-sam", claimedName: "sam", book: ["u-sam": serverOnly], roster: ["u-sam": "sam"], lookup: true).badge == .unverified
              // …and without that match (another id, nobody, no answer) it is flagged.
              && ContactTrust.display(userId: "u-sam", claimedName: "sam", book: [:], lookup: false).badge == .unconfirmed
              && ContactTrust.display(userId: "u-sam", claimedName: "sam", book: [:], lookup: false).text.hasPrefix("Unknown contact")
              && ContactTrust.display(userId: "u-sam", claimedName: "sam", book: [:], lookup: nil) == .init(text: "sam", badge: .unconfirmed)
              && ContactTrust.merged(existing: book["u-merhan"], name: "mallory", level: .unverified) == book["u-merhan"]
              && ContactTrust.display(userId: "u-x", claimedName: nil, book: [:]).text.hasPrefix("Unknown contact"))
        check("contact_lookalike_strong_warning",
              ContactTrust.display(userId: "u-ghost", claimedName: "m\u{0435}rhan", book: book, lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-ghost", claimedName: "merhan", book: book, lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-ghost", claimedName: "mer\u{200B}han", book: book, lookup: true).text.hasPrefix("Unknown contact")
              && ContactTrust.display(userId: "u-ghost", claimedName: "VERA", book: book, lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-merhan", claimedName: "whatever", book: book) == .init(text: "merhan", badge: .none)
              // …but an unverified namesake outside every roster is not grounds for it:
              && ContactTrust.display(userId: "u-b", claimedName: "sam", book: ["u-a": Contact(name: "sam", level: .unverified)], lookup: true).badge == .unverified)
        // An accepted member of a shared server the user has never messaged: nobody else may
        // wear their name — while their own row stays merely "unverified".
        check("contact_lookalike_of_accepted_member",
              ContactTrust.display(userId: "u-ghost", claimedName: "j\u{043E}rdan", book: [:], roster: ["u-jordan": "jordan"], lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-ghost", claimedName: "jordan", book: [:], roster: ["u-jordan": "jordan"], lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-jordan", claimedName: "jordan", book: [:], roster: ["u-jordan": "jordan"], lookup: true) == .init(text: "jordan", badge: .unverified))
        // Characters no Skwod name has are a strong warning on their own, collision or not.
        check("contact_unusual_characters_strong_warning",
              ContactTrust.display(userId: "u-new", claimedName: "z\u{043E}e", book: [:], lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-new", claimedName: "zoe\u{200B}", book: [:], lookup: true).badge == .impersonation
              && ContactTrust.display(userId: "u-new", claimedName: "\u{FF5A}\u{FF4F}\u{FF45}", book: [:], lookup: true).text.hasPrefix("Unknown contact"))
        // Opening conversations: looking is not vouching, and a flagged name is not trusted
        // just because the user started the conversation.
        let unverifiedSam = Contact(name: "sam", level: .unverified)
        check("contact_tap_existing_changes_nothing",
              ContactTrust.afterOpening(existing: unverifiedSam, isNewConversation: false, name: "sam", badge: .unverified) == unverifiedSam
              && ContactTrust.afterOpening(existing: nil, isNewConversation: false, name: "sam", badge: .unverified) == nil
              && ContactTrust.afterOpening(existing: book["u-vera"], isNewConversation: false, name: "x", badge: .none) == book["u-vera"])
        check("contact_start_with_flagged_stays_unverified",
              ContactTrust.afterOpening(existing: nil, isNewConversation: true, name: "merhan", badge: .impersonation)?.level == .unverified
              && ContactTrust.afterOpening(existing: unverifiedSam, isNewConversation: true, name: "sam", badge: .unconfirmed)?.level == .unverified
              && !ContactTrust.mayAccept(.impersonation) && ContactTrust.mayAccept(.unverified) && ContactTrust.mayAccept(.unconfirmed))
        check("contact_start_with_unflagged_becomes_known",
              ContactTrust.afterOpening(existing: nil, isNewConversation: true, name: "sam", badge: .unverified) == Contact(name: "sam", level: .known)
              && ContactTrust.afterOpening(existing: book["u-vera"], isNewConversation: true, name: "vera", badge: .verified)?.level == .verified)
        check("contact_verify_promotes",
              ContactTrust.withVerification(Contact(name: "sam", level: .unverified), name: "sam", verified: true)?.level == .verified
              && ContactTrust.withVerification(nil, name: "sam", verified: true) == Contact(name: "sam", level: .verified)
              && ContactTrust.withVerification(Contact(name: "vera", level: .verified), name: "x", verified: false) == Contact(name: "vera", level: .known)
              && ContactTrust.display(userId: "u-vera", claimedName: "vera", book: book).badge == .verified
              && ContactTrust.merged(existing: Contact(name: "sam", level: .unverified), name: "sam", level: .known).level == .known)
        // Rings: a server's deadline is clamped to the app's own, and a call push is matched to
        // its skwod by tag — several untagged rings are asked about, never auto-joined.
        let ringNow: Int64 = 1_800_000_000_000
        let ringCap = ringNow + Int64(CallCoordinator.ringSeconds * 1000)
        check("ring_deadline_clamped", CallCoordinator.clampedDeadline(expiresAt: ringNow + 3_600_000, now: ringNow) == ringCap
              && CallCoordinator.clampedDeadline(expiresAt: .max, now: ringNow) == ringCap
              && CallCoordinator.clampedDeadline(expiresAt: ringNow + 10_000, now: ringNow) == ringNow + 10_000
              && CallCoordinator.clampedDeadline(expiresAt: ringNow - 1, now: ringNow) == nil
              && CallCoordinator.clampedDeadline(expiresAt: 0, now: ringNow) == ringCap)
        check("ring_pick", CallCoordinator.pick(ringing: ["a", "b"], tagOwner: nil, current: "a", answered: false) == .ask(["a", "b"])
              && CallCoordinator.pick(ringing: ["b"], tagOwner: nil, current: "a", answered: false) == .use("b")
              && CallCoordinator.pick(ringing: [], tagOwner: nil, current: "a", answered: false) == .none
              // tagged: only the tag's owner may supply the ring
              && CallCoordinator.pick(ringing: ["a", "b"], tagOwner: .some("b"), current: "a", answered: true) == .use("b")
              && CallCoordinator.pick(ringing: ["a"], tagOwner: .some("b"), current: "a", answered: false) == .none
              && CallCoordinator.pick(ringing: ["a", "b"], tagOwner: .some(nil), current: "a", answered: false) == .none
              // answered, untagged: no silent switch to another skwod
              && CallCoordinator.pick(ringing: ["b"], tagOwner: nil, current: "a", answered: true) == .ask(["b"])
              && CallCoordinator.pick(ringing: ["a"], tagOwner: nil, current: "a", answered: true) == .use("a"))
        // Attachment bounds: a size is the sender's claim, and a download is never open-ended.
        check("attachment_size_gate", AttachmentLimits.acceptable(declaredSize: 5_000_000)
              && AttachmentLimits.acceptable(declaredSize: Int64(AttachmentLimits.hardCap))
              && !AttachmentLimits.acceptable(declaredSize: Int64(AttachmentLimits.hardCap) + 1)
              && !AttachmentLimits.acceptable(declaredSize: -1) && !AttachmentLimits.acceptable(declaredSize: .max))
        check("attachment_auto_download", !AttachmentLimits.mayAutoDownload(kind: .image, declaredSize: 2_000, surface: .feed, expensiveNetwork: false)
              && AttachmentLimits.mayAutoDownload(kind: .image, declaredSize: 2_000_000, surface: .chat, expensiveNetwork: false)
              && !AttachmentLimits.mayAutoDownload(kind: .image, declaredSize: 2_000_000, surface: .chat, expensiveNetwork: true)
              && !AttachmentLimits.mayAutoDownload(kind: .image, declaredSize: Int64(AttachmentLimits.autoCap) + 1, surface: .feed, expensiveNetwork: false)
              && !AttachmentLimits.mayAutoDownload(kind: .video, declaredSize: 1_000, surface: .feed, expensiveNetwork: false)
              && !AttachmentLimits.mayAutoDownload(kind: .file, declaredSize: 1_000, surface: .chat, expensiveNetwork: false))
        check("attachment_bounded_read", boundedReadOutcome ?? false)
        #if os(macOS)
        let file = AttachmentCache.prepared().appendingPathComponent("selfcheck-\(UUID().uuidString).command")
        try? AttachmentCache.write(Data("#!/bin/sh\n".utf8), to: file)
        check("quarantine_xattr", AttachmentCache.isQuarantined(file))
        try? FileManager.default.removeItem(at: file)
        #endif
        return out.joined(separator: " ")
    }

    /// `e2e.json`: what this client holds about membership and its contacts.
    @MainActor
    private static func dumpTrust(app: AppState, chat: ChatModel, client: SkwodClient, space: RealSpace, me: String) async {
        var contactState: [String: Any] = [:]
        for (name, id) in contacts {
            let s = await client.contactStatus(userId: id)
            contactState[name] = ["verified": s.verified, "sends_held": s.sendsHeld, "devices": s.devices,
                                  "unvouched_devices": s.unvouchedDevices, "safety_number": safety[name] ?? ""]
        }
        var state: [String: Any] = [
            "me": me,
            "device": app.deviceId ?? "",
            "server_id": space.serverId,
            "channel_id": space.channelId,
            "waiting": app.waiting.waiting(in: space.serverId).map { ["user_id": $0.userId, "username": $0.username,
                                                                      "source": $0.source == .request ? "request" : "held",
                                                                      "trust": "\($0.trust)", "new": $0.isNew,
                                                                      "fingerprint": $0.shortFingerprint ?? "",
                                                                      "fingerprint_pinned": $0.fingerprintPinned] },
            "held_members": await client.heldMembers(serverId: space.serverId),
            "contacts": contactState,
            "results": results,
            "live": await liveState(app: app, chat: chat),
        ]
        if let owner = await client.spaceOwner(serverId: space.serverId) { state["pinned_server_owner"] = owner }
        if let owner = await client.instanceOwner() { state["pinned_instance_owner"] = owner }
        if let data = try? JSONSerialization.data(withJSONObject: state, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: outDir.appendingPathComponent("e2e.json"), options: .atomic)
        }
    }

    /// Resident memory of this process, in bytes (to show an upload did not load the file).
    static func residentMemory() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count) }
        }
        return result == KERN_SUCCESS ? info.resident_size : 0
    }

    /// SHA-256 of a file, read in pieces.
    static func sha256(of url: URL) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Before anything else runs. `SKWOD_E2E_RTC_LOG=1` sends the media engine's own (WebRTC)
    /// log to the unified log — it names local addresses, so it is for troubleshooting a test
    /// run only.
    @MainActor
    static func atLaunch() {
        if env("SKWOD_E2E_RTC_LOG") == "1" { LiveKitSDK.setLogger(OSLogger(minLevel: .debug, rtc: true)) }
        // Provisional permission needs no prompt (a prompt cannot be answered without taps and
        // would cover the screen): notifications are then delivered quietly to Notification
        // Center, where `live.delivered` reads them back from the system.
        if env("SKWOD_E2E_NOTIF") == "1" {
            UNUserNotificationCenter.current().requestAuthorization(options: [.provisional, .alert, .sound]) { _, _ in }
        }
        if env("SKWOD_E2E_LOOPBACK_ICE") == "1" { CallDebug.gatherLoopbackCandidates() }
        #if os(macOS)
        startWindowPictures()
        #endif
    }

    #if os(macOS)
    /// With `SKWOD_E2E_OUT` set, keep `window-<n>.png` (the app's own windows) current, from
    /// launch — so a run can be followed, and its screens kept, without touching the pointer.
    @MainActor
    static func startWindowPictures() {
        guard env("SKWOD_E2E_OUT") != nil else { return }
        Task { @MainActor in
            var tries = 0
            while true {
                try? await Task.sleep(for: .seconds(3))
                try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
                // A launch from a script sometimes comes up with no window at all, and then
                // nothing of the app runs (its work hangs off views). Ask for one.
                if !NSApp.windows.contains(where: { $0.isVisible && $0.frame.width > 300 }), tries < 5 {
                    tries += 1
                    NSApp.activate(ignoringOtherApps: true)
                    if !NSApp.sendAction(Selector(("newWindowForTab:")), to: nil, from: nil) {
                        NSApp.sendAction(Selector(("newWindow:")), to: nil, from: nil)
                    }
                }
                CallDebug.saveWindows(to: outDir)
            }
        }
    }
    #endif

    @MainActor
    private static func run(_ command: String, app: AppState, serverId: String) {
        switch command {
        case "call": CallCoordinator.shared.open(serverId: serverId)
        case "hangup": app.activeCall = nil
        case "decline": CallCoordinator.shared.decline()
        case "answer":
            #if os(iOS)
            CallManager.shared.debugAnswer()
            #else
            CallCoordinator.shared.answer()
            #endif
        case "shot":
            #if os(macOS)
            CallDebug.saveWindows(to: outDir)
            #endif
        case "notif":
            UNUserNotificationCenter.current().requestAuthorization(options: [.provisional, .alert, .sound]) { _, _ in }
        default:
            NotificationCenter.default.post(name: .skwodE2ECallCommand, object: command)
        }
    }
}
#endif
