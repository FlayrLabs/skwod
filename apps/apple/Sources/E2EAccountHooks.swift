#if DEBUG
import Foundation
import SwiftUI

/// DEBUG-only hooks for the build-44 ACCOUNT flows (devices, sign-out, erase, recovery key,
/// restore, PIN, approvals, the cache lock). Compiled out of Release.
///
/// These flows happen exactly where the main shell is NOT on screen — signed out, waiting for a
/// restore, removed — so they have a driver of their own that only needs the app state, started
/// at launch. Commands go, one per line, into `<out>/acct-cmd.txt` (consumed); the state and
/// every command's outcome are kept current in `<out>/account.json`. Each command calls what the
/// matching button calls:
///
/// `devices` · `renamedevice:<name>` · `removedevice:<name or id prefix>` · `marklost` (the newest
/// erased device) · `signout` · `signoutall` · `erasecheck` · `erase` / `eraselost` / `eraseoffline` ·
/// `switch:<n or workspace id prefix>` (open another skwod, as its tile does) ·
/// `recoverykey` (generate, confirm, turn on — the key is written to account.json: a TEST key) ·
/// `compromised` · `restore:<key>` · `retryrestore[:<pin>]` · `link` (begin a device link, wait
/// for the approval) · `approvelink:<code>` · `deferrecovery[:<code>]` ("Decide later") · `approverecovery:<code>` / `blockrecovery:<code>`
/// (the pending request showing that code) · `reset[:<pin>]` · `forgotpin` · `setpin:<pin>` ·
/// `setupagain` · `refresh` (what a realtime nudge does) · `show:<sheet>` / `hide` (put a screen
/// up for a picture: devices, erase, activity, reports, recoverykey, setup, restore; `addskwod`
/// is the rail's "Join or host a Skwod" form, which joins a second skwod when the invite variables are set) ·
/// `selfcheck` (the pure rules of these screens).
///
/// `SKWOD_E2E_NSE_HOLD=<seconds>`: before the app opens any cache, a stand-in for the
/// notification extension takes the cache lock the way the extension does and gives it up only
/// when the app asks (`store.yield`), after `SKWOD_E2E_NSE_YIELD_DELAY` seconds (default 1.5) —
/// as if it were finishing a write. `account.json` → `storelock` lists each step with its
/// time: the app must be seen WAITING, then the stand-in releasing, then the app holding the
/// lock, and only then `cache_opened`.
extension E2E {
    @MainActor private static var accountResults: [[String: String]] = []
    @MainActor private static var lastState = ""
    @MainActor private static var testRecoveryKey = ""
    @MainActor private static var linkCode = ""
    @MainActor private static var deviceList: [[String: Any]] = []
    @MainActor private static var maxDevices = 0
    @MainActor private static var eraseState: [String: Any] = [:]

    @MainActor static func sawDeviceState(_ state: DeviceState) { lastState = "\(state)" }
    static func cacheOpened() { StoreLockTrace.note("cache_opened") }

    @MainActor private static func record(_ command: String, _ outcome: String) {
        accountResults.append(["command": command, "result": outcome, "at": String(Int(Date().timeIntervalSince1970 * 1000))])
    }

    /// Started from `AppState.init` (before `restore()` opens anything).
    @MainActor
    static func startAccountDriver(_ app: AppState) {
        guard env("SKWOD_E2E_OUT") != nil else { return }
        StoreLockTrace.enabled = true
        startExtensionStandIn()
        Task { @MainActor [weak app] in
            try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
            var pending = (env("SKWOD_E2E_ACCT") ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            while let app {
                let file = outDir.appendingPathComponent("acct-cmd.txt")
                if let text = try? String(contentsOf: file, encoding: .utf8) {
                    try? FileManager.default.removeItem(at: file)
                    pending += text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                }
                // Commands wait until the app has finished restoring (and, for most, has a client).
                if !app.restoring, !app.isConnecting {
                    for command in pending where !command.isEmpty { await account(command, app: app) }
                    pending = []
                }
                await dumpAccount(app)
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// The notification extension's part of the lock hand-over, played inside this process:
    /// a second `StoreLock` (its own file descriptor, so the two really contend) used exactly as
    /// `NotificationDecryptor.rewrite` uses the shared one.
    private static func startExtensionStandIn() {
        guard let hold = env("SKWOD_E2E_NSE_HOLD").flatMap(Double.init), hold > 0 else { return }
        let delay = env("SKWOD_E2E_NSE_YIELD_DELAY").flatMap(Double.init) ?? 1.5
        // A build with no shared container has no lock file: give both sides one.
        let directory = SharedContainer.groupURL ?? SharedContainer.privateURL
        StoreLock.shared.directoryOverride = directory
        let ext = StoreLock()
        ext.directoryOverride = directory
        try? FileManager.default.removeItem(at: directory.appendingPathComponent("store.yield"))
        guard ext.tryAcquire() else { StoreLockTrace.note("ext_could_not_acquire"); return }
        StoreLockTrace.note("ext_acquired")
        let yielding = YieldFlag()
        ext.onYield { yielding.set() }
        Thread.detachNewThread {
            let deadline = Date().addingTimeInterval(hold)
            while Date() < deadline, !yielding.isSet, !ext.yieldRequested { usleep(50_000) }
            StoreLockTrace.note(yielding.isSet || ext.yieldRequested ? "ext_saw_yield" : "ext_timed_out")
            // "Finishing what it was writing" before it lets go.
            usleep(UInt32(delay * 1_000_000))
            StoreLockTrace.note("ext_released")
            ext.release()
        }
    }

    @MainActor
    private static func account(_ command: String, app: AppState) async {
        let parts = command.split(separator: ":", maxSplits: 1).map(String.init)
        let arg = parts.count > 1 ? parts[1] : ""
        func fail(_ error: Error) -> String { "error: \(coreErrorText(error)) [\(String(describing: error).prefix(60))]" }
        // Commands that need no client.
        switch parts[0] {
        case "show":
            app.e2eSheet = arg
            record(command, "ok")
            return
        case "hide":
            app.e2eSheet = nil
            record(command, "ok")
            return
        case "selfcheck":
            record(command, accountSelfCheck())
            return
        case "signout":
            let before = app.deviceId ?? ""
            app.leaveCurrent()
            record(command, "ok device_before=\(before) signed_out=\(app.session == nil)")
            return
        case "signoutall":
            app.signOut()
            record(command, "ok signed_out=\(app.session == nil)")
            return
        case "switch":
            // switch:<n> (the n-th skwod of the rail, from 0) or switch:<workspace id prefix> —
            // what tapping that skwod's tile does.
            guard let target = Int(arg).flatMap({ app.workspaces.indices.contains($0) ? app.workspaces[$0] : nil })
                    ?? app.workspaces.first(where: { !arg.isEmpty && $0.id.hasPrefix(arg) }) else { record(command, "error: no such skwod"); return }
            let before = app.current?.id ?? ""
            await app.activate(target)
            record(command, "ok from=\(before) to=\(app.current?.id ?? "") bound=\(app.bound?.workspaceId ?? "") cache_open=\(app.bound?.cacheOpen ?? false)")
            return
        default:
            break
        }
        guard let client = app.client else { record(command, "error: no client"); return }
        switch parts[0] {
        case "devices":
            if let list = await app.refreshDeviceNames() {
                maxDevices = Int(list.maxDevices)
                deviceList = list.devices.map { ["device_id": $0.deviceId, "name": $0.name ?? "", "created_at": $0.createdAt,
                                                 "last_active_at": $0.lastActiveAt, "this_device": $0.isThisDevice, "verified": $0.verified] }
                record(command, "count=\(list.devices.count) max=\(list.maxDevices) names=\(list.devices.map { $0.name ?? "-" }.joined(separator: ","))")
            } else { record(command, "error: could not list") }
        case "renamedevice":
            do { try await client.renameDevice(name: DeviceLabel.cleaned(arg)); record(command, "ok") } catch { record(command, fail(error)) }
        case "removedevice":
            guard let list = await app.refreshDeviceNames(),
                  let target = list.devices.first(where: { !$0.isThisDevice && ($0.name == arg || $0.deviceId.hasPrefix(arg)) })
                    ?? (arg.isEmpty ? list.devices.first(where: { !$0.isThisDevice }) : nil) else { record(command, "error: no such device"); return }
            do {
                try await client.unregisterDevice(deviceId: target.deviceId)
                await app.surfaceSecurityNotices()
                // What the Devices screen does next: the key was retired, make a new one.
                app.recoveryKeyPrompt = .deviceRemoved
                record(command, "ok removed=\(target.deviceId.prefix(8)) backup_enabled=\(await client.keyBackupEnabled())")
            } catch { record(command, fail(error)) }
        case "marklost":
            guard let erased = (try? await client.erasedDevices())?.max(by: { $0.erasedAt < $1.erasedAt }) else { record(command, "error: no erased device"); return }
            do { try await client.markErasedDeviceRemoved(identityKeyHex: erased.identityKeyHex); record(command, "ok") } catch { record(command, fail(error)) }
        case "erasecheck":
            do {
                let c = try await client.eraseCheck()
                eraseState = ["has_key_backup": c.hasKeyBackup, "other_devices": c.otherDevices, "safe": c.safe]
                record(command, "safe=\(c.safe) backup=\(c.hasKeyBackup) others=\(c.otherDevices)")
            } catch { record(command, fail(error)) }
        case "erase", "eraselost", "eraseoffline":
            let workspace = app.current?.id ?? ""
            do {
                try await app.eraseCurrentDevice(asLost: parts[0] == "eraselost", evenIfOffline: parts[0] == "eraseoffline")
                let keyGone = Keychain.getWithStatus("cache-key-\(workspace)").value == nil
                let fileGone = !FileManager.default.fileExists(atPath: SharedContainer.cachePath(forWorkspace: workspace))
                let mutesGone = WorkspaceItems.keychainAccounts(workspace).allSatisfy { Keychain.getWithStatus($0).value == nil }
                record(command, "ok cache_file_gone=\(fileGone) cache_key_gone=\(keyGone) mutes_gone=\(mutesGone) workspaces=\(app.workspaces.count)")
            } catch { record(command, fail(error)) }
        case "recoverykey":
            // What the sheet does: generate, the user proves they saved it, turn it on.
            let key = generateRecoveryKey()
            guard RecoveryKeyCheck.matches(RecoveryKeyCheck.tail(of: key), key: key) else { record(command, "error: tail check"); return }
            do {
                try await client.enableKeyBackup(passphrase: key)
                testRecoveryKey = key
                app.recoveryKeyPrompt = nil
                let from = await client.recoveryKeyInstantFrom()
                record(command, "ok instant_from=\(from ?? 0) text=\(RecoveryKeySheet.instantText(from))")
                NotificationCenter.default.post(name: .skwodAccountChanged, object: nil)
            } catch { record(command, fail(error)) }
        case "compromised":
            do {
                try await client.reportRecoveryKeyCompromised()
                app.recoveryKeyPrompt = .compromised
                record(command, "ok backup_enabled=\(await client.keyBackupEnabled())")
            } catch { record(command, fail(error)) }
        case "restore":
            let outcome = await AccountRestore.run(app: app, client: client, key: arg)
            record(command, "\(outcome) device=\(app.deviceId ?? "") fingerprint=\(await client.recoveryFingerprint())")
        case "retryrestore":
            let outcome = await AccountRestore.retry(app: app, client: client, pin: arg.isEmpty ? nil : arg)
            record(command, "\(outcome) device=\(app.deviceId ?? "")")
        case "link":
            do {
                linkCode = try await client.beginDeviceLink()
                record(command, "code=\(linkCode)")
                Task { @MainActor in
                    for _ in 0..<150 {
                        if let done = try? await client.completeDeviceLink(), !done.isEmpty {
                            app.needsDeviceLink = false
                            await app.deviceBecameActive()
                            record("link:completed", "device=\(app.deviceId ?? "")")
                            return
                        }
                        try? await Task.sleep(for: .seconds(2))
                    }
                    record("link:completed", "error: timed out")
                }
            } catch { record(command, fail(error)) }
        case "approvelink":
            do { record(command, try await client.approveDeviceLink(code: arg) ? "ok" : "no device waiting with that code") } catch { record(command, fail(error)) }
        case "approverecovery", "blockrecovery":
            await app.accountChanged()
            // A request the user put off is still theirs to answer (the Devices screen offers it).
            let putOff = DeferredRecoveries.shared.requests(workspaceId: app.current?.id, queued: app.recoveryRequests)
            guard let request = (app.recoveryRequests + putOff).first(where: { arg.isEmpty || $0.fingerprint == arg }) else {
                record(command, "error: no request with that code (pending: \(app.recoveryRequests.map(\.fingerprint).joined(separator: ",")))")
                return
            }
            let answer = await app.answer(request, approve: parts[0] == "approverecovery")
            if case .failed = answer {} else { DeferredRecoveries.shared.remove(requestId: request.requestId) }
            record(command, "\(answer) code=\(request.fingerprint)")
        case "deferrecovery":
            // What "Decide later" on the approval sheet does.
            guard let request = app.recoveryRequests.first(where: { arg.isEmpty || $0.fingerprint == arg }), let workspace = app.current?.id else {
                record(command, "error: no request with that code")
                return
            }
            DeferredRecoveries.shared.put(request, workspaceId: workspace)
            app.recoveryRequests.removeAll { $0.requestId == request.requestId }
            record(command, "ok deferred=\(DeferredRecoveries.shared.requests(workspaceId: workspace, queued: app.recoveryRequests).map(\.fingerprint).joined(separator: ","))")
        case "reset":
            do {
                _ = try await client.resetDevices(pin: arg.isEmpty ? nil : arg)
                app.needsDeviceLink = false
                await app.deviceBecameActive()
                record(command, "ok device=\(app.deviceId ?? "")")
            } catch CoreError.PinRequired {
                app.needsDeviceLink = false
                app.pinPrompt = PinPrompt(purpose: .reset)
                record(command, "PinRequired → pin screen")
            } catch CoreError.PinIncorrect(_, let left) {
                app.needsDeviceLink = false
                app.pinPrompt = PinPrompt(purpose: .reset, attemptsLeft: Int(left))
                record(command, "PinIncorrect attempts_left=\(left) → pin screen: \(PinEntrySheet.attemptsText(Int(left)))")
            } catch CoreError.ResetPending(let detail) {
                app.needsDeviceLink = false
                app.resetPending = detail
                record(command, "ResetPending → hold screen")
            } catch { record(command, fail(error)) }
        case "forgotpin":
            do {
                _ = try await client.resetDevicesForgotPin()
                await app.deviceBecameActive()
                record(command, "ok device=\(app.deviceId ?? "")")
            } catch CoreError.ResetPending(let detail) {
                app.pinPrompt = nil
                app.resetPending = detail
                record(command, "ResetPending → hold screen: \(detail)")
            } catch { record(command, fail(error)) }
        case "setpin":
            do {
                try await client.setRegistrationPin(pin: arg, currentPin: nil)
                await client.kvSet(key: RegistrationPinSheet.flagKey, value: "1")
                record(command, "ok")
            } catch { record(command, fail(error)) }
        case "setupagain":
            await app.setUpAgain()
            record(command, "ok needs_setup=\(app.needsDeviceLink)")
        case "refresh":
            await app.accountChanged()
            record(command, "ok")
        default:
            record(command, "error: unknown command")
        }
    }

    /// The pure rules of the account screens.
    @MainActor
    private static func accountSelfCheck() -> String {
        var failed: [String] = []
        func check(_ name: String, _ ok: Bool) { if !ok { failed.append(name) } }
        let key = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ"
        check("tail", RecoveryKeyCheck.tail(of: key) == "UVWXYZ")
        check("tail-match-loose", RecoveryKeyCheck.matches("uv-wx yz", key: key))
        check("tail-mismatch", !RecoveryKeyCheck.matches("UVWXY0", key: key))
        check("tail-short", !RecoveryKeyCheck.matches("WXYZ", key: key))
        let now = Date(timeIntervalSince1970: 1_000_000)
        func until(_ s: Double) -> String { HoldCountdown.text(until: Int64((1_000_000 + s) * 1000), now: now) }
        check("countdown-days", until(6 * 86400 + 23 * 3600 + 5) == "in 6 days 23 hours")
        check("countdown-day", until(86400 + 10) == "in 1 day")
        check("countdown-hours", until(5 * 3600 + 30) == "in 5 hours")
        check("countdown-minutes", until(12 * 60 + 1) == "in 12 minutes")
        check("countdown-now", until(20) == "any moment now" && until(-500) == "any moment now")
        check("attempts", PinEntrySheet.attemptsText(3) == "Wrong PIN. 3 tries left." && PinEntrySheet.attemptsText(1) == "Wrong PIN. 1 try left."
              && PinEntrySheet.attemptsText(0) == "Too many wrong PINs. Try again in 15 minutes.")
        check("instant-future", RecoveryKeySheet.instantText(Int64((1_000_000 + 7 * 86400) * 1000), now: now).hasPrefix("From "))
        check("instant-past", RecoveryKeySheet.instantText(Int64(999_000 * 1000), now: now) == "Restoring with this key is instant.")
        check("instant-none", RecoveryKeySheet.instantText(nil, now: now) == "Restoring with this key is instant.")
        // "Decide later" keeps a restore request reachable: one per device, per skwod, and
        // not offered twice while a request for that device is in the prompt queue.
        let first = RecoveryRequest(deviceId: "d1", requestId: "r1", fingerprint: "AAAA-1111")
        let second = RecoveryRequest(deviceId: "d1", requestId: "r2", fingerprint: "BBBB-2222")
        let other = RecoveryRequest(deviceId: "d2", requestId: "r3", fingerprint: "CCCC-3333")
        var putOff = DeferredRecoveries.adding(first, workspaceId: "w1", to: [])
        check("deferred-kept", DeferredRecoveries.visible(putOff, workspaceId: "w1", queued: []) == [first])
        check("deferred-per-skwod", DeferredRecoveries.visible(putOff, workspaceId: "w2", queued: []).isEmpty
              && DeferredRecoveries.visible(putOff, workspaceId: nil, queued: []).isEmpty)
        check("deferred-hidden-while-queued", DeferredRecoveries.visible(putOff, workspaceId: "w1", queued: [second]).isEmpty)
        putOff = DeferredRecoveries.adding(other, workspaceId: "w1", to: DeferredRecoveries.adding(second, workspaceId: "w1", to: putOff))
        check("deferred-replaced", DeferredRecoveries.visible(putOff, workspaceId: "w1", queued: []) == [second, other])
        check("lock-rule", AppLock.shouldLock(awaySeconds: 61, delaySeconds: 60) && !AppLock.shouldLock(awaySeconds: 30, delaySeconds: 60)
              && AppLock.shouldLock(awaySeconds: 0.1, delaySeconds: 0))
        check("screen-security-new", PrivacySettings.screenSecurityDefault(storedChoice: nil, hasWorkspaces: false))
        check("screen-security-existing", !PrivacySettings.screenSecurityDefault(storedChoice: nil, hasWorkspaces: true))
        check("screen-security-chosen", !PrivacySettings.screenSecurityDefault(storedChoice: false, hasWorkspaces: false)
              && PrivacySettings.screenSecurityDefault(storedChoice: true, hasWorkspaces: true))
        check("label", DeviceLabel.cleaned("  My\nPhone  ") == "My Phone" && DeviceLabel.cleaned(String(repeating: "x", count: 90)).count == 40)
        check("quote-match", ReportResolution.compare(excerpt: "hi", local: "hi") == .matches)
        check("quote-differs", ReportResolution.compare(excerpt: "hi", local: "bye") == .differs)
        check("quote-unchecked", ReportResolution.compare(excerpt: "hi", local: nil) == .unchecked && ReportResolution.compare(excerpt: nil, local: "x") == .unchecked)
        // A report is resolved against THIS device's data; what the reporter chose decides nothing.
        let map = ["chan-a": "server-a", "chan-b": "server-b"]
        func resolve(subject: String?, server: String?, channel: String? = "chan-a", message: String? = "m1",
                     row: ReportResolution.Row? = .init(authorId: "mallory", content: "rude")) -> ReportResolution {
            ReportResolution.resolve(subjectUserId: subject, serverId: server, channelId: channel, messageId: message, excerpt: "rude",
                                     cached: row, channelServer: map, me: "owner")
        }
        let honest = resolve(subject: "mallory", server: "server-a")
        check("report-honest", honest.mayRemove && honest.mayModerate && honest.target?.authorId == "mallory" && honest.target?.serverId == "server-a" && honest.quote == .matches)
        // The id points at Mallory's message but the report names innocent Bob: no action, a warning.
        let framed = resolve(subject: "bob", server: "server-a")
        check("report-wrong-person", framed.subjectMismatch && !framed.mayRemove && !framed.mayModerate && framed.target?.authorId == "mallory"
              && framed.warnings == ["The reporter named a different person than the one who wrote this message."])
        // …or a different server than the channel is in.
        let elsewhere = resolve(subject: "mallory", server: "server-b")
        check("report-wrong-server", elsewhere.serverMismatch && !elsewhere.mayModerate && elsewhere.target?.serverId == "server-a")
        // No message on this device (or a deleted one, a core row, my own, an unknown channel): nothing resolved.
        check("report-no-message", resolve(subject: "bob", server: "server-a", row: nil).target == nil && !resolve(subject: "bob", server: "server-a", row: nil).mayModerate)
        check("report-deleted", resolve(subject: "mallory", server: "server-a", row: .init(authorId: "mallory", content: nil, isDeleted: true)).target == nil)
        check("report-core-row", resolve(subject: "mallory", server: "server-a", row: .init(authorId: "mallory", content: "x", isCoreRow: true)).target == nil)
        check("report-own-message", resolve(subject: "owner", server: "server-a", row: .init(authorId: "owner", content: "x")).target == nil
              && resolve(subject: nil, server: nil, row: .init(authorId: "__me__", content: "x")).target == nil)
        check("report-unknown-channel", resolve(subject: "mallory", server: "server-a", channel: "chan-zzz").target == nil)
        check("report-no-ids", resolve(subject: "mallory", server: "server-a", channel: nil, message: nil).target == nil)
        check("sheet-order", {
            let request = RecoveryRequest(deviceId: "d", requestId: "r", fingerprint: "AAAA-BBBB")
            return AccountSheetRoute.approve(request).id == "approve-r" && AccountSheetRoute.pin(PinPrompt(purpose: .reset)).id != AccountSheetRoute.pin(PinPrompt(purpose: .restore)).id
        }())
        check("group-title", GroupDM.title(memberNames: ["Ann", "Bo", "Cy"]) == "Ann, Bo, Cy"
              && GroupDM.title(memberNames: ["A", "B", "C", "D", "E"], limit: 3) == "A, B, C +2")
        // Who is in a group is fixed on this device: the server's listing never changes it.
        let mine = GroupDM(conversationId: "g1", memberUserIds: ["bob", "carol"])
        let ghosted = GroupDM.reconcile(accepted: [mine], listed: [("g1", ["bob", "carol", "ghost"]), ("g2", ["dave", "erin"]), ("g3", ["x", "y"])], declined: ["g3"])
        check("group-ghost-ignored", ghosted.accepted.first?.memberUserIds == ["bob", "carol"] && ghosted.accepted.first?.serverDisagrees == true)
        check("group-unseen-is-invitation", ghosted.invitations.map(\.conversationId) == ["g2"] && ghosted.accepted.count == 1)
        let same = GroupDM.reconcile(accepted: [mine], listed: [("g1", ["carol", "bob"])])
        check("group-same-set", same.accepted.first?.serverDisagrees == false && same.invitations.isEmpty)
        check("group-unlisted-kept", GroupDM.reconcile(accepted: [mine], listed: []).accepted.first?.memberUserIds == ["bob", "carol"])
        check("group-outsider-dropped", !mine.accepts(senderId: "ghost", fromSelf: false) && mine.accepts(senderId: "bob", fromSelf: false)
              && mine.accepts(senderId: "anything", fromSelf: true))
        // Conversation ids are claimed locally, first come first served; a clash changes nothing.
        // 1) The server lists a DIRECT conversation's id as a group: no invitation, a conflict,
        //    and the route stays direct.
        let asGroup = GroupDM.reconcile(accepted: [mine], listed: [("dm1", ["bob", "carol"])], direct: ["dm1"])
        check("clash-dm-listed-as-group", asGroup.invitations.isEmpty && asGroup.conflicts == ["dm1"] && asGroup.accepted == [mine]
              && GroupDM.route(conversationId: "dm1", direct: ["dm1"], accepted: ["g1"], invitations: []) == .direct)
        // 2) The server lists an accepted GROUP's id as a direct conversation: the DM store may
        //    not take it, the group is untouched (members and all), and the route stays group.
        let untouched = GroupDM.reconcile(accepted: [mine], listed: [("g1", ["bob", "carol"])], direct: [])
        check("clash-group-listed-as-dm", !GroupDM.mayClaim("g1", heldByOtherStore: ["g1"]) && untouched.accepted.first?.memberUserIds == ["bob", "carol"]
              && untouched.conflicts.isEmpty && GroupDM.route(conversationId: "g1", direct: [], accepted: ["g1"], invitations: []) == .group)
        // 3) Whatever the listing says, an accepted group is never removed by it.
        check("clash-never-deletes", GroupDM.reconcile(accepted: [mine], listed: [("g1", ["x"])], direct: ["g1"]).accepted.first?.memberUserIds == ["bob", "carol"])
        check("route-others", GroupDM.route(conversationId: "g2", direct: [], accepted: [], invitations: ["g2"]) == .invitation
              && GroupDM.route(conversationId: "zz", direct: [], accepted: [], invitations: []) == .unknown
              && GroupDM.mayClaim("new", heldByOtherStore: ["g1"]))
        check("group-size", GroupDM.sizeProblem(others: 1) != nil && GroupDM.sizeProblem(others: 2) == nil
              && GroupDM.sizeProblem(others: 9) == nil && GroupDM.sizeProblem(others: 10) != nil)
        return failed.isEmpty ? "ok" : "FAILED: " + failed.joined(separator: ",")
    }

    @MainActor
    private static func dumpAccount(_ app: AppState) async {
        var state: [String: Any] = [
            "at": Int(Date().timeIntervalSince1970 * 1000),
            "restoring": app.restoring,
            "signed_in": app.session != nil,
            "signed_out_notice": app.signedOut.map { ["name": $0.name, "by_user": $0.byUser] as [String: Any] } ?? NSNull(),
            "user_id": app.current?.userId ?? "",
            "workspace": app.current?.id ?? "",
            "workspaces": app.workspaces.map { ["id": $0.id, "signed_out": $0.isSignedOut, "user_id": $0.userId] as [String: Any] },
            "device_id": app.deviceId ?? "",
            "device_state": lastState,
            "stopped": app.stopped.map { "\($0)" } ?? "",
            "sheet": app.accountSheet?.id ?? "",
            "needs_setup": app.needsDeviceLink,
            "recovery_waiting": app.recoveryWaiting,
            "reset_pending": app.resetPending ?? "",
            "pin_prompt": app.pinPrompt.map { ["purpose": "\($0.purpose)", "attempts_left": $0.attemptsLeft ?? -1] as [String: Any] } ?? NSNull(),
            "deferred_recovery_requests": DeferredRecoveries.shared.requests(workspaceId: app.current?.id, queued: app.recoveryRequests).map(\.fingerprint),
            "recovery_requests": app.recoveryRequests.map { ["device_id": $0.deviceId, "request_id": $0.requestId, "fingerprint": $0.fingerprint] },
            "recovery_outcome": app.recoveryOutcome?.message ?? "",
            "recovery_key_prompt": app.recoveryKeyPrompt?.rawValue ?? "",
            "notice": app.securityNotice.map { ["title": $0.title, "message": $0.message] } ?? [:],
            "security_activity": app.securityActivity.map { ["kind": $0.kind, "title": $0.title, "message": $0.message, "at_ms": $0.atMs] as [String: Any] },
            "devices": deviceList,
            "max_devices": maxDevices,
            "erase_check": eraseState,
            "test_recovery_key": testRecoveryKey,
            "link_code": linkCode,
            "reports": app.reports.map { ["report_id": $0.reportId, "category": $0.category, "note": $0.note ?? "", "excerpt": $0.excerpt ?? "",
                                          "channel_id": $0.channelId ?? "", "message_id": $0.messageId ?? ""] },
            "storelock": StoreLockTrace.snapshot(),
            "store_lock_held": StoreLock.shared.isHeld,
            "applock": ["enabled": AppLock.shared.enabled, "locked": AppLock.shared.isLocked],
            "screen_security": PrivacySettings.screenSecurity,
            "results": accountResults,
        ]
        if let w = app.current {
            state["cache_excluded_from_backup"] = SharedContainer.cacheIsExcludedFromBackup(forWorkspace: w.id)
            state["cache_file_exists"] = FileManager.default.fileExists(atPath: SharedContainer.cachePath(forWorkspace: w.id))
        }
        if let client = app.client, app.deviceId != nil || app.recoveryWaiting {
            state["backup_enabled"] = await client.keyBackupEnabled()
            state["recovery_fingerprint"] = await client.recoveryFingerprint()
            state["recovery_completes_at"] = await client.recoveryCompletesAt() ?? 0
            state["recovery_contested"] = await client.recoveryContested()
            state["recovery_key_instant_from"] = await client.recoveryKeyInstantFrom() ?? 0
        }
        if let data = try? JSONSerialization.data(withJSONObject: state, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: outDir.appendingPathComponent("account.json"), options: .atomic)
        }
    }
}

/// A screen put up by the `show:<name>` hook (for pictures). DEBUG only.
struct E2ESheet: View {
    let name: String
    var body: some View {
        switch name {
        case "devices": DevicesView()
        case "erase": EraseDeviceSheet()
        case "activity": SecurityActivityView()
        case "reports": ReportsInboxView()
        case "recoverykey": RecoveryKeySheet(reason: .manual)
        case "setup": DeviceSetupSheet()
        case "restore": RestoreWithKeySheet()
        case "newgroup": NewGroupSheet { _ in nil }
        // "Join or host a Skwod" (the rail's add tile): with SKWOD_E2E_INVITE / _USER /
        // _PASSWORD set, the form adopts the invite and submits — a SECOND skwod is joined.
        case "addskwod": AuthView(onConnected: {})
        default: Text("Unknown screen: \(name)").padding(40)
        }
    }
}
#endif
