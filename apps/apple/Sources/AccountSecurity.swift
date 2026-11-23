import Foundation
#if os(iOS)
import UIKit
#endif

/// Build 44a, the app's half: devices, recovery key, restore, security activity.
///
/// The rules live in the core (docs/FFI-CHANGES.md, "Build 44a"). What is here is routing —
/// which screen a state or a notice opens — and the small amount of state those screens share.

// MARK: - Small models

/// What this device calls itself until its owner renames it. Sealed to the account's own
/// devices by the core; the server never sees it.
enum DeviceLabel {
    static var suggested: String {
        #if os(iOS)
        // `UIDevice.current.name` is the generic model name since iOS 16 ("iPhone"), which is
        // exactly as much as this should say by default.
        let name = UIDevice.current.name
        return name.isEmpty ? "iPhone" : String(name.prefix(maxLength))
        #else
        return "Mac"
        #endif
    }

    static let maxLength = 40

    /// A name as the user typed it, made safe to store: trimmed, one line, bounded.
    static func cleaned(_ raw: String) -> String {
        let oneLine = raw.replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
        return String(oneLine.prefix(maxLength))
    }
}

/// A restore of this account that is waiting for one of its devices to approve or block it.
/// `requestId` is the id from the notice that announced it — an approval is for THAT request.
struct RecoveryRequest: Identifiable, Equatable {
    let deviceId: String
    let requestId: String
    /// The short code (`XXXX-XXXX`) the waiting device shows too.
    let fingerprint: String
    var id: String { requestId }
}

/// Why the account PIN is being asked for.
struct PinPrompt: Identifiable, Equatable {
    enum Purpose: Equatable {
        /// Resetting the account's devices (`resetDevices(pin:)`).
        case reset
        /// Completing a restore that is waiting (`retryRestore(pin:)`).
        case restore
    }
    let purpose: Purpose
    /// From `PinIncorrect`: tries left before the 15-minute lock. nil = not tried yet.
    var attemptsLeft: Int? = nil
    var id: String { "\(purpose)" }
}

/// Why the recovery-key flow is on screen. Decides its header line and whether "Not now" is offered.
enum RecoveryKeyReason: String, Identifiable, Equatable {
    /// First run: this device is set up and the account has no recovery key.
    case firstRun
    /// The user opened it from Profile.
    case manual
    /// A device was removed from the account, which retired the key.
    case deviceRemoved
    /// The user reported the key compromised.
    case compromised
    /// The core says no recovery key is in force (`recovery_key_needed`).
    case needed

    var id: String { rawValue }

    var header: String? {
        switch self {
        case .firstRun, .manual: return nil
        case .deviceRemoved: return "Your old recovery key was retired with that device."
        case .compromised: return "Your old recovery key no longer works."
        case .needed: return "Your account has no recovery key now."
        }
    }
}

/// The recovery key as a person types part of it back.
enum RecoveryKeyCheck {
    /// Letters and digits only, upper-cased: spaces, dashes and case never matter.
    static func normalized(_ s: String) -> String {
        String(s.uppercased().unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) && $0.isASCII })
    }

    /// What the user is asked to type: the last 6 characters of the key.
    static func tail(of key: String) -> String { String(normalized(key).suffix(6)) }

    static func matches(_ typed: String, key: String) -> Bool {
        let want = tail(of: key)
        return want.count == 6 && normalized(typed) == want
    }
}

/// Dates as the account screens word them.
enum AccountDates {
    static func day(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .omitted)
    }

    static func dayAndTime(_ ms: Int64) -> String {
        Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .abbreviated, time: .shortened)
    }

    /// "Active now" under five minutes, else a relative time.
    static func active(_ ms: Int64, now: Date = Date()) -> String {
        guard ms > 0 else { return "Not active yet" }
        let age = now.timeIntervalSince1970 - Double(ms) / 1000
        if age < 5 * 60 { return "Active now" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return "Active " + f.localizedString(for: Date(timeIntervalSince1970: Double(ms) / 1000), relativeTo: now)
    }

    static func relative(_ ms: Int64, now: Date = Date()) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: Date(timeIntervalSince1970: Double(ms) / 1000), relativeTo: now)
    }
}

// MARK: - AppState

@MainActor
extension AppState {
    private static let activityKey = "security.activity"
    private static let snoozeKey = "recovery.promptSnoozedUntil"
    private static let snooze: TimeInterval = 7 * 24 * 60 * 60

    // MARK: Security activity (persistent rows)

    /// Read the stored list — STRICTLY (`kv_read`). The log is the record of what happened to
    /// this account's security; it is never replaced by an empty one because it could not be
    /// read:
    /// - no client: nothing is shown, nothing is marked read;
    /// - the read fails: what is on screen stays, the log is NOT marked read, and nothing is
    ///   written until a later read succeeds (events logged meanwhile wait in memory);
    /// - it is read but cannot be decoded: its bytes are first kept under a key of their own
    ///   (`security.activity.unreadable.<ms>`, read back), then the log continues with what
    ///   could be salvaged and says so. If the copy cannot be written, it stays unread.
    func loadSecurityActivity() async {
        guard let asked = bound else { securityActivity = []; activityReadFor = nil; activityShownFor = nil; return }
        showActivity(of: asked.workspaceId)
        let client = asked.client
        let stored: String?
        do { stored = try await client.kvRead(key: Self.activityKey) } catch { return }
        guard bound?.workspaceId == asked.workspaceId, bound?.turn == asked.turn else { return }
        var events: [SecurityEvent] = []
        var keptAs: String?
        if let stored, !stored.isEmpty {
            if let decoded = try? JSONDecoder().decode([SecurityEvent].self, from: Data(stored.utf8)) {
                events = decoded
            } else {
                let side = "\(Self.activityKey).unreadable.\(Int64(Date().timeIntervalSince1970 * 1000))"
                do {
                    try await client.kvWrite(key: side, value: stored)
                    guard try await client.kvRead(key: side) == stored else { return }
                } catch { return }
                guard bound?.workspaceId == asked.workspaceId, bound?.turn == asked.turn else { return }
                events = SecurityEvent.salvage(stored)
                keptAs = side
            }
        }
        // Events logged while the log could not be read belong to this workspace's log too.
        let waiting = activityWaiting.filter { $0.workspaceId == asked.workspaceId }.map(\.event)
        activityWaiting.removeAll { $0.workspaceId == asked.workspaceId }
        securityActivity = SecurityEvent.merged(events, adding: waiting)
        activityReadFor = asked.workspaceId
        if let keptAs {
            await logSecurity(kind: "security_activity_unreadable", title: "Security activity could not be read",
                              message: "The record of security events Skwod keeps on this device could not be fully read. Skwod kept what it could read and continues with that. Nothing was deleted: the data as it was is kept on this device (as “\(keptAs)”).",
                              atMs: Int64(Date().timeIntervalSince1970 * 1000))
        } else if !waiting.isEmpty {
            _ = await writeSecurityActivity(through: asked)
        }
    }

    /// Append one event (newest first, at most 100 kept) to the list in the encrypted cache.
    /// Returns whether the event's row is STORED. While the log has not been read (or the
    /// write fails) the event is shown and waits in memory; it is written with the next
    /// successful read or write — the stored log is never overwritten by a list that was not
    /// built on it.
    @discardableResult
    func logSecurity(kind: String, title: String, message: String, atMs: Int64) async -> Bool {
        guard let asked = bound else { return false }
        showActivity(of: asked.workspaceId)
        let event = SecurityEvent(kind: kind, title: title, message: message, atMs: atMs)
        if securityActivity.contains(where: { $0.kind == kind && $0.atMs == atMs && $0.title == title }) {
            return activityReadFor == asked.workspaceId && !activityWaiting.contains { $0.event == event }
        }
        securityActivity = SecurityEvent.merged(securityActivity, adding: [event])
        guard activityReadFor == asked.workspaceId else {
            activityWaiting.append((asked.workspaceId, event))
            return false
        }
        if await writeSecurityActivity(through: asked) { return true }
        activityWaiting.append((asked.workspaceId, event))
        return false
    }

    /// What is on screen is `workspaceId`'s: another workspace's events never stay under it.
    private func showActivity(of workspaceId: String) {
        guard activityShownFor != workspaceId else { return }
        activityShownFor = workspaceId
        activityReadFor = nil
        securityActivity = activityWaiting.filter { $0.workspaceId == workspaceId }.map(\.event).sorted { $0.atMs > $1.atMs }
    }

    /// Write the log as it is now. False when it was not written (or the workspace changed).
    private func writeSecurityActivity(through asked: BoundClient<SkwodClient>) async -> Bool {
        guard activityReadFor == asked.workspaceId, bound?.workspaceId == asked.workspaceId,
              let data = try? JSONEncoder().encode(securityActivity), let json = String(data: data, encoding: .utf8) else { return false }
        do { try await asked.client.kvWrite(key: Self.activityKey, value: json) } catch { return false }
        activityWaiting.removeAll { $0.workspaceId == asked.workspaceId }
        return true
    }

    // MARK: Devices

    /// Re-read this account's devices (names for notices; the Devices screen reads the same).
    @discardableResult
    func refreshDeviceNames() async -> DeviceList? {
        guard let client, let list = try? await client.listDevices() else { return nil }
        var names: [String: String] = [:]
        for d in list.devices { if let n = d.name, !n.isEmpty { names[d.deviceId] = n } }
        deviceNames = names
        return list
    }

    /// Something about this account's devices or recovery changed (a realtime nudge, or the
    /// user just did it): re-read the device list from the server, then show what the core
    /// concluded. The events carry nothing to act on by themselves.
    func accountChanged() async {
        guard let client else { return }
        do {
            try await client.refreshOwnDevices()
        } catch {
            if await routeIfDeviceError(error) { return }
        }
        await refreshDeviceNames()
        await surfaceSecurityNotices()
        await routeDeviceState()
        NotificationCenter.default.post(name: .skwodAccountChanged, object: nil)
    }

    private static func removedFlag(_ workspaceId: String) -> String { WorkspaceItems.removedDevicePrefix + workspaceId }

    /// This device was told it had been removed, and the core has not confirmed or refuted it yet.
    var removalFlagged: Bool { current.map { UserDefaults.standard.bool(forKey: Self.removedFlag($0.id)) } ?? false }

    /// The server says a device of this account was removed. If it names THIS device, say so
    /// at once and plainly — the removal also ended this session, and without this the only
    /// thing the user would see is an unexplained log-in screen. It is the server's word until
    /// the core has confirmed it (`setUpAgain` only forgets the registration once it has).
    func ownDeviceRemoved(deviceId removed: String?) async {
        if let removed, !removed.isEmpty, removed == deviceId, let w = current {
            UserDefaults.standard.set(true, forKey: Self.removedFlag(w.id))
            stopped = .removed
            inboxTask?.cancel()
            await logSecurity(kind: "this_device_removed", title: "This device was removed",
                              message: "Another of your devices removed this one from your account.",
                              atMs: Int64(Date().timeIntervalSince1970 * 1000))
        }
        await accountChanged()
    }

    /// After binding: this device was told (last run, or before its session ended) that it had
    /// been removed. Ask the server through the core, which is what settles it.
    func confirmRemovalIfFlagged() async {
        guard let client, let w = current, UserDefaults.standard.bool(forKey: Self.removedFlag(w.id)) else { return }
        do {
            try await client.refreshOwnDevices()
            // The server accepts this device after all: the flag was wrong, or is stale.
            UserDefaults.standard.removeObject(forKey: Self.removedFlag(w.id))
        } catch {
            if await routeIfDeviceError(error) { UserDefaults.standard.removeObject(forKey: Self.removedFlag(w.id)) }
        }
    }

    /// A contact removed one of their devices: re-read theirs, so a later restore of that
    /// device is told apart from one that erased itself (see FFI-CHANGES, "Why a device left").
    /// The realtime `backup_fetched` (server M-4): the key backup was downloaded by a session
    /// that is not a current device of the account. A notice AND a row in Security activity;
    /// the server does not store the event, so a device that was offline never sees it.
    func backupFetched(atMs: Int64) async {
        guard let alert = SecurityAlert.from(kind: "backup_fetched", userId: session?.userId ?? "", deviceId: "",
                                             wasVerified: false, serverId: nil, name: { _ in "You" }) else { return }
        await logSecurity(kind: "backup_fetched", title: alert.title, message: alert.message, atMs: atMs)
        enqueueNotice(alert)
        if !appActive {
            realtime.notify(title: alert.title, body: "Open Skwod to see what to do.",
                            privacy: .fixed, thread: "account", id: "backup-fetched-\(atMs)")
        }
    }

    /// The realtime `device_recovery_multiple` (server L1): more than one install is waiting to
    /// restore the same device. A notice and a row in Security activity.
    func recoveryMultiple(atMs: Int64) async {
        guard let alert = SecurityAlert.from(kind: "recovery_multiple", userId: session?.userId ?? "", deviceId: "",
                                             wasVerified: false, serverId: nil, name: { _ in "You" }) else { return }
        await logSecurity(kind: "recovery_multiple", title: alert.title, message: alert.message, atMs: atMs)
        enqueueNotice(alert)
    }

    func contactDeviceRemoved(userId: String) async {
        guard let client, !userId.isEmpty else { return }
        try? await client.refreshDevicesOf(userId: userId)
        await surfaceSecurityNotices()
    }

    // MARK: Recovery requests (approve / block on this device)

    func noteRecoveryRequest(_ n: SecurityNotice) {
        guard let requestId = n.requestId, !requestId.isEmpty else { return }
        let request = RecoveryRequest(deviceId: n.deviceId, requestId: requestId, fingerprint: n.fingerprint ?? "")
        // Several installs may be asking to restore the same device (server audit L1): each
        // request has its own id, code and prompt, side by side — none replaces another.
        if !recoveryRequests.contains(request) { recoveryRequests.append(request) }
        Task {
            await logSecurity(kind: "recovery_requested", title: "A restore was requested",
                              message: "Code \(request.fingerprint).", atMs: Int64(n.atMs))
        }
        if !appActive {
            realtime.notify(title: "Restore your account?", body: "A new device is asking to restore your account. Open Skwod to approve or block it.",
                            privacy: .fixed, thread: "account", id: "recovery-\(requestId)")
        }
    }

    enum RecoveryAnswer: Equatable { case approved, blocked, changed, failed(String) }

    /// Approve or block the request ON SCREEN — by its id, so an answer can never land on a
    /// request that replaced it. `changed`: it was replaced; nothing was approved, and the
    /// newer request arrives as a fresh notice with its own code.
    func answer(_ request: RecoveryRequest, approve: Bool) async -> RecoveryAnswer {
        guard let client else { return .failed("Not connected.") }
        do {
            if approve {
                try await client.approveRecovery(deviceId: request.deviceId, requestId: request.requestId)
            } else {
                try await client.cancelRecovery(deviceId: request.deviceId, requestId: request.requestId)
            }
            // Approving one restore of a device ends every other request for it (server L1).
            recoveryRequests.removeAll { $0.requestId == request.requestId || (approve && $0.deviceId == request.deviceId) }
            await logSecurity(kind: approve ? "recovery_approved" : "recovery_blocked",
                              title: approve ? "You approved a restore" : "You blocked a restore",
                              message: "Code \(request.fingerprint).", atMs: Int64(Date().timeIntervalSince1970 * 1000))
            // Approving a restore of THIS device stops this install once it completes.
            await accountChanged()
            return approve ? .approved : .blocked
        } catch CoreError.RecoveryChanged {
            recoveryRequests.removeAll { $0.requestId == request.requestId }
            // The newer request is already listed by the server: pick it up now.
            await accountChanged()
            return .changed
        } catch {
            if await routeIfDeviceError(error) { return .failed("This device can no longer answer for your account.") }
            return .failed(coreErrorText(error, fallback: "Couldn't reach your Skwod — try again."))
        }
    }

    // MARK: Recovery key

    /// First-run prompt: this device is set up, the account has no recovery key, and the user
    /// has not said "Not now" in the last 7 days.
    func maybePromptForRecoveryKey() async {
        guard let client, deviceId != nil, stopped == nil, !recoveryWaiting, !needsDeviceLink,
              recoveryKeyPrompt == nil, !(await client.keyBackupEnabled()) else { return }
        #if DEBUG
        if E2E.env("SKWOD_E2E_NO_RECOVERY_PROMPT") == "1" { return }
        #endif
        let until = Double(await client.kvGet(key: Self.snoozeKey) ?? "") ?? 0
        guard Date().timeIntervalSince1970 >= until else { return }
        recoveryKeyPrompt = .firstRun
    }

    func snoozeRecoveryKeyPrompt() async {
        await client?.kvSet(key: Self.snoozeKey, value: String(Date().timeIntervalSince1970 + Self.snooze))
    }

    // MARK: After a restore or a link

    /// This install just became a working device (linked, restored, or reset): take its state,
    /// start syncing, and rebuild the sidebar from what came back.
    func deviceBecameActive() async {
        await routeDeviceState()
        guard deviceId != nil else { return }
        resetPending = nil
        pinPrompt = nil
        if let w = current { await activate(w) }
        await chatModel?.recoverMemberships()
        await chatModel?.refreshDMList()
    }

    /// The stopped install is being set up again as a NEW device of the account: forget the
    /// old registration (space keys, pins and contacts are kept) and offer link / restore / reset.
    func setUpAgain() async {
        // Signed out as well (a removal ends the session): log in first; binding then asks the
        // server and comes back here.
        guard let client, session != nil else { stopped = nil; return }
        // Only what the CORE has confirmed makes this install forget its registration.
        switch await client.deviceState() {
        case .superseded:
            // The session is the superseded install's: the server refuses it everything but
            // binding (not the key backup a restore needs). End it here — keys and cache stay —
            // and log in again; the new session sets this install up as a new device.
            await client.forgetRegistration()
            stopped = nil
            if let w = current { await handleSignedOut(w) }
        case .removed:
            await client.forgetRegistration()
            stopped = nil
            await routeDeviceState(registerIfNew: true)
        default:
            stopped = nil
            await confirmRemovalIfFlagged()
            await routeDeviceState(registerIfNew: true)
            if stopped != nil { await setUpAgain() }
        }
    }
}

extension Notification.Name {
    /// This account's devices, recovery key or reports changed: open account screens reload.
    static let skwodAccountChanged = Notification.Name("skwod.account.changed")
}
