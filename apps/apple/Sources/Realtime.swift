import Foundation
import UserNotifications
#if os(macOS)
import AppKit
#endif
#if os(iOS)
import UIKit

/// A few seconds of guaranteed run time while leaving the foreground, so the frame that tells
/// the server "push me from now on" is really sent before the process is suspended.
@MainActor
final class BackgroundGrace {
    private var id: UIBackgroundTaskIdentifier = .invalid

    init(_ name: String) {
        id = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            Task { @MainActor in self?.end() }
        }
    }

    func end() {
        guard id != .invalid else { return }
        UIApplication.shared.endBackgroundTask(id)
        id = .invalid
    }
}
#endif

/// Live client for the server's WebSocket relay (`/api/ws`): instant presence + message events.
///
/// The relay carries ciphertext and routing metadata only, and notifications built here follow the
/// same invariant (SECURITY.md #4): they name the channel, never message content.
///
/// - Presence: on connect (and on every status change) we send a presence frame — the server fans it
///   out to every server we're a member of, so other devices flip us online/offline INSTANTLY
///   instead of waiting out the heartbeat + poll + 3-minute stale window.
/// - Calls: `ring` / `ring_cancel` on our own user topic (`user:<id>`) start and end the
///   incoming-call UI (`CallCoordinator`) — CallKit on iOS, the in-app banner on macOS.
/// - Everything else is handed to `onEvent` untouched (`AppState.realtimeEvent`), which is what
///   drives refreshes instead of polling: `message`, `message_update`, `message_delete`,
///   `reaction`, `channel_cleared` on channel topics; `sealed` (something is in our mailbox: a DM,
///   keys), `device_added`, `link_request`, `join_request`, `join_approved`, `join_denied` on our
///   user topic; `member_joined`, `channels_changed` on server topics.
/// - An event says only THAT something happened. Whether it deserves a notification is decided
///   after decrypting it on this device (`AppState`): the server does not know — and is never
///   told — whether a message is chat, a like, a game move or a key hand-off.
/// - iOS closes the socket when the app goes to the background (`suspend`): the server only
///   push-wakes an install that has no live socket.
@MainActor
final class Realtime: NSObject, ObservableObject {
    /// userId → (status, learnedAt). Merged over polled member lists for instant flips; entries
    /// older than the server's 3-minute stale window are ignored at read time.
    @Published var presence: [String: PresenceSeen] = [:]

    struct PresenceSeen {
        let status: String
        let at: Date
    }

    /// channelId/conversationId → display name, for notification titles (set by ChatModel).
    var chatNames: [String: String] = [:]
    /// The topic currently on screen — its messages never notify.
    var focusedTopic: String? {
        didSet {
            if let focusedTopic, focusedTopic != oldValue, appActive { clearDelivered(topic: focusedTopic) }
            // Opening a conversation is seeing its mentions.
            if let focusedTopic, let wid = mentionWorkspaceId { MentionBadges.clear(topic: focusedTopic, workspaceId: wid) }
        }
    }
    /// Whether the app is frontmost; background messages always notify.
    var appActive = true

    private var task: URLSessionWebSocketTask?
    private var subscribed: Set<String> = []
    private var wantedTopics: Set<String> = []
    private var baseUrl = ""
    private var token = ""
    private var myUserId = ""
    private var myStatus = "online"
    private var closedByUs = true
    private var reconnectDelay: TimeInterval = 1
    private var pingTask: Task<Void, Never>?
    /// Closed on purpose while the app is in the background (iOS); `reconnectNow` reopens it.
    private var suspended = false
    /// iOS: whether the app is in front, as last told to the server (`sendPushState`).
    private var pushActive = true
    /// Whether the socket in `task` has delivered a frame yet (the server answers our first
    /// frames at once) — the moment it does, the connection is up and `onConnected` fires.
    private var live = false
    /// Every event except `presence`: (topic, event name, payload).
    var onEvent: ((String, String, [String: Any]) -> Void)?
    /// People this account blocked (`BlockList`): their presence is not tracked or shown.
    var blockedIds: Set<String> = [] {
        didSet { for id in blockedIds where presence[id] != nil { presence[id] = nil } }
    }
    /// A socket came up (first connect and every reconnect): whatever was posted while there was
    /// none produced no event, so the app catches up now.
    var onConnected: (() -> Void)?

    override init() {
        super.init()
        // Banners for local notifications while the app is in front (see the extension below).
        UNUserNotificationCenter.current().delegate = self
    }

    /// Whether a socket is open and has spoken.
    var isLive: Bool { task != nil && live }

    /// The freshest status for a member: a live event within the stale window wins over the poll.
    func liveStatus(userId: String, polled: String) -> String {
        if let seen = presence[userId], Date().timeIntervalSince(seen.at) < 180 { return seen.status }
        return polled
    }

    /// Status for a user with no accompanying poll (DM rows, people strip): the freshest known
    /// entry (live event or seeded poll), staled to offline after the server's 3-minute window.
    func status(userId: String) -> String {
        guard let seen = presence[userId] else { return "offline" }
        return Date().timeIntervalSince(seen.at) < 180 ? seen.status : "offline"
    }

    /// Merge a polled member-list snapshot into the store. A poll never clobbers a live event that
    /// arrived moments ago (the socket is fresher than any poll cycle).
    func seedPresence(_ statuses: [String: String]) {
        var merged = presence
        let now = Date()
        for (uid, status) in statuses {
            if let existing = merged[uid], now.timeIntervalSince(existing.at) < 5 { continue }
            merged[uid] = PresenceSeen(status: status, at: now)
        }
        presence = merged
    }

    /// Server ids parsed from the subscribed topics — the app-level poll walks these.
    var subscribedServerIds: Set<String> {
        Set(wantedTopics.compactMap { $0.hasPrefix("server:") ? String($0.dropFirst(7)) : nil })
    }

    /// (Re)bind to a workspace and connect. Safe to call repeatedly (workspace switches).
    func configure(baseUrl: String, token: String, userId: String, status: String) {
        self.baseUrl = baseUrl
        self.token = token
        self.myUserId = userId
        self.myStatus = status
        presence = [:]
        closedByUs = false
        suspended = false
        reconnectDelay = 1
        openSocket()
    }

    /// Replace the desired topic set (called whenever the sidebar's spaces/DMs change).
    func setTopics(_ topics: Set<String>) {
        var topics = topics.filter { !$0.hasPrefix("user:") }
        // Our own user topic carries `ring` (someone is calling) — always wanted.
        if !myUserId.isEmpty { topics.insert("user:\(myUserId)") }
        wantedTopics = topics
        guard task != nil else { return }
        for t in topics.subtracting(subscribed) { send(["type": "subscribe", "topic": t]) }
        for t in subscribed.subtracting(topics) { send(["type": "unsubscribe", "topic": t]) }
        subscribed = topics
    }

    /// Push a status change through the socket (instant fan-out to everyone subscribed).
    func sendPresence(_ status: String) {
        myStatus = status
        send(["type": "presence", "status": status])
    }

    /// iOS: tell the server whether the app is in front (`AppState.pushPhase` decides when).
    /// Once it is not, the server push-wakes this
    /// install for every message instead of trusting the socket — which stays open for a while
    /// after the process stops reading it. Sent inside a background task so it gets out.
    /// A server that predates the frame answers with an error frame, which is ignored.
    func sendPushState(active: Bool) {
        #if os(iOS)
        guard pushActive != active else { return }
        pushActive = active
        guard let t = task, let frame = Realtime.pushFrame(active: active) else { return }
        let grace = BackgroundGrace("skwod.push-state")
        t.send(.string(frame)) { _ in
            Task { @MainActor in
                // Over p2p "sent" means "handed to the in-process proxy": a beat for it to
                // reach the host.
                try? await Task.sleep(for: .milliseconds(400))
                grace.end()
            }
        }
        #endif
    }

    private static func pushFrame(active: Bool) -> String? {
        (try? JSONSerialization.data(withJSONObject: ["type": "push", "state": active ? "active" : "background"]))
            .flatMap { String(data: $0, encoding: .utf8) }
    }

    /// The network changed or the app came back: re-open the socket now rather than waiting for
    /// the dead one to time out. No-op when not configured.
    func reconnectNow() {
        guard !closedByUs, !baseUrl.isEmpty else { return }
        suspended = false
        reconnectDelay = 1
        openSocket()
    }

    /// The app is going to the background (iOS): say "offline" — which also makes this install
    /// push-wakeable at once — and close the socket rather than let the system kill it silently
    /// a little later. The binding (address, topics) is kept; `reconnectNow` brings it back.
    func suspend() {
        guard !closedByUs, !suspended else { return }
        suspended = true
        pingTask?.cancel(); pingTask = nil
        guard let t = task else { return }
        task = nil
        live = false
        subscribed = []
        let frame = (try? JSONSerialization.data(withJSONObject: ["type": "presence", "status": "offline"]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? ""
        // Close only once the frame is on the wire, so the server sees "offline" first — and
        // hold the process awake until it is: without a background task the app could be
        // suspended with the frame still queued, leaving a socket the server took for live.
        #if os(iOS)
        let grace = BackgroundGrace("skwod.goodbye")
        t.send(.string(frame)) { _ in
            Task { @MainActor in
                // Over p2p "sent" means "handed to the in-process proxy": a beat for it to
                // reach the host before the stream is torn down, and for the close to follow.
                try? await Task.sleep(for: .milliseconds(400))
                t.cancel(with: .goingAway, reason: nil)
                try? await Task.sleep(for: .milliseconds(300))
                grace.end()
            }
        }
        #else
        t.send(.string(frame)) { _ in t.cancel(with: .goingAway, reason: nil) }
        #endif
    }

    func disconnect() {
        closedByUs = true
        suspended = false
        live = false
        pingTask?.cancel(); pingTask = nil
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        subscribed = []
        presence = [:]
    }

    // MARK: - Socket lifecycle

    private func openSocket() {
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        live = false
        subscribed = []
        guard !suspended, !baseUrl.isEmpty, var comps = URLComponents(string: baseUrl) else { return }
        comps.scheme = (comps.scheme == "http") ? "ws" : "wss"
        comps.path = (comps.path.hasSuffix("/") ? String(comps.path.dropLast()) : comps.path) + "/api/ws"
        guard let url = comps.url else { return }
        // Send the session token in the Authorization header, NOT ?token= — query strings get
        // written to reverse-proxy / server access logs, leaking the bearer token at rest.
        var req = URLRequest(url: url)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let t = URLSession.shared.webSocketTask(with: req)
        task = t
        t.resume()
        receiveLoop(on: t)
        // Announce presence + subscribe as the first frames; the server answers subscribed/error.
        send(["type": "presence", "status": myStatus])
        // Where the app is, on every socket: the server then goes by this alone (not by
        // presence — "offline" is also what a backgrounded call says, and it stays in-band).
        #if os(iOS)
        send(["type": "push", "state": pushActive ? "active" : "background"])
        #endif
        setTopics(wantedTopics)
        startPing()
    }

    private func startPing() {
        pingTask?.cancel()
        pingTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(30))
                await self?.send(["type": "ping"])
            }
        }
    }

    private func receiveLoop(on t: URLSessionWebSocketTask) {
        t.receive { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self, self.task === t else { return }
                switch result {
                case .success(let msg):
                    if !self.live {
                        self.live = true
                        self.onConnected?()
                    }
                    if case .string(let text) = msg { self.handle(text) }
                    self.receiveLoop(on: t)
                case .failure:
                    self.task = nil
                    self.live = false
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func scheduleReconnect() {
        guard !closedByUs, !suspended else { return }
        let delay = reconnectDelay
        reconnectDelay = min(reconnectDelay * 2, 60)
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard let self, !self.closedByUs, !self.suspended, self.task == nil else { return }
            self.openSocket()
        }
    }

    /// A `typing` event on a topic this client listens to (topic, user id).
    var onTyping: ((String, String) -> Void)?
    /// The workspace whose mention badges an opened conversation clears.
    var mentionWorkspaceId: String?
    /// Someone's message arrived on a topic (topic, author id): they stopped typing it.
    var onPosted: ((String, String) -> Void)?

    /// "I'm typing" into `topic` (the open conversation). The caller throttles
    /// (`TypingSendThrottle`); the server drops more than one a second anyway.
    func sendTyping(topic: String) {
        guard !topic.isEmpty else { return }
        send(["type": "typing", "topic": topic])
    }

    var currentUserId: String { myUserId }

    private func send(_ obj: [String: Any]) {
        guard let task, let data = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: data, encoding: .utf8) else { return }
        task.send(.string(text)) { _ in }
    }

    // MARK: - Events

    private func handle(_ text: String) {
        reconnectDelay = 1   // healthy traffic resets the backoff
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["type"] as? String == "event",
              let topic = obj["topic"] as? String,
              let event = obj["event"] as? String,
              let payload = obj["payload"] as? [String: Any] else { return }
        // Only what this client asked to hear: an event on any other topic is not acted on.
        guard RealtimeTopicRule.accepts(topic: topic, wanted: wantedTopics) else { return }
        switch event {
        case "presence":
            if let uid = payload["user_id"] as? String, let status = payload["status"] as? String, !blockedIds.contains(uid) {
                presence[uid] = PresenceSeen(status: status, at: Date())
            }
        case "typing":
            // Only ever shown in the open conversation (`TypingState`); never a notification.
            if let uid = payload["user_id"] as? String { onTyping?(topic, uid) }
        default:
            if event == "message", let author = payload["author_id"] as? String { onPosted?(topic, author) }
            onEvent?(topic, event, payload)
        }
    }

    // MARK: - Local notifications

    /// The privacy rule for everything a notification carries, and what this run's redacted
    /// notifications stood for (in memory only).
    private var shaper = NotificationShaper()

    /// The target behind a token from a clicked notification, if this run issued it.
    func target(forToken token: String) -> NotificationTarget? {
        shaper.target(forToken: token, now: Date().timeIntervalSince1970)
    }

    /// A skwod's local data was deleted: this run's tokens for it lead nowhere from now on.
    func forgetNotificationTargets(workspaceId: String) { shaper.forget(workspaceId: workspaceId) }

    /// Whether a notification about `topic` would be redundant: that chat is on screen.
    func isOnScreen(_ topic: String) -> Bool { appActive && topic == focusedTopic }

    /// The user is reading `topic` here: what Notification Center still holds about it is
    /// stale. (Only this device's: reading on another device sends no signal a server could
    /// relay — it is not told what was read — so those stay until the chat is opened here.)
    func clearDelivered(topic: String) {
        let center = UNUserNotificationCenter.current()
        let threads = [topic, shaper.knownStandIn(for: "thread|" + topic)].compactMap { $0 }
        center.getDeliveredNotifications { delivered in
            let ids = delivered.filter { threads.contains($0.request.content.threadIdentifier) }.map(\.request.identifier)
            if !ids.isEmpty { center.removeDeliveredNotifications(withIdentifiers: ids) }
        }
    }

    /// Post a local notification (asking for permission the first time). `id` makes later ones
    /// about the same thing replace it instead of stacking.
    /// `sound`: whether the notification itself makes a sound (`MessageAlert` decides: not
    /// while the app is in front, where the app's own sound is the one sound).
    /// `target`: the conversation a click on it opens.
    /// `privacy` (required — there is no safe default): whether the text names someone or
    /// quotes something (`.personal`: replaced by "New message" with previews off or app lock
    /// on) or is a sentence of the app's own (`.fixed`).
    func notify(title: String, body: String, privacy: NotificationText, thread: String, id: String = UUID().uuidString, sound: Bool = true, target: NotificationTarget? = nil) {
        // What is actually written into the notification — text, thread, request identifier,
        // userInfo — is `NotificationShaper`'s: with app lock on (whether or not the app
        // happens to be unlocked right now: a banner is shown outside the app's gate) or
        // previews off, none of it names a skwod, server, channel or conversation.
        let locked = AppLock.shared.enabled || NotificationState.appLockEnabled
        let shape = shaper.shape(title: title, body: body, text: privacy, thread: thread, identifier: id, target: target,
                                 appLock: locked, previews: NotificationState.showPreviews, now: Date().timeIntervalSince1970)
        let content = UNMutableNotificationContent()
        content.title = shape.title
        content.body = shape.body
        content.sound = sound ? .default : nil
        content.threadIdentifier = shape.thread
        content.userInfo = shape.userInfo
        let id = shape.identifier
        let (title, body) = (shape.title, shape.body)
        #if DEBUG
        Realtime.posted.append(["title": title, "body": body, "thread": thread, "at": Int(Date().timeIntervalSince1970 * 1000)])
        if Realtime.posted.count > 200 { Realtime.posted.removeFirst(Realtime.posted.count - 200) }
        #endif
        requestAuthIfNeeded { granted in
            guard granted else { return }
            let req = UNNotificationRequest(identifier: id, content: content, trigger: nil)
            UNUserNotificationCenter.current().add(req)
        }
    }

    #if DEBUG
    /// Every local notification this run asked for (whether or not the system allowed it) — the
    /// end-to-end checks read it to prove what did and did NOT notify.
    static var posted: [[String: Any]] = []
    #endif

    private func requestAuthIfNeeded(_ then: @escaping (Bool) -> Void) {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .notDetermined:
                center.requestAuthorization(options: [.alert, .sound, .badge]) { ok, _ in then(ok) }
            case .denied:
                then(false)
            default:
                then(true)
            }
        }
    }
}

extension Notification.Name {
    /// A notification was opened: `userInfo` has "workspace" (id, may be empty), "scope" and
    /// "tag" (a wake tag, may be empty) and "token" (`NotificationTokens`, may be empty). `AppState.openFromNotification` follows it.
    static let skwodOpenChat = Notification.Name("skwod.openChat")
}

/// Show banners even while the app is frontmost (a message in a channel you're NOT reading).
extension Realtime: UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // A remote "New message" alert arriving while the app is in front is redundant: the live
        // connection already raised a local notification (or the chat is on screen).
        if notification.request.trigger is UNPushNotificationTrigger {
            completionHandler([])
            return
        }
        completionHandler([.banner, .sound])
    }

    /// A notification was clicked / tapped: open the conversation it was about, in the skwod
    /// it came from. A local one says so itself; one rewritten by the notification extension
    /// carries its conversation as the thread and its skwod as the wake tag.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let content = response.notification.request.content
        let target = NotificationTarget(userInfo: content.userInfo)
        let thread = content.threadIdentifier
        let tag = content.userInfo["tag"] as? String
        let token = content.userInfo[NotificationTokens.key] as? String
        Task { @MainActor in
            NotificationCenter.default.post(name: .skwodOpenChat, object: nil, userInfo: [
                "workspace": target?.workspaceId ?? "", "scope": target?.scope ?? thread, "tag": tag ?? "", "token": token ?? "",
            ])
        }
        completionHandler()
    }
}
