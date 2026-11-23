import SwiftUI
import Combine

/// The sidebar's persisted, observable list of what the user can open: joined spaces (each = a
/// server + channel) and DM conversations. Held once at the app level and shared into the
/// NavigationSplitView, so selecting an item in the sidebar drives the chat detail pane — and the
/// lists survive relaunches (stored in the encrypted cache under the active workspace).
@MainActor
final class ChatModel: ObservableObject {
    @Published var spaces: [RealSpace] = [] {
        didSet {
            app?.primaryChannelId = spaces.first?.channelId   // for the address auto-follow watcher
            syncRealtimeTopics()
        }
    }
    /// Group direct conversations (3–10 people), as the server lists them (`GroupDMs.swift`).
    /// ACCEPTED groups: each with the member set this device fixed when it started or accepted
    /// the group — the only people its messages are sealed to.
    var groups: [GroupDM] { store.groups }
    /// Group conversations the server lists that this device has not accepted (invitations).
    var pendingGroups: [GroupDM] { store.invitations }
    var dms: [DMConversation] { store.dms }
    /// The 1:1 and group stores of the active workspace, and every rule about which of them
    /// owns a conversation id (`ConversationStore.swift`). Nothing else changes those lists.
    private(set) var store = ConversationStore(backend: nil, workspaceId: "")
    private var storeBackend: CoreConversationBackend?

    /// Stores (with their backends) that were replaced while they still had unsaved changes.
    private var parked: [String: (ConversationStore, CoreConversationBackend)] = [:]

    /// Keep the current pair if it is a workspace's, was read, and has something unwritten.
    private func park() {
        guard store.ready, !store.workspaceId.isEmpty, store.hasUnsaved, let storeBackend else { return }
        parked[store.workspaceId] = (store, storeBackend)
    }

    /// Nothing is kept for a workspace whose data was deleted.
    func forgetParked(workspaceId: String) { parked[workspaceId] = nil }

    /// What the conversation stores still have to write, handed over for a caller that is
    /// about to take the client down and cannot wait (`ConversationStore.takeUnsaved`).
    func takeUnsavedConversations() -> [(key: String, value: String)] { store.takeUnsaved() }

    /// What is current right now, to hold on to across a server call (`StoreTicket`).
    func ticket() -> StoreTicket? {
        StoreTicket(boundWorkspaceId: app?.bound?.workspaceId, turn: app?.bound?.turn, store: store)
    }

    /// Is what `ticket` captured still current? If not, what the call brought back is dropped.
    func holds(_ ticket: StoreTicket) -> Bool {
        ticket.isCurrent(boundWorkspaceId: app?.bound?.workspaceId, turn: app?.bound?.turn, store: store)
    }

    /// A fresh pair of stores for the workspace that is now active. Whatever was still running
    /// against the previous pair finishes there and shows nowhere.
    ///
    /// The pair being replaced is PARKED if it still has something to write that could not be
    /// written (its cache was not open): it is taken up again — with everything it holds —
    /// the next time its workspace is bound, and writes then. (In memory only: it does not
    /// survive the app being closed.)
    private func bindStore(workspaceId: String) {
        guard let app else { return }
        // (What was said about another workspace's conversations is not shown in this one.)
        conversationProblem = nil
        park()
        if let (kept, keptBackend) = parked.removeValue(forKey: workspaceId) {
            objectWillChange.send()
            storeBackend = keptBackend
            store = kept
            syncRealtimeTopics()
            return
        }
        let backend = CoreConversationBackend(app: app, workspaceId: workspaceId)
        let fresh = ConversationStore(backend: backend, workspaceId: workspaceId,
                                      me: app.current.flatMap { $0.id == workspaceId ? $0.userId : nil })
        fresh.willChange = { [weak self] in self?.objectWillChange.send() }
        fresh.didChange = { [weak self, weak fresh] in if let self, self.store === fresh { self.syncRealtimeTopics() } }
        fresh.onNotice = { [weak self, weak fresh] notice in if let self, let fresh, self.store === fresh { self.say(notice, from: fresh) } }
        fresh.nameHints = { [weak self, weak fresh] in
            guard let self, let fresh else { return [:] }
            return await self.nameHints(for: fresh)
        }
        objectWillChange.send()
        storeBackend = backend
        store = fresh
        syncRealtimeTopics()
    }
    /// server id → the ONE channel that server's feed and stories live in (`feedChannel`): the
    /// server's hidden feed channel, or — until its owner's app has made one — its lowest text
    /// channel. Never "whichever channel is first on this device".
    @Published private(set) var feedChannels: [String: String] = [:] {
        didSet { if feedChannels != oldValue { syncRealtimeTopics() } }
    }

    /// Ask the core which channel each joined server's feed is in.
    func resolveFeedChannels() async {
        guard let app, let client = app.client, let asked = app.bindTicket() else { return }
        var resolved = feedChannels.filter { id, _ in spaces.contains(where: { $0.serverId == id }) }
        for group in serverGroups where !group.serverId.isEmpty && group.serverId != "demo" {
            if let channelId = try? await client.feedChannel(serverId: group.serverId), !channelId.isEmpty {
                resolved[group.serverId] = channelId
            }
        }
        // Asked of one skwod's server: never written into the sidebar of another.
        guard app.holds(asked) else { return }
        if resolved != feedChannels { feedChannels = resolved }
    }

    /// The item currently shown in the detail pane.
    @Published var selection: SidebarItem? {
        didSet {
            // Tell the relay which chat is on screen — its messages shouldn't notify.
            switch selection {
            case .space(let s): app?.realtime.focusedTopic = "channel:\(s.channelId)"
            case .dm(let d): app?.realtime.focusedTopic = "dm:\(d.conversationId)"
            case .group(let g): app?.realtime.focusedTopic = "dm:\(g.conversationId)"
            default: app?.realtime.focusedTopic = nil
            }
            // Remember the last-opened channel so re-entering this skwod reopens it (across devices,
            // via the synced kv store). Only channels — DMs/home don't override it.
            if case .space(let s) = selection, !loadingSelection {
                lastChannelId = s.channelId
                Task { await persistLastChannel(s.channelId) }
            }
        }
    }
    /// Suppresses the persist while we're restoring the remembered selection on load.
    private var loadingSelection = false
    /// The channelId to reopen on next load (synced via kv).
    private var lastChannelId: String?

    /// Keep the live relay subscribed to every joined channel + DM, with names for notifications.
    private func syncRealtimeTopics() {
        guard let app else { return }
        var topics = Set(spaces.map { "channel:\($0.channelId)" })
        // Each server's feed lives in a channel of its own that is in no sidebar list.
        topics.formUnion(feedChannels.values.map { "channel:\($0)" })
        topics.formUnion(dms.map { "dm:\($0.conversationId)" })
        topics.formUnion(groups.map { "dm:\($0.conversationId)" })
        topics.formUnion(pendingGroups.map { "dm:\($0.conversationId)" })
        for g in groups { app.realtime.chatNames[g.conversationId] = title(of: g) }
        topics.formUnion(spaces.map { "server:\($0.serverId)" })   // presence events arrive here
        for s in spaces { app.realtime.chatNames[s.channelId] = s.channelName }
        // A direct conversation is never titled with the name the SERVER gave its peer: only
        // with a name this device trusts for them, and only once the user made the
        // conversation their own (`NotificationTitles.direct`). Otherwise a server could list
        // an accomplice as "mom" and have the notification say so.
        let bookRead = app.contacts.isLoaded(for: store.workspaceId)
        func directTitle(_ d: DMConversation) -> String {
            let shown = app.contacts.display(d.peerUserId, claimedName: d.name)
            let trusted = bookRead && (shown.badge == .none || shown.badge == .verified) ? shown.text : nil
            return NotificationTitles.direct(isClaimed: d.isClaimed, trustedName: trusted)
        }
        for d in dms { app.realtime.chatNames[d.conversationId] = directTitle(d) }
        // The same local labels, for the notification extension (shared defaults, on-device only).
        // Keyed by the workspace the STORE belongs to (not whichever is "current" at this
        // moment of a switch), and only once that store has been read: an unread store's empty
        // lists would otherwise wipe the names and the sender sets the extension works from.
        let wid = store.workspaceId
        if store.ready, !wid.isEmpty, app.current?.id == wid {
            var names: [String: String] = [:]
            for s in spaces where !s.channelId.isEmpty && s.channelId != "demo" { names["channel:\(s.channelId)"] = s.channelName }
            // (Every conversation keeps its key — the extension looks only in the ones named
            // here — but an untrusted one gets the generic title.)
            for d in dms { names["dm:\(d.conversationId)"] = directTitle(d) }
            for g in groups { names["dm:\(g.conversationId)"] = title(of: g) }
            // Who a mention banner may name (`MentionNotice`): only peers of a claimed direct
            // conversation whose name this device trusts — the same name that titles it.
            for d in ConversationStore.holders(dms) where !d.peerUserId.isEmpty {
                let t = directTitle(d)
                if t != NotificationTitles.generic { names[MentionNotice.personPrefix + d.peerUserId] = t }
            }
            // A server's feed channel is in no list; the extension still has to look in it.
            for (serverId, channelId) in feedChannels where names["channel:\(channelId)"] == nil {
                names["channel:\(channelId)"] = (spaces.first(where: { $0.serverId == serverId })?.name ?? "Skwod") + " feed"
            }
            NotificationState.setNames(names, workspaceId: wid)
            // Whose rows the extension may announce under those titles: a group's are its
            // members as this device holds them, nobody else's.
            var senders = NotificationSenders.allowed(dms: dms, groups: groups, silent: store.silentIds)
            // Whose @everyone counts in each channel (`EveryoneRule`), for the extension.
            for s in spaces where !s.channelId.isEmpty && s.channelId != "demo" {
                if let ids = everyoneSenders[s.serverId], !ids.isEmpty { senders[EveryoneRule.sendersKey(channelId: s.channelId)] = ids.sorted() }
            }
            NotificationState.setSenders(senders, workspaceId: wid)
        }
        app.realtime.setTopics(topics)
    }
    /// True when the skwod (home) rail icon is active — the list shows Direct Messages instead of a
    /// server's channels.
    @Published var homeMode = false
    /// The server (guild) picked in the rail whose channels the middle column shows. Usually follows
    /// the selected channel; set directly when a server is tapped in the rail before a channel is open.
    @Published var railServerId: String?
    /// True while a just-joined server is being provisioned (host installs our keys, channels decrypt).
    /// The sidebar shows a "setting up" spinner instead of the empty state during this window.
    @Published var provisioning = false
    private var discoverCount = 0

    private(set) weak var app: AppState?
    private var labelsWatch: NSObjectProtocol?
    private(set) var loadedFor: String?   // workspace id the lists were loaded for
    /// The workspace `spaces` were read for (nil while switching).
    var spacesWorkspaceId: String? { loadedFor }
    private var loadedTurn: Int?     // …and the bind turn of the client they were loaded through
    private var spacesRead = false   // `spaces` was read from this workspace's (open) cache
    private var loadFinishedFor: String?
    private var wantsLastChannel = false

    func bind(_ app: AppState) {
        self.app = app
        app.chatModel = self
        // Previews were turned back on (or app lock off): the extension gets its titles and
        // sender sets again now (`NotificationState.dropConversationLabelsIfUnused`).
        labelsWatch = NotificationCenter.default.addObserver(forName: NotificationState.conversationLabelsWanted, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.syncRealtimeTopics() }
        }
        app.avatars.bind(app)
        // The titles handed to the notification extension follow the contact book: a contact
        // verified, accepted or flagged later changes what its conversation may be called.
        contactWatch = app.contacts.objectWillChange.sink { [weak self] _ in
            guard let self, !self.titlesStale else { return }
            self.titlesStale = true
            Task { @MainActor [weak self] in
                self?.titlesStale = false
                self?.syncRealtimeTopics()
            }
        }
    }
    private var contactWatch: AnyCancellable?
    private var titlesStale = false

    /// Load the persisted lists for the active workspace (called when it changes). `openLastChannel`
    /// restores the last-viewed channel (app launch); otherwise land on the overview (skwod switch,
    /// where tapping the tile explicitly means "show me the server list").
    func loadIfNeeded(openLastChannel: Bool = false) async {
        guard let app, let wid = app.current?.id else { return }
        if openLastChannel { wantsLastChannel = true }
        // Only through the client that has THIS workspace's cache open. While switching,
        // `current` is already the new workspace before its client exists (and the previous
        // one's is gone): loading then would read nothing — or, worse, someone else's lists.
        // `AppState.activate` calls again once the client is bound.
        guard let bound = app.bound, bound.workspaceId == wid else {
            // Same workspace, between two binds of it (a retry): everything stays as it is.
            if loadedFor != nil, loadedFor != wid {
                loadedFor = nil; loadedTurn = nil; loadFinishedFor = nil; spacesRead = false
                selection = nil; railServerId = nil
                spaces = []
                objectWillChange.send()
                park()
                store = ConversationStore(backend: nil, workspaceId: "")
                storeBackend = nil
                syncRealtimeTopics()
            }
            return
        }
        // Loaded once per BIND, not once per workspace: a client that came up without the cache
        // (no key yet, the notification extension held the lock, the file would not open) read
        // nothing, and the client of the next bind — the one with the cache — has to be read.
        guard loadedFor != wid || loadedTurn != bound.turn else {
            // Already loaded through this client: only the "reopen my last channel" part is
            // left to do.
            if loadFinishedFor == wid, wantsLastChannel, selection == nil { wantsLastChannel = false; await restoreLastChannel() }
            return
        }
        let sameWorkspace = loadedFor == wid
        loadedFor = wid
        loadedTurn = bound.turn
        if !sameWorkspace {
            // (A new bind of the SAME workspace leaves what is on screen where it is.)
            selection = nil
            railServerId = nil
            // What was left is another workspace's (account's) business.
            tombstones = LeaveTombstones()
            spaces = []
            spacesRead = false
        }
        if sameWorkspace, store.ready {
            // These stores were read from this workspace's cache and hold everything decided
            // since: they stay, and what they could not write meanwhile is written now.
            await store.flush()
        } else {
            // Never read (or another workspace's): a fresh pair, read below — or the pair
            // that was parked for this workspace with changes it could not write.
            bindStore(workspaceId: wid)
            if store.ready { await store.flush() }
        }
        if bound.cacheOpen, !spacesRead { await readSpaces(through: bound) }
        // BOTH conversation stores (and the ignored groups) are read from the cache before
        // anything is asked of the server: a listing or a delivery checked against a store
        // that has not been read yet would pass as "nobody holds this id". Until this
        // returns true every server-driven path below does nothing (`ConversationStore.ready`)
        // — and without the cache open it does not return true.
        await store.load()
        await app.contacts.loadIfNeeded()
        app.contacts.retrySave()
        // (The titles written while the book was not read yet were the generic ones.)
        syncRealtimeTopics()
        migrateContacts()
        await refreshRoster()
        if wantsLastChannel { wantsLastChannel = false; await restoreLastChannel() }
        loadFinishedFor = wid
        // Conversations started on another of this account's devices, and anything that arrived
        // while the app was closed.
        await refreshDMList()
        await refreshGroups()
        await app.syncMailbox()
    }

    /// Write what the conversation stores still have to write (before their client goes).
    func flushConversations() async { await store.flush() }

    // MARK: Direct messages that arrive

    /// Make sure the conversation with `peerUserId` — the authenticated sender of a decrypted
    /// DM — is in the sidebar (without opening it), and return what to call them in a
    /// notification.
    ///
    /// A conversation is bound to its peer ACCOUNT for good, and that binding is made here, on
    /// the device, from the decrypted sender — never from the server's participant list. A
    /// sender that does not match the entry held for this conversation id gets an entry of its
    /// own; no entry is ever re-keyed to another account. The server's conversation list
    /// contributes at most a NAME HINT, only from a row naming the same account, and a hint is
    /// never more than "unverified" (`ContactTrust`).
    @discardableResult
    func upsertDM(conversationId: String, peerUserId: String) async -> String? {
        guard let app else { return nil }
        // Decided by the store: nothing before both stores are read, and never an entry for an
        // id a group holds (the group stands as it is; the event is dropped, said once).
        guard let delivered = await store.deliverDM(conversationId: conversationId, peerUserId: peerUserId) else { return nil }
        return await spokenName(of: peerUserId, claimedName: delivered.name, isNew: delivered.isNew)
    }

    /// What to call the sender of a direct message the store accepted, in a notification. A
    /// sender just listed is noted (unverified) and its claimed name cross-checked first.
    func spokenName(of peerUserId: String, claimedName: String, isNew: Bool) async -> String? {
        guard let app else { return nil }
        if isNew {
            app.contacts.note(peerUserId, name: claimedName, level: .unverified)
            await app.contacts.check(peerUserId, name: claimedName)
        }
        return app.contacts.display(peerUserId, claimedName: claimedName).spoken
    }

    /// List every 1:1 conversation of this ACCOUNT — including ones started on another of its
    /// devices — and add the ones this device does not show yet. Such a conversation is known
    /// only from the server's list, so its name is UNVERIFIED until a decrypted message or
    /// something the user does says otherwise; a row never renames or re-keys an entry this
    /// device already holds, and never makes one for an id a group holds.
    func refreshDMList() async {
        guard let app, let ticket = ticket() else { return }
        for added in await ticket.store.refreshDMList() {
            // The listing was this workspace's: nothing of it is noted in another one's book.
            guard holds(ticket) else { return }
            app.contacts.note(added.peerUserId, name: added.name, level: .unverified)
            await app.contacts.check(added.peerUserId, name: added.name)
        }
    }

    /// The user wrote in this conversation: whatever listed it first, it is theirs now.
    func claimDM(_ d: DMConversation) { store.claimDM(conversationId: d.conversationId, peerUserId: d.peerUserId) }

    /// Conversations stored by a build that kept no trust information: one this device started
    /// itself (the only kind those builds could hold — the user picked the person) is KNOWN;
    /// anything else starts UNVERIFIED.
    private func migrateContacts() {
        guard let app else { return }
        for d in dms where app.contacts.entries[d.peerUserId] == nil {
            let startedHere = d.startedHere ?? !d.peerDeviceId.isEmpty
            app.contacts.note(d.peerUserId, name: d.name, level: ContactTrust.migratedLevel(startedHere: startedHere))
        }
    }

    /// Select the remembered last-opened channel (kv-synced, so it follows you across devices), or
    /// the first available channel. No-op if the sidebar has no channels yet.
    private func restoreLastChannel() async {
        guard let app, let client = app.client else { return }
        lastChannelId = await client.kvGet(key: "\(app.current?.id ?? "")|lastChannel")
        let target = spaces.first(where: { $0.channelId == lastChannelId }) ?? spaces.first
        guard let target else { return }
        loadingSelection = true
        railServerId = target.serverId
        selection = .space(target)
        loadingSelection = false
    }

    private func persistLastChannel(_ channelId: String) async {
        guard let app, let client = app.client else { return }
        await client.kvSet(key: "\(app.current?.id ?? "")|lastChannel", value: channelId)
    }

    func addSpace(_ s: RealSpace) {
        guard !tombstones.hides(s.serverId) else { return }
        if !spaces.contains(where: { $0.channelId == s.channelId }) { spaces.insert(s, at: 0) }
        homeMode = false
        selection = .space(s)
        Task { await persist(spaces, key: "sidebar.spaces") }
        touchKeyBackup()
    }

    /// Refresh the server-stored key backup after key material changes (space created/joined/
    /// provisioned). Cheap and passphrase-free; a silent no-op when backup isn't enabled.
    /// Debounced: discovery adds channels one by one, and each add landing here must coalesce
    /// into one upload instead of a burst that eats the server's backup rate limit.
    private func touchKeyBackup() {
        guard let client = app?.client else { return }
        keyBackupTask?.cancel()
        keyBackupTask = Task {
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled else { return }
            _ = try? await client.updateKeyBackup()
        }
    }
    private var keyBackupTask: Task<Void, Never>?

    /// The server whose channels the middle column shows: the selected channel's server, else the
    /// rail-picked server, else the first one. Drives the new "servers in the rail" layout.
    var currentServer: ServerGroup? {
        let groups = serverGroups
        var sid = railServerId
        if case .space(let s) = selection { sid = s.serverId }
        return groups.first { $0.serverId == sid } ?? groups.first
    }

    /// True when `group` is the server highlighted in the middle SERVERS list (its channel boxes /
    /// chat are showing in the main pane).
    func isServerActive(_ group: ServerGroup) -> Bool {
        if homeMode || selection == .feed { return false }
        if case .space(let s) = selection { return s.serverId == group.serverId }
        return railServerId == group.serverId
    }

    /// Pick a server in the middle list: show its channels as BOXES in the main pane (no channel open
    /// yet). Pass nil to show every server's channels (the skwod overview).
    func showServerBoxes(_ serverId: String?) {
        homeMode = false
        railServerId = serverId
        if serverId == nil { highlightedChannelId = nil }
        selection = nil
    }

    /// The channel highlighted in the list (first one when a server is opened) — on iOS this is
    /// purely visual and does NOT slide into the chat; the user taps a channel to open it.
    @Published var highlightedChannelId: String?

    /// Open a channel's chat from a box in the overview.
    /// Open the conversation a notification was about (`channel:<id>` / `dm:<id>`). False if
    /// this skwod's lists do not (yet) hold it.
    @discardableResult
    func open(scope: String) -> Bool {
        if scope.hasPrefix("channel:") {
            let id = String(scope.dropFirst(8))
            guard let s = spaces.first(where: { $0.channelId == id }) else { return false }
            openChannel(s)
            return true
        }
        guard scope.hasPrefix("dm:") else { return false }
        let id = String(scope.dropFirst(3))
        if let g = groups.first(where: { $0.conversationId == id }) {
            homeMode = true
            selection = .group(g)
            return true
        }
        if let d = dms.first(where: { $0.conversationId == id }) {
            homeMode = true
            selection = .dm(d)
            return true
        }
        return false
    }

    func openChannel(_ s: RealSpace) {
        homeMode = false
        highlightedChannelId = s.channelId
        selection = .space(s)
    }

    /// Open a server from the RAIL: show its channels with the first highlighted. On iOS stay on the
    /// list (don't slide into the full-screen chat); on macOS also open it in the detail pane (the
    /// 3-pane desktop layout has no navigation cost, so showing the first channel is good UX).
    func openServer(_ g: ServerGroup) {
        homeMode = false
        railServerId = g.serverId
        highlightedChannelId = g.channels.first?.channelId
        #if os(iOS)
        selection = nil
        #else
        selection = g.channels.first.map { .space($0) }
        #endif
    }

    /// True when a server is picked so the middle column shows ITS channels — whether or not a
    /// channel's chat is open (railServerId drives it, not just selection).
    var inChannelsMode: Bool {
        if case .space = selection { return true }
        return railServerId != nil
    }

    /// Channels grouped by server — the skwod → servers → channels hierarchy the sidebar renders.
    /// Insertion order is preserved (newest server first, since addSpace inserts at the front).
    var serverGroups: [ServerGroup] {
        var order: [String] = []
        var byServer: [String: ServerGroup] = [:]
        for s in spaces {
            if byServer[s.serverId] == nil {
                order.append(s.serverId)
                byServer[s.serverId] = ServerGroup(serverId: s.serverId, name: s.name, channels: [])
            }
            byServer[s.serverId]?.channels.append(s)
        }
        return order.compactMap { byServer[$0] }
    }

    /// After a re-login or reinstall: the sidebar cache + device keys are gone but memberships
    /// survive server-side. Rediscover every server we belong to and ask each host to re-provision
    /// this (new) device — channels and keys reappear once the host's inbox sync answers. No invite
    /// code needed: membership is the credential.
    func recoverMemberships() async {
        guard let app, let client = app.client, let asked = app.bindTicket(),
              let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/servers"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let servers = obj["servers"] as? [[String: Any]] else { return }
        // The list is the answer of the skwod that was bound when it was asked.
        guard app.holds(asked) else { return }
        let me = app.session?.userId
        for srv in servers {
            guard app.holds(asked) else { return }
            guard let sid = srv["server_id"] as? String,
                  let ownerId = srv["owner_id"] as? String,
                  !spaces.contains(where: { $0.serverId == sid }) else { continue }
            // Any confirmed member can provision us — but ask BOTH another member AND all of this
            // account's OWN other devices, because whichever is ONLINE gets to answer. (Asking only
            // the other member fails when they're offline; and only an own device's space key is
            // accepted anyway — a different account's SKEY is rejected by the trust guard. So the
            // own-device ask is the reliable path for a linked second device.)
            guard let members = try? await client.listMembers(serverId: sid) else { continue }
            let provisioner = members.first(where: { $0.userId == ownerId && $0.userId != me })
                ?? members.first(where: { $0.userId != me })
            var peer: (userId: String, deviceId: String)?
            if let p = provisioner, let found = try? await client.findUser(username: p.username), found.userId == p.userId {
                peer = (found.userId, found.deviceId)
                try? await client.requestProvision(serverId: sid, hostUserId: found.userId, hostDeviceId: found.deviceId)
            }
            if let me, let ownDevices = try? await client.listOwnDevices() {
                for device in ownDevices where device != app.deviceId {
                    if peer == nil { peer = (me, device) }
                    try? await client.requestProvision(serverId: sid, hostUserId: me, hostDeviceId: device)
                }
            }
            // A join that is being watched already covers this server.
            if discoveries[sid] != nil { continue }
            Task { await discover(serverId: sid, hostUserId: peer?.userId, hostDeviceId: peer?.deviceId, quiet: true) }
        }
    }

    /// Discover channels added to servers we're already in (the host created them after we joined).
    /// We hold the space key, so new channels arrive with readable names; sender keys flow through
    /// the share-on-open exchange. Appends quietly — no selection change, persisted only on change.
    func syncServerChannels() async {
        guard let app, let client = app.client, let asked = app.bindTicket() else { return }
        var added = false
        for group in serverGroups where !group.serverId.isEmpty && group.serverId != "demo" {
            guard let channels = try? await client.listChannels(serverId: group.serverId) else { continue }
            // A server may hold this answer while the user switches skwods: its channels go
            // into the sidebar of the skwod that was asked, or nowhere.
            guard app.holds(asked) else { return }
            // A voice room is not a place to type: it never belongs in a text-channel list.
            // (Builds before 43b listed them; drop any that were saved.)
            let voice = Set(channels.filter { $0.kind == "voice" }.map(\.channelId))
            if spaces.contains(where: { voice.contains($0.channelId) }) {
                if case .space(let open) = selection, voice.contains(open.channelId) { selection = nil }
                spaces.removeAll { voice.contains($0.channelId) }
                added = true
            }
            // Left or deleted while that listing was in flight: it stays out.
            if tombstones.hides(group.serverId) { continue }
            for ch in channels where ch.kind != "voice" {
                guard let name = ch.name, !spaces.contains(where: { $0.channelId == ch.channelId }) else { continue }
                spaces.append(RealSpace(name: group.name, channelName: name, serverId: group.serverId,
                                        channelId: ch.channelId, inviteCode: "", spaceKeyHex: ""))
                added = true
            }
        }
        guard app.holds(asked) else { return }
        if added { await persist(spaces, key: "sidebar.spaces") }
        await resolveFeedChannels()
        await refreshRoster()
        // Deleted servers (and ones this account was removed from) leave the sidebar.
        await refreshServerList()
    }

    /// Who the user would recognise by name in the servers they share: each server's ACCEPTED
    /// members — listed by the server, not held by the core, not waiting to be let in. Nobody
    /// else may wear one of those names unflagged (`ContactTrust`). Then cross-check, once,
    /// the server-claimed names that are on screen.
    func refreshRoster() async {
        guard let app, let client = app.client, let asked = app.bindTicket() else { return }
        let me = app.session?.userId
        var names: [(String, String)] = dms.map { ($0.peerUserId, $0.name) }
        for sid in Set(spaces.map(\.serverId)) where !sid.isEmpty && sid != "demo" {
            guard let members = try? await client.listMembers(serverId: sid) else { continue }
            let held = Set(await client.heldMembers(serverId: sid))
            let pending = Set(((try? await client.listJoinRequests(serverId: sid)) ?? []).map(\.userId))
            var accepted: [String: String] = [:]
            for m in members where m.userId != me && !held.contains(m.userId) && !pending.contains(m.userId) {
                accepted[m.userId] = m.username
            }
            // One skwod's member list never becomes another's roster (or its name checks).
            guard app.holds(asked) else { return }
            app.contacts.setRoster(serverId: sid, members: accepted)
            names += members.filter { $0.userId != me }.map { ($0.userId, $0.username) }
        }
        for (userId, name) in names {
            guard app.holds(asked) else { return }
            await app.contacts.check(userId, name: name)
        }
    }

    // MARK: Server actions (build 46)

    /// server id → its owner's user id, from the server list (`GET /api/servers`, members only).
    @Published var serverOwners: [String: String] = [:]

    /// server id → this account's role there (owner / admin / member), from the server's lists.
    @Published var serverRoles: [String: ServerRole] = [:]
    private var rolesAskedAt: [String: Date] = [:]

    /// server id → the owner this device has PINNED (`spaceOwner`), nil = none pinned.
    @Published var pinnedOwners: [String: String?] = [:]

    /// server id → whose @everyone counts there (`EveryoneRule`: the pinned owner, and admins
    /// the server lists who are members this device is not holding and has not blocked).
    @Published var everyoneSenders: [String: Set<String>] = [:]

    func everyoneHonoured(_ sender: String?, in serverId: String) -> Bool {
        guard let sender, !sender.isEmpty else { return false }
        if let pinned = pinnedOwners[serverId] ?? nil, pinned == sender { return !BlockList.shared.contains(sender) }
        return everyoneSenders[serverId]?.contains(sender) == true
    }

    func ownership(of serverId: String) -> ServerOwnership {
        ServerOwnership.decide(me: app?.session?.userId ?? "", pinned: pinnedOwners[serverId] ?? nil, hostSays: serverOwners[serverId])
    }

    /// This account's role in a server, for its menu. Owner only by the PINNED owner.
    func role(in serverId: String) -> ServerRole {
        if ownership(of: serverId) == .me { return .owner }
        return serverRoles[serverId] ?? .member
    }

    /// Ask each server (at most every 5 minutes) which roles this account holds there.
    private func refreshRoles(_ serverIds: [String]) async {
        guard let app, let client = app.client, let me = app.session?.userId, let token = app.session?.token,
              let base = URL(string: app.serverURL), !app.serverURL.isEmpty, let asked = app.bindTicket() else { return }
        for sid in serverIds {
            if let at = rolesAskedAt[sid], Date().timeIntervalSince(at) < 300 { continue }
            rolesAskedAt[sid] = Date()
            var req = URLRequest(url: base.appendingPathComponent("api/servers/\(sid)/members"))
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            guard let (data, resp) = try? await URLSession.shared.data(for: req),
                  (resp as? HTTPURLResponse)?.statusCode == 200,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let members = obj["members"] as? [[String: Any]],
                  let roles = try? await client.listRoles(serverId: sid), app.holds(asked) else { continue }
            let mine = members.first { $0["user_id"] as? String == me }?["role_ids"] as? [String] ?? []
            let pinned = await client.spaceOwner(serverId: sid)
            let held = Set(await client.heldMembers(serverId: sid))
            guard app.holds(asked) else { return }
            let ruleRoles: [ServerRoleRule.Role] = roles.map { .init(id: $0.roleId, permissions: $0.permissions, isDefault: $0.isDefault) }
            pinnedOwners[sid] = .some(pinned)
            serverRoles[sid] = ServerRoleRule.role(me: me, ownerId: pinned, myRoleIds: mine, roles: ruleRoles)
            var perms: [String: Int64] = [:]
            for m in members.prefix(5000) {
                guard let uid = m["user_id"] as? String, !uid.isEmpty else { continue }
                // Assigned roles only: the default role's bits are not an admin's (`everyonePermissions`).
                perms[uid] = ServerRoleRule.everyonePermissions(memberRoleIds: (m["role_ids"] as? [String]) ?? [], roles: ruleRoles)
            }
            let allowed = EveryoneRule.allowed(pinnedOwner: pinned, memberPermissions: perms, held: held,
                                               blocked: Set(perms.keys.filter { BlockList.shared.contains($0) }))
            if everyoneSenders[sid] != allowed {
                everyoneSenders[sid] = allowed
                syncRealtimeTopics()
            }
        }
    }

    /// Ask the skwod which servers this account is in (and who owns them). A server this device
    /// lists that the answer does NOT contain was deleted, or this account was removed from it:
    /// it leaves the sidebar (its keys stay; the user did not ask to forget anything). Only a
    /// complete, successful answer prunes.
    func refreshServerList() async {
        guard let app, let asked = app.bindTicket(), let token = app.session?.token,
              let base = URL(string: app.serverURL), !app.serverURL.isEmpty else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/servers"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let owners = ServerListRule.owners(data), app.holds(asked) else { return }
        serverOwners = owners
        await refreshRoles(Array(owners.keys))
        let gone = Set(spaces.map(\.serverId)).filter { !$0.isEmpty && $0 != "demo" && owners[$0] == nil }
        if !gone.isEmpty { dropServers(gone) }
    }

    /// Leave a server (a member): the server removes the membership (the same route a kick uses
    /// on oneself); this device then forgets the space's keys and drops it from the sidebar.
    /// Returns a sentence when it failed.
    func leaveServer(_ serverId: String) async -> String? {
        guard let app, let client = app.client, let me = app.session?.userId, let token = app.session?.token,
              let base = URL(string: app.serverURL), !app.serverURL.isEmpty else { return "Not connected — try again in a moment." }
        // Authoritative here from the moment it is confirmed (`LeaveTombstones`): the server goes
        // now, and nothing already in flight can bring it back while the host answers.
        guard let asked = app.bindTicket(), tombstones.begin(serverId) else { return nil }
        let before = spaces
        let openBefore = selection
        hideServers([serverId])
        var req = URLRequest(url: base.appendingPathComponent("api/servers/\(serverId)/members/\(me)"))
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let code = ((try? await URLSession.shared.data(for: req))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        // Another skwod (or account) is on screen now: its sidebar is not touched. (Its
        // tombstones were reset by the switch; this one's list is read afresh next time.)
        guard app.holds(asked) else {
            if code == 200 || code == 404 { await client.forgetSpace(serverId: serverId) }
            return nil
        }
        // 404: not a member any more — the same outcome.
        guard code == 200 || code == 404 else {
            // It did not happen: the channels come back where they were.
            if tombstones.failed(serverId) {
                spaces = LeaveTombstones.restore(before: before, now: spaces, serverId: serverId, server: \.serverId, key: \.channelId)
                if selection == nil, case .space(let open) = openBefore, open.serverId == serverId { selection = openBefore }
                Task { await persist(spaces, key: "sidebar.spaces") }
            }
            return code == 400 ? "You own this server: delete it instead." : "Couldn't leave the server — check your connection and try again."
        }
        tombstones.confirm(serverId)
        await client.forgetSpace(serverId: serverId)
        dropServers([serverId])
        return nil
    }

    /// Delete a server for everyone (its owner only; signed by this device through the core).
    func deleteServer(_ serverId: String) async -> String? {
        guard let client = app?.client else { return "Not connected — try again in a moment." }
        do { try await client.deleteSpace(serverId: serverId) } catch {
            return sendFailureText(error)
        }
        await client.forgetSpace(serverId: serverId)
        dropServers([serverId])
        return nil
    }

    /// Every channel of these servers leaves the sidebar (and the selection, if it was one).
    /// Servers dropped from the sidebar (left, deleted, or no longer listed for this account):
    /// work that was already in flight when it happened (a channel listing, a quiet discovery)
    /// must not put them back. Only a new join of that server (`joinByCode`) clears the mark.
    /// (`LeaveTombstones`: a leave in progress, or a server gone for good on this device.)
    private var tombstones = LeaveTombstones()

    private func dropServers(_ ids: Set<String>) {
        tombstones.dropped(ids)
        hideServers(ids)
    }

    /// Take these servers' channels out of the sidebar (and the selection) now.
    private func hideServers(_ ids: Set<String>) {
        // A join still being watched for one of them (waiting for keys) stops here.
        for id in ids { discoveries[id]?.cancel(); discoveries[id] = nil }
        if case .space(let open) = selection, ids.contains(open.serverId) { selection = nil }
        if let rail = railServerId, ids.contains(rail) { railServerId = nil }
        spaces.removeAll { ids.contains($0.serverId) }
        Task { await persist(spaces, key: "sidebar.spaces") }
    }

    /// Remove a channel from the sidebar (client-side only — the space itself lives on).
    func removeSpace(_ s: RealSpace) {
        spaces.removeAll { $0.id == s.id }
        if selection == .space(s) { selection = nil }
        Task { await persist(spaces, key: "sidebar.spaces") }
    }

    // MARK: Joining

    /// Where a join stands, for the banner the user sees while it is not finished.
    enum JoinStatus: Equatable {
        /// The request is with the host; nothing happens until they let us in.
        case waitingForApproval
        /// We are a member; the server's keys are on their way. `problem` says why it is slow.
        case settingUp(problem: String?)
        case denied
        case failed(String)
    }
    @Published var joinStatus: JoinStatus?
    /// server id → the task watching for that server's channels to become readable.
    private var discoveries: [String: Task<Void, Never>] = [:]
    /// Bumped to make the watchers look NOW (an approval, a mailbox sync, a reconnect).
    private var discoverKick = 0
    private var joinInFlight = false

    /// Join a server with ONLY an invite code. If the invite needs host approval the join goes
    /// pending; either way the server is then watched until its keys arrive (space key + channel
    /// keys) and every channel is revealed the moment they do. The join is remembered on disk
    /// (`PendingJoinStore`) until it is finished, so quitting the app in the middle loses nothing.
    /// Returns an error string to show inline, or nil if the join was accepted/queued.
    func joinByCode(_ code: String, afterSignup: Bool = false) async -> String? {
        guard let app, let client = app.client, let address = app.current?.server else { return "Not signed in." }
        var record = PendingJoinStore.get(address: address) ?? PendingJoin(code: code)
        record.code = code
        PendingJoinStore.set(record, address: address)
        let result: JoinResult
        do { result = try await client.joinByCode(inviteCode: code) }
        catch {
            let d = String(describing: error).lowercased()
            let definitive = d.contains("400") || d.contains("403") || d.contains("404") || d.contains("410")
                || d.contains("no longer valid") || d.contains("forbidden")
            // An invite the server refuses will not get better: forget it. Anything else (the
            // host is unreachable) is kept and tried again on the next launch / reconnect.
            if definitive { PendingJoinStore.clear(address: address) }
            // The code a HOST signs up with is the instance's one-time owner code: it made
            // them the owner and is not an invite to any server, so there is nothing to join
            // and nothing to report.
            if definitive, afterSignup {
                await app.refreshServerCreatePermission()
                if app.isInstanceOwner { joinStatus = nil; return nil }
            }
            let message = definitive ? "That invite isn't valid any more. Ask your host for a fresh one."
                                     : "Couldn't reach the host to join. Skwod will try again."
            joinStatus = .failed(message)
            return message
        }
        record.serverId = result.serverId
        tombstones.rejoined(result.serverId)   // joined (again) on purpose
        record.hostUserId = result.hostUserId
        record.hostDeviceId = result.hostDeviceId
        record.awaitingApproval = result.pending
        PendingJoinStore.set(record, address: address)
        joinStatus = result.pending ? .waitingForApproval : .settingUp(problem: nil)
        watch(record)
        return nil
    }

    /// Pick an unfinished join back up (launch, reconnect): either the join itself never
    /// happened (the app was closed between sign-up and joining), or it did and the keys have
    /// not arrived yet.
    func resumePendingJoin() async {
        guard let app, app.client != nil, let address = app.current?.server,
              let record = PendingJoinStore.get(address: address) else { return }
        guard let serverId = record.serverId else {
            guard !joinInFlight else { return }
            joinInFlight = true
            defer { joinInFlight = false }
            _ = await joinByCode(record.code, afterSignup: true)
            return
        }
        if spaces.contains(where: { $0.serverId == serverId }) {
            PendingJoinStore.clear(address: address)   // finished while we were not looking
            if joinStatus != nil { joinStatus = nil }
            return
        }
        if discoveries[serverId] == nil {
            joinStatus = record.awaitingApproval ? .waitingForApproval : .settingUp(problem: nil)
            watch(record)
        } else {
            discoverKick += 1
        }
    }

    /// The host decided on our join request (`join_approved` / `join_denied`).
    func joinDecided(serverId: String, approved: Bool) async {
        guard let app, let address = app.current?.server else { return }
        var record = PendingJoinStore.get(address: address)
        if approved {
            // A late decision about a server this device has since left or seen deleted.
            if tombstones.hides(serverId) && record?.serverId != serverId { return }
            if record?.serverId == serverId {
                record?.awaitingApproval = false
                if let record { PendingJoinStore.set(record, address: address) }
            }
            joinStatus = .settingUp(problem: nil)
            if discoveries[serverId] == nil {
                watch(record?.serverId == serverId ? record! : PendingJoin(code: "", serverId: serverId, awaitingApproval: false))
            }
            discoverKick += 1
            if !app.appActive {
                app.realtime.notify(title: "You're in", body: "The host let you in. Open Skwod to see the channels.",
                                    privacy: .fixed, thread: "join:\(serverId)", id: "joined-\(serverId)")
            }
        } else {
            if record?.serverId == serverId { PendingJoinStore.clear(address: address) }
            discoveries[serverId]?.cancel()
            discoveries[serverId] = nil
            joinStatus = .denied
            app.realtime.notify(title: "Request declined", body: "The host declined your request to join.",
                                privacy: .fixed, thread: "join:\(serverId)", id: "joined-\(serverId)")
        }
    }

    /// The user gave up waiting (or dismissed a finished notice).
    func dismissJoinStatus(forget: Bool) {
        if forget, let address = app?.current?.server {
            if let serverId = PendingJoinStore.get(address: address)?.serverId {
                discoveries[serverId]?.cancel()
                discoveries[serverId] = nil
            }
            PendingJoinStore.clear(address: address)
        }
        joinStatus = nil
    }

    /// The mailbox was just synced: keys may have arrived — let the watchers look now.
    func mailboxSynced() { if !discoveries.isEmpty { discoverKick += 1 } }

    private func watch(_ record: PendingJoin) {
        guard let serverId = record.serverId else { return }
        discoveries[serverId]?.cancel()
        discoveries[serverId] = Task { [weak self] in
            await self?.discover(serverId: serverId, hostUserId: record.hostUserId, hostDeviceId: record.hostDeviceId,
                                 quiet: false, joining: true)
            self?.discoveries[serverId] = nil
        }
    }

    /// Wait until we are a member AND have been provisioned, then add each channel to the
    /// sidebar. Each pass syncs the mailbox (which installs the space key + channel sender keys
    /// when they have arrived), then lists channels; decrypted names mean provisioning is done.
    ///
    /// It looks when told to (`discoverKick`: the `join_approved` event, a `sealed` mailbox
    /// sync, a reconnect) and otherwise every 25 s. A user-started join (`joining`) is watched
    /// for as long as it is pending — it is also resumed on the next launch; background
    /// recovery gives up after a while. While a member without keys, the request for them is
    /// repeated with backoff and a failure is SHOWN, not swallowed.
    /// `quiet` = append channels without changing the user's current selection (background recovery
    /// of many servers at login must not yank the user into a freshly-discovered channel); an
    /// explicit user-initiated join passes quiet=false so it opens the joined channel.
    private func discover(serverId: String, hostUserId: String?, hostDeviceId: String?, quiet: Bool = false, joining: Bool = false) async {
        // A discovery belongs to the skwod it was started in. It outlives rebinds of that
        // skwod (it waits for the client to come back), but after a switch to another skwod it
        // stops: what the first server lists is never added to the second's sidebar.
        guard let app, let origin = app.current?.id else { return }
        func stillThere() -> Bool { app.current?.id == origin && (app.bound == nil || app.bound?.workspaceId == origin) }
        discoverCount += 1; provisioning = true
        defer { discoverCount -= 1; if discoverCount == 0 { provisioning = false } }
        var pass = 0
        var askDelay = 0.0          // seconds until the next provision request (0 = ask now)
        var nextAsk = Date.distantPast
        while !Task.isCancelled {
            guard stillThere() else { return }
            guard let client = try? BoundClient.of(app.bound, for: origin) else {
                try? await Task.sleep(for: .seconds(2)); continue
            }
            await app.syncMailbox()
            var member = false
            if let channels = try? await client.listChannels(serverId: serverId) {
                guard stillThere(), app.bound?.workspaceId == origin else { return }
                member = true
                let named = channels.filter { $0.name != nil && $0.kind != "voice" }
                if !named.isEmpty {
                    let spaceName = (try? await client.serverName(serverId: serverId)).flatMap { $0 } ?? "Server"
                    guard stillThere(), app.bound?.workspaceId == origin else { return }
                    // Left or deleted meanwhile (the watch was cancelled): it stays out.
                    if Task.isCancelled || tombstones.hides(serverId) { return }
                    for ch in named {
                        let space = RealSpace(name: spaceName, channelName: ch.name ?? "channel", serverId: serverId,
                                              channelId: ch.channelId, inviteCode: "", spaceKeyHex: "")
                        if quiet { addSpaceQuietly(space) } else { addSpace(space) }
                    }
                    if joining {
                        if let address = app.current?.server { PendingJoinStore.clear(address: address) }
                        joinStatus = nil
                    }
                    return
                }
            }
            // A member whose keys have not come: ask whoever can hand them over — and keep
            // asking, a little less often each time. (While the request still needs approval
            // there is nobody to ask: the approver provisions us when they let us in.)
            if member, joining, Date() >= nextAsk {
                if case .waitingForApproval = joinStatus { joinStatus = .settingUp(problem: nil) }
                var asked = false
                var failure: Error?
                if let hu = hostUserId, let hd = hostDeviceId {
                    do { try await client.requestProvision(serverId: serverId, hostUserId: hu, hostDeviceId: hd); asked = true }
                    catch { failure = error }
                }
                if !asked, let members = try? await client.listMembers(serverId: serverId) {
                    for m in members where m.userId != app.session?.userId {
                        guard let found = try? await client.findUser(username: m.username), found.userId == m.userId else { continue }
                        do {
                            try await client.requestProvision(serverId: serverId, hostUserId: found.userId, hostDeviceId: found.deviceId)
                            asked = true
                            break
                        } catch { failure = error }
                    }
                }
                guard stillThere() else { return }
                askDelay = askDelay == 0 ? 10 : min(askDelay * 2, 300)
                nextAsk = Date().addingTimeInterval(askDelay)
                if asked {
                    if pass >= 2 { joinStatus = .settingUp(problem: "Still waiting for the server's keys. They come from a member who is online — the host's app may be closed.") }
                } else {
                    joinStatus = .settingUp(problem: "Couldn't ask for the server's keys yet (\(coreErrorText(failure ?? CoreError.Invalid(detail: "nobody to ask"), fallback: "the host can't be reached")). Trying again in \(Int(askDelay)) s.")
                }
            }
            pass += 1
            if !joining, pass >= 40 { return }
            // Wait for a nudge, or 25 s (background recovery: 3 s, as before).
            let kick = discoverKick
            let slices = joining ? 50 : 6
            for _ in 0..<slices where kick == discoverKick && !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
    }

    /// Append a channel without touching selection/homeMode — for background discovery.
    private func addSpaceQuietly(_ s: RealSpace) {
        guard !spaces.contains(where: { $0.channelId == s.channelId }), !tombstones.hides(s.serverId) else { return }
        let wasEmpty = spaces.isEmpty
        spaces.append(s)
        // First channels to arrive after an empty load (re-login recovery) — open one so the skwod
        // lands on a conversation instead of the blank overview.
        if wasEmpty, selection == nil, !homeMode {
            Task { await restoreLastChannel() }
        }
        Task { await persist(spaces, key: "sidebar.spaces") }
        touchKeyBackup()
    }

    /// Enter the DMs/Friends home (the skwod rail icon): the list shows your Direct Messages.
    func showHome() { homeMode = true; selection = nil }

    // MARK: navigation history (back/forward titlebar arrows)

    @Published private(set) var canGoBack = false
    @Published private(set) var canGoForward = false
    private var backStack: [SidebarItem?] = []
    private var forwardStack: [SidebarItem?] = []
    private var navigating = false

    /// Record a selection change into the history — called from the shell's onChange, so every way a
    /// selection can change (sidebar click, rail switch, join flow) is captured in one place.
    func recordNavigation(from old: SidebarItem?) {
        if navigating { navigating = false; return }
        backStack.append(old)
        forwardStack.removeAll()
        updateNavFlags()
    }

    func goBack() {
        guard let prev = backStack.popLast() else { return }
        navigating = true
        forwardStack.append(selection)
        selection = prev
        updateNavFlags()
    }

    func goForward() {
        guard let next = forwardStack.popLast() else { return }
        navigating = true
        backStack.append(selection)
        selection = next
        updateNavFlags()
    }

    private func updateNavFlags() {
        canGoBack = !backStack.isEmpty
        canGoForward = !forwardStack.isEmpty
    }

    /// The user opened a conversation with this person.
    ///
    /// One that already exists is only SELECTED — tapping a conversation never raises anyone's
    /// trust. A NEW one is the user picking that person, which makes them a KNOWN contact —
    /// unless the name is flagged (a look-alike, unusual characters, a directory lookup that
    /// does not lead to this account or could not be made): then it starts UNVERIFIED and only
    /// the explicit "I know them — accept" raises it (`ContactTrust.afterOpening`).
    ///
    /// `ticket` is what was current when the SERVER was asked whose conversation this is
    /// (`openDM`): the entry is made in that workspace's store or not at all, and the contact
    /// is noted in that workspace's book or not at all.
    @discardableResult
    func addDM(_ d: DMConversation, in ticket: StoreTicket? = nil) -> OpenedDM {
        guard let ticket = ticket ?? self.ticket(), holds(ticket) else { return .switched }
        // Refused when the server answered "open a DM" with the id of a group this device
        // holds: nothing is added, the group is not touched (`ConversationStore.addDM`).
        switch ticket.store.addDM(d) {
        case .refused:
            return .refused
        case .refusedIgnored:
            return .ignoredGroup
        case .existing(let held):
            selection = .dm(held)
            return .opened
        case .added(let entry):
            if let contacts = app?.contacts {
                let (userId, name) = (entry.peerUserId, entry.name)
                Task {
                    // The directory cross-check first: without it the name counts as unconfirmed.
                    await contacts.check(userId, name: name)
                    // Still the workspace the conversation was opened in? (The lookup is a
                    // server call: it can be held until the user is somewhere else.)
                    guard self.holds(ticket) else { return }
                    contacts.opened(userId, name: name, isNewConversation: true)
                }
            }
            selection = .dm(entry)
            return .opened
        }
    }

    /// How "open a chat with …" ended, for whoever asked to show.
    enum OpenedDM: Equatable {
        case opened
        /// The user is in another workspace by now (or none is ready): nothing was done there.
        case switched
        /// The server's answer conflicts with what this device holds; nothing changed.
        case refused
        /// The id is that of a group the user said to ignore.
        case ignoredGroup
        case notFound
        case failed

        /// A sentence to show (nil when there is nothing to say).
        var problem: String? {
            switch self {
            case .opened, .switched: return nil
            case .refused: return "This conversation's server data conflicts with what Skwod holds, so the chat was not opened. See Security activity."
            case .ignoredGroup: return "The server answered with a conversation id that is used by a group you ignored, so the chat was not opened. To use it, stop ignoring that group (Ignored groups, in your conversation list)."
            case .notFound: return "No user with that name (or no device yet)."
            case .failed: return "Couldn't start the chat."
            }
        }
    }

    /// The user asked for a chat with `username` (and, when they picked a person rather than
    /// typing a name, with exactly the account `expecting`).
    ///
    /// Two server calls are made before anything is stored — "who is this name" and "open the
    /// conversation" — and a server can hold either answer until the user has switched to
    /// another workspace. So what is current is captured FIRST (`StoreTicket`), both calls go
    /// through that workspace's own client, and the answer is used only if the same workspace,
    /// client and store are still current: otherwise it is dropped — no entry, no contact.
    func openDM(username: String, expecting userId: String? = nil) async -> OpenedDM {
        guard let app, let ticket = ticket(), let client = try? BoundClient.of(app.bound, for: ticket.workspaceId) else { return .failed }
        let conversation: DMConversation
        do {
            let found = try await client.findUser(username: username)
            if let userId, found.userId != userId { return .notFound }
            let conversationId = try await client.openDm(peerUserId: found.userId)
            conversation = DMConversation(name: username, peerUserId: found.userId, peerDeviceId: found.deviceId, conversationId: conversationId)
        } catch {
            let d = String(describing: error).lowercased()
            return d.contains("not found") || d.contains("404") ? .notFound : .failed
        }
        guard holds(ticket) else { return .switched }
        return addDM(conversation, in: ticket)
    }

    /// Groups the user said to ignore (ids are all this device keeps of them).
    var ignoredGroups: [String] { store.declined.sorted() }
    /// A saved list was lost as a whole and the user has not said they have seen it.
    var reviewPending: Bool { store.reviewPending }

    /// Is there something `ConversationNotices` shows? (A list with nothing else in it is then
    /// still not "empty".)
    var hasConversationNotices: Bool {
        conversationsUnreadable || reviewPending || conversationProblem != nil || !ignoredGroups.isEmpty
    }

    /// Something about the conversations to tell the user where the lists are (a refused
    /// "open chat" from a place that has no room for an error of its own).
    @Published var conversationProblem: String?

    /// "Stop ignoring" a group: its id is free again; if the server still lists the group it
    /// comes back as an invitation.
    func unignore(_ conversationId: String) async {
        guard store.unignore(conversationId) else { return }
        await refreshGroups()
    }

    /// The user has seen that a saved list was lost (`ConversationStore.clearReview`).
    func clearReview() async {
        store.clearReview()
        await refreshDMList()
    }

    /// The conversations of this workspace could not be read although its cache is open, more
    /// than once: say so (with "try again") rather than show an empty list.
    var conversationsUnreadable: Bool {
        !store.ready && store.loadFailures >= 2 && !store.workspaceId.isEmpty
            && app?.bound?.workspaceId == store.workspaceId && app?.bound?.cacheOpen == true
    }

    /// "Try again" for `conversationsUnreadable`.
    func retryConversations() async {
        guard await store.load() else { return }
        await refreshDMList()
        await refreshGroups()
    }

    #if DEBUG
    /// Screenshot/demo aid only.
    func setDemo(dms: [DMConversation]) { store.setDemo(dms: dms) }
    #endif

    // MARK: persistence (JSON in the encrypted cache)

    /// Write the joined spaces — only once they were READ from this workspace's cache
    /// (`spacesRead`): a list that was never read is not the list, and writing it would
    /// replace the stored one (each entry carries the invite the space was joined with).
    private func persist<T: Encodable>(_ value: T, key: String) async {
        guard let app, spacesRead, let bound = app.bound, bound.workspaceId == loadedFor, bound.cacheOpen,
              let data = try? JSONEncoder().encode(value),
              let json = String(data: data, encoding: .utf8) else { return }
        try? await bound.client.kvWrite(key: "\(bound.workspaceId)|\(key)", value: json)
    }

    /// Read the joined spaces STRICTLY (`kv_read`). A read that fails leaves them unread (and
    /// unwritten); a stored value that cannot be decoded is first kept under a key of its own,
    /// then the list continues with what can be salvaged, and it is said.
    private func readSpaces(through bound: BoundClient<SkwodClient>) async {
        let key = "\(bound.workspaceId)|sidebar.spaces"
        let json: String?
        do { json = try await bound.client.kvRead(key: key) } catch { return }
        guard let app, app.bound?.turn == bound.turn, loadedFor == bound.workspaceId, !spacesRead else { return }
        // (Spaces joined while the list could not be read are kept.)
        let joinedMeanwhile = spaces
        var stored: [RealSpace] = []
        var keptAs: String?
        if let json, !json.isEmpty {
            if let decoded = try? JSONDecoder().decode([RealSpace].self, from: Data(json.utf8)) {
                stored = decoded
            } else {
                let side = "\(key).unreadable.\(Int64(Date().timeIntervalSince1970 * 1000))"
                do {
                    try await bound.client.kvWrite(key: side, value: json)
                    guard try await bound.client.kvRead(key: side) == json else { return }
                } catch { return }
                guard app.bound?.turn == bound.turn, loadedFor == bound.workspaceId, !spacesRead else { return }
                if let top = try? JSONSerialization.jsonObject(with: Data(json.utf8)), let elements = top as? [Any] {
                    stored = elements.compactMap { element in
                        guard JSONSerialization.isValidJSONObject(element), let data = try? JSONSerialization.data(withJSONObject: element) else { return nil }
                        return try? JSONDecoder().decode(RealSpace.self, from: data)
                    }
                }
                keptAs = side
            }
        }
        // (A server dropped since — left, deleted — is not read back from a list saved before.)
        stored.removeAll { tombstones.hides($0.serverId) }
        spaces = joinedMeanwhile.filter { j in !stored.contains(where: { $0.channelId == j.channelId }) } + stored
        spacesRead = true
        if keptAs != nil || !joinedMeanwhile.isEmpty { await persist(spaces, key: "sidebar.spaces") }
        if let keptAs {
            await app.logSecurity(kind: "spaces_unreadable", title: "Your list of servers could not be read",
                                  message: "The list of servers and channels Skwod keeps on this device could not be fully read. Skwod kept what it could read; the rest comes back when the servers are synced. Nothing was deleted: the data as it was is kept on this device (as “\(keptAs)”).",
                                  atMs: Int64(Date().timeIntervalSince1970 * 1000))
        }
    }
}

/// One server inside the skwod, with its channels — a sidebar category.
struct ServerGroup: Identifiable {
    let serverId: String
    let name: String
    var channels: [RealSpace]
    var id: String { serverId }
}

/// A selectable sidebar destination.
enum SidebarItem: Hashable {
    /// The cross-conversation home behind the skwod rail icon (Direct Messages / Friends).
    case home
    /// The E2EE Feed (posts + stories) — a rail destination on macOS, a tab on iOS.
    case feed
    case space(RealSpace)
    case dm(DMConversation)
    /// A group direct conversation (3–10 people).
    case group(GroupDM)
}

/// A join that has been started and is not finished: the invite code, and — once the server
/// answered — which server it is for and who can hand over its keys.
struct PendingJoin: Codable, Equatable {
    var code: String
    var serverId: String? = nil
    var hostUserId: String? = nil
    var hostDeviceId: String? = nil
    /// The host has to let us in (a bare code); false once approved, or for auto-join invites.
    var awaitingApproval = true
}

/// Unfinished joins, by skwod address, kept across launches: signing up only creates the
/// account, and the join itself (membership, then keys) can take until the host is online.
/// Without this, quitting the app between the two left an account that was in no server and
/// had forgotten the invite. Stored in the Keychain — an invite code is a credential.
enum PendingJoinStore {
    private static let account = "pending-joins"

    private static func load() -> [String: PendingJoin] {
        guard let json = Keychain.get(account), let data = json.data(using: .utf8),
              let all = try? JSONDecoder().decode([String: PendingJoin].self, from: data) else { return [:] }
        return all
    }

    private static func save(_ all: [String: PendingJoin]) {
        if all.isEmpty { Keychain.delete(account); return }
        if let data = try? JSONEncoder().encode(all), let json = String(data: data, encoding: .utf8) {
            Keychain.set(json, for: account)
        }
    }

    static func get(address: String) -> PendingJoin? { load()[address] }

    static func set(_ join: PendingJoin, address: String) {
        var all = load()
        guard all[address] != join else { return }
        all[address] = join
        save(all)
    }

    static func clear(address: String) {
        var all = load()
        if all.removeValue(forKey: address) != nil { save(all) }
    }

    static func clearAll() { Keychain.delete(account) }
}

/// The stores' view of the core: the cache, and what the server lists.
@MainActor
final class CoreConversationBackend: ConversationBackend {
    private weak var app: AppState?
    private let workspaceId: String
    init(app: AppState, workspaceId: String) { self.app = app; self.workspaceId = workspaceId }

    /// Only ever the client that has THIS store's workspace open — decided from the
    /// client-and-its-workspace pair, not from whichever client and whichever "current"
    /// workspace happen to be set (they change at different moments during a switch).
    private func client() throws -> SkwodClient { try BoundClient.of(app?.bound, for: workspaceId) }
    /// …and, for the stores themselves, only while it has the cache OPEN: a client that is up
    /// without one answers every read with "nothing", which is not what is stored.
    private func cache() throws -> SkwodClient { try BoundClient.withCache(app?.bound, for: workspaceId) }

    // The core's STRICT read and write: "no cache attached" and "the read failed" are thrown
    // (`CoreError.NoCache` / `.Cache`), never answered as "nothing stored"; a write that did
    // not happen is thrown too, so the store keeps it pending.
    func kvGet(key: String) async throws -> String? { try await cache().kvRead(key: key) }
    func kvSet(key: String, value: String) async throws { try await cache().kvWrite(key: key, value: value) }
    func listDms() async throws -> [ListedDM] {
        try await client().listDms().map { ListedDM(conversationId: $0.conversationId, peerUserId: $0.peerUserId, peerUsername: $0.peerUsername) }
    }
    func listGroupDms() async throws -> [(conversationId: String, memberUserIds: [String])] {
        try await client().listGroupDms().map { ($0.conversationId, $0.memberUserIds) }
    }
    func findUserId(username: String) async throws -> String { try await client().findUser(username: username).userId }
    func openGroupDm(memberUserIds: [String]) async throws -> String { try await client().openGroupDm(memberUserIds: memberUserIds) }
}
