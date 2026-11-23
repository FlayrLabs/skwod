import Foundation

/// What the live connection reports, turned into refreshes and notifications — instead of every
/// screen polling the server every second or two.
///
/// The relay tells the app THAT something happened, never what: an event carries ciphertext and
/// routing ids only, and the server does not know (and is not told) whether a channel message is
/// chat, a like, a comment, an avatar or a game move. So nothing is concluded from an event
/// except "look": the app fetches, the core decrypts, and only then does this code decide what
/// to show and whether to notify.
extension Notification.Name {
    /// Something changed in a channel (new message, edit, delete, reaction, cleared). `object`
    /// is the channel id. Screens showing that channel — chat, the feed, a game — refresh.
    static let skwodChannelChanged = Notification.Name("skwod.live.channelChanged")
    /// A direct message was filed into the local cache. `object` is the conversation id.
    static let skwodDMChanged = Notification.Name("skwod.live.dmChanged")
    /// The live socket came (back) up: events may have been missed, so every open screen
    /// catches up once.
    static let skwodLiveConnected = Notification.Name("skwod.live.connected")
    /// A server's membership or channel list changed. `object` is the server id.
    static let skwodServerChanged = Notification.Name("skwod.live.serverChanged")
}

/// Screens refresh on live events; this is how often they also look on their own, in case an
/// event was lost. Deliberately slow.
enum LiveSync {
    static let safetyInterval: Duration = .seconds(45)

    /// What a notification says about a decrypted body, honouring the "show previews" setting.
    static func preview(_ body: String) -> String {
        guard NotificationState.showPreviews else { return "New message" }
        if body.hasPrefix("\u{2}skwod/attach|") { return "Sent an attachment" }
        if body.hasPrefix("\u{2}skwod/music|") { return "Shared a song" }
        if body.hasPrefix("\u{2}skwod/feed|") { return "Posted to the feed" }
        if body.hasPrefix("\u{2}skwod/story|") { return "Added to their story" }
        if body.hasPrefix("\u{2}skwod/") { return "New activity" }
        let oneLine = body.replacingOccurrences(of: "\n", with: " ")
        return oneLine.count > 180 ? String(oneLine.prefix(180)) + "…" : oneLine
    }
}

@MainActor
extension AppState {
    // MARK: Events

    /// One event from the live connection (everything except presence).
    func realtimeEvent(topic: String, event: String, payload: [String: Any]) {
        guard let me = current?.userId, !me.isEmpty else { return }
        #if DEBUG
        E2E.sawEvent(event)
        #endif
        if topic.hasPrefix("channel:") {
            let channelId = String(topic.dropFirst("channel:".count))
            switch ChannelEventRule.action(for: event) {
            case .refreshAndConsiderNotifying:
                NotificationCenter.default.post(name: .skwodChannelChanged, object: channelId)
                // Our own message, or the chat on screen (which is refreshing right now): no
                // notification to consider. Otherwise fetch it and see what it is.
                // Nor anything from someone this account blocked (the core would not show it).
                let author = payload["author_id"] as? String
                if author != me, !BlockList.shared.contains(author), !realtime.isOnScreen(topic), let messageId = payload["message_id"] as? String {
                    considerNotifying(channelId: channelId, messageId: messageId)
                }
            case .refresh:
                // Edits, deletes, reactions — and `channel_cleared`. The event is the server's
                // word and nothing in it is signed by a member with the right to clear, so it
                // is never an order to delete this device's decrypted history: the app does NOT
                // pass it to the core's purge (`channelCleared`). The open view looks again;
                // whether a clear is honoured is the core's decision on a clear it can verify.
                NotificationCenter.default.post(name: .skwodChannelChanged, object: channelId)
            case .ignore:
                break
            }
        } else if topic == "user:\(me)" {
            let serverId = payload["server_id"] as? String ?? ""
            switch event {
            case "sealed":
                // Something is in our sealed mailbox: a DM, a key hand-off, a provision request.
                Task { await syncMailbox() }
            case "device_added":
                // A device joined this account: pick up its announcement and show the notice.
                Task { await syncMailbox(); await accountChanged() }
            case "link_request":
                linkRequested()
                Task { await accountChanged() }
            case "device_removed":
                // One of OUR devices left the account (perhaps this one), or — the same event on
                // our own topic — a contact removed one of theirs.
                let who = payload["user_id"] as? String ?? me
                if who == me {
                    let removed = payload["device_id"] as? String
                    Task { await ownDeviceRemoved(deviceId: removed) }
                } else {
                    Task { await contactDeviceRemoved(userId: who) }
                }
            case "device_rekeyed" where (payload["user_id"] as? String).map { !$0.isEmpty && $0 != me } ?? false:
                // A contact's device was restored onto another install (its generation rose):
                // re-read their devices, so what that device held of ours is rotated on the
                // next maintenance / send (the core's side of server M-3).
                let who = payload["user_id"] as? String ?? ""
                Task { await contactDeviceRemoved(userId: who) }
            case "backup_fetched":
                // The server says the account's key backup was downloaded by a session that is
                // not one of its devices. Nothing in it can be checked; it is shown and kept.
                let at = (payload["at"] as? NSNumber)?.int64Value ?? Int64(Date().timeIntervalSince1970 * 1000)
                Task { await backupFetched(atMs: at) }
            case "device_recovery_multiple":
                // More than one install is waiting to restore the same device (server L1).
                let at = (payload["at"] as? NSNumber)?.int64Value ?? Int64(Date().timeIntervalSince1970 * 1000)
                Task { await recoveryMultiple(atMs: at); await accountChanged() }
            case "device_recovery_requested", "device_rekeyed", "account_restored", "recovery_key_changed",
                 "backup_updated", "sessions_revoked":
                // Nudges only: re-read the account's devices and show what the core concluded
                // (a restore to approve, a new install, a changed recovery key…).
                Task { await accountChanged(); if event == "sessions_revoked" { await checkSession() } }
            case "join_request", "invite_full":
                // (`invite_full`: an invite has as many people waiting as it may — the same
                // screen shows it, on the invite, with what to do.)
                joinRequested(serverId: serverId)
            case "join_approved":
                Task { await chatModel?.joinDecided(serverId: serverId, approved: true) }
            case "join_denied":
                Task { await chatModel?.joinDecided(serverId: serverId, approved: false) }
            case "ring":
                guard !serverId.isEmpty else { return }
                // A muted conversation does not silence calls; a muted skwod does.
                guard MuteCenter.shared.callsRing(workspaceId: current?.id ?? "") else { return }
                CallCoordinator.shared.ringReceived(
                    serverId: serverId, channelId: payload["channel_id"] as? String ?? "",
                    from: payload["from"] as? String ?? "", ringId: payload["ring_id"] as? String ?? "",
                    expiresAt: (payload["expires_at"] as? NSNumber)?.int64Value ?? 0)
            case "ring_cancel":
                CallCoordinator.shared.ringCancelled(channelId: payload["channel_id"] as? String ?? "",
                                                     ringId: payload["ring_id"] as? String)
            default:
                break
            }
        } else if topic.hasPrefix("server:") {
            let serverId = String(topic.dropFirst("server:".count))
            switch event {
            case "device_removed", "device_rekeyed":
                // A member removed one of their devices, or one was restored onto another
                // install: re-read theirs, so that device coming back later is told apart from
                // one that erased itself, and what a re-keyed device held of ours is rotated.
                let who = payload["user_id"] as? String ?? ""
                if who == me { Task { await accountChanged() } } else if !who.isEmpty { Task { await contactDeviceRemoved(userId: who) } }
            case "member_joined", "member_approved", "member_removed", "channels_changed":
                NotificationCenter.default.post(name: .skwodServerChanged, object: serverId)
                Task {
                    await waiting.refresh(serverId: serverId)
                    await chatModel?.syncServerChannels()
                }
            default:
                break
            }
        } else if topic.hasPrefix("dm:"), event == "message" {
            Task { await syncMailbox() }
        }
    }

    /// The socket came up — at launch and after every reconnect. Whatever happened while there
    /// was none produced no event here, so catch up once and let open screens do the same.
    func realtimeConnected() {
        NotificationCenter.default.post(name: .skwodLiveConnected, object: nil)
        Task {
            // Blocks first (a block made on another device hides its subject here before
            // anything is drawn), then whatever was queued while there was no connection.
            await BlockList.shared.refresh(self)
            await syncMailbox()
            await Outbox.flush(self)
            _ = await client?.resumeUploads()
            if let pending = await client?.pendingUploads(), !pending.isEmpty { UploadProgressStore.shared.watch(self) }
            await Outbox.flush(self)
            await chatModel?.refreshDMList()
            await chatModel?.refreshGroups()
            await accountChanged()
            await chatModel?.resumePendingJoin()
        }
    }

    // MARK: Mailbox (direct messages, keys)

    /// Sync the sealed mailbox now: file the DMs it brought, act on control traffic (key
    /// hand-offs, provision requests), surface security notices. Coalesced — a burst of `sealed`
    /// events makes one pass, then one more.
    func syncMailbox() async {
        guard client != nil else { return }
        if mailboxBusy { mailboxAgain = true; return }
        mailboxBusy = true
        defer { mailboxBusy = false }
        repeat {
            mailboxAgain = false
            guard let client, let me = session?.userId else { return }
            // What the server answers belongs to the workspace that is current NOW (`StoreTicket`).
            let ticket = chatModel?.ticket()
            do {
                handle(try await client.syncDms(), ticket)
            } catch {
                // Removed, superseded, a restore still waiting — or the network, or the server
                // no longer knows this session.
                if await routeIfDeviceError(error) { return }
                await checkSession()
                return
            }
            _ = try? await client.processControlInbox(myUserId: me)
            await drainDmEvents()
            await surfaceSecurityNotices()
            // Reports sealed to this account (the skwod's owner) arrive with the mailbox.
            await refreshReports()
            await chatModel?.mailboxSynced()
        } while mailboxAgain
    }

    /// DMs that some other core call drained from the mailbox on its way (a channel fetch, the
    /// control inbox…). No network. Call after those.
    func drainDmEvents() async {
        guard let client else { return }
        let ticket = chatModel?.ticket()
        handle(await client.takeDmEvents(), ticket)
    }

    /// File each new DM under its conversation in the sidebar, tell the open DM view, and notify
    /// — unless it is a copy of something this account sent from another device, or that
    /// conversation is on screen.
    ///
    /// `ticket` was taken BEFORE the client was asked. The whole batch is dropped unless the
    /// same workspace, client and store are still current — a server that held its answer
    /// while the user switched workspaces gets nothing filed or announced in the other one —
    /// and every event is decided in the captured store, re-checked after each suspension.
    private func handle(_ events: [DmEvent], _ ticket: StoreTicket?) {
        guard !events.isEmpty, let chatModel, let ticket, chatModel.holds(ticket) else { return }
        // Listings started after this point are new enough to decide about these events.
        let mark = ticket.store.listingMark()
        Task {
            for e in events {
                guard chatModel.holds(ticket) else { return }
                // Decided from what THIS device holds. A group's event updates the GROUP — it
                // never makes a 1:1 conversation with whoever sent it; an ignored group shows
                // nothing; and until both stores are read nothing is filed at all.
                let name: String?
                switch await chatModel.decide(conversationId: e.conversationId, senderId: e.peerUserId, fromSelf: e.fromSelf, isGroup: e.isGroup, since: mark, in: ticket) {
                case .drop:
                    // Nothing may be shown: the stores are not read, an ignored group, a
                    // conversation that could not be asked about, a direct conversation the
                    // store would not list for this sender — or someone who is not in the
                    // group as THIS device holds it (a ghost the server added, say): nothing
                    // is redrawn, nothing notifies, and the thread never shows their rows.
                    continue
                case .group(let held):
                    name = chatModel.title(of: held)
                case .invitation:
                    // A group this device has not accepted: say that there is an invitation,
                    // once, and nothing of what was written in it.
                    NotificationCenter.default.post(name: .skwodDMChanged, object: e.conversationId)
                    if e.kind == "message", !e.fromSelf, notified.insert("invite-\(e.conversationId)").inserted, !BlockList.shared.contains(e.peerUserId) {
                        realtime.notify(title: "Group invitation", body: "You were added to a group. Open Skwod to see who is in it.",
                                        privacy: .fixed, thread: "dm:\(e.conversationId)", id: "invite-\(e.conversationId)")
                    }
                    continue
                case .direct(let claimed, let isNew):
                    name = await chatModel.spokenName(of: e.peerUserId, claimedName: claimed, isNew: isNew)
                    guard chatModel.holds(ticket) else { return }
                }
                NotificationCenter.default.post(name: .skwodDMChanged, object: e.conversationId)
                #if DEBUG
                E2E.sawDm(e, name: name)
                #endif
                // An edit, a delete or a reaction redraws the conversation; only a new message notifies.
                guard e.kind == "message" else { continue }
                // Nothing from someone this account blocked ever notifies. (The core drops what
                // a blocked account sends; this is the same rule where the banner is made, for
                // a group conversation the blocked person is also in and for a block that has
                // not reached the core's list yet.)
                guard !BlockList.shared.contains(e.peerUserId) else { continue }
                guard !e.fromSelf, messageNotifies(text: e.text), notified.insert(e.messageId).inserted else { continue }
                // One notification per message across both processes: not again if the
                // notification extension already announced it (a push wake that raced this),
                // and the extension will not announce what is shown or notified here.
                let ledger = bound?.workspaceId ?? ""
                guard NotificationState.markAnnounced([e.messageId], workspaceId: ledger).count == 1 else { continue }
                let topic = "dm:\(e.conversationId)"
                let alert = incomingAlert(topic: topic)
                if alert.inAppSound { SoundPlayer.play(.received) }
                guard alert.banner else { continue }
                realtime.notify(title: name ?? "Direct message", body: LiveSync.preview(e.text), privacy: .personal, thread: topic,
                                sound: alert.bannerSound, target: NotificationTarget(workspaceId: ledger, scope: topic))
            }
        }
    }

    /// What a message that passed every content rule (someone else's, not blocked, real chat,
    /// claimed in the announced ledger) does here: `MessageAlert` — nothing for the chat on
    /// screen or under Do Not Disturb, the app's own sound with a silent banner in front,
    /// a banner with sound otherwise.
    func incomingAlert(topic: String) -> MessageAlert.Outcome {
        let muted = MuteCenter.shared.isMuted(workspaceId: bound?.workspaceId ?? current?.id ?? "", scope: topic)
        let outcome = MessageAlert.received(.init(
            muted: muted,
            doNotDisturb: myStatus == "dnd",
            appActive: realtime.appActive,
            onScreen: realtime.isOnScreen(topic),
            soundOn: SoundSettings.received,
            lastSoundAt: SoundPlayer.lastReceivedAt,
            now: Date().timeIntervalSince1970))
        #if DEBUG
        E2E.sawAlert(topic: topic, muted: muted, outcome: outcome)
        #endif
        return outcome
    }

    // MARK: Channel notifications

    /// A `message` event named a message from someone else in a channel that is not on screen.
    /// Fetch what arrived, decrypt it, and notify only if it is real chat: likes, comments,
    /// avatars, game moves, address and system traffic never notify, and neither does a message
    /// this device cannot read. A burst of events is one fetch and one notification.
    func considerNotifying(channelId: String, messageId: String) {
        notifyQueue[channelId, default: []].insert(messageId)
        guard notifyRunning.insert(channelId).inserted else { return }
        Task {
            defer { notifyRunning.remove(channelId) }
            // A beat, so a burst lands in one pass.
            try? await Task.sleep(for: .milliseconds(300))
            while let ids = notifyQueue.removeValue(forKey: channelId), !ids.isEmpty {
                let asked = bound
                guard let client, let me = session?.userId,
                      let rows = try? await client.fetchChannelMessages(channelId: channelId, myUserId: me) else { return }
                // Fetched for the workspace that was active when it was asked: not announced
                // (under another workspace's names) after a switch.
                guard let asked, bound?.workspaceId == asked.workspaceId, bound?.turn == asked.turn else { return }
                await drainDmEvents()
                let serverId = chatModel?.spaces.first(where: { $0.channelId == channelId })?.serverId
                avatars.ingest(rows, authority: await avatars.authority(serverId: serverId))
                let fresh = rows.filter { m in
                    ids.contains(m.messageId) && !m.isDeleted
                        && m.authorId != me && m.authorId != "__me__" && !m.isSystem && !m.isUndecryptable
                        && !BlockList.shared.contains(m.authorId)
                        && !(m.content ?? "").isEmpty && messageNotifies(text: m.content ?? "")
                        && !notified.contains(m.messageId)
                }
                #if DEBUG
                E2E.sawChannelFetch(channelId: channelId, announced: ids.count, notifying: fresh.count)
                #endif
                // (See the direct-message path: one notification per message across the app
                // and the notification extension.)
                for m in fresh { notified.insert(m.messageId) }
                let claimed = Set(NotificationState.markAnnounced(fresh.map(\.messageId), workspaceId: asked.workspaceId))
                let unannounced = fresh.filter { claimed.contains($0.messageId) }
                guard let newest = unannounced.last else { continue }
                let topic = "channel:\(channelId)"
                let alert = incomingAlert(topic: topic)
                if !alert.banner { continue }
                // A post in a server's feed is announced as that, and not at all while the feed
                // is what the user is looking at.
                let feedOf = chatModel?.feedChannels.first(where: { $0.value == channelId })?.key
                if feedOf != nil, appActive, chatModel?.selection == .feed { continue }
                if alert.inAppSound { SoundPlayer.play(.received) }
                let feedTitle = feedOf.flatMap { id in chatModel?.spaces.first(where: { $0.serverId == id })?.name }.map { "\($0) · Feed" }
                let title = realtime.chatNames[channelId].map { "#\($0)" } ?? feedTitle ?? "Skwod"
                let body = unannounced.count > 1 && NotificationState.showPreviews
                    ? "\(unannounced.count) new messages" : LiveSync.preview(newest.content ?? "")
                // One notification per channel: a later one replaces it rather than stacking.
                realtime.notify(title: title, body: body, privacy: .personal, thread: topic, id: "msg-\(channelId)",
                                sound: alert.bannerSound, target: NotificationTarget(workspaceId: asked.workspaceId, scope: topic))
            }
        }
    }

    // MARK: Account events

    /// Another device asked to be linked to this account.
    private func linkRequested() {
        linkRequests += 1
        enqueueNotice(SecurityAlert(
            title: "A device wants to join your account",
            message: "Someone signed in to your account on a new device and is asking to be linked. If that is you, open Profile → Encryption → Devices → Link a device and enter the code shown on the new device. If it isn't, change your password."))
        if !appActive {
            realtime.notify(title: "Link a device?", body: "A new device is asking to join your account.",
                            privacy: .fixed, thread: "account", id: "link-request")
        }
    }

    /// Someone asked to join a server this account can approve people for: refresh the "Waiting
    /// to join" list (which drives the badge on the members button) and tell the user — they
    /// are the only one who can let the newcomer in.
    private func joinRequested(serverId: String) {
        guard !serverId.isEmpty else { return }
        Task {
            await waiting.refresh(serverId: serverId)
            let people = waiting.waiting(in: serverId)
            let server = chatModel?.spaces.first(where: { $0.serverId == serverId })?.name ?? "your server"
            let body: String
            if people.count == 1, people[0].trust == .ok {
                // Named as this device may name them: "(unverified)" unless the user knows them.
                let who = contacts.display(people[0].userId, claimedName: people[0].username).spoken
                body = "\(who) is waiting to join \(server)."
            } else if people.count > 1 {
                body = "\(people.count) people are waiting to join \(server)."
            } else {
                // The name has not checked out (yet): never put an unverified name in a banner.
                body = "Someone is waiting to join \(server)."
            }
            #if DEBUG
            E2E.sawJoinRequest(serverId: serverId, waiting: people.count)
            #endif
            realtime.notify(title: "Waiting to join", body: body + " Open Members to let them in.",
                            privacy: .personal, thread: "join:\(serverId)", id: "join-\(serverId)")
        }
    }
}
