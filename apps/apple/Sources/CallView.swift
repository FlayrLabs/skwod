import SwiftUI
import LiveKit
import AVFoundation

/// A real end-to-end-encrypted LiveKit call (voice + video) for a server's voice channel.
///
/// Media is encrypted on-device, per frame, with per-call random keys the core generates and sends
/// over sealed libsignal sessions only — the SFU on the host forwards ciphertext. Audio AND video
/// tracks go through the same key provider (the room's one `BaseKeyProvider`), so turning the
/// camera on adds nothing the server can read. FAIL-CLOSED: no keys → we refuse to connect rather
/// than join media in the clear (ADR-007), and a remote track that is not encrypted is never
/// rendered.
///
/// For a p2p skwod `voiceToken` returns a loopback LiveKit URL: signaling and media both travel
/// through the p2p session to the host.
struct CallView: View {
    /// The server whose voice room to join; nil = the server currently in view.
    var serverId: String?

    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var call = CallSession()

    var body: some View {
        ZStack {
            SkwodBackground()
            content.padding(platformPadding)
            #if os(macOS)
                .frame(minWidth: 620, minHeight: 520)
            #endif
        }
        .task { await call.start(app: app, serverId: serverId ?? chat.currentServer?.serverId) }
        .onDisappear { call.end() }
    }

    private var platformPadding: CGFloat {
        #if os(macOS)
        return 24
        #else
        return 14
        #endif
    }

    @ViewBuilder private var content: some View {
        VStack(spacing: 14) {
            header
            switch call.phase {
            case .preparing, .connecting:
                Spacer()
                ProgressView().controlSize(.large)
                Text(call.phase == .preparing ? "Setting up encryption…" : "Connecting…")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.6))
                Spacer()
            case .failed:
                Spacer()
                Image(systemName: "lock.trianglebadge.exclamationmark").font(.system(size: 50)).foregroundStyle(.orange)
                Text(call.errorText).font(.subheadline).multilineTextAlignment(.center).foregroundStyle(.white.opacity(0.75))
                    .padding(.horizontal, 20)
                Button("Close") { dismiss() }.controlSize(.large).buttonStyle(.glass)
                Spacer()
            case .connected:
                grid
                if call.blockedUnencrypted {
                    Label("Someone in this call isn't encrypting. Their audio and video are blocked on this device.",
                          systemImage: "lock.slash.fill")
                        .font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
                }
                if let note = call.notice {
                    Text(note).font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
                }
                ringRow
                controls
            }
        }
    }

    private var header: some View {
        VStack(spacing: 5) {
            Text("Call · General").font(.title3.bold()).foregroundStyle(.white)
            Label("End-to-end encrypted", systemImage: "lock.fill").font(.caption).foregroundStyle(.green)
            if call.phase == .connected {
                Text("In the call · \(call.room.remoteParticipants.count + 1) connected")
                    .font(.caption).foregroundStyle(.white.opacity(0.6))
            }
        }
    }

    private var grid: some View {
        let remotes = call.room.remoteParticipants.values
            .sorted { ($0.identity?.stringValue ?? "") < ($1.identity?.stringValue ?? "") }
        let count = remotes.count + 1
        #if os(macOS)
        let columns = [GridItem(.adaptive(minimum: count <= 1 ? 420 : 240), spacing: 10)]
        #else
        let columns = Array(repeating: GridItem(.flexible(), spacing: 8), count: count <= 1 ? 1 : 2)
        #endif
        return ScrollView {
            LazyVGrid(columns: columns, spacing: 10) {
                ParticipantTile(participant: call.room.localParticipant, label: "You", isLocal: true,
                                revision: call.revision)
                ForEach(remotes, id: \.identity) { p in
                    let id = p.identity?.stringValue ?? ""
                    ParticipantTile(participant: p, label: app.contacts.authorLabel(id, claimedName: call.names[id] ?? p.name),
                                    isLocal: false, revision: call.revision)
                }
            }
            .padding(.top, 4)
        }
    }

    /// Nobody else here yet: ring the members who could pick up (matches Android).
    @ViewBuilder private var ringRow: some View {
        if call.room.remoteParticipants.isEmpty {
            Button { Task { await call.ringEveryone() } } label: {
                Label(call.ringLabel, systemImage: "bell.and.waves.left.and.right")
            }
            .buttonStyle(.glass).disabled(call.ringState != .idle)
            .accessibilityIdentifier("call.ring")
        }
    }

    private var controls: some View {
        HStack(spacing: 16) {
            CallButton(icon: call.micOn ? "mic.fill" : "mic.slash.fill", label: call.micOn ? "Mute" : "Unmute",
                       active: call.micOn, id: "call.mic") { Task { await call.toggleMic() } }
            CallButton(icon: call.camOn ? "video.fill" : "video.slash.fill",
                       label: call.camOn ? "Turn camera off" : "Turn camera on",
                       active: call.camOn, id: "call.camera") { Task { await call.toggleCamera() } }
                .disabled(call.camBusy)
            #if os(iOS)
            if call.camOn && call.canSwitchCamera {
                CallButton(icon: "arrow.triangle.2.circlepath.camera.fill", label: "Switch camera",
                           active: true, id: "call.switch") { Task { await call.switchCamera() } }
            }
            CallButton(icon: call.speakerOn ? "speaker.wave.2.fill" : "ear.fill",
                       label: call.speakerOn ? "Use the earpiece" : "Use the speaker",
                       active: call.speakerOn, id: "call.speaker") { call.toggleSpeaker() }
            #endif
            Button { call.end(); dismiss() } label: {
                Image(systemName: "phone.down.fill").font(.title3).foregroundStyle(.white)
                    .frame(width: 54, height: 54).background(Circle().fill(Color.red))
            }
            .buttonStyle(.plain).help("Leave").accessibilityLabel("Leave").accessibilityIdentifier("call.leave")
        }
        .padding(.bottom, 6)
    }
}

private struct CallButton: View {
    let icon: String, label: String
    let active: Bool
    let id: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: icon).font(.title3).foregroundStyle(.white)
                .frame(width: 54, height: 54)
                .background(Circle().fill(active ? Color.white.opacity(0.14) : Color.red.opacity(0.85)))
        }
        .buttonStyle(.plain).help(label).accessibilityLabel(label).accessibilityIdentifier(id)
    }
}

/// One participant: their decrypted camera video when they publish one, else an initial.
private struct ParticipantTile: View {
    @ObservedObject var participant: Participant
    let label: String
    let isLocal: Bool
    /// Bumped by the session on every track event, so the tile re-reads its track.
    let revision: Int

    /// The camera track to draw — only ever an ENCRYPTED one for a remote participant: frames the
    /// SFU could have read (or made up) are not shown as if they were part of this call.
    private var videoTrack: VideoTrack? {
        guard let pub = participant.videoTracks.first(where: { $0.source == .camera }), !pub.isMuted,
              isLocal || pub.encryptionType != .none else { return nil }
        return pub.track as? VideoTrack
    }

    private var micMuted: Bool {
        guard let pub = participant.audioTracks.first else { return true }
        return pub.isMuted
    }

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 16, style: .continuous).fill(.white.opacity(0.06))
            if let track = videoTrack {
                SwiftUIVideoView(track, layoutMode: .fill, mirrorMode: isLocal ? .auto : .off)
                    .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .accessibilityLabel("\(label), video")
            } else {
                ZStack {
                    Circle().fill(.white.opacity(0.1)).frame(width: 76, height: 76)
                    Text(String(label.prefix(1)).uppercased())
                        .font(.system(size: 30, weight: .semibold)).foregroundStyle(.white.opacity(0.85))
                }
            }
            VStack {
                Spacer()
                HStack(spacing: 5) {
                    if micMuted { Image(systemName: "mic.slash.fill").font(.caption2) }
                    Text(label).font(.caption).lineLimit(1)
                    Spacer(minLength: 0)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 7).padding(.vertical, 3)
                .background(Capsule().fill(.black.opacity(0.45)))
                .fixedSize(horizontal: true, vertical: false)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
        }
        .aspectRatio(tileRatio, contentMode: .fit)
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous)
            .strokeBorder(participant.isSpeaking ? Color.green : .clear, lineWidth: 3))
    }

    private var tileRatio: CGFloat {
        #if os(macOS)
        return 4.0 / 3.0
        #else
        return 0.8
        #endif
    }
}

// MARK: - The call itself

/// One call: the LiveKit room, its E2EE key provider, and what the controls do. Owned by
/// `CallView`; ends when the view goes away.
@MainActor
final class CallSession: NSObject, ObservableObject {
    enum Phase { case preparing, connecting, connected, failed }
    enum RingState: Equatable { case idle, sending, rang(Int), failed }

    @Published private(set) var phase: Phase = .preparing
    @Published private(set) var errorText = ""
    @Published private(set) var micOn = true
    @Published private(set) var camOn = false
    @Published private(set) var camBusy = false
    @Published private(set) var speakerOn = true
    @Published private(set) var ringState: RingState = .idle
    /// userId → username, for tile labels (LiveKit identity == user id).
    @Published private(set) var names: [String: String] = [:]
    /// Tracks come and go without the participant map changing; every such event bumps this.
    @Published private(set) var revision = 0
    /// A short, non-fatal note under the grid (camera permission refused, …).
    @Published private(set) var notice: String?
    /// A participant is publishing media that is not end-to-end encrypted. This device never
    /// subscribes to such a track (see `admitEncryptedTracks`).
    @Published private(set) var blockedUnencrypted = false
    /// Remote track sids this device has asked to receive.
    private var admitted: Set<String> = []

    let room = Room()
    private weak var app: AppState?
    private var keyProvider: BaseKeyProvider?
    private(set) var channelId = ""
    private var serverId = ""
    private var myUserId = ""
    private var callSalt: String?
    private var refresh: Task<Void, Never>?
    private var started = false
    private var ended = false
    private(set) var keysRegistered = 0
    /// The key index our outgoing frames are sealed under right now.
    var sendingKeyIndex: Int { Int(keyProvider?.getCurrentKeyIndex() ?? -1) }
    #if DEBUG
    private var synthetic: SyntheticMedia?
    private var commands: NSObjectProtocol?
    #endif

    var ringLabel: String {
        switch ringState {
        case .idle: return "Ring everyone"
        case .sending: return "Ringing…"
        case .rang(let n): return n == 0 ? "Nobody else can pick up right now" : "Ringing everyone…"
        case .failed: return "Couldn't ring — try again in a minute"
        }
    }

    /// A camera that has a front and a back (never the DEBUG synthetic source).
    var canSwitchCamera: Bool {
        (room.localParticipant.firstCameraVideoTrack as? LocalVideoTrack)?.capturer is CameraCapturer
    }

    // MARK: Joining

    func start(app: AppState, serverId: String?) async {
        guard !started else { return }
        started = true
        self.app = app
        guard let client = app.client, let me = app.session?.userId, let serverId else {
            fail("You're not in a server."); return
        }
        self.serverId = serverId
        myUserId = me
        room.add(delegate: self)
        CallCoordinator.shared.session = self
        #if DEBUG
        CallDebug.session = self
        CallDebug.lastError = nil
        listenForCommands()
        #endif
        // A ring for this room is answered by being here.
        CallCoordinator.shared.joined(serverId: serverId)
        do {
            guard await microphoneAllowed() else {
                fail("Skwod needs the microphone for calls. Allow it in Settings, then start the call again.")
                return
            }
            // 1. Resolve the voice channel + learn member names.
            do {
                channelId = try await client.ensureVoiceChannel(serverId: serverId, name: "General")
            } catch let error where String(describing: error).contains("403") {
                // The room is created the first time someone who may manage channels opens it.
                fail("This server has no call room yet. Ask the host to open the call once — after that everyone can start one.")
                return
            }
            await loadNames(client: client)

            // 2. FAIL CLOSED if this device can't do E2EE for the channel (not registered, no sender
            //    certificate). The real per-call keys are generated after connect, once we know the
            //    room session id.
            let precheck = try await client.voiceKeys(channelId: channelId, myUserId: me, callSalt: nil)
            guard !precheck.isEmpty else {
                fail("Couldn't set up encryption yet. Open the server's chat so the keys sync, then start the call again.")
                return
            }
            let provider = BaseKeyProvider(isSharedKey: false)
            keyProvider = provider

            // 3. Token + connect with E2EE on. The keyring is still empty here, which is itself
            //    fail-closed: nothing can be decrypted or published until keys are registered.
            let tok = try await client.voiceToken(channelId: channelId)
            guard let url = tok.url, !url.isEmpty else { fail("Calls aren't set up on this Skwod."); return }
            guard !ended else { return }
            phase = .connecting
            // ONE key provider for the room: LiveKit attaches a frame cryptor fed by it to every
            // track this device publishes or receives — microphone and camera alike.
            let opts = RoomOptions(e2eeOptions: E2EEOptions(keyProvider: provider),
                                   reportRemoteTrackStatistics: Self.wantsStatistics)
            try await room.connect(url: url, token: tok.token, connectOptions: Self.connectOptions(for: url), roomOptions: opts)
            guard !ended else { await room.disconnect(); return }

            // 4. Per-call keys: each device generates a RANDOM media key for this room session and
            //    sends it — over sealed libsignal sessions only — to the people in the call. Only
            //    then does the mic go live; the camera only on request.
            callSalt = try await room.sid().stringValue
            let keys = try await client.voiceSync(channelId: channelId, myUserId: me, callSalt: callSalt ?? "",
                                                  participantUserIds: participantIds(me: me))
            guard !keys.isEmpty else { fail("Couldn't set up this call's keys."); return }
            register(keys, with: provider) // own key last — pins our outgoing index
            admitEncryptedTracks()
            _ = try? await room.localParticipant.setMicrophone(enabled: true)
            #if DEBUG
            synthetic?.startTone()
            #endif
            guard !ended else { await room.disconnect(); return }
            phase = .connected
            startKeyRefresh(me: me)
        } catch CoreError.UpdateRequired {
            fail("Update required: this Skwod and this app use different encryption versions.")
        } catch {
            #if DEBUG
            CallDebug.lastError = String(describing: error)
            #endif
            // Deliberately generic: the underlying error can carry an address.
            fail("Couldn't join the call. Check your connection and try again.")
        }
    }

    /// Leave: stop capture, drop the keys, tell the system call UI. Safe to call more than once.
    func end() {
        guard !ended else { return }
        ended = true
        refresh?.cancel()
        #if DEBUG
        synthetic?.stop()
        synthetic = nil
        if let commands { NotificationCenter.default.removeObserver(commands) }
        if CallDebug.session === self { CallDebug.session = nil }
        #endif
        let room = room
        Task { await room.disconnect() }
        if CallCoordinator.shared.session === self { CallCoordinator.shared.session = nil }
        CallCoordinator.shared.callViewClosed()
    }

    private func fail(_ message: String) {
        errorText = message
        phase = .failed
    }

    /// Microphone permission, asked with the system prompt the first time.
    private func microphoneAllowed() async -> Bool {
        #if DEBUG
        if SyntheticMedia.audioWanted {
            // No device at all: the engine runs in manual-rendering mode and a generated tone is
            // what gets published (DEBUG end-to-end runs only).
            let media = synthetic ?? SyntheticMedia()
            synthetic = media
            return media.prepareAudio()
        }
        #endif
        return await LiveKitSDK.ensureDeviceAccess(for: [.audio])
    }

    /// Member names for the tiles. (Key exchange happens in `voiceSync`.)
    private func loadNames(client: SkwodClient) async {
        guard let members = try? await client.listMembers(serverId: serverId) else { return }
        var found = names
        for m in members { found[m.userId] = m.username }
        names = found
    }

    // MARK: Keys

    /// Who is in the room right now (LiveKit identity == user id), plus us. The core sends our media
    /// key only to these users and ROTATES it when one of them drops out of this list, so someone
    /// who left the call (or was kicked from the server) can't decrypt what is said afterwards.
    private func participantIds(me: String) -> [String] {
        var ids = room.remoteParticipants.values.compactMap { $0.identity?.stringValue }
        ids.append(me)
        return ids
    }

    private func register(_ keys: [VoiceKey], with provider: BaseKeyProvider) {
        for k in keys {
            // LiveKit's setKey treats the string as raw key material; base64 keeps the 32 raw bytes
            // identical across Mac/iOS/Android so every client derives the same AES key.
            provider.setKey(key: Data(k.key).base64EncodedString(), participantId: k.identity, index: Int32(k.keyIndex))
        }
        // Registering a per-participant key does NOT make it the one we encrypt with — the SDK
        // keeps sending under its current index (0) until told otherwise. So point our outgoing
        // frames (audio and video) at our own newest key explicitly. Without this a rotated key
        // is never used (someone who left could keep decrypting), and a call re-joined within
        // the same room session — where our key starts above index 0 — sends nothing at all.
        if let own = keys.last(where: { $0.identity == myUserId }) {
            let index = Int32(own.keyIndex)
            if provider.getCurrentKeyIndex() != index { provider.setCurrentKeyIndex(index) }
        }
        keysRegistered = keys.count
    }

    /// Keep keys in step with who is in the call: a joiner gets our key and we pick up theirs; when
    /// someone leaves, the core hands back a fresh key at the next key index (registered here, own
    /// key last, so LiveKit switches our outgoing frames — audio and video — to it). Polled every
    /// 2 s — the window in which a leaver could still decrypt is bounded by that.
    private func startKeyRefresh(me: String) {
        refresh = Task { [weak self] in
            var tick = 0
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard let self, !self.ended, let client = self.app?.client, let provider = self.keyProvider,
                      let salt = self.callSalt else { continue }
                if tick % 5 == 0 { await self.loadNames(client: client) }
                tick += 1
                if let keys = try? await client.voiceSync(channelId: self.channelId, myUserId: me, callSalt: salt,
                                                          participantUserIds: self.participantIds(me: me)) {
                    self.register(keys, with: provider)
                }
                self.admitEncryptedTracks()
            }
        }
    }

    // MARK: Controls

    func toggleMic() async {
        let want = !micOn
        micOn = want
        _ = try? await room.localParticipant.setMicrophone(enabled: want)
        revision &+= 1
    }

    func toggleCamera() async {
        guard phase == .connected, !camBusy else { return }
        camBusy = true
        defer { camBusy = false; revision &+= 1 }
        let want = !camOn
        notice = nil
        #if DEBUG
        if SyntheticMedia.videoWanted {
            let media = synthetic ?? SyntheticMedia()
            synthetic = media
            camOn = want ? await media.startVideo(in: room) : { media.stopVideo(in: room); return false }()
            return
        }
        #endif
        if want, !(await LiveKitSDK.ensureDeviceAccess(for: [.video])) {
            notice = "Skwod needs the camera for video. Allow it in Settings, then turn the camera on again."
            return
        }
        do {
            try await room.localParticipant.setCamera(enabled: want)
            camOn = want
        } catch {
            camOn = false
            if want { notice = "Couldn't start the camera." }
        }
    }

    func switchCamera() async {
        guard let capturer = (room.localParticipant.firstCameraVideoTrack as? LocalVideoTrack)?.capturer as? CameraCapturer else { return }
        _ = try? await capturer.switchCameraPosition()
    }

    func toggleSpeaker() {
        speakerOn.toggle()
        #if os(iOS)
        AudioManager.shared.isSpeakerOutputPreferred = speakerOn
        #endif
    }

    /// "Ring everyone": the skwod rings every member who could pick up — a `ring` event for the
    /// devices that are connected, a wake through the push gateway for the ones that are asleep.
    func ringEveryone() async {
        guard ringState == .idle, !channelId.isEmpty, let app, let token = app.session?.token,
              let base = URL(string: app.serverURL), !app.serverURL.isEmpty else { return }
        ringState = .sending
        var req = URLRequest(url: base.appendingPathComponent("api/channels/\(channelId)/ring"))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data("{}".utf8)
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200 else {
            ringState = .failed
            // The server allows three rings a minute; let the button come back.
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(20))
                if self?.ringState == .failed { self?.ringState = .idle }
            }
            return
        }
        let rang = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["rang"] as? Int ?? 0
        ringState = .rang(rang)
        #if DEBUG
        CallDebug.rang = rang
        #endif
    }

    /// When the SFU is reached on this device's loopback — the p2p tunnel's forwarder, or a Mac
    /// host's own SFU — its one ICE candidate is `127.0.0.1`, so there is nothing a STUN or TURN
    /// server could add. LiveKit hands every client public STUN servers by default (Google's and
    /// Twilio's); asking them would tell those companies this device's address every time a call
    /// starts. So for a loopback SFU the server's list is replaced with one entry that never
    /// leaves the device (the SDK only takes an override that is not empty; port 9 is "discard").
    /// An external SFU (a host's own LiveKit project) keeps the list its server sends, which may
    /// include the TURN servers a restrictive network needs.
    ///
    /// Nothing is subscribed to automatically: `admitEncryptedTracks` picks what this device
    /// receives.
    private static func connectOptions(for url: String) -> ConnectOptions {
        guard let host = URLComponents(string: url)?.host?.lowercased(), InviteLink.isLoopback(host) else {
            return ConnectOptions(autoSubscribe: false)
        }
        return ConnectOptions(autoSubscribe: false,
                              iceServers: [IceServer(urls: ["stun:127.0.0.1:9"], username: nil, credential: nil)])
    }

    /// FAIL CLOSED on what we receive: subscribe to a remote track only if the SFU lists it as
    /// end-to-end encrypted. A track published in the clear is never subscribed to — so it is
    /// neither played nor drawn — and the call says so. (A track that CLAIMS encryption but is
    /// not sealed with a key we hold fails to decrypt and yields nothing.)
    ///
    /// Without this, anyone holding a room token — or the SFU itself, which this app does not
    /// trust with media — could put audio or video into an "end-to-end encrypted" call.
    fileprivate func admitEncryptedTracks() {
        guard !ended else { return }
        var sawUnencrypted = false
        for participant in room.remoteParticipants.values {
            for case let pub as RemoteTrackPublication in participant.trackPublications.values {
                if pub.encryptionType == .none { sawUnencrypted = true; continue }
                let sid = pub.sid.stringValue
                guard !admitted.contains(sid) else { continue }
                admitted.insert(sid)
                Task { [weak self] in
                    do { try await pub.set(subscribed: true) } catch {
                        await MainActor.run { _ = self?.admitted.remove(sid) }   // retried on the next sweep
                    }
                }
            }
        }
        if blockedUnencrypted != sawUnencrypted { blockedUnencrypted = sawUnencrypted }
    }

    private static var wantsStatistics: Bool {
        #if DEBUG
        return E2E.env("SKWOD_E2E_OUT") != nil
        #else
        return false
        #endif
    }

    #if DEBUG
    /// DEBUG end-to-end hooks: the same functions the buttons call, without a tap.
    private func listenForCommands() {
        commands = NotificationCenter.default.addObserver(forName: .skwodE2ECallCommand, object: nil, queue: .main) { [weak self] note in
            guard let command = note.object as? String else { return }
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch command {
                case "camera": await self.toggleCamera()
                case "mute": await self.toggleMic()
                case "switch": await self.switchCamera()
                case "speaker": self.toggleSpeaker()
                case "ring": await self.ringEveryone()
                default: break
                }
            }
        }
    }
    #endif
}

extension CallSession: RoomDelegate {
    nonisolated private func bump() {
        Task { @MainActor [weak self] in
            self?.admitEncryptedTracks()
            self?.revision &+= 1
        }
    }

    nonisolated func room(_ room: Room, participantDidConnect participant: RemoteParticipant) { bump() }
    nonisolated func room(_ room: Room, participantDidDisconnect participant: RemoteParticipant) { bump() }
    nonisolated func room(_ room: Room, participant: LocalParticipant, didPublishTrack publication: LocalTrackPublication) { bump() }
    nonisolated func room(_ room: Room, participant: LocalParticipant, didUnpublishTrack publication: LocalTrackPublication) { bump() }
    nonisolated func room(_ room: Room, participant: RemoteParticipant, didPublishTrack publication: RemoteTrackPublication) { bump() }
    nonisolated func room(_ room: Room, participant: RemoteParticipant, didUnpublishTrack publication: RemoteTrackPublication) { bump() }
    nonisolated func room(_ room: Room, participant: RemoteParticipant, didSubscribeTrack publication: RemoteTrackPublication) { bump() }
    nonisolated func room(_ room: Room, participant: RemoteParticipant, didUnsubscribeTrack publication: RemoteTrackPublication) { bump() }
    nonisolated func room(_ room: Room, participant: Participant, trackPublication: TrackPublication, didUpdateIsMuted isMuted: Bool) { bump() }

    nonisolated func room(_ room: Room, trackPublication: TrackPublication, didUpdateE2EEState state: E2EEState) {
        #if DEBUG
        let sid = trackPublication.sid.stringValue
        let text = state.toString()
        Task { @MainActor in CallDebug.e2ee[sid] = text }
        #endif
        bump()
    }

    /// The room went away under us (host stopped, kicked, network gone for good).
    nonisolated func room(_ room: Room, didDisconnectWithError error: LiveKitError?) {
        Task { @MainActor [weak self] in
            guard let self, !self.ended, self.phase == .connected else { return }
            self.refresh?.cancel()
            self.fail("The call ended.")
        }
    }
}
