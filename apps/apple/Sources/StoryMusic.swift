import SwiftUI
import AVFoundation

/// Plays the chosen part of a story's song — in the viewer (autostart, loop, pause while held)
/// and in the composer (hearing the part while picking it).
///
/// The audio is the song's PREVIEW: the one source every viewer can play, on any platform, with
/// no Apple Music subscription and no permission prompt. That is why this is not
/// `MusicPreviewPlayer`, which asks for Apple Music access and plays the whole track for
/// subscribers. It is NEVER fetched from Apple by this device — that would show Apple every
/// viewer's IP address. The viewer's own Skwod host fetches it (`BlobStore.musicPreview`,
/// see `StoryMusicPolicy`); what plays here is that answer, from a temporary file.
@MainActor
final class StoryClipPlayer: ObservableObject {
    static let shared = StoryClipPlayer()

    /// The song has no preview the host will fetch, or it would not load.
    @Published private(set) var unavailable = false
    /// Why (shown beside the artist), when `unavailable`.
    @Published private(set) var problem = "no preview to play"
    /// The host is being asked for the audio.
    @Published private(set) var loading = false
    /// Sound is coming out (ready, not held, not finished loading).
    @Published private(set) var playing = false
    /// The real length of the loaded preview (nil until it is known).
    @Published private(set) var previewMs: Int?
    /// The viewer's own mute, remembered across stories and launches.
    @Published var muted = UserDefaults.standard.bool(forKey: StoryClipPlayer.mutedKey) {
        didSet {
            UserDefaults.standard.set(muted, forKey: Self.mutedKey)
            player?.isMuted = muted
            if player != nil { if muted { releaseAudio() } else { takeAudioIfAudible() } }
        }
    }

    private static let mutedKey = "skwod.story.muted"
    private var player: AVPlayer?
    private var trackId: String?
    private var clip = MusicClip.fallback
    private var held = false
    private var timeObserver: Any?
    private var statusObserver: NSKeyValueObservation?
    private var endObserver: NSObjectProtocol?
    /// Bumped by every start and stop: an answer for an earlier story is dropped.
    private var generation = 0
    private var file: URL?

    private static var directory: URL { FileManager.default.temporaryDirectory.appendingPathComponent("skwod-story-music", isDirectory: true) }

    /// Start (or restart) `clip` of `track`. Does nothing audible when the song has no usable
    /// preview — `unavailable` says so — and nothing at all during a call (`inCall`): the call
    /// owns the audio session, and a story must never take it.
    func start(_ track: MusicTrack, clip: MusicClip, inCall: Bool, app: AppState) {
        guard !inCall else { stop(); return }
        // Another song of this app's must not keep playing underneath.
        MusicPreviewPlayer.shared.stop()
        if trackId == track.id, player != nil || loading {
            setClip(clip)
            return
        }
        stop()
        guard let url = track.hostPreviewURL, let store = BlobStore(app: app) else {
            problem = "no preview to play"
            unavailable = true
            return
        }
        trackId = track.id
        self.clip = clip
        unavailable = false
        loading = true
        let mine = generation
        Task { [weak self] in
            let result: Result<Data, Error>
            do { result = .success(try await store.musicPreview(url)) } catch { result = .failure(error) }
            guard let self, self.generation == mine else { return }
            self.loading = false
            switch result {
            case .success(let data):
                // Played from a file of this app's own, gone when the story closes.
                let dir = Self.directory
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let file = dir.appendingPathComponent(UUID().uuidString + ".m4a")
                guard (try? data.write(to: file, options: .atomic)) != nil else { self.fail("couldn't load the song"); return }
                self.file = file
                self.begin(file)
            case .failure(BlobStore.MusicPreviewError.hostTooOld):
                self.fail("this Skwod's host needs an update to play story music")
            case .failure:
                self.fail("couldn't load the song")
            }
        }
    }

    private func fail(_ why: String) {
        problem = why
        unavailable = true
        stop(keepUnavailable: true)
    }

    /// Play the audio the host handed over.
    private func begin(_ url: URL) {
        takeAudioIfAudible()
        let item = AVPlayerItem(url: url)
        let p = AVPlayer(playerItem: item)
        p.isMuted = muted
        p.actionAtItemEnd = .none
        player = p
        statusObserver = item.observe(\.status, options: [.new]) { [weak self] item, _ in
            let status = item.status
            let seconds = item.duration.seconds
            Task { @MainActor in self?.itemChanged(status: status, durationSeconds: seconds, of: item) }
        }
        endObserver = NotificationCenter.default.addObserver(forName: .AVPlayerItemDidPlayToEndTime, object: item, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.loop() }
        }
        // The end of the chosen part: back to its start, for as long as the story is open.
        timeObserver = p.addPeriodicTimeObserver(forInterval: CMTime(value: 1, timescale: 20), queue: .main) { [weak self] time in
            MainActor.assumeIsolated {
                guard let self, self.playing else { return }
                if Int(time.seconds * 1000) >= self.clip.window(previewMs: self.previewMs).endMs { self.loop() }
            }
        }
    }

    private func itemChanged(status: AVPlayerItem.Status, durationSeconds: Double, of item: AVPlayerItem) {
        guard player?.currentItem === item else { return }
        switch status {
        case .readyToPlay:
            if durationSeconds.isFinite, durationSeconds > 0 { previewMs = Int(durationSeconds * 1000) }
            loop()
        case .failed:
            fail("couldn't load the song")
        default: break
        }
    }

    #if os(iOS)
    private var holdsSession = false
    #endif

    /// iPhone: like any other sound of an app in front — silent when the ring/silent switch
    /// is, and other apps' audio pauses for it. Not while muted: a story nobody hears must not
    /// stop the music the user is listening to.
    private func takeAudioIfAudible() {
        #if os(iOS)
        guard !muted, player != nil || trackId != nil, !holdsSession else { return }
        try? AVAudioSession.sharedInstance().setCategory(.soloAmbient, mode: .default)
        try? AVAudioSession.sharedInstance().setActive(true)
        holdsSession = true
        #endif
    }

    /// Give the audio back, so what was playing before (another app's music) can resume.
    private func releaseAudio() {
        #if os(iOS)
        guard holdsSession else { return }
        holdsSession = false
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        #endif
    }

    /// Jump to the start of the chosen part and carry on (unless held).
    private func loop() {
        guard let player else { return }
        let start = clip.window(previewMs: previewMs).startMs
        player.seek(to: CMTime(value: CMTimeValue(start), timescale: 1000), toleranceBefore: .zero, toleranceAfter: .zero) { [weak self] _ in
            Task { @MainActor in self?.resumeIfFree() }
        }
    }

    private func resumeIfFree() {
        guard let player, player.currentItem?.status == .readyToPlay else { return }
        if held { player.pause(); playing = false } else { player.play(); playing = true }
    }

    /// The composer moved the selection: play the new part from its start.
    func setClip(_ clip: MusicClip) {
        guard clip != self.clip else { return }
        self.clip = clip
        if player?.currentItem?.status == .readyToPlay { loop() }
    }

    /// The story is being held (a finger on it, the app not in front): pause; released: go on
    /// from where it stopped.
    func setHeld(_ held: Bool) {
        guard held != self.held else { return }
        self.held = held
        resumeIfFree()
    }

    func stop() { stop(keepUnavailable: false) }

    private func stop(keepUnavailable: Bool) {
        if let timeObserver, let player { player.removeTimeObserver(timeObserver) }
        timeObserver = nil
        statusObserver?.invalidate(); statusObserver = nil
        if let endObserver { NotificationCenter.default.removeObserver(endObserver) }
        endObserver = nil
        generation += 1
        loading = false
        player?.pause()
        player = nil
        if let file { try? FileManager.default.removeItem(at: file) }
        file = nil
        releaseAudio()
        trackId = nil
        held = false
        playing = false
        previewMs = nil
        if !keepUnavailable { unavailable = false }
    }
}

// MARK: - Viewer

/// The song on an open story: it starts by itself, plays the part the author chose, loops while
/// the story is open and pauses while the story is held. One tap mutes (remembered).
///
/// With "Play story music only when I tap" on (`StoryMusicPolicy`), nothing is fetched when the
/// story opens: the song shows with a play button, and the tap is what asks the host for it.
/// No artwork is shown here — loading it would be a request from this device to Apple.
struct StoryMusicStrip: View {
    let track: MusicTrack
    /// The author's choice; nil on a story from a build before 45.
    let clip: MusicClip?
    /// The story is being held, or the app is not in front.
    let held: Bool
    @EnvironmentObject private var app: AppState
    @ObservedObject private var player = StoryClipPlayer.shared
    @Environment(\.openURL) private var openURL
    @AppStorage(StoryMusicPolicy.tapToPlayKey) private var tapToPlay = false
    /// The viewer tapped the song (tap-to-play): this story's audio may be fetched.
    @State private var tapped = false

    private var onOpen: StoryMusicPolicy.OnOpen {
        StoryMusicPolicy.onOpen(tapToPlay: tapToPlay, tapped: tapped, inCall: app.activeCall != nil, hasPreview: track.hostPreviewURL != nil)
    }

    private func startIfAllowed() {
        guard onOpen == .fetch else { return }
        player.start(track, clip: clip ?? .fallback, inCall: app.activeCall != nil, app: app)
        player.setHeld(held)
    }

    var body: some View {
        HStack(spacing: 10) {
            artwork
            VStack(alignment: .leading, spacing: 2) {
                Text(track.title).font(.subheadline.weight(.semibold)).foregroundStyle(.white).lineLimit(1)
                Text(status).font(.caption).foregroundStyle(.white.opacity(0.65)).lineLimit(1)
            }
            Spacer(minLength: 0)
            if let url = track.safeAppleMusicURL {
                Button { openURL(url) } label: {
                    Image(systemName: "arrow.up.forward.circle").font(.system(size: 22)).foregroundStyle(.white.opacity(0.6))
                }
                .buttonStyle(.plain).accessibilityLabel("Open in Apple Music")
            }
            if onOpen == .waitForTap {
                Button { tapped = true; startIfAllowed() } label: {
                    Image(systemName: "play.fill")
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(.black)
                        .frame(width: 34, height: 34).background(.skAccent, in: Circle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Play this story's song")
                .accessibilityIdentifier("story.playMusic")
            } else if player.loading {
                ProgressView().controlSize(.small).tint(.white).frame(width: 34, height: 34)
            } else if onOpen == .fetch, !player.unavailable {
                Button { player.muted.toggle() } label: {
                    Image(systemName: player.muted ? "speaker.slash.fill" : "speaker.wave.2.fill")
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(.white)
                        .frame(width: 34, height: 34).background(.white.opacity(0.14), in: Circle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(player.muted ? "Unmute" : "Mute")
                .accessibilityIdentifier("story.mute")
            }
        }
        .padding(10)
        .background(.black.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.skAccent.opacity(0.25), lineWidth: 1))
        // Never over a call (the call owns the audio), and not before a tap when the viewer
        // asked for that.
        .onAppear { startIfAllowed() }
        .onChange(of: held) { _, now in player.setHeld(now) }
        .onDisappear { player.stop() }
    }

    private var status: String {
        if onOpen == .waitForTap { return "\(track.artist) · tap to play" }
        if track.hostPreviewURL == nil { return "\(track.artist) · no preview to play" }
        if player.unavailable { return "\(track.artist) · \(player.problem)" }
        if player.muted { return "\(track.artist) · muted" }
        return track.artist
    }

    private var artwork: some View {
        RoundedRectangle(cornerRadius: 8, style: .continuous).fill(.white.opacity(0.08))
            .frame(width: 40, height: 40)
            .overlay { Image(systemName: "music.note").foregroundStyle(.white.opacity(0.5)) }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay(alignment: .bottomTrailing) {
                if player.playing && !player.muted {
                    Image(systemName: "waveform").font(.system(size: 9, weight: .bold)).foregroundStyle(.black)
                        .padding(3).background(.skAccent, in: Circle()).offset(x: 4, y: 4)
                }
            }
    }
}

// MARK: - Composer

/// "Which part plays": the song, a length (5 / 10 / 15 s) and a strip of the preview with a
/// window to drag. The selection plays, looped, while it is being chosen.
///
/// The strip stands for the song's ~30-second preview — the audio every viewer can play. Its
/// bars are a drawing (the same for a given song each time), not the measured waveform.
struct MusicClipTrimmer: View {
    let track: MusicTrack
    @Binding var clip: MusicClip
    var onRemove: () -> Void
    @ObservedObject private var player = StoryClipPlayer.shared
    @EnvironmentObject private var app: AppState
    /// Where the window started when the current drag began.
    @State private var dragOrigin: Int?

    private var previewMs: Int { player.previewMs ?? MusicClip.assumedPreviewMs }
    private var window: (startMs: Int, endMs: Int) { clip.window(previewMs: previewMs) }
    private static let barCount = 44

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "music.note").font(.caption.bold())
                Text("\(track.title) — \(track.artist)").font(.caption.weight(.semibold)).lineLimit(1)
                Spacer(minLength: 4)
                Button { player.muted.toggle() } label: {
                    Image(systemName: player.muted ? "speaker.slash.fill" : "speaker.wave.2.fill").font(.caption.bold())
                }
                .buttonStyle(.plain).accessibilityLabel(player.muted ? "Unmute" : "Mute")
                Button(action: onRemove) { Image(systemName: "xmark").font(.caption2.bold()) }
                    .buttonStyle(.plain).accessibilityLabel("Remove song")
            }
            if player.unavailable {
                Text("This song can't be played here (\(player.problem)), so it will show on your story without sound.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.7)).fixedSize(horizontal: false, vertical: true)
            } else {
                strip
                HStack(spacing: 8) {
                    ForEach(MusicClip.durationChoices, id: \.self) { seconds in
                        let on = clip.durationMs == seconds * 1000
                        Button {
                            clip = MusicClip.chosen(startMs: clip.startMs, durationSeconds: seconds, previewMs: previewMs)
                        } label: {
                            Text("\(seconds)s").font(.caption.weight(.bold))
                                .foregroundStyle(on ? .black : .white)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                                .background(on ? AnyShapeStyle(.white) : AnyShapeStyle(.white.opacity(0.15)), in: Capsule())
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("story.clip.\(seconds)")
                    }
                    Spacer()
                    Text("\(Self.clock(window.startMs)) – \(Self.clock(window.endMs))")
                        .font(.caption.monospacedDigit()).foregroundStyle(.white.opacity(0.75))
                }
            }
        }
        .foregroundStyle(.white)
        .padding(12)
        .background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        // The author picked this song and is choosing its part: fetched (via the host) at once.
        .onAppear { player.start(track, clip: clip, inCall: app.activeCall != nil, app: app) }
        .onChange(of: clip) { _, now in player.setClip(now) }
        .onChange(of: player.previewMs) { _, real in
            // The preview turned out shorter than assumed: keep the selection inside it.
            guard let real else { return }
            let w = clip.window(previewMs: real)
            let fitted = MusicClip(startMs: w.startMs, durationMs: w.endMs - w.startMs)
            if fitted != clip { clip = fitted }
        }
        .onDisappear { player.stop() }
    }

    private var strip: some View {
        GeometryReader { geo in
            let width = max(geo.size.width, 1)
            let perMs = width / CGFloat(max(previewMs, 1))
            let x = CGFloat(window.startMs) * perMs
            let w = max(CGFloat(window.endMs - window.startMs) * perMs, 12)
            ZStack(alignment: .leading) {
                HStack(alignment: .center, spacing: 2) {
                    ForEach(0..<Self.barCount, id: \.self) { i in
                        let center = (CGFloat(i) + 0.5) / CGFloat(Self.barCount) * width
                        Capsule()
                            .fill(center >= x && center <= x + w ? AnyShapeStyle(Color.skAccent) : AnyShapeStyle(.white.opacity(0.3)))
                            .frame(maxWidth: .infinity)
                            .frame(height: 6 + 30 * Self.barHeight(i, seed: track.id))
                    }
                }
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .strokeBorder(.white, lineWidth: 2)
                    .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .frame(width: w, height: 44)
                    .offset(x: x)
            }
            .frame(height: 44)
            .contentShape(Rectangle())
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { v in
                        // A touch outside the window moves it there first; then it follows the finger.
                        let origin = dragOrigin ?? {
                            let inside = v.startLocation.x >= x && v.startLocation.x <= x + w
                            return inside ? window.startMs : Int((v.startLocation.x - w / 2) / perMs)
                        }()
                        dragOrigin = origin
                        let moved = origin + Int(v.translation.width / perMs)
                        let next = MusicClip.chosen(startMs: moved, durationSeconds: clip.durationMs / 1000, previewMs: previewMs)
                        // Whole tenths of a second: the player is not restarted for every pixel.
                        let snapped = MusicClip(startMs: next.startMs / 100 * 100, durationMs: next.durationMs)
                        if snapped != clip { clip = snapped }
                    }
                    .onEnded { _ in dragOrigin = nil }
            )
            .accessibilityElement()
            .accessibilityLabel("Part of the song that plays")
            .accessibilityValue("\(Self.clock(window.startMs)) to \(Self.clock(window.endMs))")
            .accessibilityAdjustableAction { direction in
                let step = direction == .increment ? 1000 : -1000
                clip = MusicClip.chosen(startMs: clip.startMs + step, durationSeconds: clip.durationMs / 1000, previewMs: previewMs)
            }
            .accessibilityIdentifier("story.clip.strip")
        }
        .frame(height: 44)
    }

    /// 0…1, the same for a given song and bar every time.
    static func barHeight(_ index: Int, seed: String) -> CGFloat {
        var h: UInt64 = 1469598103934665603
        for b in seed.utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
        h = (h ^ UInt64(index &+ 1)) &* 1099511628211
        h ^= h >> 29
        return 0.25 + 0.75 * CGFloat(h % 1000) / 1000
    }

    static func clock(_ ms: Int) -> String {
        let s = max(ms, 0) / 1000
        return "\(s / 60):" + String(format: "%02d", s % 60)
    }
}
