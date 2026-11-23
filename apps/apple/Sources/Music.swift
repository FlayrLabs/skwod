import SwiftUI
import MusicKit
import AVFoundation

/// Apple Music search via MusicKit. Requests authorization on demand; degrades gracefully (empty
/// results + a prompt) if the user declines or Apple Music isn't available.
@MainActor
final class MusicService: ObservableObject {
    static let shared = MusicService()
    @Published var authorized = MusicAuthorization.currentStatus == .authorized
    @Published var denied = MusicAuthorization.currentStatus == .denied
    @Published var results: [MusicTrack] = []
    @Published var searching = false

    /// Ask for Apple Music access (no-op if already decided).
    func ensureAuthorized() async {
        guard MusicAuthorization.currentStatus == .notDetermined else {
            authorized = MusicAuthorization.currentStatus == .authorized
            denied = MusicAuthorization.currentStatus == .denied
            return
        }
        let status = await MusicAuthorization.request()
        authorized = status == .authorized
        denied = status == .denied
    }

    /// Search for songs matching `term`. Prefers MusicKit (full catalog) when the app is authorized
    /// AND the build can mint a developer token (App ID registered + team-signed); otherwise — or on
    /// any MusicKit failure, e.g. ad-hoc-signed dev builds — falls back to Apple's public iTunes
    /// Search API, which needs no account or entitlement and returns the same previews/artwork.
    func search(_ term: String) async {
        let q = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { results = []; return }
        searching = true
        defer { searching = false }
        // Never gate search on an authorization prompt — MusicKit only when ALREADY authorized
        // (ad-hoc dev builds can hang in the request); otherwise the public iTunes API.
        if MusicAuthorization.currentStatus == .authorized, let hits = try? await musicKitSearch(q), !hits.isEmpty {
            results = hits
            return
        }
        results = (try? await Self.itunesSearch(q)) ?? []
    }

    private func musicKitSearch(_ q: String) async throws -> [MusicTrack] {
        var req = MusicCatalogSearchRequest(term: q, types: [Song.self])
        req.limit = 25
        let resp = try await req.response()
        return resp.songs.map { s in
            MusicTrack(
                id: s.id.rawValue,
                title: s.title,
                artist: s.artistName,
                artworkURL: s.artwork?.url(width: 200, height: 200),
                previewURL: s.previewAssets?.first?.url,
                appleMusicURL: s.url
            )
        }
    }

    // MARK: iTunes Search API fallback

    private struct ITunesResponse: Decodable { let results: [ITunesTrack] }
    private struct ITunesTrack: Decodable {
        let trackId: Int?
        let trackName: String?
        let artistName: String?
        let artworkUrl100: String?
        let previewUrl: String?
        let trackViewUrl: String?
    }

    static func itunesSearch(_ term: String) async throws -> [MusicTrack] {
        var comps = URLComponents(string: "https://itunes.apple.com/search")!
        comps.queryItems = [
            URLQueryItem(name: "term", value: term),
            URLQueryItem(name: "media", value: "music"),
            URLQueryItem(name: "entity", value: "song"),
            URLQueryItem(name: "limit", value: "25"),
        ]
        guard let url = comps.url else { return [] }
        let (data, _) = try await URLSession.shared.data(from: url)
        let resp = try JSONDecoder().decode(ITunesResponse.self, from: data)
        return resp.results.compactMap { t in
            guard let title = t.trackName, let artist = t.artistName else { return nil }
            return MusicTrack(
                id: t.trackId.map(String.init) ?? UUID().uuidString,
                title: title,
                artist: artist,
                artworkURL: t.artworkUrl100.map { $0.replacingOccurrences(of: "100x100", with: "200x200") }.flatMap(URL.init(string:)),
                previewURL: t.previewUrl.flatMap(URL.init(string:)),
                appleMusicURL: t.trackViewUrl.flatMap(URL.init(string:))
            )
        }
    }
}

/// Plays a song card's ~30-second preview (chat, feed posts). One shared player, so only a
/// single song sounds at a time and any card can reflect what's playing.
///
/// Like a story's song (`StoryClipPlayer`), the audio is NEVER fetched from Apple by this
/// device — that would show Apple the address of whoever looks at a friend's card. The viewer's
/// own Skwod host fetches it (`BlobStore.musicPreview`); what plays is that answer, from a
/// temporary file.
///
/// The one exception is the viewer's own choice: with "Play full songs with my Apple Music
/// account" on (off by default), an authorised subscriber gets the whole track through
/// MusicKit — the device talking to Apple under the user's Apple ID, which is exactly what the
/// setting says. Access is asked for when the setting is turned on, never here.
@MainActor
final class MusicPreviewPlayer: ObservableObject {
    static let shared = MusicPreviewPlayer()
    @Published var playingID: String?
    /// The host is being asked for this card's audio.
    @Published private(set) var loadingID: String?
    /// The card whose song could not be played, and why (until another is tapped).
    @Published private(set) var failed: (id: String, why: String)?

    /// The song sounding now is the whole track (Apple Music), not the preview.
    @Published private(set) var playingFull = false

    private var previewPlayer: AVPlayer?
    private var endObserver: NSObjectProtocol?
    private var file: URL?
    private var usingFullPlayer = false

    /// The whole track, if the viewer chose that and Apple Music will play it for them.
    /// Never prompts: the permission is asked for where the setting is switched on.
    private func playFullIfChosen(_ track: MusicTrack) async -> Bool {
        let on = UserDefaults.standard.bool(forKey: StoryMusicPolicy.fullSongsKey)
        let authorized = MusicAuthorization.currentStatus == .authorized
        // Asked only when both hold, so nothing reaches Apple for a viewer who did not opt in.
        let canPlay = on && authorized ? ((try? await MusicSubscription.current)?.canPlayCatalogContent ?? false) : false
        guard StoryMusicPolicy.cardPlayback(fullSongsOn: on, authorized: authorized, canPlayCatalog: canPlay) == .fullTrack else { return false }
        do {
            let request = MusicCatalogResourceRequest<Song>(matching: \.id, equalTo: MusicItemID(track.id))
            guard let song = try await request.response().items.first, loadingID == track.id else { return false }
            let player = ApplicationMusicPlayer.shared
            player.queue = [song]
            try await player.play()
            guard loadingID == track.id else { player.pause(); return true }
            usingFullPlayer = true
            playingFull = true
            loadingID = nil
            playingID = track.id
            return true
        } catch {
            return false   // region, unavailable, a dev build without the entitlement: the preview
        }
    }

    func toggle(_ track: MusicTrack, app: AppState) {
        if playingID == track.id || loadingID == track.id { stop(); return }
        stop()
        StoryClipPlayer.shared.stop()
        failed = nil
        loadingID = track.id
        Task { [weak self] in
            guard let self else { return }
            if await self.playFullIfChosen(track) { return }
            guard self.loadingID == track.id else { return }
            guard let url = track.hostPreviewURL, let store = BlobStore(app: app) else {
                self.loadingID = nil
                self.failed = (track.id, "No preview to play")
                return
            }
            let result: Result<Data, Error>
            do { result = .success(try await store.musicPreview(url)) } catch { result = .failure(error) }
            // Another card was tapped (or this one again) while the host answered: drop it.
            guard self.loadingID == track.id else { return }
            self.loadingID = nil
            switch result {
            case .success(let data):
                let dir = FileManager.default.temporaryDirectory.appendingPathComponent("skwod-card-music", isDirectory: true)
                try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let file = dir.appendingPathComponent(UUID().uuidString + ".m4a")
                guard (try? data.write(to: file, options: .atomic)) != nil else { self.failed = (track.id, "Couldn't load the song"); return }
                self.file = file
                self.play(file, id: track.id)
            case .failure(BlobStore.MusicPreviewError.hostTooOld):
                self.failed = (track.id, "This Skwod's host needs an update to play songs")
            case .failure:
                self.failed = (track.id, "Couldn't load the song")
            }
        }
    }

    private func play(_ url: URL, id: String) {
        let p = AVPlayer(url: url)
        previewPlayer = p
        playingID = id
        p.play()
        endObserver = NotificationCenter.default.addObserver(
            forName: .AVPlayerItemDidPlayToEndTime, object: p.currentItem, queue: .main
        ) { [weak self] _ in MainActor.assumeIsolated { self?.stop() } }
    }

    func stop() {
        previewPlayer?.pause()
        previewPlayer = nil
        if let file { try? FileManager.default.removeItem(at: file) }
        file = nil
        if usingFullPlayer {
            ApplicationMusicPlayer.shared.pause()
            usingFullPlayer = false
        }
        playingFull = false
        loadingID = nil
        playingID = nil
        if let o = endObserver { NotificationCenter.default.removeObserver(o); endObserver = nil }
    }
}

/// A song's artwork, fetched for this device by its Skwod host (`BlobStore.musicArtwork`) —
/// never from Apple directly, which is what `AsyncImage(url:)` would do the moment a friend's
/// card scrolled into view. `load` false: nothing is fetched at all (the placeholder shows).
struct HostArtwork: View {
    let track: MusicTrack
    var load = true
    @EnvironmentObject private var app: AppState
    @State private var image: Image?

    private static let cache = NSCache<NSURL, NSData>()

    var body: some View {
        ZStack {
            if let image { image.resizable().scaledToFill() }
            else { Image(systemName: "music.note").foregroundStyle(.white.opacity(0.5)) }
        }
        .task(id: "\(track.id)|\(load)") {
            guard load, image == nil, let url = track.hostArtworkURL else { return }
            if let hit = Self.cache.object(forKey: url as NSURL) { image = Image(data: hit as Data); return }
            guard let store = BlobStore(app: app), let data = try? await store.musicArtwork(url), let decoded = Image(data: data) else { return }
            Self.cache.setObject(data as NSData, forKey: url as NSURL)
            image = decoded
        }
    }
}

// MARK: - Views

/// A compact "now attached" music card shown inside a post or story: artwork, title, artist, a
/// play/pause preview button, and a deep-link to Apple Music.
struct MusicCard: View {
    let track: MusicTrack
    @ObservedObject private var player = MusicPreviewPlayer.shared
    @Environment(\.openURL) private var openURL
    @EnvironmentObject private var app: AppState
    /// "Play story music only when I tap" covers song cards too: with it on, not even the
    /// artwork is fetched until this card's play button is tapped.
    @AppStorage(StoryMusicPolicy.tapToPlayKey) private var tapToPlay = false
    @State private var tapped = false

    private var isPlaying: Bool { player.playingID == track.id }

    var body: some View {
        HStack(spacing: 12) {
            artwork
            VStack(alignment: .leading, spacing: 2) {
                Text(track.title).font(.subheadline.weight(.semibold)).foregroundStyle(.white).lineLimit(1)
                Text(track.artist).font(.caption).foregroundStyle(.white.opacity(0.6)).lineLimit(1)
                if let failed = player.failed, failed.id == track.id {
                    Text(failed.why).font(.caption2).foregroundStyle(.orange.opacity(0.9)).lineLimit(1)
                } else {
                    Label("Apple Music", systemImage: "applelogo").font(.caption2).foregroundStyle(.white.opacity(0.4))
                }
            }
            Spacer(minLength: 0)
            // The 30 s preview, fetched through this Skwod's host on tap. The whole song is in
            // Apple Music, one explicit tap away.
            HStack(spacing: 8) {
                if let url = track.safeAppleMusicURL {
                    Button { openURL(url) } label: {
                        Image(systemName: "arrow.up.forward.circle").font(.system(size: 22)).foregroundStyle(.white.opacity(0.5))
                    }.buttonStyle(.plain)
                }
                if player.loadingID == track.id {
                    ProgressView().controlSize(.small).tint(.skAccent).frame(width: 34, height: 34)
                } else {
                    Button { tapped = true; player.toggle(track, app: app) } label: {
                        Image(systemName: isPlaying ? "pause.circle.fill" : "play.circle.fill")
                            .font(.system(size: 34)).foregroundStyle(.skAccent)
                    }.buttonStyle(.plain)
                }
            }
        }
        .padding(10)
        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.skAccent.opacity(0.25), lineWidth: 1))
    }

    @ViewBuilder private var artwork: some View {
        RoundedRectangle(cornerRadius: 8, style: .continuous)
            .fill(.white.opacity(0.08))
            .frame(width: 48, height: 48)
            .overlay { HostArtwork(track: track, load: StoryMusicPolicy.cardLoadsArtwork(tapToPlay: tapToPlay, tapped: tapped)) }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

/// The Apple Music search sheet: type a song, tap to attach. Handles the not-yet-authorized and
/// declined states inline.
struct MusicSearchSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var svc = MusicService.shared
    @State private var term = ""
    var onPick: (MusicTrack) -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                SkwodBackground()
                VStack(spacing: 12) {
                    searchField
                    if svc.searching {
                        ProgressView().tint(.skAccent).padding(.top, 24)
                        Spacer()
                    } else if svc.results.isEmpty {
                        prompt(term.isEmpty ? "Search Apple Music to add a song." : "No songs found.")
                    } else {
                        List(svc.results) { t in
                            Button { onPick(t); dismiss() } label: { MusicRow(track: t) }
                                .listRowBackground(Color.clear)
                                .listRowSeparatorTint(.white.opacity(0.08))
                        }
                        .listStyle(.plain)
                        .scrollContentBackground(.hidden)
                    }
                }
                .padding(.horizontal, 16).padding(.top, 8)
            }
            .navigationTitle("Add music")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 560)   // macOS sheets size to content; give results room
        #endif
        .task { await svc.ensureAuthorized() }
    }

    private var searchField: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass").foregroundStyle(.white.opacity(0.5))
            TextField("Songs, artists…", text: $term)
                .textFieldStyle(.plain).foregroundStyle(.white)
                #if os(iOS)
                .autocorrectionDisabled()
                #endif
                .onSubmit { Task { await svc.search(term) } }
                .task(id: term) {
                    // Live search: task(id:) cancels on each keystroke → a natural 400ms debounce.
                    try? await Task.sleep(for: .milliseconds(400))
                    if !Task.isCancelled { await svc.search(term) }
                }
            if !term.isEmpty {
                Button { term = ""; svc.results = [] } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.white.opacity(0.4)) }
                    .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
        .background(.white.opacity(0.06), in: Capsule())
    }

    private func prompt(_ text: String) -> some View {
        VStack {
            Spacer()
            Image(systemName: "music.note.list").font(.system(size: 44)).foregroundStyle(.white.opacity(0.25))
            Text(text).font(.subheadline).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center).padding(.top, 8)
            Spacer()
        }
    }
}

/// One search result row.
private struct MusicRow: View {
    let track: MusicTrack
    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 6, style: .continuous).fill(.white.opacity(0.08))
                .frame(width: 44, height: 44)
                .overlay {
                    if let url = track.artworkURL {
                        AsyncImage(url: url) { img in img.resizable().scaledToFill() } placeholder: {
                            Image(systemName: "music.note").foregroundStyle(.white.opacity(0.4))
                        }
                    } else {
                        Image(systemName: "music.note").foregroundStyle(.white.opacity(0.4))
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(track.title).foregroundStyle(.white).lineLimit(1)
                Text(track.artist).font(.caption).foregroundStyle(.white.opacity(0.55)).lineLimit(1)
            }
            Spacer()
            Image(systemName: "plus.circle.fill").foregroundStyle(.skAccent)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}
