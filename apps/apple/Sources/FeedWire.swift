import Foundation

// What travels INSIDE end-to-end-encrypted messages: the song card, the attachment descriptor,
// the feed/story payload and a story's song clip. Foundation only, so the logic tests compile
// this file as it is (`SkwodLogicTests`) — and the same JSON is read and written by the Android
// app (`Attachments.kt`, `Feed.kt`, `MusicClip` in `Policies.kt`).

/// A song picked from Apple Music, attached to a post or story. Stored as lightweight value fields
/// (MusicKit's own types aren't Hashable/Codable-friendly). Preview playback uses the 30-second
/// preview URL — which needs NO Apple Music subscription — and "Open in Music" deep-links the track.
struct MusicTrack: Identifiable, Hashable, Codable {
    var id: String            // MusicItemID raw value
    var title: String
    var artist: String
    var artworkURL: URL?
    var previewURL: URL?
    var appleMusicURL: URL?
}

/// A music card arrives inside a MESSAGE, so its three URLs are whatever the sender typed. Loading
/// one fetches it from this device (revealing its IP address, and when the card is on screen), and
/// "open in Apple Music" hands one to the system. So they are only ever used when they are https
/// and on Apple's own hosts; anything else renders as the placeholder / is not offered.
extension MusicTrack {
    /// `*.mzstatic.com` (artwork, previews), `*.apple.com` and `*.itunes.apple.com` — https only,
    /// no credentials in the URL, default port.
    static func isAppleHost(_ url: URL?) -> Bool {
        guard let url, url.scheme?.lowercased() == "https", url.user == nil, url.password == nil,
              url.port == nil || url.port == 443, let host = url.host?.lowercased(), !host.isEmpty else { return false }
        return ["mzstatic.com", "apple.com", "itunes.apple.com"].contains { host == $0 || host.hasSuffix("." + $0) }
    }

    var safeArtworkURL: URL? { Self.isAppleHost(artworkURL) ? artworkURL : nil }
    var safePreviewURL: URL? { Self.isAppleHost(previewURL) ? previewURL : nil }
    var safeAppleMusicURL: URL? { Self.isAppleHost(appleMusicURL) ? appleMusicURL : nil }
}

/// How a story's song reaches the viewer's ears — and what never happens.
///
/// The audio is Apple's preview of the song. A viewer's app NEVER fetches it from Apple: that
/// would show Apple the IP address of everyone who opens the story. It asks the viewer's own
/// Skwod host (`POST /api/music/preview`), which fetches it and hands the bytes back. The host
/// then knows this account played this preview, now; Apple sees only the host.
///
/// By default that happens when the story opens (it starts by itself). With "Play story music
/// only when I tap" on, NOTHING is fetched until the viewer taps the song — still via the host.
enum StoryMusicPolicy {
    /// UserDefaults key of "Play story music only when I tap" (default off).
    static let tapToPlayKey = "skwod.story.tapToPlay"
    /// The one host the server fetches previews from (`server/src/music.rs`): exact, never a suffix.
    static let previewHost = "audio-ssl.itunes.apple.com"
    /// The server relays nothing larger; neither does this app accept more.
    static let maxPreviewBytes = 4 * 1024 * 1024

    /// `url` if the host will fetch it: https, no credentials, default port, Apple's preview
    /// host exactly, a preview path. The same rules the server applies — checked here so a
    /// song that cannot play says so without a request.
    static func hostFetchable(_ url: URL?) -> URL? {
        guard let url, url.scheme?.lowercased() == "https", url.user == nil, url.password == nil, url.fragment == nil,
              url.port == nil || url.port == 443, url.host?.lowercased() == previewHost,
              url.absoluteString.count <= 600, !url.absoluteString.contains(where: { $0.isWhitespace }) else { return nil }
        let path = url.path
        guard path.hasPrefix("/itunes-assets/"), !path.contains(".."),
              [".m4a", ".mp3", ".aac"].contains(where: { path.hasSuffix($0) }) else { return nil }
        return url
    }

    /// The image hosts the server fetches artwork from: exact names, never a suffix.
    static let artworkHosts: Set<String> = ["is1-ssl.mzstatic.com", "is2-ssl.mzstatic.com", "is3-ssl.mzstatic.com", "is4-ssl.mzstatic.com", "is5-ssl.mzstatic.com"]
    static let maxArtworkBytes = 300 * 1024

    /// `url` if the host will fetch it as artwork (`POST /api/music/artwork`) — the server's rules.
    static func artworkFetchable(_ url: URL?) -> URL? {
        guard let url, url.scheme?.lowercased() == "https", url.user == nil, url.password == nil, url.fragment == nil,
              url.port == nil || url.port == 443, let host = url.host?.lowercased(), artworkHosts.contains(host),
              url.absoluteString.count <= 600, !url.absoluteString.contains(where: { $0.isWhitespace }) else { return nil }
        let path = url.path.lowercased()
        guard url.path.hasPrefix("/image/thumb/"), !path.contains(".."),
              [".jpg", ".jpeg", ".png", ".webp"].contains(where: { path.hasSuffix($0) }) else { return nil }
        return url
    }

    /// UserDefaults key of "Play full songs with my Apple Music account" (default off).
    static let fullSongsKey = "skwod.music.fullSongs"

    enum CardPlayback: Equatable {
        /// The whole track, through Apple Music on this device (Apple sees which song).
        case fullTrack
        /// The ~30 s preview, fetched by this Skwod's host (Apple does not see the viewer).
        case hostPreview
    }

    /// How a song CARD (chat, feed) plays when tapped. The whole track only when the viewer
    /// turned that on AND has given Apple Music access AND has a subscription that can play
    /// the catalogue; in every other case the preview through the host. Stories never use
    /// this: they always play the poster's chosen part of the preview, through the host.
    static func cardPlayback(fullSongsOn: Bool, authorized: Bool, canPlayCatalog: Bool) -> CardPlayback {
        fullSongsOn && authorized && canPlayCatalog ? .fullTrack : .hostPreview
    }

    /// Does a song card (chat, feed) fetch its artwork — through the host — as it comes on
    /// screen? Not with tap-to-play on: then nothing about the card is fetched until its play
    /// button is tapped.
    static func cardLoadsArtwork(tapToPlay: Bool, tapped: Bool) -> Bool { !tapToPlay || tapped }

    enum OnOpen: Equatable {
        /// Ask the host for the audio now.
        case fetch
        /// Fetch nothing; show the song with a play button.
        case waitForTap
        /// Nothing will sound (a call is on, or the song has no preview the host will fetch).
        case silent
    }

    /// What happens to a story's song when the story opens (`tapped`: the viewer asked for it).
    static func onOpen(tapToPlay: Bool, tapped: Bool, inCall: Bool, hasPreview: Bool) -> OnOpen {
        if inCall || !hasPreview { return .silent }
        return tapToPlay && !tapped ? .waitForTap : .fetch
    }
}

extension MusicTrack {
    /// The preview, if this skwod's host will fetch it for the viewer.
    var hostPreviewURL: URL? { StoryMusicPolicy.hostFetchable(previewURL) }
    /// The artwork, if this skwod's host will fetch it for the viewer.
    var hostArtworkURL: URL? { StoryMusicPolicy.artworkFetchable(artworkURL) }
}

/// Which part of a song's preview a story plays: Instagram's "pick the bit" — a start and a
/// length, in milliseconds, inside the encrypted story payload. The server never sees it.
///
/// What it selects FROM is the song's preview (`MusicTrack.previewURL`, about 30 seconds, on
/// Apple's hosts): the one audio source every viewer can play — any platform, no Apple Music
/// subscription, no account. A clip therefore lies within those ~30 seconds.
///
/// Both numbers are the SENDER's. `init(from:)` brings whatever arrives inside the bounds, and
/// `window(previewMs:)` clamps once more against the real length of the audio at playback.
struct MusicClip: Codable, Hashable {
    var startMs: Int
    var durationMs: Int

    /// The lengths the composer offers (seconds).
    static let durationChoices = [5, 10, 15]
    static let defaultDurationMs = 15_000
    static let minDurationMs = 1_000
    /// A preview is ~30 s (a few are longer); nothing beyond this is ever selected or played.
    static let maxDurationMs = 30_000
    static let maxStartMs = 600_000
    /// What a preview is assumed to be until the audio itself says.
    static let assumedPreviewMs = 30_000

    /// A story with a song and no clip (builds before 45, or a clip that could not be read).
    static let fallback = MusicClip(startMs: 0, durationMs: defaultDurationMs)

    init(startMs: Int, durationMs: Int) {
        self.durationMs = min(max(durationMs, Self.minDurationMs), Self.maxDurationMs)
        self.startMs = min(max(startMs, 0), Self.maxStartMs)
    }

    /// What the composer makes: one of the offered lengths, starting where the strip was
    /// dragged to, kept inside a preview of `previewMs`.
    static func chosen(startMs: Int, durationSeconds: Int, previewMs: Int = assumedPreviewMs) -> MusicClip {
        let seconds = durationChoices.contains(durationSeconds) ? durationSeconds : defaultDurationMs / 1000
        let preview = max(previewMs, minDurationMs)
        let duration = min(seconds * 1000, preview)
        return MusicClip(startMs: min(max(startMs, 0), preview - duration), durationMs: duration)
    }

    private enum CodingKeys: String, CodingKey { case startMs, durationMs }

    /// Lenient about the numbers (an integer or a decimal; clamped), strict about the shape:
    /// both must be there and be numbers.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func number(_ key: CodingKeys) throws -> Int {
            if let i = try? c.decode(Int.self, forKey: key) { return i }
            let d = try c.decode(Double.self, forKey: key)
            guard d.isFinite else { throw DecodingError.dataCorruptedError(forKey: key, in: c, debugDescription: "not finite") }
            return Int(min(max(d, -1), Double(Self.maxStartMs + 1)))
        }
        self.init(startMs: try number(.startMs), durationMs: try number(.durationMs))
    }

    /// Where playback starts and ends (ms) in a preview that is really `previewMs` long (nil =
    /// not known yet). Never past the end of the audio, never empty.
    func window(previewMs: Int?) -> (startMs: Int, endMs: Int) {
        guard let previewMs, previewMs > 0 else { return (startMs, startMs + durationMs) }
        let duration = min(durationMs, previewMs)
        let start = min(startMs, previewMs - duration)
        return (start, start + duration)
    }
}

/// The attachment descriptor carried (E2EE) in the message body.
struct ChatAttachment: Codable, Hashable {
    enum Kind: String, Codable { case image, video, audio, file }
    var name: String
    var mime: String
    var size: Int64
    var kind: Kind
    var blobId: String
    /// The blob's single-use key — only channel/DM members ever see it. 64 bytes (AES-256 ‖
    /// HMAC-SHA256) when `digestB64` is set; a bare 32-byte AES-GCM key on attachments sent by
    /// builds ≤ 40 (decrypt-only, so old history still opens).
    var keyB64: String
    /// SHA-256 of the uploaded ciphertext. Binds this message to exactly that blob.
    var digestB64: String? = nil
    /// Small JPEG preview (images/videos) so the chat renders instantly before download.
    var thumbB64: String?
    var caption: String?
    /// Download capability for an attachment that travels in a DIRECT MESSAGE: the server only
    /// holds its hash (`download_token_hash`), so whoever can read this descriptor can fetch
    /// the blob — and the server never learns who that is. Absent on channel attachments,
    /// which the server serves to readers of the message the blob is linked to.
    var token: String? = nil
}

/// The on-wire payload (JSON after the tag).
///
/// A photo travels as an ATTACHMENT (`att`: sealed, uploaded to the blob store, linked to this
/// message so the server's members can fetch it) plus a SMALL inline thumbnail (`photoB64`) so
/// the post draws at once and builds that predate attachments in the feed still show something.
/// It is never inlined at full size: a message body over 150 kB is refused by the core.
///
/// `clip` (build 45, stories): which part of `music`'s preview plays. It sits beside the song,
/// not inside it, so builds that do not know it still read the song.
struct FeedPayload: Codable {
    var text: String?
    var music: MusicTrack?
    var photoB64: String?
    var att: ChatAttachment?
    var clip: MusicClip?
    var ts: Int64

    init(text: String? = nil, music: MusicTrack? = nil, photoB64: String? = nil, att: ChatAttachment? = nil,
         clip: MusicClip? = nil, ts: Int64) {
        self.text = text; self.music = music; self.photoB64 = photoB64; self.att = att; self.clip = clip; self.ts = ts
    }

    private enum CodingKeys: String, CodingKey { case text, music, photoB64, att, clip, ts }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        text = try c.decodeIfPresent(String.self, forKey: .text)
        music = try c.decodeIfPresent(MusicTrack.self, forKey: .music)
        photoB64 = try c.decodeIfPresent(String.self, forKey: .photoB64)
        att = try c.decodeIfPresent(ChatAttachment.self, forKey: .att)
        // The clip is an extra: one this build cannot read (a string, a negative number, a
        // shape from a later build) is dropped, and the story is still shown with its song.
        clip = (try? c.decodeIfPresent(MusicClip.self, forKey: .clip)).flatMap { $0 }
        ts = try c.decode(Int64.self, forKey: .ts)
    }
}

