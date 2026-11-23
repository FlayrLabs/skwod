import XCTest

/// Build 45: a story's song clip (the model, its place in the encrypted payload, and the JSON
/// the Android app writes), the host's upload limit as the apps apply it, and where "Start
/// server" / "Invite friends" lead on a hosting Mac. Compiled from the apps' own source files.
final class Build45Tests: XCTestCase {
    // The same literals are in the Android test (`Build45Test.kt`): each platform must read
    // what the other writes.
    /// A story as the ANDROID app writes it (org.json: slashes not escaped).
    static let androidStory = #"{"photoB64":"AAEC","music":{"id":"1440833098","title":"Song","artist":"Artist","appleMusicURL":"https://music.apple.com/us/album/x/1?i=2","artworkURL":"https://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg","previewURL":"https://audio-ssl.itunes.apple.com/itunes-assets/p.m4a"},"clip":{"startMs":7000,"durationMs":10000},"ts":1763700000000}"#
    /// A story as the APPLE app writes it (JSONEncoder).
    static let appleStory = #"{"music":{"id":"1440833098","title":"Song","artist":"Artist","artworkURL":"https:\/\/is1-ssl.mzstatic.com\/image\/thumb\/a\/200x200bb.jpg","previewURL":"https:\/\/audio-ssl.itunes.apple.com\/itunes-assets\/p.m4a","appleMusicURL":"https:\/\/music.apple.com\/us\/album\/x\/1?i=2"},"clip":{"startMs":12500,"durationMs":15000},"ts":1763700000000}"#

    private func payload(_ json: String) throws -> FeedPayload {
        try JSONDecoder().decode(FeedPayload.self, from: Data(json.utf8))
    }

    private var song: MusicTrack {
        MusicTrack(id: "1440833098", title: "Song", artist: "Artist",
                   artworkURL: URL(string: "https://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg"),
                   previewURL: URL(string: "https://audio-ssl.itunes.apple.com/itunes-assets/p.m4a"),
                   appleMusicURL: URL(string: "https://music.apple.com/us/album/x/1?i=2"))
    }

    // MARK: the clip model

    func testTheComposerOnlyMakesClipsOfTheOfferedLengthsInsideThePreview() {
        XCTAssertEqual(MusicClip.durationChoices, [5, 10, 15])
        XCTAssertEqual(MusicClip.chosen(startMs: 7000, durationSeconds: 10), MusicClip(startMs: 7000, durationMs: 10_000))
        // A start past the end is pulled back so the whole clip fits the 30 s preview.
        XCTAssertEqual(MusicClip.chosen(startMs: 29_000, durationSeconds: 15), MusicClip(startMs: 15_000, durationMs: 15_000))
        XCTAssertEqual(MusicClip.chosen(startMs: -400, durationSeconds: 5), MusicClip(startMs: 0, durationMs: 5000))
        // A length that is not offered becomes the default.
        XCTAssertEqual(MusicClip.chosen(startMs: 0, durationSeconds: 12).durationMs, 15_000)
        XCTAssertEqual(MusicClip.chosen(startMs: 0, durationSeconds: 0).durationMs, 15_000)
        // A preview shorter than the length: the clip is the whole preview.
        XCTAssertEqual(MusicClip.chosen(startMs: 3000, durationSeconds: 15, previewMs: 9000), MusicClip(startMs: 0, durationMs: 9000))
    }

    func testAClipFromSomeoneElseIsBroughtInsideTheBounds() {
        XCTAssertEqual(MusicClip(startMs: -5, durationMs: 0), MusicClip(startMs: 0, durationMs: 1000))
        XCTAssertEqual(MusicClip(startMs: .max, durationMs: .max), MusicClip(startMs: MusicClip.maxStartMs, durationMs: 30_000))
        XCTAssertEqual(MusicClip(startMs: .min, durationMs: .min), MusicClip(startMs: 0, durationMs: 1000))
    }

    func testPlaybackNeverRunsPastTheRealAudio() {
        let clip = MusicClip(startMs: 20_000, durationMs: 15_000)
        // Length not known yet: as written.
        XCTAssertEqual(clip.window(previewMs: nil).startMs, 20_000)
        XCTAssertEqual(clip.window(previewMs: nil).endMs, 35_000)
        // A 30 s preview: the window slides back to fit.
        XCTAssertEqual(clip.window(previewMs: 30_000).startMs, 15_000)
        XCTAssertEqual(clip.window(previewMs: 30_000).endMs, 30_000)
        // A preview shorter than the clip: all of it, from the start.
        XCTAssertEqual(clip.window(previewMs: 8000).startMs, 0)
        XCTAssertEqual(clip.window(previewMs: 8000).endMs, 8000)
        // A sender's absurd start cannot seek beyond the audio.
        let w = MusicClip(startMs: 599_000, durationMs: 5000).window(previewMs: 29_500)
        XCTAssertEqual(w.startMs, 24_500)
        XCTAssertEqual(w.endMs, 29_500)
        XCTAssertEqual(MusicClip.fallback.window(previewMs: 30_000).endMs, 15_000)
    }

    // MARK: in the encrypted payload

    func testTheClipIsWrittenBesideTheSongAndReadBack() throws {
        let out = FeedPayload(music: song, clip: MusicClip.chosen(startMs: 12_500, durationSeconds: 15), ts: 1_763_700_000_000)
        let json = String(data: try JSONEncoder().encode(out), encoding: .utf8)!
        // The clip is its own object of whole milliseconds, next to `music`, not inside it.
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let clip = try XCTUnwrap(object["clip"] as? [String: Any])
        XCTAssertEqual(clip["startMs"] as? Int, 12_500)
        XCTAssertEqual(clip["durationMs"] as? Int, 15_000)
        XCTAssertEqual(clip.count, 2)
        XCTAssertNil((object["music"] as? [String: Any])?["clip"])
        let back = try payload(json)
        XCTAssertEqual(back.clip, MusicClip(startMs: 12_500, durationMs: 15_000))
        XCTAssertEqual(back.music, song)
        // What this app writes means what the fixture the Android test reads says.
        let fixture = try payload(Self.appleStory)
        XCTAssertEqual(fixture.clip, back.clip)
        XCTAssertEqual(fixture.music, back.music)
        // No song picked: no clip key at all.
        let plain = String(data: try JSONEncoder().encode(FeedPayload(text: "hi", ts: 1)), encoding: .utf8)!
        XCTAssertFalse(plain.contains("clip"))
    }

    func testAStoryWrittenByTheAndroidAppPlaysTheSameClip() throws {
        let p = try payload(Self.androidStory)
        XCTAssertEqual(p.clip, MusicClip(startMs: 7000, durationMs: 10_000))
        XCTAssertEqual(p.music, song)
        XCTAssertEqual(p.music?.safePreviewURL?.host, "audio-ssl.itunes.apple.com")
        XCTAssertEqual(p.photoB64, "AAEC")
    }

    func testAStoryFromBuild44HasNoClipAndStillReads() throws {
        let p = try payload(#"{"music":{"id":"1","title":"Song","artist":"Artist"},"ts":5}"#)
        XCTAssertNil(p.clip)
        XCTAssertEqual(p.music?.title, "Song")
    }

    func testAClipThisBuildCannotReadDoesNotLoseTheStory() throws {
        for bad in [#""soon""#, "7", "null", "[1,2]", #"{"startMs":"7000","durationMs":10000}"#, #"{"startMs":7000}"#, "{}", #"{"startMs":true,"durationMs":false}"#] {
            let p = try payload(#"{"music":{"id":"1","title":"Song","artist":"Artist"},"clip":\#(bad),"ts":5}"#)
            XCTAssertNil(p.clip, bad)
            XCTAssertEqual(p.music?.title, "Song", bad)
        }
        // Numbers out of range are clamped rather than refused; decimals are read.
        let wild = try payload(#"{"ts":5,"clip":{"startMs":-3,"durationMs":99999999999}}"#)
        XCTAssertEqual(wild.clip, MusicClip(startMs: 0, durationMs: 30_000))
        let decimal = try payload(#"{"ts":5,"clip":{"startMs":7000.9,"durationMs":1.0e4}}"#)
        XCTAssertEqual(decimal.clip, MusicClip(startMs: 7000, durationMs: 10_000))
        let huge = try payload(#"{"ts":5,"clip":{"startMs":1e300,"durationMs":5000}}"#)
        XCTAssertEqual(huge.clip, MusicClip(startMs: MusicClip.maxStartMs, durationMs: 5000))
    }

    func testOnlyApplesHostsAreEverPlayed() {
        var t = song
        t.previewURL = URL(string: "https://evil.example/p.m4a")
        XCTAssertNil(t.safePreviewURL)
        t.previewURL = URL(string: "http://audio-ssl.itunes.apple.com/p.m4a")
        XCTAssertNil(t.safePreviewURL)
        t.previewURL = URL(string: "https://audio-ssl.itunes.apple.com.evil.example/p.m4a")
        XCTAssertNil(t.safePreviewURL)
    }

    // MARK: story music goes through the host

    func testOnlyAPreviewTheHostWillFetchIsEverAskedFor() {
        func ok(_ s: String) -> Bool { StoryMusicPolicy.hostFetchable(URL(string: s)) != nil }
        XCTAssertTrue(ok("https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview211/v4/cd/x/mzaf_1.plus.aac.p.m4a"))
        XCTAssertEqual(song.hostPreviewURL, song.previewURL)
        for bad in ["http://audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
                    "https://evil.example/itunes-assets/a.m4a",
                    "https://audio-ssl.itunes.apple.com.evil.example/itunes-assets/a.m4a",
                    "https://audio-ssl.itunes.apple.com@evil.example/itunes-assets/a.m4a",
                    "https://user:pw@audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
                    "https://audio-ssl.itunes.apple.com:8443/itunes-assets/a.m4a",
                    // On Apple's hosts (so the card shows it), but not the preview host: not fetched.
                    "https://is1-ssl.mzstatic.com/itunes-assets/a.m4a",
                    "https://music.apple.com/itunes-assets/a.m4a",
                    "https://audio-ssl.itunes.apple.com/other/a.m4a",
                    "https://audio-ssl.itunes.apple.com/itunes-assets/a.html",
                    "https://audio-ssl.itunes.apple.com/itunes-assets/a.m4a#x",
                    "https://127.0.0.1/itunes-assets/a.m4a"] {
            XCTAssertFalse(ok(bad), bad)
        }
        XCTAssertNil(StoryMusicPolicy.hostFetchable(nil))
    }

    func testStoryMusicStartsByItselfUnlessTheViewerChoseTapToPlay() {
        typealias P = StoryMusicPolicy
        // Default (the setting off): fetched — through the host — as the story opens.
        XCTAssertEqual(P.onOpen(tapToPlay: false, tapped: false, inCall: false, hasPreview: true), .fetch)
        // Tap-to-play: nothing is fetched until the tap; then it is.
        XCTAssertEqual(P.onOpen(tapToPlay: true, tapped: false, inCall: false, hasPreview: true), .waitForTap)
        XCTAssertEqual(P.onOpen(tapToPlay: true, tapped: true, inCall: false, hasPreview: true), .fetch)
        // Never during a call, tapped or not; never for a song the host will not fetch.
        for tapToPlay in [true, false] {
            for tapped in [true, false] {
                XCTAssertEqual(P.onOpen(tapToPlay: tapToPlay, tapped: tapped, inCall: true, hasPreview: true), .silent)
                XCTAssertEqual(P.onOpen(tapToPlay: tapToPlay, tapped: tapped, inCall: false, hasPreview: false), .silent)
            }
        }
        // The setting is off until the viewer turns it on.
        let suite = "skwod-build45-music-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertFalse(defaults.bool(forKey: P.tapToPlayKey))
        XCTAssertEqual(P.tapToPlayKey, "skwod.story.tapToPlay")
    }

    func testSongCardArtworkGoesThroughTheHostAndOnlyFromApplesImageHosts() {
        func ok(_ s: String) -> Bool { StoryMusicPolicy.artworkFetchable(URL(string: s)) != nil }
        XCTAssertTrue(ok("https://is1-ssl.mzstatic.com/image/thumb/Music112/v4/df/x/18UMGIM31076.rgb.jpg/200x200bb.jpg"))
        XCTAssertTrue(ok("https://is5-ssl.mzstatic.com/image/thumb/a/200x200bb.png"))
        XCTAssertEqual(song.hostArtworkURL, song.artworkURL)
        for bad in ["http://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg",
                    "https://mzstatic.com/image/thumb/a/200x200bb.jpg",
                    "https://evil.mzstatic.com/image/thumb/a/200x200bb.jpg",
                    "https://is6-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg",
                    "https://is1-ssl.mzstatic.com.evil.example/image/thumb/a/200x200bb.jpg",
                    "https://is1-ssl.mzstatic.com@evil.example/image/thumb/a/200x200bb.jpg",
                    "https://is1-ssl.mzstatic.com:8443/image/thumb/a/200x200bb.jpg",
                    "https://is1-ssl.mzstatic.com/other/a.jpg",
                    "https://is1-ssl.mzstatic.com/image/thumb/a/x.svg",
                    "https://audio-ssl.itunes.apple.com/image/thumb/a/200x200bb.jpg",
                    "https://127.0.0.1/image/thumb/a/200x200bb.jpg"] {
            XCTAssertFalse(ok(bad), bad)
        }
        XCTAssertNil(StoryMusicPolicy.artworkFetchable(nil))
        // The preview host is not an artwork host, and the other way round.
        XCTAssertNil(StoryMusicPolicy.hostFetchable(song.artworkURL))
        XCTAssertNil(StoryMusicPolicy.artworkFetchable(song.previewURL))
    }

    func testTapToPlayAlsoKeepsSongCardsFromFetchingAnythingUntilTapped() {
        XCTAssertTrue(StoryMusicPolicy.cardLoadsArtwork(tapToPlay: false, tapped: false))
        XCTAssertFalse(StoryMusicPolicy.cardLoadsArtwork(tapToPlay: true, tapped: false))
        XCTAssertTrue(StoryMusicPolicy.cardLoadsArtwork(tapToPlay: true, tapped: true))
    }

    func testFullSongsPlayOnlyForAViewerWhoOptedInAndCanPlayThem() {
        typealias P = StoryMusicPolicy
        XCTAssertEqual(P.cardPlayback(fullSongsOn: true, authorized: true, canPlayCatalog: true), .fullTrack)
        // Off (the default): the preview through the host, whatever the account could do.
        XCTAssertEqual(P.cardPlayback(fullSongsOn: false, authorized: true, canPlayCatalog: true), .hostPreview)
        // On, but no access given, or no subscription: the preview through the host.
        XCTAssertEqual(P.cardPlayback(fullSongsOn: true, authorized: false, canPlayCatalog: true), .hostPreview)
        XCTAssertEqual(P.cardPlayback(fullSongsOn: true, authorized: true, canPlayCatalog: false), .hostPreview)
        XCTAssertEqual(P.cardPlayback(fullSongsOn: false, authorized: false, canPlayCatalog: false), .hostPreview)
        // Off until the user turns it on; its own switch, apart from tap-to-play.
        let suite = "skwod-build45-full-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertFalse(defaults.bool(forKey: P.fullSongsKey))
        XCTAssertNotEqual(P.fullSongsKey, P.tapToPlayKey)
    }

    // MARK: the host's upload limit

    func testTheServersAnswerIsReadAndBounded() {
        func parse(_ s: String) -> Int64? { UploadLimit.parse(Data(s.utf8)) }
        let mib = UploadLimit.mib
        XCTAssertEqual(parse(#"{"max_upload_bytes":262144000,"max_upload_mb":250,"host_set":true}"#), 250 * mib)
        // The 413 carries it too.
        XCTAssertEqual(parse(#"{"error":"that file is too large","max_upload_bytes":2097152}"#), 2 * mib)
        // Outside the bounds: brought inside. Not a number: no answer.
        XCTAssertEqual(parse(#"{"max_upload_bytes":1}"#), UploadLimit.minBytes)
        XCTAssertEqual(parse(#"{"max_upload_bytes":99999999999999999999}"#), UploadLimit.maxBytes)
        XCTAssertNil(parse(#"{"max_upload_bytes":"lots"}"#))
        XCTAssertNil(parse(#"{"max_upload_bytes":true}"#))
        XCTAssertNil(parse(#"{"max_upload_bytes":-5}"#))
        XCTAssertNil(parse(#"{"max_upload_bytes":0}"#))
        XCTAssertNil(parse(#"{"error":"not found"}"#))
        XCTAssertNil(parse("not json"))
    }

    func testAFileIsCheckedAgainstTheHostsLimitBeforeItIsSent() {
        let mib = UploadLimit.mib
        XCTAssertTrue(UploadLimit.allowsUpload(size: 100 * mib, limit: UploadLimit.defaultBytes))
        XCTAssertFalse(UploadLimit.allowsUpload(size: 100 * mib + 1, limit: UploadLimit.defaultBytes))
        XCTAssertTrue(UploadLimit.allowsUpload(size: 400 * mib, limit: 500 * mib))
        XCTAssertFalse(UploadLimit.allowsUpload(size: 30 * mib, limit: 25 * mib))
        XCTAssertFalse(UploadLimit.allowsUpload(size: -1, limit: 25 * mib))
        // Encrypted in one piece (a story's photo): never over 100 MB, and never over a lower limit.
        XCTAssertFalse(UploadLimit.allowsUpload(size: 400 * mib, limit: 500 * mib, inMemory: true))
        XCTAssertTrue(UploadLimit.allowsUpload(size: 100 * mib, limit: 500 * mib, inMemory: true))
        XCTAssertFalse(UploadLimit.allowsUpload(size: 30 * mib, limit: 25 * mib, inMemory: true))
    }

    func testLoweringTheLimitNeverLocksOutFilesThatAreAlreadyThere() {
        let mib = UploadLimit.mib
        XCTAssertEqual(UploadLimit.downloadCap(limit: 25 * mib), 100 * mib)
        XCTAssertEqual(UploadLimit.downloadCap(limit: 100 * mib), 100 * mib)
        XCTAssertEqual(UploadLimit.downloadCap(limit: 500 * mib), 500 * mib)
        XCTAssertEqual(UploadLimit.downloadCap(limit: .max), UploadLimit.maxBytes)
    }

    func testAHugeServerLimitNeverRaisesWhatIsHeldInMemory() {
        let mib = UploadLimit.mib
        for limit in [100 * mib, 500 * mib, 1900 * mib, 1 << 40, Int64.max] {
            XCTAssertEqual(UploadLimit.inMemoryDownloadCap(limit: limit), 100 * mib, "\(limit)")
            XCTAssertLessThanOrEqual(UploadLimit.downloadCap(limit: limit), UploadLimit.maxBytes, "\(limit)")
        }
        XCTAssertEqual(UploadLimit.inMemoryDownloadCap(limit: 25 * mib), 100 * mib)
        // What a server can make the app believe is itself bounded.
        XCTAssertEqual(UploadLimit.parse(Data(#"{"max_upload_bytes":9223372036854775807}"#.utf8)), UploadLimit.maxBytes)
        XCTAssertEqual(UploadLimit.parse(Data(#"{"max_upload_bytes":1e30}"#.utf8)), UploadLimit.maxBytes)
    }

    func testTheRealNumberIsWhatTheUserReads() {
        let mib = UploadLimit.mib
        XCTAssertEqual(UploadLimit.label(100 * mib), "100 MB")
        XCTAssertEqual(UploadLimit.label(25 * mib), "25 MB")
        XCTAssertEqual(UploadLimit.label(1024 * mib), "1 GB")
        XCTAssertEqual(UploadLimit.label(1536 * mib), "1.5 GB")
        XCTAssertEqual(UploadLimit.label(1900 * mib), "1.9 GB")
        XCTAssertEqual(UploadLimit.tooLargeSentence(limit: 250 * mib), "That file is too large — this Skwod's host allows up to 250 MB per file.")
        XCTAssertTrue(UploadLimit.hostChoicesMB.allSatisfy { (1...1900).contains($0) })
    }

    func testEachSkwodKeepsItsOwnLimitAndAnOldServerMeansTheOldCap() throws {
        let suite = "skwod-build45-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let mib = UploadLimit.mib
        let (a, b) = ("ws-a-\(suite)", "ws-b-\(suite)")
        UploadLimit.activate(workspace: a, defaults: defaults)
        XCTAssertEqual(UploadLimit.current, 100 * mib, "nothing learned yet")
        UploadLimit.learned(500 * mib, workspace: a, defaults: defaults)
        XCTAssertEqual(UploadLimit.current, 500 * mib)
        // Another skwod's answer does not change the one in front…
        UploadLimit.learned(25 * mib, workspace: b, defaults: defaults)
        XCTAssertEqual(UploadLimit.current, 500 * mib)
        // …and is there when that skwod comes to the front, and back again.
        UploadLimit.activate(workspace: b, defaults: defaults)
        XCTAssertEqual(UploadLimit.current, 25 * mib)
        UploadLimit.activate(workspace: a, defaults: defaults)
        XCTAssertEqual(UploadLimit.current, 500 * mib)
        // A server that does not know the question (older than build 45): the old 100 MB.
        UploadLimit.learned(nil, workspace: a, defaults: defaults)
        XCTAssertEqual(UploadLimit.current, 100 * mib)
    }

    // MARK: where Start server and Invite friends lead

    func testWithoutAnOwnerEveryEntryPointLeadsToTheSetup() {
        typealias D = HostSetupRoute.Decision
        // The menu bar's Start on a fresh Mac: start, and set up (build 44 only started).
        XCTAssertEqual(HostSetupRoute.decide(.startServer, hasOwnerWorkspace: false, serverUp: false), D(screen: .setupWizard, startServer: true))
        // The server is already up with no owner (started by build 44's menu): Invite must not
        // open a panel that has nobody to make the invite.
        XCTAssertEqual(HostSetupRoute.decide(.inviteFriends, hasOwnerWorkspace: false, serverUp: true), D(screen: .setupWizard, startServer: false))
        XCTAssertEqual(HostSetupRoute.decide(.inviteFriends, hasOwnerWorkspace: false, serverUp: false), D(screen: .setupWizard, startServer: true))
        XCTAssertEqual(HostSetupRoute.decide(.startServer, hasOwnerWorkspace: false, serverUp: true), D(screen: .setupWizard, startServer: false))
        for action in [HostSetupRoute.Action.startServer, .inviteFriends] {
            for up in [true, false] {
                XCTAssertNotEqual(HostSetupRoute.decide(action, hasOwnerWorkspace: false, serverUp: up).screen, .invitePanel)
            }
        }
    }

    func testOnceSetUpStartAndInviteBehaveAsBefore() {
        typealias D = HostSetupRoute.Decision
        XCTAssertEqual(HostSetupRoute.decide(.startServer, hasOwnerWorkspace: true, serverUp: false), D(screen: .none, startServer: true))
        XCTAssertEqual(HostSetupRoute.decide(.startServer, hasOwnerWorkspace: true, serverUp: true), D(screen: .none, startServer: false))
        XCTAssertEqual(HostSetupRoute.decide(.inviteFriends, hasOwnerWorkspace: true, serverUp: true), D(screen: .invitePanel, startServer: false))
        // Nothing to invite to while the server is off: the wizard is where it gets started.
        XCTAssertEqual(HostSetupRoute.decide(.inviteFriends, hasOwnerWorkspace: true, serverUp: false), D(screen: .setupWizard, startServer: false))
    }

    // MARK: deleting a skwod's local data takes everything kept under its id

    func testWipingASkwodDeletesItsCacheKeyItsMutesAndEverythingElseKeptUnderItsId() {
        let (suite, sharedSuite) = ("skwod-build45-wipe-\(UUID().uuidString)", "skwod-build45-wipe-shared-\(UUID().uuidString)")
        let defaults = UserDefaults(suiteName: suite)!
        let shared = UserDefaults(suiteName: sharedSuite)!
        defer { defaults.removePersistentDomain(forName: suite); shared.removePersistentDomain(forName: sharedSuite) }
        let (a, b) = ("ws-a", "ws-b")
        // A Keychain stand-in holding what the app stores for two skwods.
        var secrets: [String: String] = ["workspaces": "[]"]
        for id in [a, b] {
            secrets[KeyAccess.cacheKeyPrefix + id] = String(repeating: "ab", count: 32)
            secrets[KeyAccess.mutesPrefix + id] = #"{"dm:someone":-1}"#
            secrets[KeyAccess.skwodMutePrefix + id] = "-1"
            secrets[KeyAccess.notifNamesPrefix + id] = #"{"dm:someone":"Someone"}"#
            secrets[KeyAccess.notifSendersPrefix + id] = #"{"dm:someone":["u1"]}"#
            secrets[KeyAccess.retiredMuteConvsPrefix + id] = "1"
            defaults.set(true, forKey: WorkspaceItems.removedDevicePrefix + id)
            UploadLimit.learned(250 * UploadLimit.mib, workspace: id, defaults: defaults)
            for what in ["names", "senders", "seen", "announced"] { shared.set("x", forKey: WorkspaceItems.sharedDefaultsPrefix(id) + what) }
        }
        shared.set(["dm:someone": 1.0], forKey: WorkspaceItems.soundLedgerKey)
        shared.set(false, forKey: "notif.showPreviews")

        WorkspaceItems.wipe(workspaceId: a, deleteSecret: { secrets[$0] = nil }, defaults: defaults, shared: shared)

        // Nothing of the wiped skwod is left: not its key, and not who was muted in it.
        XCTAssertNil(secrets[KeyAccess.cacheKeyPrefix + a])
        XCTAssertNil(secrets[KeyAccess.mutesPrefix + a], "the muted conversations of an erased skwod were kept")
        XCTAssertNil(secrets[KeyAccess.skwodMutePrefix + a], "the mute of an erased skwod was kept")
        XCTAssertNil(secrets[KeyAccess.notifNamesPrefix + a], "the conversation titles of an erased skwod were kept")
        XCTAssertNil(secrets[KeyAccess.notifSendersPrefix + a], "the sender sets of an erased skwod were kept")
        XCTAssertFalse(secrets.keys.contains { $0.hasSuffix(a) })
        XCTAssertFalse(defaults.dictionaryRepresentation().keys.contains { $0.hasSuffix(a) })
        XCTAssertFalse(shared.dictionaryRepresentation().keys.contains { $0.contains(a) })
        XCTAssertNil(shared.object(forKey: WorkspaceItems.soundLedgerKey))
        // The other skwod, the workspace list and the settings are untouched.
        XCTAssertEqual(secrets.keys.filter { $0.hasSuffix(b) }.count, 6)
        XCTAssertNotNil(secrets["workspaces"])
        XCTAssertEqual(defaults.dictionaryRepresentation().keys.filter { $0.hasSuffix(b) }.count, 2)
        XCTAssertEqual(shared.dictionaryRepresentation().keys.filter { $0.hasPrefix(WorkspaceItems.sharedDefaultsPrefix(b)) }.count, 4)
        XCTAssertEqual(shared.object(forKey: "notif.showPreviews") as? Bool, false)
        // No id, nothing deleted (an empty id must never match every item by prefix).
        WorkspaceItems.wipe(workspaceId: "", deleteSecret: { secrets[$0] = nil }, defaults: defaults, shared: shared)
        XCTAssertEqual(secrets.count, 7)
    }

    /// Every per-skwod Keychain prefix `KeyAccess` knows is one the wipe deletes: an item
    /// added there without being added to `WorkspaceItems` fails here.
    func testEveryPerSkwodKeychainItemIsOnTheWipeList() {
        for prefix in [KeyAccess.cacheKeyPrefix, KeyAccess.mutesPrefix, KeyAccess.skwodMutePrefix,
                       KeyAccess.notifNamesPrefix, KeyAccess.notifSendersPrefix, KeyAccess.retiredMuteConvsPrefix] {
            XCTAssertTrue(WorkspaceItems.keychainPrefixes.contains(prefix), prefix)
        }
        XCTAssertEqual(Set(WorkspaceItems.keychainAccounts("w")),
                       ["cache-key-w", "mutes-w", "mute-skwod-w", "notif-names-w", "notif-senders-w", "mute-convs-w"])
        // Every Keychain item whose class follows the cache key is kept per skwod, so it is wiped.
        for prefix in [KeyAccess.notifNamesPrefix, KeyAccess.notifSendersPrefix] {
            XCTAssertTrue(KeyAccess.followsCacheKey(prefix + "w"))
        }
        XCTAssertEqual(Set(WorkspaceItems.defaultsKeys("w")), ["skwod.removedDevice.w", "skwod.uploadLimit.w"])
    }

    // MARK: a contact's changed key: held, accepted, never "sent"

    func testTheConversationBannerFollowsTheContactsStatusNotTheNotice() {
        typealias H = IdentityHold
        // Nothing held (also after a refused impersonation: the notice came, nothing changed).
        XCTAssertEqual(H.decide(sendsHeld: false, devices: 1, unvouchedDevices: 0, failedOnIdentity: false), .none)
        // Verified, then their devices changed: on hold.
        XCTAssertEqual(H.decide(sendsHeld: true, devices: 2, unvouchedDevices: 0, failedOnIdentity: false), .onHold)
        // Replaced phone: the only device left is one nobody of theirs vouched for — on hold too.
        XCTAssertEqual(H.decide(sendsHeld: false, devices: 0, unvouchedDevices: 1, failedOnIdentity: false), .onHold)
        // A new, unvouched device next to one that still gets messages.
        XCTAssertEqual(H.decide(sendsHeld: false, devices: 1, unvouchedDevices: 1, failedOnIdentity: false), .unacceptedDevice)
        // A send that failed on their keys holds the conversation whatever the status says.
        XCTAssertEqual(H.decide(sendsHeld: false, devices: 1, unvouchedDevices: 0, failedOnIdentity: true), .onHold)
        XCTAssertEqual(H.onHold.headline(name: "Sam"), "Sam's security key changed. Messages to them are on hold until you accept or verify.")
        XCTAssertNil(H.none.headline(name: "Sam"))
        // The core outbox's sentence for a send refused on the contact's keys.
        XCTAssertTrue(H.isIdentityFailure("Their safety number changed. Check it, then send again."))
        XCTAssertFalse(H.isIdentityFailure("That is too big to send."))
    }

    // MARK: a call push and a muted skwod

    func testACallPushIsQuietOnlyWhenEverySkwodItCouldBeFromIsMuted() {
        let two: [(id: String, wakeTag: String?)] = [("a", "tag-a"), ("b", "tag-b")]
        let muted: (Set<String>) -> (String) -> Bool = { set in { set.contains($0) } }
        // The tag names the skwod: its mute alone decides.
        XCTAssertTrue(MuteList.wakeIsMuted(tag: "tag-a", signedIn: two, skwodIsMuted: muted(["a"])))
        XCTAssertFalse(MuteList.wakeIsMuted(tag: "tag-b", signedIn: two, skwodIsMuted: muted(["a"])))
        // No tag (an older gateway), or one nobody owns: quiet only if all are muted.
        XCTAssertFalse(MuteList.wakeIsMuted(tag: nil, signedIn: two, skwodIsMuted: muted(["a"])))
        XCTAssertFalse(MuteList.wakeIsMuted(tag: "", signedIn: two, skwodIsMuted: muted(["a"])))
        XCTAssertFalse(MuteList.wakeIsMuted(tag: "unknown", signedIn: two, skwodIsMuted: muted(["a"])))
        XCTAssertTrue(MuteList.wakeIsMuted(tag: nil, signedIn: two, skwodIsMuted: muted(["a", "b"])))
        // A skwod without a tag is never taken for the owner of an empty one.
        XCTAssertFalse(MuteList.wakeIsMuted(tag: "", signedIn: [("a", ""), ("b", nil)], skwodIsMuted: muted(["a"])))
        // Nothing readable (before the first unlock, or signed in nowhere): it rings.
        XCTAssertFalse(MuteList.wakeIsMuted(tag: "tag-a", signedIn: [], skwodIsMuted: { _ in true }))
    }

    // MARK: "Waiting to restore"

    /// A contested restore request (another install asked to restore the same device) never
    /// completes by the hold: the line says it waits for an approval, with no countdown.
    func testAContestedRestoreWaitsForAnApprovalAndPromisesNoCountdown() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let inSevenDays = Int64((1_000_000 + 7 * 86_400) * 1000)
        XCTAssertEqual(RestoreWaitLine.text(completesAt: inSevenDays, contested: false, now: now), "Or wait: it completes by itself in 7 days.")
        XCTAssertEqual(RestoreWaitLine.text(completesAt: inSevenDays, contested: true, now: now), "Waiting for approval on one of your devices.")
        XCTAssertEqual(RestoreWaitLine.text(completesAt: nil, contested: true, now: now), "Waiting for approval on one of your devices.")
        XCTAssertNil(RestoreWaitLine.text(completesAt: nil, contested: false, now: now), "nothing until the server has said")
        XCTAssertFalse(RestoreWaitLine.text(completesAt: inSevenDays, contested: true, now: now)!.contains("day"))
    }
}
