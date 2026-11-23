import XCTest

/// Build 45 audit (Apple A1, A2, A3, A6): what keeps one skwod's base URL, session, cache file
/// and server answers out of another's. Compiled from the apps' own source file.
final class WorkspaceIsolationTests: XCTestCase {
    // MARK: A1 — the base URL belongs to the workspace it was resolved for

    func testABaseResolvedForOneSkwodIsNeverTheBaseOfAnother() {
        let a = LiveBase(workspaceId: "skwod-a", url: "https://a.example")
        XCTAssertEqual(LiveBase.url(a, for: "skwod-a"), "https://a.example")
        // Mid-switch: `current` is already B, A's base is still the one that was resolved.
        XCTAssertEqual(LiveBase.url(a, for: "skwod-b"), "", "B's token would be sent to A's server")
        XCTAssertEqual(LiveBase.url(a, for: nil), "")
        XCTAssertEqual(LiveBase.url(nil, for: "skwod-a"), "")
    }

    // MARK: A2 — a server's instance id is never a path

    func testOnlyPlainIdsAreUsedAsWritten() {
        // Every id the app has ever made: the 16-hex address slug, the server's 32-hex
        // instance id, a lowercased UUID. Their cache files keep their names.
        for id in ["9f86d081884c7d65", "0123456789abcdef0123456789abcdef", "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"] {
            XCTAssertTrue(WorkspaceIdRule.isSafe(id), id)
            XCTAssertEqual(WorkspaceIdRule.fileComponent(for: id), id)
            XCTAssertEqual(WorkspaceIdRule.acceptedInstanceId(id), id)
        }
    }

    func testAServerSuppliedPathIsRefusedAndNeverReachesAFileName() {
        let hostile = ["uploads/../skwod-9f86d081884c7d65", "../x", "a/b", "a\\b", "..", ".", "", "a b", "a.b", "é",
                       "a\u{0}b", String(repeating: "a", count: 65), "a%2fb", "~", "a:b"]
        for id in hostile {
            XCTAssertFalse(WorkspaceIdRule.isSafe(id), id)
            XCTAssertNil(WorkspaceIdRule.acceptedInstanceId(id), id)
            let part = WorkspaceIdRule.fileComponent(for: id)
            XCTAssertTrue(WorkspaceIdRule.isSafe(part), "what stands in for \(id) must itself be plain")
            XCTAssertNotEqual(part, id)
            // The cache file stays inside its directory whatever the id says.
            let dir = URL(fileURLWithPath: "/tmp/skwod-test-dir", isDirectory: true)
            let file = dir.appendingPathComponent("skwod-\(part).sqlite3").standardizedFileURL
            XCTAssertEqual(file.deletingLastPathComponent().path, dir.standardizedFileURL.path)
        }
        XCTAssertNil(WorkspaceIdRule.acceptedInstanceId(nil))
        // Two different hostile ids never share a file.
        XCTAssertNotEqual(WorkspaceIdRule.fileComponent(for: "../a"), WorkspaceIdRule.fileComponent(for: "../b"))
    }

    // MARK: A3 — a live event never deletes local history

    func testChannelClearedFromTheServerOnlyRefreshes() {
        XCTAssertEqual(ChannelEventRule.action(for: "channel_cleared"), .refresh)
        XCTAssertEqual(ChannelEventRule.action(for: "message"), .refreshAndConsiderNotifying)
        for e in ["message_update", "message_delete", "reaction"] { XCTAssertEqual(ChannelEventRule.action(for: e), .refresh) }
        XCTAssertEqual(ChannelEventRule.action(for: "purge_everything"), .ignore)
    }

    // MARK: A6 — a server's answer is written only where it was asked

    func testAnAnswerHeldAcrossASwitchOrARebindIsDropped() {
        XCTAssertNil(BindTicket(workspaceId: nil, turn: 3), "no client bound: nobody was asked")
        let asked = BindTicket(workspaceId: "skwod-a", turn: 3)!
        XCTAssertTrue(asked.isCurrent(workspaceId: "skwod-a", turn: 3))
        XCTAssertFalse(asked.isCurrent(workspaceId: "skwod-b", turn: 4), "the user switched skwods")
        XCTAssertFalse(asked.isCurrent(workspaceId: "skwod-a", turn: 5), "the same skwod, but another client")
        XCTAssertFalse(asked.isCurrent(workspaceId: nil, turn: nil), "signed out")
    }

    func testEventsOnTopicsThatWereNeverAskedForAreNotHeard() {
        let wanted: Set<String> = ["user:me", "channel:c1", "server:s1"]
        XCTAssertTrue(RealtimeTopicRule.accepts(topic: "channel:c1", wanted: wanted))
        XCTAssertTrue(RealtimeTopicRule.accepts(topic: "user:me", wanted: wanted))
        XCTAssertFalse(RealtimeTopicRule.accepts(topic: "channel:other", wanted: wanted))
        XCTAssertFalse(RealtimeTopicRule.accepts(topic: "user:someone-else", wanted: wanted))
        XCTAssertFalse(RealtimeTopicRule.accepts(topic: "channel:c1", wanted: []))
    }

    // MARK: A7 — a tapped link dials nobody

    func testALinkFromOutsideIsNotCheckedWithItsHostUntilTheUserSubmits() {
        XCTAssertFalse(InviteDialRule.mayDialBeforeSubmit(.outsideLink))
        XCTAssertTrue(InviteDialRule.mayDialBeforeSubmit(.userAction))
        let link = "https://evil.example#code"
        XCTAssertFalse(InviteDialRule.mayProbe(entry: link, outsideEntry: link))
        XCTAssertFalse(InviteDialRule.mayProbe(entry: " " + link + "\n", outsideEntry: link))
        // The user changed the field themselves, or nothing arrived from outside.
        XCTAssertTrue(InviteDialRule.mayProbe(entry: "https://friend.example", outsideEntry: link))
        XCTAssertTrue(InviteDialRule.mayProbe(entry: link, outsideEntry: nil))
    }

    // MARK: A12 — app lock is not a preference

    func testAppLockSettingsFailLockedAndOnlyMigrateOnce() {
        // The stored item decides, whatever the old preference says (`defaults write … false`).
        let on = AppLockSetting(enabled: true, afterSeconds: 300)
        XCTAssertEqual(AppLockSetting.resolve(stored: .value(on.encoded!), legacyEnabled: false, legacyDelay: 3600).setting, on)
        XCTAssertFalse(AppLockSetting.resolve(stored: .value(on.encoded!), legacyEnabled: false, legacyDelay: nil).migrate)
        // No item yet: the old preference, once, and it is written to the item.
        let moved = AppLockSetting.resolve(stored: .absent, legacyEnabled: true, legacyDelay: nil)
        XCTAssertEqual(moved.setting, AppLockSetting(enabled: true, afterSeconds: AppLockSetting.defaultDelay))
        XCTAssertTrue(moved.migrate)
        XCTAssertFalse(AppLockSetting.resolve(stored: .absent, legacyEnabled: false, legacyDelay: 60).setting.enabled)
        // There but unreadable, or not what the app wrote: locked, at once.
        for stored in [AppLockSetting.Stored.unreadable, .value("{}"), .value("garbage")] {
            let r = AppLockSetting.resolve(stored: stored, legacyEnabled: false, legacyDelay: 3600)
            XCTAssertEqual(r.setting, AppLockSetting(enabled: true, afterSeconds: 0))
            XCTAssertFalse(r.migrate)
        }
    }

    func testLockingLaterNeedsTheOwnerLockingSoonerDoesNot() {
        XCTAssertTrue(AppLockSetting.delayChangeNeedsAuthentication(from: 60, to: 3600))
        XCTAssertTrue(AppLockSetting.delayChangeNeedsAuthentication(from: 0, to: 60))
        XCTAssertFalse(AppLockSetting.delayChangeNeedsAuthentication(from: 3600, to: 0))
        XCTAssertFalse(AppLockSetting.delayChangeNeedsAuthentication(from: 60, to: 60))
    }

    // MARK: A14 — a cached attachment is only found by the same content

    func testACopyDecryptedForOneMessageIsNotHandedBackForAnother() {
        let mine = AttachmentCacheName.fileName(blobId: "b1", digestB64: "ZGlnZXN0QQ==", keyB64: "a2V5QQ==", safeName: "photo.jpg")
        let theirs = AttachmentCacheName.fileName(blobId: "b1", digestB64: "ZGlnZXN0Qg==", keyB64: "a2V5Qg==", safeName: "photo.jpg")
        XCTAssertNotEqual(mine, theirs, "same blob id and name, other content: another file")
        XCTAssertNotEqual(mine, AttachmentCacheName.fileName(blobId: "b1", digestB64: "ZGlnZXN0QQ==", keyB64: "a2V5Qg==", safeName: "photo.jpg"))
        XCTAssertNotEqual(mine, AttachmentCacheName.fileName(blobId: "b1", digestB64: nil, keyB64: "a2V5QQ==", safeName: "photo.jpg"))
        XCTAssertEqual(mine, AttachmentCacheName.fileName(blobId: "b1", digestB64: "ZGlnZXN0QQ==", keyB64: "a2V5QQ==", safeName: "photo.jpg"))
        XCTAssertTrue(mine.hasPrefix("b1-") && mine.hasSuffix("-photo.jpg"))
        // The tag itself is plain: it never adds a path.
        XCTAssertTrue(WorkspaceIdRule.isSafe(AttachmentCacheName.contentTag(digestB64: "../x", keyB64: "/")))
    }

    // MARK: A15 — only the image formats phones make

    func testInboundImagesAreAFewFormatsOfABoundedSize() {
        for ok in ["public.jpeg", "public.png", "public.heic", "public.heif", "com.compuserve.gif", "org.webmproject.webp"] {
            XCTAssertTrue(InboundImageRule.allowed(typeIdentifier: ok), ok)
        }
        for no in ["public.tiff", "com.adobe.photoshop-image", "com.adobe.pdf", "public.svg-image", "com.apple.icns",
                   "com.adobe.raw-image", "com.microsoft.bmp", "public.jpeg-2000", "com.ilm.openexr-image", ""] {
            XCTAssertFalse(InboundImageRule.allowed(typeIdentifier: no), no)
        }
        XCTAssertFalse(InboundImageRule.allowed(typeIdentifier: nil))
        XCTAssertTrue(InboundImageRule.plausible(width: 8064, height: 6048), "a 48 MP phone photo")
        XCTAssertFalse(InboundImageRule.plausible(width: 8000, height: 8000), "64 MP")
        XCTAssertFalse(InboundImageRule.plausible(width: 60_000, height: 60_000))
        XCTAssertFalse(InboundImageRule.plausible(width: 0, height: 10))
        XCTAssertFalse(InboundImageRule.plausible(width: 70_000, height: 1))
    }
}
