#if DEBUG
import Foundation
import LiveKit
import AVFoundation
import CoreVideo
import CoreGraphics
import CoreText
import CoreImage
#if os(macOS)
import AppKit
#endif

extension Notification.Name {
    /// DEBUG end-to-end hooks → the open call (`object` is the command word).
    static let skwodE2ECallCommand = Notification.Name("skwod.e2e.call-command")
    /// Open the safety-number screen of the DM on screen (E2E `showsafety`).
    static let skwodE2EShowSafety = Notification.Name("skwod.e2e.show-safety")
    /// Open the member list of the channel on screen (E2E `showmembers`).
    static let skwodE2EShowMembers = Notification.Name("skwod.e2e.show-members")
    /// Open the full-size view of every picture attachment on screen (what a tap does).
    static let skwodE2EShowAttachment = Notification.Name("skwod.e2e.show-attachment")
    /// The channel on screen pages one step further back ("Load older messages").
    static let skwodE2ELoadOlder = Notification.Name("skwod.e2e.load-older")
    /// The Feed screen posts through its own model. `object`: ["text": String, "photo": Data?].
    static let skwodE2EFeedPost = Notification.Name("skwod.e2e.feed-post")
}

/// What the call code learned, for the DEBUG end-to-end checks (written to `call.json` by
/// `E2E.drive`; never shown, never logged, compiled out of Release).
@MainActor
enum CallDebug {
    static weak var session: CallSession?
    /// track sid → the frame cryptor's last reported state ("ok", "missing_key", …).
    static var e2ee: [String: String] = [:]
    static var rang: Int?
    /// Why the last join failed (the UI shows a generic sentence; the cause can carry an address).
    static var lastError: String?
    static var lastRing: [String: Any]?
    /// What CallKit was asked and what it answered (iOS).
    static var callKit: [String: Any] = [:]

    /// Make the media engine gather a candidate on the loopback interface too (it ignores that
    /// interface by default). The LiveKit SDK has no switch for it, so this reaches the WebRTC
    /// factory through the Objective-C runtime: every peer connection is created with the
    /// factory option `ignoreLoopbackNetworkAdapter = NO`.
    ///
    /// Why a test run needs it: on iOS the engine only uses the interfaces the system's path
    /// monitor calls available. With a full-tunnel VPN on the Mac that is the VPN interface
    /// alone, and a socket bound to the VPN address cannot exchange packets with `127.0.0.1` —
    /// which is where a local SFU (and the p2p tunnel's forwarder) listens.
    static func gatherLoopbackCandidates() {
        guard let factory = NSClassFromString("LKRTCPeerConnectionFactory"),
              let options = NSClassFromString("LKRTCPeerConnectionFactoryOptions") as? NSObject.Type else { return }
        let selector = NSSelectorFromString("peerConnectionWithConfiguration:constraints:delegate:")
        guard let method = class_getInstanceMethod(factory, selector) else { return }
        typealias Original = @convention(c) (AnyObject, Selector, AnyObject, AnyObject, AnyObject?) -> AnyObject?
        let original = unsafeBitCast(method_getImplementation(method), to: Original.self)
        let replacement: @convention(block) (AnyObject, AnyObject, AnyObject, AnyObject?) -> AnyObject? = { me, configuration, constraints, delegate in
            let o = options.init()
            o.setValue(false, forKey: "ignoreLoopbackNetworkAdapter")
            _ = me.perform(NSSelectorFromString("setOptions:"), with: o)
            return original(me, selector, configuration, constraints, delegate)
        }
        method_setImplementation(method, imp_implementationWithBlock(replacement))
    }

    /// track sid → a tap on a REMOTE camera track's decoded frames (what this device could
    /// decrypt and decode), saved as `remote-video-<sid>.png` next to `call.json`.
    private static var grabbers: [String: FrameGrabber] = [:]

    /// Save the newest decoded frame of every remote camera track.
    static func saveRemoteFrames(to dir: URL) {
        guard let s = session else { grabbers = [:]; return }
        for p in s.room.remoteParticipants.values {
            for pub in p.videoTracks {
                guard let track = pub.track as? VideoTrack else { continue }
                let sid = pub.sid.stringValue
                if grabbers[sid] == nil {
                    let g = FrameGrabber()
                    grabbers[sid] = g
                    track.add(videoRenderer: g)
                }
                if let png = grabbers[sid]?.png() {
                    try? png.write(to: dir.appendingPathComponent("remote-video-\(sid).png"), options: .atomic)
                }
            }
        }
    }

    #if os(macOS)
    /// Save a picture of each of this app's own windows (`window-<n>.png`), drawn by the app
    /// itself from its view tree — no screen capture, so no screen-recording permission. Video
    /// surfaces are drawn by the GPU and come out empty here; `remote-video-*.png` covers those.
    static func saveWindows(to dir: URL) {
        let windows = NSApp.windows.filter { $0.isVisible && $0.frame.width > 300 && $0.frame.height > 300 }
        for (i, window) in windows.enumerated() {
            guard let view = window.contentView, let layer = view.layer else { continue }
            let scale = window.backingScaleFactor
            let width = Int(view.bounds.width * scale), height = Int(view.bounds.height * scale)
            guard width > 0, height > 0, let ctx = CGContext(
                data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { continue }
            ctx.setFillColor(red: 0.05, green: 0.05, blue: 0.09, alpha: 1)
            ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
            ctx.scaleBy(x: scale, y: scale)
            if !view.isFlipped {
                layer.render(in: ctx)
            } else {
                ctx.translateBy(x: 0, y: view.bounds.height)
                ctx.scaleBy(x: 1, y: -1)
                layer.render(in: ctx)
            }
            guard let image = ctx.makeImage() else { continue }
            if let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) {
                try? png.write(to: dir.appendingPathComponent("window-\(i).png"), options: .atomic)
            }
        }
    }
    #endif

    static func snapshot(app: AppState) -> [String: Any] {
        var out: [String: Any] = [
            "activeCall": app.activeCall?.serverId ?? NSNull(),
            "incomingCall": app.incomingCall.map { ["server_id": $0.serverId, "channel_id": $0.channelId, "label": $0.label] } ?? NSNull(),
            "lastRing": lastRing ?? NSNull(),
            "rang": rang ?? NSNull(),
            "callKit": callKit,
            "lastError": lastError ?? NSNull(),
        ]
        guard let s = session else { out["phase"] = "idle"; return out }
        switch s.phase {
        case .preparing: out["phase"] = "preparing"
        case .connecting: out["phase"] = "connecting"
        case .connected: out["phase"] = "connected"
        case .failed: out["phase"] = "failed"; out["error"] = s.errorText
        }
        out["channelId"] = s.channelId
        out["micOn"] = s.micOn
        out["cameraOn"] = s.camOn
        out["keysRegistered"] = s.keysRegistered
        out["blockedUnencrypted"] = s.blockedUnencrypted
        out["sendingKeyIndex"] = s.sendingKeyIndex
        out["syntheticVideo"] = SyntheticMedia.videoWanted
        out["syntheticAudio"] = SyntheticMedia.audioWanted
        out["local"] = s.room.localParticipant.trackPublications.values.map(describe)
        out["remotes"] = s.room.remoteParticipants.values.map { p in
            ["identity": p.identity?.stringValue ?? "", "tracks": p.trackPublications.values.map(describe)] as [String: Any]
        }
        return out
    }

    private static func describe(_ pub: TrackPublication) -> [String: Any] {
        var d: [String: Any] = [
            "sid": pub.sid.stringValue,
            "kind": pub.kind == .video ? "video" : "audio",
            "source": pub.source == .camera ? "camera" : (pub.source == .microphone ? "microphone" : "other"),
            "encryption": String(describing: pub.encryptionType),
            "e2eeState": e2ee[pub.sid.stringValue] ?? "unknown",
            "subscribed": pub.isSubscribed,
            "muted": pub.isMuted,
        ]
        if let g = grabbers[pub.sid.stringValue] { d["framesRendered"] = g.count }
        if let inbound = pub.track?.statistics?.inboundRtpStream.first {
            if let v = inbound.bytesReceived { d["bytesReceived"] = v }
            if let v = inbound.framesDecoded { d["framesDecoded"] = v }
            if let v = inbound.frameWidth { d["frameWidth"] = v }
            if let v = inbound.frameHeight { d["frameHeight"] = v }
            if let v = inbound.audioLevel { d["audioLevel"] = v }
            if let v = inbound.totalAudioEnergy { d["totalAudioEnergy"] = v }
            if let v = inbound.totalSamplesReceived { d["totalSamplesReceived"] = v }
        }
        return d
    }
}

/// Keeps the newest decoded frame of one remote video track.
final class FrameGrabber: NSObject, VideoRenderer, @unchecked Sendable {
    @MainActor var isAdaptiveStreamEnabled: Bool { false }
    @MainActor var adaptiveStreamSize: CGSize { .zero }

    private let lock = NSLock()
    private var latest: CVPixelBuffer?
    private var frames = 0

    var count: Int { lock.lock(); defer { lock.unlock() }; return frames }

    nonisolated func render(frame: VideoFrame) {
        guard let buffer = frame.toCVPixelBuffer() else { return }
        lock.lock()
        latest = buffer
        frames += 1
        lock.unlock()
    }

    func png() -> Data? {
        lock.lock()
        let buffer = latest
        lock.unlock()
        guard let buffer else { return nil }
        let image = CIImage(cvPixelBuffer: buffer)
        return CIContext().pngRepresentation(of: image, format: .RGBA8, colorSpace: CGColorSpaceCreateDeviceRGB())
    }
}

/// DEBUG-only stand-ins for the camera and the microphone, for end-to-end runs where there is no
/// device to capture from (the iOS Simulator has no camera) or where touching the real ones would
/// put a permission prompt on the machine running the test. The tracks they publish go through
/// the room's E2EE exactly like real ones. Compiled out of Release.
///
/// - video: always in the Simulator; elsewhere only with `SKWOD_E2E_SYNTHETIC_MEDIA=1`.
/// - audio: only with `SKWOD_E2E_SYNTHETIC_MEDIA=1` (generated beeps, no audio device opened).
@MainActor
final class SyntheticMedia {
    private static var requested: Bool { E2E.env("SKWOD_E2E_SYNTHETIC_MEDIA") == "1" }

    static var videoWanted: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return requested
        #endif
    }

    static var audioWanted: Bool { requested }

    private var videoTimer: DispatchSourceTimer?
    private var toneTimer: DispatchSourceTimer?
    /// Manual rendering is switched on once and left on for the life of the process: switching
    /// the engine back and forth between calls leaves the second call silent.
    private static var manualAudio = false
    private let queue = DispatchQueue(label: "io.skwod.e2e.synthetic-media")

    // MARK: audio

    /// Put the audio engine in manual-rendering mode: no input or output device is opened.
    func prepareAudio() -> Bool {
        if Self.manualAudio { return true }
        do {
            try AudioManager.shared.setManualRenderingMode(true)
            Self.manualAudio = true
            return true
        } catch {
            return false
        }
    }

    /// Feed short beeps (three pitches, with gaps) into the published microphone track — not a
    /// steady tone, which noise suppression flattens to almost nothing.
    func startTone() {
        guard Self.manualAudio, toneTimer == nil,
              let format = AVAudioFormat(commonFormat: .pcmFormatFloat32, sampleRate: 48_000, channels: 1, interleaved: false) else { return }
        var phase = 0.0
        var tick = 0
        let pitches = [440.0, 660.0, 880.0]
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 0.2, repeating: .milliseconds(10))
        timer.setEventHandler {
            guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: 480),
                  let samples = buffer.floatChannelData?[0] else { return }
            buffer.frameLength = 480
            tick += 1
            // 250 ms per beep: 200 ms of sound, 50 ms of silence.
            let slot = tick % 25
            let step = 2.0 * Double.pi * pitches[(tick / 25) % pitches.count] / 48_000.0
            for i in 0..<480 {
                samples[i] = slot < 20 ? Float(sin(phase)) * 0.3 : 0
                phase += step
            }
            AudioManager.shared.mixer.capture(appAudio: buffer)
        }
        timer.resume()
        toneTimer = timer
    }

    // MARK: video

    /// Publish a generated picture as this participant's camera track.
    func startVideo(in room: Room) async -> Bool {
        let track = await LocalVideoTrack.createBufferTrack(
            name: Track.cameraName, source: .camera,
            options: BufferCaptureOptions(dimensions: Dimensions(width: 640, height: 480), fps: 15))
        guard let capturer = track.capturer as? BufferCapturer else { return false }
        var n = 0
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(66))
        timer.setEventHandler {
            n += 1
            if let frame = Self.frame(number: n) { capturer.capture(frame) }
        }
        timer.resume()
        videoTimer = timer
        // The first frame has to exist before publishing (the SDK needs the dimensions).
        try? await Task.sleep(for: .milliseconds(300))
        do {
            try await room.localParticipant.publish(videoTrack: track)
            return true
        } catch {
            timer.cancel()
            videoTimer = nil
            return false
        }
    }

    func stopVideo(in room: Room) {
        videoTimer?.cancel()
        videoTimer = nil
        let local = room.localParticipant
        if let pub = local.videoTracks.first(where: { $0.source == .camera }) as? LocalTrackPublication {
            Task { try? await local.unpublish(publication: pub) }
        }
    }

    func stop() {
        videoTimer?.cancel()
        videoTimer = nil
        toneTimer?.cancel()
        toneTimer = nil
    }

    /// One 640×480 frame: a platform-coloured field, a square that moves, the platform's name
    /// and the frame number — enough to tell on the far side whose picture it is and that it moves.
    nonisolated private static func frame(number: Int) -> CVPixelBuffer? {
        let width = 640, height = 480
        var buffer: CVPixelBuffer?
        let attrs: [CFString: Any] = [kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary]
        guard CVPixelBufferCreate(kCFAllocatorDefault, width, height, kCVPixelFormatType_32BGRA,
                                  attrs as CFDictionary, &buffer) == kCVReturnSuccess, let buffer else { return nil }
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let ctx = CGContext(
            data: CVPixelBufferGetBaseAddress(buffer), width: width, height: height, bitsPerComponent: 8,
            bytesPerRow: CVPixelBufferGetBytesPerRow(buffer), space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue) else { return nil }
        #if os(iOS)
        let name = "iOS Simulator"
        ctx.setFillColor(red: 0.10, green: 0.32, blue: 0.78, alpha: 1)
        #else
        let name = "macOS"
        ctx.setFillColor(red: 0.85, green: 0.42, blue: 0.08, alpha: 1)
        #endif
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
        ctx.setFillColor(red: 1, green: 1, blue: 1, alpha: 0.9)
        let x = (number * 7) % (width - 90)
        ctx.fill(CGRect(x: x, y: 60, width: 90, height: 90))
        draw("\(name) · synthetic camera", size: 34, at: CGPoint(x: 28, y: 300), in: ctx)
        draw("frame \(number)", size: 46, at: CGPoint(x: 28, y: 220), in: ctx)
        return buffer
    }

    nonisolated private static func draw(_ text: String, size: CGFloat, at point: CGPoint, in ctx: CGContext) {
        let font = CTFontCreateWithName("Helvetica-Bold" as CFString, size, nil)
        let attributes: [NSAttributedString.Key: Any] = [
            NSAttributedString.Key(kCTFontAttributeName as String): font,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(red: 1, green: 1, blue: 1, alpha: 1),
        ]
        let line = CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: attributes))
        ctx.textPosition = point
        CTLineDraw(line, ctx)
    }
}
#endif
