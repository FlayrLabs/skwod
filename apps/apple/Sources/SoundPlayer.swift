import AudioToolbox
import Foundation
#if os(macOS)
import AppKit
#endif

/// The app's own short sounds (`Resources/Sounds`, rendered by `tools/sounds/render.py` —
/// original, synthesised, nothing third-party).
///
/// Played as system sounds (AudioToolbox): on iOS that is the "ambient" behaviour without
/// touching the shared audio session — they follow the silent switch, mix with whatever music
/// is playing instead of interrupting it, and leave a call's audio session (CallKit / LiveKit
/// own it) alone. On macOS they follow the alert volume.
@MainActor
enum SoundPlayer {
    enum Sound: String { case sent, received, callJoin = "call_join", callLeave = "call_leave", ring }

    private static var ids: [Sound: SystemSoundID] = [:]
    private(set) static var lastReceivedAt: TimeInterval = 0

    static func play(_ sound: Sound) {
        guard let id = id(for: sound) else { return }
        if sound == .received { lastReceivedAt = Date().timeIntervalSince1970 }
        AudioServicesPlaySystemSound(id)
    }

    private static func id(for sound: Sound) -> SystemSoundID? {
        if let id = ids[sound] { return id }
        guard let url = Bundle.main.url(forResource: "skwod_\(sound.rawValue)", withExtension: "wav") else { return nil }
        var id: SystemSoundID = 0
        guard AudioServicesCreateSystemSoundID(url as CFURL, &id) == kAudioServicesNoError else { return nil }
        ids[sound] = id
        return id
    }
}
