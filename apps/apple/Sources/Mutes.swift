import SwiftUI

/// The app's side of mutes: the lists (`MuteStore`), observable so rows redraw, and the two
/// small pieces of UI every list uses — the "Mute" entries of a context menu and the muted
/// mark on a row.
@MainActor
final class MuteCenter: ObservableObject {
    static let shared = MuteCenter()

    /// Bumped on every change (rows observe it).
    @Published private(set) var revision = 0
    private var lists: [String: MuteList] = [:]

    private var now: TimeInterval { Date().timeIntervalSince1970 }

    /// The skwod on screen.
    var currentWorkspaceId: String { WorkspaceStore.currentId ?? "" }

    func list(_ workspaceId: String) -> MuteList {
        if let known = lists[workspaceId] { return known }
        let loaded = MuteStore.load(workspaceId: workspaceId)
        lists[workspaceId] = loaded
        return loaded
    }

    /// Is a message in `scope` of that skwod muted (the conversation, or the whole skwod)?
    func isMuted(workspaceId: String, scope: String) -> Bool { list(workspaceId).isMuted(scope: scope, now: now) }

    /// Is exactly `key` (a conversation, or `MuteList.skwod`) muted?
    func holds(workspaceId: String, key: String) -> Bool { list(workspaceId).holds(key, now: now) }

    func callsRing(workspaceId: String) -> Bool { list(workspaceId).callsRing(now: now) }

    func mute(workspaceId: String, key: String, for duration: MuteList.Duration) {
        var l = list(workspaceId)
        l.mute(key, for: duration, now: now)
        store(l, workspaceId)
    }

    func unmute(workspaceId: String, key: String) {
        var l = list(workspaceId)
        l.unmute(key)
        store(l, workspaceId)
    }

    /// The skwod's local data was deleted (its stored mutes went with `WorkspaceItems.wipe`).
    func forget(workspaceId: String) {
        guard lists.removeValue(forKey: workspaceId) != nil else { return }
        revision += 1
    }

    private func store(_ l: MuteList, _ workspaceId: String) {
        lists[workspaceId] = l
        MuteStore.save(l, workspaceId: workspaceId)
        revision += 1
    }
}

/// The mute entries of a context menu: "Mute" with the four durations, or "Unmute".
/// `key`: a conversation scope (`channel:<id>` / `dm:<id>`) or `MuteList.skwod`.
struct MuteMenuItems: View {
    let key: String
    var workspaceId: String = MuteCenter.shared.currentWorkspaceId
    @ObservedObject private var mutes = MuteCenter.shared

    var body: some View {
        if mutes.holds(workspaceId: workspaceId, key: key) {
            Button { mutes.unmute(workspaceId: workspaceId, key: key) } label: { Label("Unmute", systemImage: "bell") }
        } else {
            Menu {
                ForEach(MuteList.Duration.allCases, id: \.self) { d in
                    Button(d.label) { mutes.mute(workspaceId: workspaceId, key: key, for: d) }
                }
            } label: { Label(key == MuteList.skwod ? "Mute this skwod" : "Mute", systemImage: "bell.slash") }
        }
    }
}

/// The small mark a muted row carries.
struct MutedMark: View {
    let key: String
    var workspaceId: String = MuteCenter.shared.currentWorkspaceId
    @ObservedObject private var mutes = MuteCenter.shared

    var body: some View {
        if mutes.holds(workspaceId: workspaceId, key: key) {
            Image(systemName: "bell.slash.fill")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.white.opacity(0.4))
                .padding(.trailing, 12)
                .accessibilityLabel("Muted")
        }
    }
}

extension View {
    /// A conversation row: the mute entries on long-press / right-click, and the muted mark.
    func muteMenu(scope: String) -> some View {
        self.contextMenu { MuteMenuItems(key: scope) }
            .overlay(alignment: .trailing) { MutedMark(key: scope) }
    }
}
