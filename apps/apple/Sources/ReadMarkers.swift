import SwiftUI

/// Where this device last read each conversation (`ReadMarker`), kept in the skwod's encrypted
/// cache (`kv_write`, one key per conversation: `UnreadRule.storageKey`). The host never sees it.
/// Read by `ChatSurface` for the "New" divider, the bar above the list, the jump pill and where a
/// conversation opens.
@MainActor @Observable
final class ReadMarkerStore {
    /// By storage key (skwod + conversation), so one skwod's markers never answer for another.
    private(set) var markers: [String: ReadMarker] = [:]
    @ObservationIgnored private var loaded: Set<String> = []
    @ObservationIgnored private var writes: [String: Task<Void, Never>] = [:]
    @ObservationIgnored weak var app: AppState?

    private func key(_ conversationId: String) -> String? {
        guard let bound = app?.bound, !conversationId.isEmpty else { return nil }
        return UnreadRule.storageKey(workspaceId: bound.workspaceId, conversationId: conversationId)
    }

    /// Has this conversation's marker been read from the cache (or is there no cache to read)?
    func isLoaded(_ conversationId: String) -> Bool {
        guard let key = key(conversationId) else { return true }
        return loaded.contains(key)
    }

    func marker(_ conversationId: String) -> ReadMarker? {
        key(conversationId).flatMap { markers[$0] }
    }

    /// Read the marker once per conversation and skwod. A read that fails counts as "never read
    /// here": the conversation opens at the bottom, and the next read-up-to writes a marker.
    func load(_ conversationId: String) async {
        guard let bound = app?.bound, bound.cacheOpen, let key = key(conversationId), !loaded.contains(key) else { return }
        let json = try? await bound.client.kvRead(key: key)
        guard self.key(conversationId) == key else { return }   // the skwod changed meanwhile
        if let json, let data = json.data(using: .utf8), let m = try? JSONDecoder().decode(ReadMarker.self, from: data) {
            // Something marked read while this was loading is kept if it is newer.
            markers[key] = markers[key].map { $0.createdAt >= m.createdAt ? $0 : m } ?? m
        }
        loaded.insert(key)
    }

    /// The reader has seen everything up to `item`. Never moves backwards; written to the cache
    /// a moment later (one write for a burst of arrivals).
    func markRead(_ conversationId: String, upTo item: UnreadItem) {
        guard let key = key(conversationId) else { return }
        let next = UnreadRule.advanced(markers[key], to: item)
        guard next != markers[key] else { return }
        markers[key] = next
        writes[key]?.cancel()
        writes[key] = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(600))
            guard !Task.isCancelled, let self, let bound = self.app?.bound, bound.cacheOpen,
                  UnreadRule.storageKey(workspaceId: bound.workspaceId, conversationId: conversationId) == key,
                  let marker = self.markers[key],
                  let data = try? JSONEncoder().encode(marker), let json = String(data: data, encoding: .utf8) else { return }
            try? await bound.client.kvWrite(key: key, value: json)
        }
    }
}

private struct ChatOnScreenKey: EnvironmentKey { static let defaultValue = true }

extension EnvironmentValues {
    /// Is the conversation actually in front of the reader? False for the iPhone drawer's chat
    /// page while the channel list covers it (it stays mounted behind the list): nothing is marked
    /// read there.
    var chatOnScreen: Bool {
        get { self[ChatOnScreenKey.self] }
        set { self[ChatOnScreenKey.self] = newValue }
    }
}

extension ChatMessage {
    var unreadItem: UnreadItem { UnreadItem(id: id, createdAt: createdAt, mine: mine, system: system != nil) }
}
