import SwiftUI

/// The composer side of @mentions: the "@…" popup and turning a draft into the text to send.
enum MentionComposer {
    /// The pseudo-member that inserts @everyone (offered only to the server's pinned owner).
    static let everyoneId = "*everyone*"

    /// Pick `member` for the "@query" at `at`.
    static func pick(_ member: MentionCandidate, draft: String, at: Int, payload: inout MentionPayload) -> String {
        if member.userId == everyoneId {
            let ns = draft as NSString
            payload.everyone = true
            return ns.replacingCharacters(in: NSRange(location: at, length: ns.length - at), with: "@everyone ")
        }
        return MentionAutocomplete.insert(name: member.name, username: member.username, userId: member.userId, into: draft, at: at, payload: &payload)
    }
}

/// The popup above the composer while typing "@…": avatar, name (already the trust label).
struct MentionSuggestions: View {
    let matches: [MentionCandidate]
    var highlighted: Int
    let onPick: (MentionCandidate) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Members").font(.system(size: 10, weight: .semibold)).textCase(.uppercase)
                .foregroundStyle(.white.opacity(0.45)).padding(.horizontal, 12).padding(.top, 8).padding(.bottom, 4)
            ForEach(Array(matches.enumerated()), id: \.element.userId) { i, m in
                Button { onPick(m) } label: {
                    HStack(spacing: 8) {
                        if m.userId == MentionComposer.everyoneId {
                            Image(systemName: "person.3.fill").font(.system(size: 12)).frame(width: 22, height: 22)
                                .foregroundStyle(.skAccent)
                        } else {
                            AvatarImage(key: AvatarStore.userKey(m.userId), name: m.name, size: 22)
                        }
                        Text(m.userId == MentionComposer.everyoneId ? "@everyone — notify every member" : m.name)
                            .font(.system(size: 13, weight: .medium)).foregroundStyle(.white).lineLimit(1)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(i == highlighted ? Color.skAccent.opacity(0.22) : .clear)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.bottom, 6)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
        .padding(.horizontal, 12)
        .accessibilityIdentifier("composer.mentions")
    }
}

/// Rendering mentions inside a message: each range shows "@<label>" — the label this device has
/// for that user id (`ContactTrust`), never the text the sender typed — in the accent colour
/// on a tinted background, as a link that opens the person's card.
enum MentionRender {
    static let scheme = "skwod-mention"

    static func apply(_ base: AttributedString, visible: String, payload: MentionPayload,
                      label: (String) -> String, everyoneAllowed: Bool,
                      trust: (String) -> ContactTrust.Display? = { _ in nil }) -> AttributedString {
        guard !payload.isEmpty else { return base }
        // Rebuild from the plain text when there are mentions: ranges are offsets into it.
        var out = AttributedString()
        let ns = visible as NSString
        var cursor = 0
        // Checked again against exactly the text shown here: only mention tokens are replaced.
        for m in MentionCodec.valid(payload.mentions, in: ns) {
            out += AttributedString(ns.substring(with: NSRange(location: cursor, length: m.start - cursor)))
            let shown = trust(m.userId)
            // The plain name in the chip; words stay for a flagged name (unconfirmed, look-alike).
            let words = shown?.chipWords.map { " (\($0))" } ?? ""
            var token = AttributedString("@" + label(m.userId) + words)
            token.foregroundColor = .skAccent
            token.backgroundColor = Color.skAccent.opacity(0.18)
            // Only an untrusted name is marked: a dotted underline for "not verified".
            if shown?.badge == .unverified { token.underlineStyle = Text.LineStyle(pattern: .dot, color: .white.opacity(0.6)) }
            token.link = URL(string: "\(scheme)://\(m.userId.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")")
            out += token
            cursor = m.start + m.length
        }
        out += AttributedString(ns.substring(from: min(cursor, ns.length)))
        if payload.everyone && everyoneAllowed, let r = out.range(of: "@everyone") {
            out[r].foregroundColor = .skAccent
            out[r].backgroundColor = Color.skAccent.opacity(0.18)
        }
        return out
    }

    static func userId(from url: URL) -> String? {
        guard url.scheme == scheme, let host = url.host(percentEncoded: false) else { return nil }
        return host.removingPercentEncoding ?? host
    }
}

/// A mentioned person's card: their avatar and the name this device has for them.
struct MentionProfileCard: View {
    let userId: String
    let label: String
    /// Build 49: the name's trust, drawn as a full badge under the plain name.
    var badge: ContactTrust.Badge = .none
    var body: some View {
        VStack(spacing: 10) {
            AvatarImage(key: AvatarStore.userKey(userId), name: label, size: 64)
            Text(label).font(.headline).foregroundStyle(.white)
            if badge != .none { TrustBadge(badge: badge) }
            Text("User \(userId.prefix(8))…").font(.caption.monospaced()).foregroundStyle(.white.opacity(0.45))
        }
        .padding(24)
        .frame(minWidth: 220)
    }
}

/// Unseen mentions of me, per conversation, on this device only: a red "@ n" on the channel
/// row, the server's rail tile and the DM list; cleared when the conversation is opened.
@MainActor
final class MentionBadges: ObservableObject {
    static let shared = MentionBadges()
    /// workspace id → topic → unseen count — a copy of the app group's `MentionBadgeLedger`,
    /// which the notification extension adds to as well.
    @Published private(set) var counts: [String: [String: Int]] = [:]
    /// What builds before the shared ledger kept (this app's own defaults).
    private static let legacyKey = "mention-badges"

    private init() {
        let defaults = SharedContainer.defaults
        if let old = UserDefaults.standard.dictionary(forKey: Self.legacyKey) as? [String: [String: Int]] {
            MentionBadgeLedger.update(defaults) { l in
                for (wid, topics) in old { for (topic, n) in topics where n > 0 { l.counts[wid, default: [:]][topic, default: 0] += n } }
            }
            UserDefaults.standard.removeObject(forKey: Self.legacyKey)
        }
        counts = MentionBadgeLedger.load(defaults).counts
    }

    /// Each message counts once, whether the app or the extension saw it first.
    static func add(ids: [String], topic: String, workspaceId: String) {
        let (l, _) = MentionBadgeLedger.update(SharedContainer.defaults) { $0.add(ids: ids, topic: topic, workspaceId: workspaceId) }
        if shared.counts != l.counts { shared.counts = l.counts }
    }

    static func clear(topic: String, workspaceId: String) {
        let (l, _) = MentionBadgeLedger.update(SharedContainer.defaults) { $0.clear(topic: topic, workspaceId: workspaceId) }
        if shared.counts != l.counts { shared.counts = l.counts }
    }

    /// Picks up what the notification extension added while the app was not running.
    static func reload() {
        let l = MentionBadgeLedger.load(SharedContainer.defaults)
        if shared.counts != l.counts { shared.counts = l.counts }
    }

    func count(_ topic: String, workspaceId: String) -> Int { counts[workspaceId]?[topic] ?? 0 }
    func count(topics: [String], workspaceId: String) -> Int { topics.reduce(0) { $0 + count($1, workspaceId: workspaceId) } }
}

/// The red "@ n".
struct MentionBadgeView: View {
    let count: Int
    var body: some View {
        if count > 0 {
            Text("@ \(count > 99 ? "99+" : String(count))")
                .font(.system(size: 10, weight: .bold)).foregroundStyle(.white)
                .padding(.horizontal, 5).padding(.vertical, 2)
                .background(Color.red, in: Capsule())
                .accessibilityLabel("\(count) unseen mention\(count == 1 ? "" : "s")")
        }
    }
}

/// The badge for one conversation in the skwod on screen.
struct TopicMentionBadge: View {
    let topic: String
    @ObservedObject private var badges = MentionBadges.shared
    var body: some View { MentionBadgeView(count: badges.count(topic, workspaceId: MuteCenter.shared.currentWorkspaceId)) }
}

/// The badge for a server: its channels' unseen mentions together.
struct ServerMentionBadge: View {
    let channelIds: [String]
    @ObservedObject private var badges = MentionBadges.shared
    var body: some View {
        MentionBadgeView(count: badges.count(topics: channelIds.map { "channel:\($0)" }, workspaceId: MuteCenter.shared.currentWorkspaceId))
    }
}
