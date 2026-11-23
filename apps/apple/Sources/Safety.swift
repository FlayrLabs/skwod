import SwiftUI

/// Blocking and reporting, the same everywhere a person appears: a message's menu, a member
/// row, a DM's header.
///
/// Both go through the core (`blockUser` / `unblockUser` / `refreshBlocks` / `reportMessage`),
/// never raw HTTP: the core is what rotates this device's delivery key, keeps the local drop
/// list, and filters a blocked person out of everything read from the cache — chat, the feed,
/// stories, comments, reactions, DMs. What the core does not read for us is filtered here:
/// notifications of live messages and presence.
@MainActor
final class BlockList: ObservableObject {
    static let shared = BlockList()
    /// Blocked user ids of the skwod on screen.
    @Published private(set) var ids: Set<String> = []
    @Published private(set) var names: [String: String] = [:]

    func contains(_ userId: String?) -> Bool { userId.map(ids.contains) ?? false }

    /// What this device already knows (no network) — right after the cache is attached.
    func adopt(_ app: AppState) {
        guard let client = app.client else { ids = []; return }
        set(Set(client.blockedUserIds()), app)
    }

    /// From the server: a block made on another of this account's devices applies here too.
    /// Called at launch and whenever the live connection comes up.
    func refresh(_ app: AppState) async {
        guard let client = app.client else { return }
        let rows = try? await client.refreshBlocks()
        guard app.client === client else { return }
        if let rows {
            for r in rows { names[r.userId] = r.username }
            set(Set(rows.map(\.userId)), app)
        } else {
            adopt(app)
        }
    }

    /// Block or unblock. Returns a sentence when it failed.
    func setBlocked(_ app: AppState, userId: String, name: String, blocked: Bool) async -> String? {
        guard let client = app.client else { return "Not connected — try again in a moment." }
        do {
            if blocked { try await client.blockUser(userId: userId) } else { try await client.unblockUser(userId: userId) }
        } catch {
            return coreErrorText(error, fallback: blocked ? "Couldn't block \(name) — check your connection." : "Couldn't unblock \(name) — check your connection.")
        }
        // Still the client that was asked? (Otherwise this would put one workspace's block
        // list up in another.)
        guard app.client === client else { return nil }
        names[userId] = name
        set(Set(client.blockedUserIds()), app)
        return nil
    }

    private func set(_ new: Set<String>, _ app: AppState) {
        let changed = new != ids
        ids = new
        app.realtime.blockedIds = new
        // Open conversations re-read history: the core now leaves that person out (or back in).
        if changed {
            NotificationCenter.default.post(name: .skwodOutboxChanged, object: nil)
            NotificationCenter.default.post(name: .skwodBlocksChanged, object: nil)
        }
    }
}

extension Notification.Name {
    static let skwodBlocksChanged = Notification.Name("skwod.blocksChanged")
}

/// What a report is about.
struct ReportTarget: Identifiable {
    let id = UUID()
    var userId: String
    var name: String
    /// The reported message's text, when the report starts from a message.
    var messageText: String?
    var serverId: String?
    /// Where the reported message is, for a CHANNEL message (nil for a DM or a person).
    var channelId: String? = nil
    var messageId: String? = nil
}

/// Per-conversation actions a message row offers beyond the chat basics. Passed through the
/// environment so the shared chat surface does not grow a parameter per action.
struct MessageExtras {
    var onReport: ((ChatMessage) -> Void)?
    var onBlock: ((ChatMessage) -> Void)?
    var onRetry: ((String) -> Void)?
    var onDiscard: ((String) -> Void)?
    /// Build 46 mentions: this account's id, a mentioned user's label (the contact book's rule,
    /// never the text the sender typed), whether a sender's @everyone counts, and opening a
    /// mentioned person's profile.
    var me: String?
    var mentionLabel: ((String) -> String)?
    var everyoneAllowed: ((String?) -> Bool)?
    var onOpenProfile: ((String) -> Void)?
    /// Who may be @mentioned here: (user id, shown name, username — what the token says).
    var mentionable: [MentionCandidate] = []
    /// Who may show as typing here (`TypingAudience`): the DM's peer, the group's held members,
    /// the channel's server members. Empty = nobody.
    var typingFrom: Set<String> = []
}

private struct MessageExtrasKey: EnvironmentKey {
    static let defaultValue = MessageExtras()
}

extension EnvironmentValues {
    var messageExtras: MessageExtras {
        get { self[MessageExtrasKey.self] }
        set { self[MessageExtrasKey.self] = newValue }
    }
}

/// Report a person (or one message of theirs) to whoever runs the skwod, and say that it went.
struct ReportSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    let target: ReportTarget
    @State private var category = "harassment"
    @State private var note = ""
    @State private var includeMessage = false
    @State private var alsoBlock = false
    @State private var sending = false
    @State private var error: String?
    @State private var sent: ReportReceipt?

    private static let categories: [(String, String)] = [
        ("harassment", "Harassment or bullying"), ("spam", "Spam"), ("illegal", "Illegal content"),
        ("impersonation", "Pretending to be someone"), ("other", "Something else"),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let sent {
                confirmation(sent)
            } else {
                form
            }
        }
        .padding(22)
        .frame(minWidth: 320, idealWidth: 420, maxWidth: 480)
        .background(Color.black.opacity(0.92))
        .preferredColorScheme(.dark)
    }

    @ViewBuilder private var form: some View {
        Text("Report \(target.name)").font(.title3.bold()).foregroundStyle(.white)
        Text("The report goes to the person who runs this skwod. Your chats stay end-to-end encrypted: they see only what you choose to include here.")
            .font(.footnote).foregroundStyle(.white.opacity(0.6)).fixedSize(horizontal: false, vertical: true)
        Picker("Reason", selection: $category) {
            ForEach(Self.categories, id: \.0) { Text($0.1).tag($0.0) }
        }
        .accessibilityIdentifier("report-category")
        TextField("Add a note (optional)", text: $note, axis: .vertical)
            .lineLimit(2...5).textFieldStyle(.roundedBorder)
            .accessibilityIdentifier("report-note")
        if let text = target.messageText, !text.isEmpty {
            Toggle(isOn: $includeMessage) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Include this message").foregroundStyle(.white)
                    Text("“\(text.prefix(200))”").font(.footnote).foregroundStyle(.white.opacity(0.55)).lineLimit(3)
                    Text("It is sent encrypted to the skwod's owner only. Without it they see who you reported and why, not what was said.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45)).fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityIdentifier("report-include-message")
        }
        Toggle("Also block \(target.name)", isOn: $alsoBlock).foregroundStyle(.white)
        if let error { Text(error).font(.footnote).foregroundStyle(.orange) }
        HStack {
            Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            Spacer()
            Button(sending ? "Sending…" : "Send report") { Task { await send() } }
                .keyboardShortcut(.defaultAction).disabled(sending)
                .accessibilityIdentifier("report-send")
        }
    }

    @ViewBuilder private func confirmation(_ receipt: ReportReceipt) -> some View {
        Label("Report sent", systemImage: "checkmark.circle.fill").font(.title3.bold()).foregroundStyle(.green)
            .accessibilityIdentifier("report-sent")
        Text(receipt.sealedToOwner
             ? "The skwod's owner will see it the next time they open Skwod. \(target.name) is not told."
             : "It is in this skwod's report list. \(target.name) is not told.")
            .font(.footnote).foregroundStyle(.white.opacity(0.7)).fixedSize(horizontal: false, vertical: true)
        if !receipt.sealedToOwner, includeMessage {
            Text("The message itself was not included: this skwod has no verified owner to encrypt it to.")
                .font(.footnote).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
        }
        HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
    }

    private func send() async {
        guard let client = app.client else { error = "Not connected — try again in a moment."; return }
        sending = true; error = nil
        defer { sending = false }
        do {
            // A channel message is reported with where it is (sealed to the owner only), so
            // the owner's reports inbox can find it and offer "Remove message".
            let receipt = try await client.reportMessageAt(
                category: category,
                note: note.isEmpty ? nil : note,
                messageText: includeMessage ? target.messageText : nil,
                subjectUserId: target.userId,
                serverId: target.serverId,
                channelId: target.channelId,
                messageId: target.channelId == nil ? nil : target.messageId)
            if alsoBlock { _ = await BlockList.shared.setBlocked(app, userId: target.userId, name: target.name, blocked: true) }
            #if DEBUG
            E2E.sawReport(id: receipt.reportId, sealed: receipt.sealedToOwner)
            #endif
            sent = receipt
        } catch {
            self.error = coreErrorText(error, fallback: "The report could not be sent — check your connection and try again.")
        }
    }
}

/// "Block X?" + the report sheet, attachable to any view that offers the two actions.
struct SafetyActions: ViewModifier {
    @EnvironmentObject private var app: AppState
    @Binding var blocking: ReportTarget?
    @Binding var reporting: ReportTarget?
    @State private var failure: String?

    func body(content: Content) -> some View {
        content
            .confirmationDialog("Block \(blocking?.name ?? "")?", isPresented: Binding(get: { blocking != nil }, set: { if !$0 { blocking = nil } }), titleVisibility: .visible) {
                Button("Block", role: .destructive) {
                    guard let t = blocking else { return }
                    Task { failure = await BlockList.shared.setBlocked(app, userId: t.userId, name: t.name, blocked: true) }
                }
            } message: {
                Text("You won't see their messages, posts, stories or reactions anywhere in this skwod, and they can't message you. They aren't told. You can unblock them from their name in the member list.")
            }
            .sheet(item: $reporting) { ReportSheet(target: $0).environmentObject(app) }
            .alert("Couldn't do that", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } })) {
                Button("OK", role: .cancel) {}
            } message: { Text(failure ?? "") }
    }
}

extension View {
    func safetyActions(blocking: Binding<ReportTarget?>, reporting: Binding<ReportTarget?>) -> some View {
        modifier(SafetyActions(blocking: blocking, reporting: reporting))
    }
}

/// "Block / Unblock" and "Report" for a person, as menu items (member rows).
struct SafetyMenuItems: View {
    @EnvironmentObject private var app: AppState
    @ObservedObject private var blocks = BlockList.shared
    let userId: String
    let name: String
    var serverId: String?
    @Binding var blocking: ReportTarget?
    @Binding var reporting: ReportTarget?

    var body: some View {
        if blocks.ids.contains(userId) {
            Button { Task { _ = await blocks.setBlocked(app, userId: userId, name: name, blocked: false) } } label: {
                Label("Unblock \(name)", systemImage: "hand.raised.slash")
            }
        } else {
            Button { blocking = ReportTarget(userId: userId, name: name, serverId: serverId) } label: {
                Label("Block \(name)…", systemImage: "hand.raised")
            }
        }
        Button(role: .destructive) { reporting = ReportTarget(userId: userId, name: name, serverId: serverId) } label: {
            Label("Report \(name)…", systemImage: "exclamationmark.bubble")
        }
    }
}
