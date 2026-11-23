import SwiftUI

/// Links inside messages. A message is written by someone else, and markdown lets them put any
/// label on any address: `[skwod.io/reset](https://evil.example/x)`. So:
///
/// 1. a link whose label is not its own address is shown WITH its real address beside it;
/// 2. only web and mail links are links at all (a `file:`, `tel:`, `x-apple…:` or custom-scheme
///    link in a message is rendered as plain text);
/// 3. nothing opens on a tap — the full address is shown first and the user confirms.
enum LinkSafety {
    /// Schemes a message may link to.
    static func isOpenable(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased() else { return false }
        switch scheme {
        case "https", "http": return !(url.host ?? "").isEmpty
        case "mailto": return true
        default: return false
        }
    }

    /// The address exactly as it will be opened, for display. The host is shown in its ASCII
    /// (punycode) form — `URL.host` already is — so a look-alike Unicode domain reads as `xn--…`.
    static func display(_ url: URL) -> String { url.absoluteString }

    /// Does the visible label already say where the link goes?
    static func labelMatches(_ label: String, _ url: URL) -> Bool {
        func norm(_ s: String) -> String {
            var t = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            for prefix in ["https://", "http://", "mailto:"] where t.hasPrefix(prefix) { t.removeFirst(prefix.count) }
            while t.hasSuffix("/") { t.removeLast() }
            return t
        }
        return norm(label) == norm(url.absoluteString)
    }

    /// Inline markdown for a message body, with every link made honest (see the type comment).
    /// Falls back to plain text when the markdown does not parse.
    static func attributed(_ s: String) -> AttributedString {
        guard var text = try? AttributedString(
            markdown: s, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)) else {
            return AttributedString(s)
        }
        // Collect link runs first (merging adjacent runs of one link, e.g. a label with bold in
        // it), then edit back to front so earlier ranges stay valid.
        var links: [(range: Range<AttributedString.Index>, url: URL)] = []
        for run in text.runs {
            guard let url = run.link else { continue }
            if let last = links.last, last.url == url, last.range.upperBound == run.range.lowerBound {
                links[links.count - 1].range = last.range.lowerBound..<run.range.upperBound
            } else {
                links.append((run.range, url))
            }
        }
        for (range, url) in links.reversed() {
            guard isOpenable(url) else {
                text[range].link = nil   // not a link this app will ever open: plain text
                continue
            }
            let label = String(text[range].characters)
            if !labelMatches(label, url) {
                var target = AttributedString(" (\(display(url)))")
                target.link = url
                target.foregroundColor = .white.opacity(0.55)
                text.insert(target, at: range.upperBound)
            }
        }
        return text
    }
}

/// Catches every link tap beneath it and asks before opening, showing the full address.
struct ConfirmLinks: ViewModifier {
    @State private var pending: URL?
    @Environment(\.openURL) private var systemOpen

    func body(content: Content) -> some View {
        content
            .environment(\.openURL, OpenURLAction { url in
                // Anything that is not a web/mail address is dropped, not handed to the system.
                if LinkSafety.isOpenable(url) { pending = url }
                return .handled
            })
            .alert("Open this link?",
                   isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }),
                   presenting: pending) { url in
                Button("Open") { systemOpen(url) }
                Button("Copy address") { Clipboard.copy(LinkSafety.display(url)) }
                Button("Cancel", role: .cancel) {}
            } message: { url in
                Text("\(LinkSafety.display(url))\n\nThis link was sent in a message. Open it only if you recognise the address.")
            }
    }
}

extension View {
    /// Links under this view show a confirmation with their real address before opening.
    func confirmingLinks() -> some View { modifier(ConfirmLinks()) }
}
