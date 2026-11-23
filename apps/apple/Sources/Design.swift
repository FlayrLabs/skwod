import SwiftUI
import UniformTypeIdentifiers
#if os(macOS)
import AppKit
typealias PlatformImage = NSImage
#elseif os(iOS)
import UIKit
typealias PlatformImage = UIImage
#endif

/// Cross-platform clipboard. `sensitive: true` is for anything that lets someone in or stands in
/// for a secret — invite links, join codes, device-link codes, recovery keys, the owner password.
/// Those copies **expire after 60 seconds** on both platforms, and never travel to other devices:
///
/// - iOS: the item is `localOnly` (no Universal Clipboard) with a system-enforced expiration.
/// - macOS: the item is flagged Concealed (clipboard managers skip it) and a timer clears the
///   pasteboard after 60 s — only if it still holds what we put there (checked by change count),
///   so we never wipe something the user copied afterwards.
///
/// Non-sensitive copies (message text the user chose to copy) behave normally.
enum Clipboard {
    static let sensitiveLifetime: TimeInterval = 60

    static func copy(_ value: String, sensitive: Bool = false) {
        #if os(macOS)
        let pb = NSPasteboard.general
        pb.clearContents()
        if sensitive {
            // Convention respected by clipboard managers / Universal Clipboard to not retain secrets.
            pb.setString(value, forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        }
        pb.setString(value, forType: .string)
        if sensitive {
            let stamp = pb.changeCount
            DispatchQueue.main.asyncAfter(deadline: .now() + sensitiveLifetime) {
                if NSPasteboard.general.changeCount == stamp { NSPasteboard.general.clearContents() }
            }
        }
        #elseif os(iOS)
        if sensitive {
            UIPasteboard.general.setItems(
                [[UTType.utf8PlainText.identifier: value]],
                options: [.expirationDate: Date().addingTimeInterval(sensitiveLifetime), .localOnly: true])
        } else {
            UIPasteboard.general.string = value
        }
        #endif
    }

    /// The pasteboard's text, on an explicit user action only (a Paste button) — never read
    /// in the background. Capped so a huge pasteboard can't be pulled into a text field.
    static func string() -> String? {
        #if os(macOS)
        let s = NSPasteboard.general.string(forType: .string)
        #else
        let s = UIPasteboard.general.string
        #endif
        guard let s, s.utf8.count <= 4096 else { return nil }
        return s
    }
}

/// App version + build number, read from the bundle (Info.plist), so the UI always shows exactly
/// which build is running. The build number is bumped on every new build (see project.yml
/// CURRENT_PROJECT_VERSION); a matching value is kept in sync with the Android versionCode.
enum AppVersion {
    static var short: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    }
    static var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"
    }
    /// e.g. "0.1.0 (14)"
    static var display: String { "\(short) (\(build))" }
}

/// Monochrome accent — pure white — so the app reads as neutral Liquid Glass: the frosted material
/// and translucency carry the depth, not a brand color. Exposed as `ShapeStyle` members so
/// `.foregroundStyle(.skAccent)`, `.tint(.skAccent)`, `.fill(.skAccent)` resolve via leading-dot.
extension ShapeStyle where Self == Color {
    static var skAccent: Color { .white }
    /// A softer neutral for secondary accents / gradients.
    static var skAccentWash: Color { Color(white: 0.72) }
}

#if os(macOS)
/// A live vibrancy layer — blurs whatever is BEHIND the window (the desktop/other apps), which is what
/// actually makes the window read as translucent Liquid Glass rather than a flat dark panel.
struct VisualEffectView: NSViewRepresentable {
    // .hudWindow is the most transparent of the blur materials — the desktop genuinely shows
    // through (.underWindowBackground reads nearly opaque in dark mode).
    var material: NSVisualEffectView.Material = .hudWindow
    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material
        v.blendingMode = .behindWindow
        v.state = .active
        return v
    }
    func updateNSView(_ v: NSVisualEffectView, context: Context) { v.material = material; v.state = .active }
}

/// Makes the hosting `NSWindow` non-opaque with a clear background so the vibrancy above can show the
/// desktop through the glass. Applied once at the app root.
struct WindowGlassConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async {
            guard let win = v.window else { return }
            win.isOpaque = false
            win.backgroundColor = .clear
            // Top strip: the native titlebar (transparent over the glass) with the
            // workspace name centered — MainView sets it via .navigationTitle. Full-size content so
            // the app's dark veil extends under the titlebar — otherwise the strip shows the raw
            // (light) vibrancy and reads as a different color than the panels below it.
            win.titlebarAppearsTransparent = true
            win.styleMask.insert(.fullSizeContentView)
        }
        return v
    }
    func updateNSView(_ nsView: NSView, context: Context) {}
}
#endif

extension View {
    /// Make the hosting macOS window translucent Liquid Glass: a live vibrancy layer (desktop blurs
    /// through) behind everything, plus the window set non-opaque so it actually shows. No-op on iOS.
    @ViewBuilder func windowGlass() -> some View {
        #if os(macOS)
        background(VisualEffectView(material: .underWindowBackground).ignoresSafeArea())
            .background(WindowGlassConfigurator())
        #else
        self
        #endif
    }
}

/// The app background — the frosted-glass backdrop every screen sits on. A deep translucent base
/// with indigo/violet/teal glows under a thin frost. The glows are what make the layered materials
/// READ as glass: over a flat dark base, material just looks black. On macOS the base stays
/// translucent so the desktop vibrancy still bleeds through beneath the glows.
struct SkwodBackground: View {
    var body: some View {
        ZStack {
            #if os(macOS)
            // A dark material base + light veil: in the main window the vibrancy behind keeps it
            // translucent; in sheet windows (no windowGlass, so no vibrancy) the material itself
            // provides the dark frosted backdrop instead of a washed-out veil over system gray.
            Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
            Color(red: 0.055, green: 0.06, blue: 0.085).opacity(0.25).ignoresSafeArea()
            #else
            Color(red: 0.055, green: 0.06, blue: 0.085).ignoresSafeArea()
            #endif
            RadialGradient(
                colors: [Color(red: 0.30, green: 0.32, blue: 0.62).opacity(0.38), .clear],
                center: .topLeading, startRadius: 0, endRadius: 700
            )
            .ignoresSafeArea()
            RadialGradient(
                colors: [Color(red: 0.42, green: 0.26, blue: 0.58).opacity(0.26), .clear],
                center: .bottomTrailing, startRadius: 0, endRadius: 760
            )
            .ignoresSafeArea()
            RadialGradient(
                colors: [Color(red: 0.18, green: 0.36, blue: 0.48).opacity(0.18), .clear],
                center: .trailing, startRadius: 0, endRadius: 520
            )
            .ignoresSafeArea()
            LinearGradient(
                colors: [Color.white.opacity(0.05), .clear, Color.black.opacity(0.14)],
                startPoint: .top, endPoint: .bottom
            )
            .ignoresSafeArea()
            #if os(iOS)
            // iOS has no behind-window vibrancy, so add the frost here. On macOS the window's own
            // NSVisualEffectView is the frost — layering material here would grey the glows out.
            Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
            #endif
        }
    }
}

/// The pre-login background — the same neutral glass look (no separate color theme).
struct AuthBackground: View {
    var body: some View { SkwodBackground() }
}

/// Backing for main-pane (detail) surfaces — the lightest step: a translucent lift over the
/// window's dark chrome, matching the chat surface. Use this INSIDE the shell (the window already
/// draws SkwodBackground); use SkwodBackground only for full-screen/standalone surfaces.
struct DetailGlass: View {
    var body: some View {
        Rectangle().fill(.white.opacity(0.085)).ignoresSafeArea()
    }
}

/// The skwod squid logo as a clean rounded app-icon tile.
struct SkwodLogoTile: View {
    var size: CGFloat = 96
    var body: some View {
        Image("SkwodLogo")
            .resizable().scaledToFit()          // brand logo keeps its color — the one splash of color
            .frame(width: size, height: size)
            .clipShape(RoundedRectangle(cornerRadius: size * 0.23, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.23, style: .continuous)
                    .strokeBorder(.white.opacity(0.14), lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.5), radius: size * 0.22, y: size * 0.08)
    }
}

/// A glass card container.
struct GlassCard<Content: View>: View {
    var cornerRadius: CGFloat = 20
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(16)
            .glassEffect(.regular, in: .rect(cornerRadius: cornerRadius, style: .continuous))
    }
}

/// A section header row.
struct SectionHeader: View {
    let title: String
    var systemImage: String? = nil
    var body: some View {
        HStack(spacing: 8) {
            if let systemImage { Image(systemName: systemImage).foregroundStyle(.skAccent) }
            Text(title).font(.headline).foregroundStyle(.white)
            Spacer()
        }
        .padding(.horizontal, 4)
    }
}

extension Color {
    /// Deterministic MONOCHROME shade from a string (avatars, server tiles) — a neutral gray whose
    /// lightness varies per name, so avatars stay distinguishable without any color.
    static func seeded(_ s: String) -> Color {
        var h = 5381
        for b in s.utf8 { h = ((h << 5) &+ h) &+ Int(b) }
        let shade = 0.34 + Double(abs(h) % 42) / 100.0   // 0.34–0.75
        return Color(white: shade)
    }
}

/// A copy-to-clipboard button with clear tactile feedback: the icon flips to a green checkmark and
/// the label reads "Copied" for ~1.5s, so a tap never feels like it did nothing. Cross-platform.
struct CopyButton: View {
    let value: String
    var compact: Bool = false
    /// Set for one-time secrets (invite tokens, owner setup code) so the copy is local-only + short-lived.
    var sensitive: Bool = false
    @State private var copied = false

    init(_ value: String, compact: Bool = false, sensitive: Bool = false) {
        self.value = value; self.compact = compact; self.sensitive = sensitive
    }

    var body: some View {
        Button {
            Clipboard.copy(value, sensitive: sensitive)
            withAnimation(.snappy) { copied = true }
            Task { try? await Task.sleep(for: .seconds(1.5)); withAnimation(.snappy) { copied = false } }
        } label: {
            if compact {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            } else {
                Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
            }
        }
        // Prominent white pill with dark content — reads clearly on the frosted glass cards where
        // copy buttons live (white-on-glass was invisible).
        .buttonStyle(.glassProminent)
        .tint(copied ? .green : .white)
        .foregroundStyle(copied ? .white : .black)
        .animation(.snappy, value: copied)
    }
}

/// Wraps sheet content so it always has a reliable way out: a NavigationStack with a "Done" button
/// (top-trailing) plus Escape-to-close. macOS sheets are app-modal and do NOT dismiss on click-outside,
/// so an explicit affordance is required — this guarantees no modal is ever a dead-end.
struct DismissableSheet<Content: View>: View {
    var doneTitle: String = "Done"
    @ViewBuilder var content: Content
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            content
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button(doneTitle) { dismiss() }.keyboardShortcut(.cancelAction)
                    }
                }
        }
        // Every sheet is frosted glass — the app behind blurs through instead of a flat panel.
        .presentationBackground(.ultraThinMaterial)
    }
}
