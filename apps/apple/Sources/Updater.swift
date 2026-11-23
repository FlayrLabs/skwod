import Foundation
import SwiftUI
#if os(iOS)
import UIKit
#endif

/// iOS in-app update prompt. The latest build is read from the project's PUBLIC release manifest
/// (one fixed https URL, the same for every install) — never from the skwod the app happens to
/// be connected to: a host must not be able to tell a member's phone which "update" to open.
/// We compare it to this binary's `CFBundleVersion` and, when behind, banner a one-tap hand-off
/// to TestFlight (Apple forbids an app replacing its own binary).
///
/// GitHub only carries that file. The build number, the text and the link are read from the
/// manifest's SIGNED statement (`UpdateManifest`): an Ed25519 signature by the release
/// publisher, checked against the key pinned in this binary, over exactly the bytes that are
/// then parsed. A manifest without a valid statement offers nothing — whoever can write to the
/// release repository cannot raise an "Update available" banner or choose where it leads. The
/// link is additionally opened only when it is https on testflight.apple.com or apps.apple.com.
///
/// Freshness: the statement expires (120 days by default). An expired one is still genuine, so
/// a newer build it names is offered, but "nothing newer" from it is reported on a manual
/// check as "can't confirm you're up to date" rather than as up to date.
///
/// macOS is NOT handled here — it self-updates through `SparkleUpdater` (EdDSA-signed appcast). On
/// macOS this type stays inert: `check()` returns immediately, so `available` is always nil.
@MainActor
final class Updater: ObservableObject {
    struct Available: Equatable {
        let build: Int
        let version: String
        let notes: String
        let testflight: String?  // iOS hand-off URL
    }

    enum Phase: Equatable {
        case idle
        case checking
        case downloading(Double)   // 0…1
        case installing
        case failed(String)
    }

    @Published var available: Available?
    @Published var phase: Phase = .idle
    /// Set when the user explicitly hit "Check for updates" so we can tell them "you're up to date"
    /// (a background check stays silent when there's nothing new).
    @Published var lastCheckWasManual = false

    private var currentBuild: Int { Int(AppVersion.build) ?? 0 }

    /// The public release manifest (GitHub release asset; see publish-release.sh).
    static let manifestURL = URL(string: "https://github.com/FlayrLabs/skwod-releases/releases/latest/download/manifest.json")!

    /// Fetch the manifest for `serverURL` and, if it advertises a newer iOS build, populate
    /// `available`. Silent on failure — a version check must never disrupt the app.
    ///
    /// iOS only: macOS updates go through Sparkle (`SparkleUpdater`), which verifies an EdDSA
    /// signature before installing. This custom checker never runs on macOS.
    func check(serverURL: String, manual: Bool = false) async {
        #if os(macOS)
        return
        #else
        // The PUBLIC release manifest — the same one Android reads and the release pipeline
        // publishes (publish-release.sh) — never the connected server's `/api/updates/manifest`:
        // whoever hosts a skwod must not be able to tell this app "a new version is available"
        // or what it says. `serverURL` is kept in the signature for callers; it is not used.
        _ = serverURL
        lastCheckWasManual = manual
        if manual { phase = .checking }
        do {
            let (data, resp) = try await URLSession.shared.data(from: Self.manifestURL)
            guard (resp as? HTTPURLResponse)?.statusCode == 200,
                  data.count <= 64 * 1024 else {
                available = nil
                if manual { phase = .idle }
                return
            }
            // Only the publisher-signed statement is believed (UpdateManifest); the unsigned
            // `ios` object in the same file is for older builds and is never read here.
            guard case .valid(let ios, let expired) = UpdateManifest.read(data) else {
                available = nil
                if manual { phase = .failed(Self.staleMessage) }
                return
            }
            guard let ios, ios.build > currentBuild else {
                available = nil
                if manual { phase = expired ? .failed(Self.staleMessage) : .idle }
                return
            }
            available = Available(build: ios.build, version: ios.version, notes: ios.notes, testflight: ios.link?.absoluteString)
            if manual { phase = .idle }
        } catch {
            if manual { phase = .failed("Couldn't reach the update server.") }
        }
        #endif
    }

    static let staleMessage = "Couldn't confirm this is the latest build: the update feed is out of date or not signed. Check skwod.io."

    /// Perform the update. iOS only: Apple forbids in-app binary swaps, so we open TestFlight.
    /// (macOS is handled entirely by Sparkle and never reaches here.)
    func install(serverURL: String) async {
        #if os(iOS)
        // The link came out of the publisher-signed statement. Even so, only ever hand a
        // genuine TestFlight / App Store https link to the system.
        guard let info = available, let tf = info.testflight, let url = UpdateManifest.appleLink(tf) else { return }
        await UIApplication.shared.open(url)
        #endif
    }

    // MARK: - Shared helpers

    private func normalizedBase(_ s: String) -> URL? {
        var t = s.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return nil }
        if !t.hasPrefix("http://") && !t.hasPrefix("https://") { t = "https://" + t }
        if t.hasSuffix("/") { t.removeLast() }
        return URL(string: t)
    }
}

/// The "A new version is available" strip shown at the top of the app when the connected server
/// advertises a newer build. One tap installs (macOS) or opens TestFlight (iOS).
struct UpdateBanner: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var updater: Updater

    var body: some View {
        if let info = updater.available {
            HStack(spacing: 12) {
                Image(systemName: "arrow.down.circle.fill").foregroundStyle(.skAccent)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Update available — \(info.version) (\(info.build))")
                        .font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                    subtitle(info)
                }
                Spacer(minLength: 8)
                actionButton(info)
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(.ultraThinMaterial, in: Capsule())
            .overlay(Capsule().stroke(.white.opacity(0.12)))
            .padding(.horizontal, 12).padding(.top, 8)
            .shadow(color: .black.opacity(0.35), radius: 12, y: 4)
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }

    @ViewBuilder private func subtitle(_ info: Updater.Available) -> some View {
        switch updater.phase {
        case .downloading(let p):
            Text("Downloading… \(Int(p * 100))%").font(.caption2).foregroundStyle(.white.opacity(0.6))
        case .installing:
            Text("Installing — the app will relaunch…").font(.caption2).foregroundStyle(.white.opacity(0.6))
        case .failed(let msg):
            Text(msg).font(.caption2).foregroundStyle(.red.opacity(0.9))
        default:
            if !info.notes.isEmpty {
                Text(info.notes).font(.caption2).foregroundStyle(.white.opacity(0.6)).lineLimit(1)
            }
        }
    }

    @ViewBuilder private func actionButton(_ info: Updater.Available) -> some View {
        switch updater.phase {
        case .downloading, .installing:
            ProgressView().controlSize(.small).tint(.white)
        default:
            Button {
                Task { await updater.install(serverURL: app.serverURL) }
            } label: {
                #if os(iOS)
                Text("Open TestFlight").font(.system(size: 13, weight: .semibold))
                #else
                Text("Update").font(.system(size: 13, weight: .semibold))
                #endif
            }
            .buttonStyle(.borderedProminent).tint(.skAccent).controlSize(.small)
        }
    }
}
