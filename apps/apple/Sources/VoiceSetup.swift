import SwiftUI

/// Host-only panel to turn on voice/video for the whole skwod. Fully transparent about how it works
/// and what the relay can/can't see, then takes the host's own LiveKit creds. Once saved, the server
/// mints room tokens and every member gets calls. The API secret only ever lives on the skwod server.
struct VoiceSetupSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var url = ""
    @State private var apiKey = ""
    @State private var apiSecret = ""
    @State private var busy = false
    @State private var error = ""
    @State private var done = false

    private var canSave: Bool {
        url.trimmingCharacters(in: .whitespaces).hasPrefix("ws")
            && !apiKey.trimmingCharacters(in: .whitespaces).isEmpty
            && !apiSecret.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header
                    privacyCard
                    stepsCard
                    formCard
                    if !error.isEmpty {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.red.opacity(0.9))
                    }
                    Button { Task { await save() } } label: {
                        HStack(spacing: 8) {
                            if busy { ProgressView().controlSize(.small) }
                            Text(done ? "Voice & video is on ✓" : "Turn on voice & video").fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glassProminent).tint(.green).foregroundStyle(.black)
                    .disabled(busy || done || !canSave)
                }
                .padding(26).frame(maxWidth: 480)
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: "waveform.badge.mic").font(.system(size: 40)).foregroundStyle(.green)
            Text("Turn on voice & video").font(.title2.bold()).foregroundStyle(.white)
            Text("Calls run on LiveKit. As the host, you connect your own LiveKit project once — then everyone on your Skwod gets voice and video. It stays off until you do this.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.6))
        }
    }

    private var privacyCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 12) {
                Text("How it stays private").font(.callout.weight(.semibold)).foregroundStyle(.white)
                privacyRow("lock.fill", "End-to-end encrypted",
                           "Calls are encrypted on-device. The relay only ever forwards ciphertext — no one, not even LiveKit, can hear or see your calls.")
                privacyRow("eye.trianglebadge.exclamationmark",
                           "What the relay can see",
                           "Only metadata: who's in a call, when, and IP addresses — never the call itself. Self-hosting keeps that private; LiveKit Cloud means LiveKit sees the metadata (but never the media).")
                privacyRow("externaldrive.badge.checkmark", "Your secret stays home",
                           "The API secret is stored only on your Skwod server to mint room tokens. It's never shipped to anyone's app.")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func privacyRow(_ icon: String, _ title: String, _ body: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).font(.system(size: 14)).foregroundStyle(.green).frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.medium)).foregroundStyle(.white.opacity(0.9))
                Text(body).font(.caption).foregroundStyle(.white.opacity(0.55))
            }
        }
    }

    private var stepsCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 8) {
                Text("Get your LiveKit keys").font(.callout.weight(.semibold)).foregroundStyle(.white)
                step(1, "Create a free project at ") { Link("cloud.livekit.io", destination: URL(string: "https://cloud.livekit.io")!).font(.caption.weight(.medium)) }
                step(2) { Text("Open the project's settings and copy its URL, API Key, and API Secret.").font(.caption).foregroundStyle(.white.opacity(0.55)) }
                step(3) { Text("Paste them below and save.").font(.caption).foregroundStyle(.white.opacity(0.55)) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private func step(_ n: Int, _ prefix: String = "", @ViewBuilder trailing: () -> some View) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(n)").font(.caption2.weight(.bold)).foregroundStyle(.black)
                .frame(width: 16, height: 16).background(Circle().fill(.white.opacity(0.85)))
            HStack(spacing: 0) {
                if !prefix.isEmpty { Text(prefix).font(.caption).foregroundStyle(.white.opacity(0.55)) }
                trailing()
            }
        }
    }

    private var formCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                field("Project URL", "wss://your-project.livekit.cloud", text: $url)
                field("API Key", "API key", text: $apiKey)
                field("API Secret", "API secret", text: $apiSecret, secure: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func field(_ label: String, _ placeholder: String, text: Binding<String>, secure: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.white.opacity(0.5))
            Group {
                if secure { SecureField(placeholder, text: text) } else { TextField(placeholder, text: text) }
            }
            .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced)).foregroundStyle(.white)
            .padding(10).glassEffect(.regular, in: .rect(cornerRadius: 10, style: .continuous))
            #if os(iOS)
            .textInputAutocapitalization(.never).autocorrectionDisabled()
            #endif
        }
    }

    private func save() async {
        guard let client = app.client else { return }
        busy = true; error = ""
        defer { busy = false }
        do {
            try await client.setVoiceConfig(
                url: url.trimmingCharacters(in: .whitespaces),
                apiKey: apiKey.trimmingCharacters(in: .whitespaces),
                apiSecret: apiSecret.trimmingCharacters(in: .whitespaces))
            done = true
            try? await Task.sleep(for: .milliseconds(700))
            dismiss()
        } catch {
            let d = String(describing: error).lowercased()
            self.error = d.contains("forbidden") || d.contains("403")
                ? "Only the host can turn this on."
                : d.contains("badrequest") || d.contains("400")
                    ? "Check the URL (wss://…), key, and secret."
                    : "Couldn't save — check the values and your connection."
        }
    }
}
