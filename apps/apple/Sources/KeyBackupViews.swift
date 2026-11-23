import SwiftUI

/// Set up passphrase key backup: the engine's keys are encrypted under a passphrase-wrapped
/// backup key and stored on the user's own server (ciphertext only — the host can't read it).
/// With backup on, signing out everywhere no longer forfeits solo servers.
struct KeyBackupSetupSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    /// Called after the backup is created and uploaded.
    var onEnabled: () -> Void

    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var busy = false
    @State private var errorText = ""
    /// The account already has a backup (made on another device / another passphrase) — enabling
    /// here REPLACES it, so the user must be told before they overwrite the old one.
    @State private var replacesExisting = false

    /// Why the passphrase is too weak to survive offline guessing (nil = acceptable). The check
    /// lives in the shared core so every platform enforces the same bar.
    private var problem: String? { passphrase.isEmpty ? nil : backupPassphraseProblem(passphrase: passphrase) }
    private var valid: Bool { !passphrase.isEmpty && problem == nil && passphrase == confirm }
    /// A generated recovery key, shown once so the user can write it down.
    @State private var generated: String?

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "key.icloud.fill").font(.system(size: 40)).foregroundStyle(.skAccent)
            Text("Use your own passphrase").font(.title2.bold()).foregroundStyle(.white)
            Text("Your identity key and space keys are sealed under this passphrase and stored on your Skwod's server as ciphertext. If you lose every device, it brings them back. The server can try guesses against a backup offline, so a short PIN is not accepted — use a long passphrase or a generated recovery key.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)

            Button {
                let key = generateRecoveryKey()
                generated = key; passphrase = key; confirm = key
            } label: {
                Label("Generate a recovery key", systemImage: "wand.and.stars").font(.caption.weight(.semibold))
            }
            .buttonStyle(.plain).foregroundStyle(.skAccent)
            if let generated {
                Text(generated)
                    .font(.system(.footnote, design: .monospaced)).foregroundStyle(.white)
                    .textSelection(.enabled).multilineTextAlignment(.center)
                    .padding(12).glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
                Text("Write this down or save it in a password manager. It is shown only once.")
                    .font(.caption2).foregroundStyle(.orange.opacity(0.9)).multilineTextAlignment(.center)
            }

            SecureField("Passphrase (14+ characters)", text: $passphrase)
                .textFieldStyle(.plain).padding(12)
                .glassEffect(.regular, in: .capsule)
            SecureField("Confirm passphrase", text: $confirm)
                .textFieldStyle(.plain).padding(12)
                .glassEffect(.regular, in: .capsule)

            if let problem {
                hint(problem.prefix(1).uppercased() + problem.dropFirst() + ".")
            } else if !confirm.isEmpty && passphrase != confirm {
                hint("Passphrases don't match.")
            }
            Text("Anyone who can guess this passphrase — including whoever runs the server — can decrypt your keys. There is no reset: a forgotten passphrase means a lost backup.")
                .font(.caption2).foregroundStyle(.orange.opacity(0.85)).multilineTextAlignment(.center)
            if replacesExisting {
                Label("This account already has a backup. Turning backup on here replaces it — the old passphrase (and any keys only that backup held) stops working.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2).foregroundStyle(.orange).multilineTextAlignment(.leading)
            }

            if !errorText.isEmpty {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red.opacity(0.9))
            }

            Button {
                Task { await enable() }
            } label: {
                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small) }
                    Text("Turn on backup").fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(busy || !valid)

            Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(28)
        .frame(minWidth: 380, maxWidth: 440)
        .background(SkwodBackground())
        .task { replacesExisting = (try? await app.client?.hasRemoteKeyBackup()) ?? false }
    }

    private func enable() async {
        guard let client = app.client else { errorText = "Not connected."; return }
        busy = true; errorText = ""
        do {
            try await client.enableKeyBackup(passphrase: passphrase)
            onEnabled()
            dismiss()
        } catch {
            errorText = friendlyError(error)
        }
        busy = false
    }

    private func hint(_ text: String) -> some View {
        Text(text).font(.caption2).foregroundStyle(.orange.opacity(0.9))
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// Surface the FFI's `Invalid { detail }` message ("wrong passphrase") instead of a raw enum dump.
private func friendlyError(_ error: Error) -> String {
    let s = String(describing: error)
    if s.contains("wrong passphrase") { return "Wrong passphrase." }
    if let r = s.range(of: "detail: \"") {
        let tail = s[r.upperBound...]
        if let end = tail.firstIndex(of: "\"") { return String(tail[..<end]) }
    }
    return "Something went wrong — check your connection."
}
