#if os(macOS)
import SwiftUI
import AppKit

/// Backing up the skwod this Mac hosts, moving it to another Mac, and moving its folder.
///
/// All three are done by the bundled server binary (`skwod-server backup | restore | move-data`,
/// `server/src/hostbackup.rs`) — the same code a Docker or Unraid host runs from its shell:
///
/// - **Export** writes ONE file, encrypted under a passphrase the host chooses: a consistent
///   copy of the database, the attachments, the key that is the skwod's address — and this
///   Mac's saved owner login, so the new Mac can sign the host in.
/// - **Import** on another Mac gives the SAME skwod: same address, same invites, same members.
///   Nothing is changed unless the whole file opens and checks out.
/// - **Changing the storage folder** moves the skwod there. (It used to point the app at an
///   empty folder — which silently started a NEW server and left the old one behind.)
extension HostManager {
    private func bundledServer() -> URL? {
        Bundle.main.url(forResource: "skwod-server", withExtension: nil, subdirectory: "host-tools")
            ?? Bundle.main.url(forResource: "skwod-server", withExtension: nil)
    }

    /// Run the bundled server binary with `args`. Nothing secret goes on its command line.
    /// `answers`: lines the tool asks for on its standard input — the backup passphrase goes
    /// this way (a pipe only the child reads), not in its environment, which other processes
    /// of the same user can read on macOS. The owner's saved login goes the same way
    /// (`backup --owner-login-stdin`, after the passphrase lines).
    private func tool(_ args: [String], env extra: [String: String] = [:], answers: [String] = []) async -> (ok: Bool, message: String) {
        guard let exe = bundledServer() else { return (false, "This copy of Skwod has no server inside it. Download Skwod again.") }
        return await withCheckedContinuation { done in
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = exe
                p.arguments = args
                var env = ProcessInfo.processInfo.environment
                for (k, v) in extra { env[k] = v }
                // Never an inherited passphrase or owner login: the tool would take them before
                // asking (and they are secrets that belong on the pipe below, not here).
                env["SKWOD_BACKUP_PASSPHRASE"] = nil
                env["SKWOD_BACKUP_OWNER_LOGIN"] = nil
                env["SKWOD_LOCAL_PROOF_SECRET"] = nil
                p.environment = env
                let (out, err, input) = (Pipe(), Pipe(), Pipe())
                p.standardOutput = out; p.standardError = err; p.standardInput = input
                do { try p.run() } catch { return done.resume(returning: (false, "The server tool could not be started.")) }
                input.fileHandleForWriting.write(Data(answers.map { $0 + "\n" }.joined().utf8))
                try? input.fileHandleForWriting.close()
                let outText = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                let errText = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                p.waitUntilExit()
                // "[skwod] restore failed: <sentence>" → the sentence. (The tool's passphrase
                // prompts are on the same stream, without a line break, in front of it.)
                let line = (p.terminationStatus == 0 ? outText : errText)
                    .split(separator: "\n").last.map(String.init) ?? ""
                let sentence = line.replacingOccurrences(of: #"^.*\[skwod\] (\w+ failed: )?"#, with: "", options: .regularExpression)
                done.resume(returning: (p.terminationStatus == 0, sentence.prefix(1).uppercased() + sentence.dropFirst()))
            }
        }
    }

    /// Stop hosting (if on) and wait for the child to be gone; returns whether it was on.
    private func pauseHosting() async -> Bool {
        let was = isHosting
        if was {
            stop()
            try? await Task.sleep(for: .milliseconds(1500))
        }
        return was
    }

    /// Why `passphrase` cannot protect a backup, or nil when it can.
    static func passphraseProblem(_ passphrase: String) -> String? {
        backupPassphraseProblem(passphrase: passphrase)
    }

    /// Export this Mac's skwod to `file`. Returns a sentence on failure.
    func exportServer(to file: URL, passphrase: String) async -> String? {
        guard hasHostedBefore else { return "This Mac is not hosting a skwod yet." }
        // Stopped for the copy: nothing is written to the folder while it is read.
        let resume = await pauseHosting()
        defer { if resume { start() } }
        var args = ["backup", "--data", dataDir.path, "--out", file.path]
        // The passphrase is asked for twice (the tool confirms it); the owner's login, when this
        // Mac has one saved, is the line after those — over the pipe, never the environment.
        var answers = [passphrase, passphrase]
        if let login = Keychain.get(Self.ownerCredentialsAccount), !login.isEmpty, !login.contains("\n") {
            args.append("--owner-login-stdin")
            answers.append(login)
        }
        try? FileManager.default.removeItem(at: file)
        let r = await tool(args, answers: answers)
        return r.ok ? nil : r.message
    }

    /// Import the skwod in `file` onto this Mac. `replace`: this Mac already hosts one — it is
    /// set aside (kept next to the data folder), not deleted. Returns a sentence on failure.
    func importServer(from file: URL, passphrase: String, replace: Bool) async -> String? {
        if hasHostedBefore && !replace { return "This Mac already hosts a skwod." }
        _ = await pauseHosting()
        // The owner's login comes out of the archive into a private file, goes straight into
        // the keychain, and the file is removed.
        let loginFile = SharedContainer.privateURL.appendingPathComponent(".owner-login-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: SharedContainer.privateURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: loginFile) }
        var args = ["restore", "--in", file.path, "--data", dataDir.path, "--owner-login-out", loginFile.path]
        if replace { args.append("--replace") }
        let r = await tool(args, answers: [passphrase])
        guard r.ok else { return r.message }
        if let login = try? String(contentsOf: loginFile, encoding: .utf8), !login.isEmpty {
            Keychain.set(login, for: Self.ownerCredentialsAccount)
        }
        return nil
    }

    /// Move the hosted skwod to `folder` (it becomes `<folder>/skwod-host-data`). With no skwod
    /// yet, this only chooses where the first one will live. Returns a sentence on failure.
    func moveStorage(to folder: URL) async -> String? {
        let target = folder.appendingPathComponent("skwod-host-data")
        guard target.standardizedFileURL != dataDir.standardizedFileURL else { return nil }
        guard hasHostedBefore else { dataDir = target; return nil }
        let resume = await pauseHosting()
        let r = await tool(["move-data", "--from", dataDir.path, "--to", target.path])
        if r.ok { dataDir = target }
        if resume { start() }
        return r.ok ? nil : r.message
    }
}

/// "Export server…" / "Import server…" in the host's options.
struct HostBackupRow: View {
    @ObservedObject var host: HostManager
    @State private var mode: Mode?
    @State private var file: URL?
    @State private var passphrase = ""
    @State private var again = ""
    @State private var busy = false
    @State private var result: String?
    @State private var failed = false
    @State private var confirmReplace = false

    enum Mode: String, Identifiable { case export, restore; var id: String { rawValue } }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Backup").font(.caption).foregroundStyle(.white.opacity(0.5))
                    Text("One encrypted file with everything: move this skwod to another Mac, or keep it safe. A copy of the database is also kept here every day for a week.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.55)).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("Export…") { chooseExport() }.buttonStyle(.glass).disabled(!host.hasHostedBefore || busy)
                    .accessibilityIdentifier("host.export")
                Button("Import…") { chooseImport() }.buttonStyle(.glass).disabled(busy)
                    .accessibilityIdentifier("host.import")
            }
            if let result {
                Text(result).font(.caption).foregroundStyle(failed ? .orange : .green)
                    .fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("host.backupResult")
            }
        }
        .sheet(item: $mode) { m in passphraseSheet(m) }
        .confirmationDialog("Replace the skwod on this Mac?", isPresented: $confirmReplace, titleVisibility: .visible) {
            Button("Import and set the current one aside", role: .destructive) { Task { await run(.restore, replace: true) } }
        } message: {
            Text("This Mac already hosts a skwod. It is not deleted: its folder is kept next to the new one, renamed.")
        }
    }

    private func chooseExport() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Skwod server backup.skwodbackup"
        panel.prompt = "Export"
        if panel.runModal() == .OK, let url = panel.url { file = url; passphrase = ""; again = ""; result = nil; mode = .export }
    }

    private func chooseImport() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.prompt = "Import"
        if panel.runModal() == .OK, let url = panel.url { file = url; passphrase = ""; again = ""; result = nil; mode = .restore }
    }

    private func problem(_ m: Mode) -> String? {
        guard m == .export else { return passphrase.isEmpty ? "" : nil }
        if passphrase.isEmpty { return "" }
        if let weak = HostManager.passphraseProblem(passphrase) { return weak }
        return passphrase == again ? nil : "The two passphrases differ."
    }

    @ViewBuilder private func passphraseSheet(_ m: Mode) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(m == .export ? "Protect the backup" : "Open the backup").font(.title3.bold())
            Text(m == .export
                 ? "Choose a passphrase of at least 14 characters. Anyone with this file AND the passphrase has your whole skwod; without the passphrase the file cannot be opened — not by you either. Write it down."
                 : "Enter the passphrase this backup was exported with.")
                .font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            SecureField("Passphrase", text: $passphrase).textFieldStyle(.roundedBorder).accessibilityIdentifier("host.passphrase")
            if m == .export {
                SecureField("Passphrase again", text: $again).textFieldStyle(.roundedBorder)
                if let p = problem(m), !p.isEmpty { Text(p).font(.caption).foregroundStyle(.orange) }
            }
            HStack {
                Button("Cancel") { mode = nil }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(m == .export ? "Export" : "Import") {
                    mode = nil
                    if m == .restore && host.hasHostedBefore { confirmReplace = true } else { Task { await run(m, replace: false) } }
                }
                .keyboardShortcut(.defaultAction).disabled(problem(m) != nil)
            }
        }
        .padding(22).frame(width: 440)
    }

    private func run(_ m: Mode, replace: Bool) async {
        guard let file else { return }
        busy = true
        defer { busy = false; passphrase = ""; again = "" }
        let failure = m == .export
            ? await host.exportServer(to: file, passphrase: passphrase)
            : await host.importServer(from: file, passphrase: passphrase, replace: replace)
        failed = failure != nil
        result = failure ?? (m == .export
            ? "Exported to \(file.lastPathComponent). Keep the passphrase with it."
            : "Imported. Press Start server: it is the same skwod, at the same address — everyone's invites keep working.")
    }
}
#endif
