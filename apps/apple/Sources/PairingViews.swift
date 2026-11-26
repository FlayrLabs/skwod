import SwiftUI

/// Profile → Devices → "Add a device" (build 48), on a device that is already signed in.
///
/// Shows a QR code the NEW device scans from its first screen ("Scan from your other device"): the
/// skwod's address and home relay, this account's username, and a fresh one-time link code that
/// expires in five minutes (`pairing.rs` in the core). No password, token or key is in it.
/// The offer is registered with the server first (signed by this device). When the new device asks
/// to be added — without a password — it shows five emoji, and this sheet shows four sets: the
/// person picks the one on the new device (a wrong pick refuses it), or "None of these". The
/// offer approves one device, once.
struct AddDeviceSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var offer: PairingOffer?
    @State private var qr: String?
    @State private var candidate: PairingCandidate?
    @State private var errorText = ""
    @State private var done = false
    @State private var busy = false
    @State private var now = Date()

    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "qrcode").font(.system(size: 36)).foregroundStyle(.skAccent)
            Text("Add a device").font(.title2.bold()).foregroundStyle(.white)
            if done {
                Label("Linked. The new device is setting itself up.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Button("Done") { dismiss() }.buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            } else if let candidate {
                Text(PairingCopy.pickTitle).font(.headline).foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                VStack(spacing: 8) {
                    ForEach(Array(candidate.choices.enumerated()), id: \.offset) { i, set in
                        Button { Task { await approve(candidate, picked: set) } } label: {
                            Text(set).font(.system(size: 30)).frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.glass).disabled(busy)
                        .accessibilityIdentifier("pair.choice.\(i)")
                    }
                }
                Text(PairingCopy.pickHint)
                    .font(.caption).foregroundStyle(.white.opacity(0.55)).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                Button(PairingCopy.noneOfThese, role: .destructive) { Task { await deny(candidate) } }
                    .buttonStyle(.glass).disabled(busy)
                    .accessibilityIdentifier("pair.deny")
                if busy { ProgressView().controlSize(.small) }
            } else if let qr, let offer {
                Text("On the new device, open Skwod and tap “Scan from your other device”.")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.65)).multilineTextAlignment(.center)
                QRCodeView(text: qr, size: 200)
                Text(remaining(offer)).font(.caption.monospacedDigit()).foregroundStyle(.white.opacity(0.5))
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Waiting for the new device…").font(.caption).foregroundStyle(.white.opacity(0.5))
                }
                Text("No password is needed on the new device: you approve it here. The code works once, for five minutes.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.45)).multilineTextAlignment(.center)
            } else if errorText.isEmpty {
                ProgressView().tint(.skAccent)
            }
            if !errorText.isEmpty {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red.opacity(0.9)).multilineTextAlignment(.center)
                Button("Make a new code") { Task { await start() } }.buttonStyle(.glass).tint(.skAccent)
            }
            if !done { Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5)) }
        }
        .padding(28)
        .frame(minWidth: 380, maxWidth: 460)
        .background(SkwodBackground())
        .task { await start() }
        .task(id: offer?.code) { await poll() }
        .onReceive(tick) { now = $0 }
    }

    private var unixNow: UInt64 { UInt64(Date().timeIntervalSince1970) }

    private func remaining(_ offer: PairingOffer) -> String {
        let left = max(0, Int(offer.expiresAt) - Int(now.timeIntervalSince1970))
        return left == 0 ? "Expired" : String(format: "Expires in %d:%02d", left / 60, left % 60)
    }

    /// Mint an offer: this skwod's key + home relay, this account's username, a fresh code.
    private func start() async {
        errorText = ""; candidate = nil; offer = nil; qr = nil
        guard let client = app.client, let userId = app.session?.userId else { errorText = "Not signed in."; return }
        // From the host itself: also right on the Mac that hosts this skwod (its own workspace
        // has no node id), and it says whether the host lets devices pair by QR.
        let info: InstanceP2p?
        do { info = try await client.instanceP2p() } catch {
            errorText = "Couldn't reach your Skwod. Check your connection and try again."
            return
        }
        guard let info else {
            errorText = "This Skwod isn't reachable by its key, so adding a device by QR isn't available. Use “Link a device…” instead."
            return
        }
        guard info.qrPairing else {
            errorText = "This Skwod's host hasn't turned on adding devices by QR. Use “Link a device…” instead."
            return
        }
        guard let username = await currentUsername() else {
            errorText = "Couldn't reach your Skwod. Check your connection and try again."
            return
        }
        do {
            let o = try pairingNewOffer(nodeId: info.nodeId, relayUrl: info.relayUrl ?? RelayHintStore.get(info.nodeId),
                                        username: username, userId: userId, now: unixNow)
            // The server accepts requests only for offers a device of the account registered.
            try await client.registerPairingOffer(offer: o)
            qr = try pairingQrEncode(offer: o)
            offer = o
        } catch {
            errorText = coreErrorText(error, fallback: "Couldn't make a code. Try again.")
        }
    }

    /// Wait for the new device's link request (without approving it), until the offer expires.
    private func poll() async {
        guard let offer, let client = app.client else { return }
        while !Task.isCancelled, candidate == nil, !done {
            do {
                if let c = try await client.pairingCandidate(offer: offer, now: unixNow) {
                    candidate = c
                    return
                }
            } catch {
                errorText = unixNow > offer.expiresAt ? "That code expired." : coreErrorText(error, fallback: "That code can't be used any more.")
                self.offer = nil; qr = nil
                return
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func approve(_ c: PairingCandidate, picked: String) async {
        guard let offer, let client = app.client else { return }
        busy = true; defer { busy = false }
        do {
            if try await client.approvePairing(offer: offer, candidate: c, picked: picked, now: unixNow) {
                done = true
            } else {
                errorText = "That request is gone. Make a new code and scan again."
                candidate = nil; self.offer = nil; qr = nil
            }
        } catch {
            errorText = coreErrorText(error)
            candidate = nil; self.offer = nil; qr = nil
        }
    }

    /// "None of these" (not this person's device, or no set matches): refuse it — the new device is told — and
    /// burn this offer; a new one gets a new code.
    private func deny(_ c: PairingCandidate) async {
        guard let offer, let client = app.client else { return }
        busy = true; defer { busy = false }
        try? await client.denyPairing(offer: offer, candidate: c)
        candidate = nil; self.offer = nil; qr = nil
        errorText = "Not added. If that wasn't a device of yours, nothing reached it. Make a new code to try again."
    }

    /// The signed-in account's username (`GET /api/auth/me`), to put in the QR.
    private func currentUsername() async -> String? {
        guard let token = app.session?.token, let base = URL(string: app.serverURL), !app.serverURL.isEmpty else { return nil }
        var req = URLRequest(url: base.appendingPathComponent("api/auth/me")); req.timeoutInterval = 10
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await RawSink.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return obj["username"] as? String
    }
}
