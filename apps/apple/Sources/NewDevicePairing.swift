import SwiftUI

/// The NEW device's half of "Add a device" by QR (build 48), started by scanning the QR another
/// device shows. No password at any point (docs/SECURITY.md "Adding a device by QR"):
///
/// 0. ask "Join <skwod> as <username>?" before dialling anything (the skwod named only by a
///    workspace this device already has, otherwise by the host's short key);
/// 1. dial the host by its node id (the transport proves the host holds that key);
/// 2. set up this device's encrypted store under the workspace id it will keep, and open a
///    session-less pair request;
/// 3. once the other device has seen this one it releases its nonce (checked against the QR's
///    commitment) and this screen shows five emoji; the person picks the same five there;
/// 4. once approved the core has claimed the one session, finished the link and registered; this
///    screen says "Approved on your other device" with the host's short key before entering;
/// 5. sign in with that session — this device lands in the app as a linked device.
///
/// Cancel, denial, expiry and errors remove what step 2 created, so nothing is left behind.
@MainActor
final class NewDevicePairing: ObservableObject, Identifiable {
    enum Phase: Equatable {
        case join
        case connecting
        case waiting
        case confirm(String)
        case approved
        case finishing
        case done
        case failed(String)
    }

    let offer: PairingOffer
    let known: Bool
    /// What this device already calls the host (a workspace it has), never what the QR says.
    let knownName: String?
    @Published private(set) var phase: Phase = .join { didSet { report() } }
    private var client: SkwodClient?
    private var lease: CacheLease?
    private var localId: String?
    private var task: Task<Void, Never>?
    private var paired: PairedDevice?
    private var address: SkwodAddress?
    private var base: String?

    nonisolated var id: String { offer.code }

    init(offer: PairingOffer, known: Bool, knownName: String? = nil) {
        self.offer = offer
        self.known = known
        self.knownName = knownName
    }

    var shortKey: String { InviteLink.shortKey(offer.nodeId) }

    var header: String {
        PairingCopy.header(shortKey: shortKey, username: offer.username, known: known)
    }

    var joinPrompt: String {
        PairingCopy.joinPrompt(knownName: knownName, shortKey: shortKey, username: offer.username)
    }

    /// Show the question; nothing is dialled until [`confirmJoin`].
    func start(app: AppState) {
        report()
        #if DEBUG
        if E2E.env("SKWOD_E2E_PAIR_QR") != nil {
            // The end-to-end run answers as a person would, after the question was on screen.
            Task { try? await Task.sleep(for: .seconds(1)); if phase == .join { confirmJoin(app: app) } }
        }
        #endif
    }

    /// "Continue": dial and open the request.
    func confirmJoin(app: AppState) {
        guard task == nil, phase == .join else { return }
        phase = .connecting
        task = Task { await run(app: app) }
    }

    /// "Continue" on the approved screen: enter the account.
    func enter(app: AppState) {
        guard phase == .approved, let paired, let address, let base, let id = localId else { return }
        phase = .finishing
        Task {
            await app.signIn(paired.session, address: address, liveBase: base, pairedLocalId: id)
            phase = .done
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
        if phase != .done && phase != .finishing { cleanUp() }
    }

    private var now: UInt64 { UInt64(Date().timeIntervalSince1970) }

    private func run(app: AppState) async {
        #if DEBUG
        E2E.pairingErrorDetail = nil
        #endif
        // An account this device already has on this skwod: nothing to pair.
        if app.workspaces.contains(where: { $0.nodeId == offer.nodeId && $0.userId == offer.userId && !$0.isSignedOut }) {
            phase = .failed("This account is already on this device.")
            return
        }
        do {
            RelayHintStore.set(offer.relayUrl, for: offer.nodeId)
            let address = SkwodAddress.p2p(nodeId: offer.nodeId, fallbackURL: nil)
            let base = try await app.liveBase(for: address)
            guard !Task.isCancelled else { return }

            // The id this device's workspace will have (a signed-out entry for this account keeps
            // its own; otherwise a fresh one), and its store — opened under the app's lock.
            let id = app.workspaces.first(where: { $0.nodeId == offer.nodeId && $0.userId == offer.userId })?.id
                ?? UUID().uuidString.lowercased()
            guard let keyHex = Keychain.cacheKeyHex(for: id) else {
                phase = .failed("Skwod couldn't set up its encrypted storage. Unlock the device and try again.")
                return
            }
            let c = SkwodClient(baseUrl: base, token: "")
            let use = c.cacheLease()
            lease = use
            switch await CacheOpening(lock: .shared, isCurrent: { !Task.isCancelled }, key: { keyHex }, lease: { use }, attach: {
                self.localId = id
                self.client = c
                _ = try await c.attachCache(path: SharedContainer.cachePath(forWorkspace: id), keyHex: $0)
            }).run() {
            case .open: break
            case .superseded: return
            case .closed: throw PairingLeft()
            case .busy, .noKey:
                phase = .failed("Skwod is busy finishing a notification. Try again in a moment.")
                return
            case .failed(let error): throw error
            }
            SharedContainer.excludeCacheFromBackup(forWorkspace: id)
            // Pin the host's identity before anything is exchanged, as a log-in does.
            if let identity = try? await fetchServerIdentity(baseUrl: base) {
                try await c.setPinnedServerKey(serverPublicB64: identity.serverPublic)
            }
            await c.setDeviceLabel(name: DeviceLabel.suggested)
            try await c.pairBegin(offer: offer, now: now)
            phase = .waiting

            while !Task.isCancelled {
                // The app was sent away meanwhile: this client's cache was taken from it, and the
                // code it answered can be answered only once (`pairBegin` again would burn it).
                if use.isOver() { throw PairingLeft() }
                if now > offer.expiresAt + 60 {
                    throw PairingExpired()
                }
                switch try await c.pairPoll(offer: offer) {
                case .waiting:
                    break
                case .confirm(let emoji):
                    if phase != .confirm(emoji) { phase = .confirm(emoji) }
                case .paired(let device):
                    // The pairing client lets go of the store; signing in opens it again.
                    client = nil
                    paired = device
                    self.address = address
                    self.base = base
                    phase = .approved
                    #if DEBUG
                    if E2E.env("SKWOD_E2E_PAIR_QR") != nil {
                        try? await Task.sleep(for: .seconds(1))
                        enter(app: app)
                    }
                    #endif
                    return
                }
                try? await Task.sleep(for: .seconds(2))
            }
        } catch is PairingLeft {
            left()
        } catch is PairingExpired {
            phase = .failed("The code expired before it was approved. Make a new one on your other device.")
            cleanUp()
        } catch {
            guard !Task.isCancelled else { return }
            if lease?.isOver() == true { left(); return }
            #if DEBUG
            E2E.pairingErrorDetail = String(describing: error)
            #endif
            phase = .failed(PairingCopy.failure(detail: coreErrorText(error, fallback: "Couldn't reach that Skwod. Check your connection and try again.")))
            cleanUp()
        }
    }

    private func left() {
        phase = .failed(PairingCopy.left)
        cleanUp()
    }

    /// Remove the store and key a pairing that did not finish created.
    private func cleanUp() {
        client = nil
        paired = nil
        guard let id = localId else { return }
        localId = nil
        // A signed-out workspace's own store is never removed here.
        if WorkspaceStore.load().contains(where: { $0.id == id }) { return }
        let path = SharedContainer.cachePath(forWorkspace: id)
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        Keychain.delete("cache-key-\(id)")
    }

    private func report() {
        #if DEBUG
        E2E.notePairing(phase)
        #endif
    }
}

private struct PairingExpired: Error {}
/// The app left the front while pairing (the cache may not be used from there).
private struct PairingLeft: Error {}

/// The screen for [`NewDevicePairing`].
struct NewDevicePairingSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var pairing: NewDevicePairing
    @State private var now = Date()
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "iphone.and.arrow.forward").font(.system(size: 36)).foregroundStyle(.skAccent)
            Text("Add this device").font(.title2.bold()).foregroundStyle(.white)
            Text(pairing.header)
                .font(.subheadline.monospaced()).foregroundStyle(.white.opacity(0.75))
                .multilineTextAlignment(.center)
                .accessibilityIdentifier("pair.header")
            switch pairing.phase {
            case .join:
                Text(pairing.joinPrompt).font(.headline).foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("pair.join")
                Text(PairingCopy.joinDetail)
                    .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Continue") { pairing.confirmJoin(app: app) }
                    .buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    .accessibilityIdentifier("pair.join.continue")
            case .connecting:
                ProgressView().tint(.skAccent)
                Text("Reaching the Skwod…").font(.caption).foregroundStyle(.white.opacity(0.55))
            case .waiting:
                ProgressView().tint(.skAccent)
                Text(PairingCopy.waitingForOther).font(.caption).foregroundStyle(.white.opacity(0.55))
                    .multilineTextAlignment(.center)
            case .confirm(let emoji):
                Text(emoji).font(.system(size: 40)).accessibilityIdentifier("pair.confirm.new")
                Text(PairingCopy.confirmInstruction())
                    .font(.subheadline).foregroundStyle(.white.opacity(0.7)).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    let left = PairingCopy.secondsLeft(expiresAt: pairing.offer.expiresAt, now: now)
                    Text(String(format: "Waiting for approval · %d:%02d", left / 60, left % 60))
                        .font(.caption.monospacedDigit()).foregroundStyle(.white.opacity(0.5))
                }
            case .approved:
                Label(PairingCopy.approved(shortKey: pairing.shortKey), systemImage: "checkmark.seal.fill")
                    .font(.callout.monospaced()).foregroundStyle(.green).multilineTextAlignment(.center)
                    .accessibilityIdentifier("pair.approved")
                Button("Continue") { pairing.enter(app: app) }
                    .buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    .accessibilityIdentifier("pair.enter")
            case .finishing:
                ProgressView().tint(.skAccent)
                Text("Setting up this device…").font(.caption).foregroundStyle(.white.opacity(0.55))
            case .done:
                Label("This device is linked.", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            case .failed(let why):
                Label(why, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("pair.failed")
            }
            Button(pairing.phase == .done ? "Done" : (isFailed ? "Close" : "Cancel")) {
                pairing.cancel()
                dismiss()
            }
            .buttonStyle(.plain).foregroundStyle(.white.opacity(0.6))
            .disabled(pairing.phase == .finishing)
        }
        .padding(28)
        .frame(minWidth: 340, maxWidth: 460)
        .background(SkwodBackground())
        .interactiveDismissDisabled()
        .task { pairing.start(app: app) }
        .onReceive(tick) { now = $0 }
        .onChange(of: pairing.phase) { _, p in if p == .done { dismiss() } }
    }

    private var isFailed: Bool { if case .failed = pairing.phase { true } else { false } }
}
