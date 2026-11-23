# Architecture Decision Records

Each ADR records a decision, the context, and its status. **Accepted** = locked and building to it.
**Open** = default chosen to keep moving, needs owner confirmation before it becomes irreversible.

---

## ADR-001 — Native per platform over one shared crypto/sync core — **Accepted**

**Context.** The rewrite must be native on iOS, macOS, and Android, keep full feature parity, and
not reimplement security-critical code three times.

**Decision.** Follow the Signal (libsignal) / Telegram (TDLib) model: one **Rust core** (crypto +
realtime sync + local encrypted cache) exposed to each native UI via UniFFI. UIs are fully native
(SwiftUI for iOS+macOS, Compose for Android). The crypto and the sync/data layer are written once.

**Consequences.** Adds a Rust↔Swift/Kotlin FFI build step; removes an entire duplicated data layer
and a second crypto audit surface. Net large win.

---

## ADR-002 — Crypto library & source license — **Superseded by ADR-011**

> Superseded 2026-11-17. Kept for the record; do not build to it.

**Context.** Official `libsignal` is **AGPLv3**. Linking it makes the whole app AGPL, which
conflicts with paid App Store distribution unless you are the sole copyright holder (how Signal and
Telegram ship GPL apps on the App Store). We are not the `libsignal` copyright holder. The owner has
decided: **the paid App Store app must stay legal.**

**Decision.** The paid-app requirement is decisive, so **official `libsignal` is NOT adopted**
(mutually exclusive with a legal paid App Store app). Instead:
- Build a **permissively-licensed in-house Signal-family implementation** in Rust (PQXDH, Double
  Ratchet, Sender Keys, Sealed Sender, SPQR, key backup/transparency) behind a `CryptoProvider`
  trait. `libsignal` remains *swappable* but is **not linked** unless the project ever abandons paid
  App Store distribution.
- **Source license: Apache-2.0** (patent grant; standard for Rust/crypto) — lets "open source" and
  "paid App Store app" coexist.

**Supersedes.** The owner's initial "adopt official libsignal" instruction — incompatible with the
paid-app requirement, which wins.

**Accepted risk / hard gate.** Hand-rolled crypto (even Signal-faithful) **must pass an independent
cryptographic audit before release** — now a blocking Phase 10 gate, not optional. This is the cost
of the license constraint; adopting `libsignal` would have removed it.

---

## ADR-003 — Payments: web-only signup (Stripe), app is login-only — **Accepted, not implemented**

> **Status (build 41): not in effect.** No Stripe checkout, entitlement service or webhook exists
> in this tree, and no build gates on payment: the server has no billing columns
> (`server/migrations/0001_init.sql`) and the apps ship with the paywall switch off
> ([APPLE.md](APPLE.md) → "Paywall flag"). Pricing for the official mobile builds is undecided.
> The text below is the original decision, kept for the record.

**Context.** Owner wants $3.99/mo, not Apple IAP. The 2025 *Epic v. Apple* ruling lets **US** App
Store apps link to external payment commission-free, but this is **US-only** — the EU operates under
the DMA and most storefronts still require IAP for in-app digital subscriptions. A US-only Stripe
link would get the iOS app rejected elsewhere.

**Decision.** **All payment happens on the web (`skwod.io`) via Stripe; the apps are login-only.**
This is the "reader app" model: the native apps contain **no purchase UI and no IAP** — a user
subscribes on the website, then signs in. Compliant in every country with **zero Apple/Google
commission**. It fits Skwod naturally because usage already requires an out-of-app **join code** from
a server operator, so web signup is part of the same onboarding step (get code → subscribe on web →
sign in).

- **Gate.** App usable only with (a) an active $3.99/mo Stripe entitlement AND (b) a valid join code.
  Entitlement verified server-side via Stripe webhooks; the client holds a short-lived signed
  entitlement token.
- **US nicety (optional).** In the US we *may* additionally drop an external payment link inside the
  app, but it's not required and not the default.
- **Self-host note.** Entitlement gating is a client/app-store concern, not a server-privacy one — a
  self-hosted server may run with gating off for its own members (open-source, their box, their rules).

---

## ADR-004 — E2EE everything; server is untrusted — **Accepted**

**Context.** Owner: "E2EE everything, lock it all down," fully self-hosted including the server.

**Decision.** The server only ever holds ciphertext + public keys + routing metadata, even though
the operator owns it. Self-hosting and E2EE are treated as independent, additive guarantees.
Consequences: search is client-side; history sync requires key backup/transfer; bots post via
sender keys; link previews are generated client-side. All accepted.

---

## ADR-005 — Self-hosting: single Rust binary + storage volume — **Accepted**

**Context.** Must be trivially self-hostable on a laptop or VPS, "select a storage volume as its DB."

**Decision.** One static Rust binary. Default state = **SQLite + encrypted blob directory on a
chosen volume**; `--data /path` is the whole configuration surface. Optional Postgres + S3 for scale.
Voice/video via a **self-hosted LiveKit SFU** shipped in the deploy bundle (docker-compose for the
one-container-per-service option; single binary for the minimal option).

**Needs confirmation.** Whether LiveKit ships bundled-by-default or as an opt-in add-on.

---

## ADR-006 — Post-quantum is mandatory when mutually supported — **Accepted**

**Context.** Original Skwod silently downgraded to classical X3DH when a peer lacked Kyber keys.

**Decision.** PQXDH negotiation records both peers' capabilities and **refuses a silent classical
downgrade** between two PQ-capable devices; classical is used only for genuinely legacy peers and is
surfaced in the UI. (See SECURITY.md.)

---

## ADR-007 — Voice E2EE fails closed — **Accepted**

**Context.** Original Skwod connected voice **unencrypted** on any E2EE setup error ("fail open").

**Decision.** If the E2EE key provider fails to initialize, the client **refuses to connect** to
voice/video and surfaces the error. No unencrypted media path exists.

---

## ADR-008 — One-command self-host installer (`skwod init`) — **Accepted**

**Context.** Owner wants a single, *simple* terminal command to stand up a full instance — the
mocked flow: check Docker → LiveKit setup (API key/secret) → start services → run migrations → print
URL + join code. (Owner clarified it does **not** need to be `npx` — just simple.)

**Decision.** Ship a **single self-contained Rust binary** with an `init` subcommand — no Node/`npx`,
no runtime dependency. Install via a one-line `curl -fsSL https://get.skwod.sh | sh` (signed,
checksum-verified) or `brew install skwod`, then run `skwod init`. The `init` subcommand renders the
interactive TUI and orchestrates the bundled `docker-compose`. All logic lives in the one binary.

**Init flow (matches the mock):**
1. `[1/4] Checking Docker…` — verify Docker + Compose present and running; friendly install hint if not.
2. `[2/4] LiveKit setup` — **auto-generate** API key + secret (or accept provided values), store in
   the instance config on the data volume; display masked.
3. `[3/4] Starting services…` — `docker-compose up -d` for server + LiveKit SFU (+ Postgres if
   selected); default is the minimal SQLite-on-volume profile.
4. `[4/4] Running migrations…` — server binary migrates the DB on the volume.
5. Print **`URL`** and a freshly generated **admin join code** (e.g. `SKWD-A7X2-M9K3`).

**Flags:** `--data <volume>` (state location), `--domain <host>` (TLS/URL), `--postgres`, `--s3`,
`--no-livekit`. Non-interactive `--yes` for scripted/VPS installs.

**Consequences.** Requires publishing a `get.skwod.sh` install script + a Homebrew formula + signed
prebuilt binaries per platform (GitHub Releases). No language runtime to ship.

**Needs confirmation.** Whether Docker is required, or we also offer a Docker-less single-process
path (`skwod run --data …`) for minimal text-only instances.

---

## ADR-009 — Native-only; no browser client; web / PWA / Electron dropped — **Accepted**

**Context.** The original had four clients: Next.js **web**, installable **PWA**, **Electron**
desktop, and Expo mobile. The rewrite targets native iOS, macOS, and Android.

**Decision.** **No browser client.** Drop web, PWA, and Electron. The native macOS app replaces
Electron. Rationale:
1. A web client is incompatible with the E2EE-everything model — it can't use Secure Enclave /
   StrongBox hardware keys and is exposed to XSS / malicious-served-JS key exfiltration. **Signal
   ships no web client for this exact reason.** It was the weakest link in the original Skwod.
2. It's a 4th client to build/maintain (WASM on the Rust core) indefinitely.
3. Native iOS/Android/macOS already cover the target users' devices.

A **plain marketing website** (landing/docs/privacy/terms + Stripe checkout pages) is still required,
but it's a separate static web property, not an app client. Full feature parity is preserved on the
three native clients.

**Future option (not now).** Windows/Linux desktop users have no client. If that need arises, close
it with a **native desktop app** (Rust core in a Tauri/native shell, keys off the browser) — **not**
a web client.

---

## ADR-010 — Rewrite methodology: fresh build, original as spec — **Accepted**

**Context.** The original app is 100% TypeScript (Next.js web · Expo/RN mobile · Electron · Deno edge
functions · shared TS crypto). The target stack is Rust + Swift + Kotlin. There is no language
overlap.

**Decision.** **Rewrite everything from scratch** in the new stack; **no code is moved, copied, or
linked** from the original. The original repo is the **reference specification** for behavior:
- **Ported as spec (design, not code):** the 40-table data model → new server schema; the 15-bit
  permission bitmask (exact bit-values) → constants; protocol constants / domain-separation labels /
  wire formats (e.g. `skwod-pqxdh-v1`) → carried verbatim where they define behavior; per-feature
  semantics → captured in a feature-parity ledger and reimplemented to match.
- **Rewritten fresh:** all crypto (algorithm-faithful + the SECURITY.md fixes), the sync/data layer,
  all UI, and the server.

**Consequence — data migration.** Because the crypto protocol and data model are rebuilt, existing
encrypted data/keys from the current app do **not** carry over automatically.

**Resolved.** Owner confirmed **clean slate** — no live users/data to migrate. No migration bridge
will be built; the new app starts fresh.

---

## ADR-011 — Adopt Signal's libsignal; relicense to AGPL-3.0-only — **Accepted** (supersedes ADR-002)

**Context.** ADR-002 chose an in-house, permissively-licensed Signal-family implementation for one
reason: `libsignal` is AGPL-3.0-only, and the project wanted a permissive licence. The cost was
written into that ADR — hand-rolled protocol crypto that would need its own independent audit, and
that diverged from Signal's in documented ways (split X25519/Ed25519 identity instead of XEdDSA, a
single-layer sealed sender, no per-message post-quantum ratchet). Builds 29–40 shipped that
implementation to a handful of TestFlight users.

The owner's requirement is that Skwod be "as secure as Signal". An unaudited reimplementation
cannot make that claim; the audited, widely deployed implementation can.

**Decision.**
1. The message protocol is **Signal's official `libsignal`** (`libsignal-protocol`, pinned to
   release `v0.108.0`, commit `8be00c282001caa3585d18de0f044c6d500348ab`, as a git dependency — it
   is not published on crates.io). PQXDH, Double Ratchet + SPQR, Sender Keys, Sealed Sender and
   safety numbers all come from it.
2. The in-house protocol implementation and the `CryptoProvider` trait are **deleted**, not kept
   behind a switch. Two protocol code paths would mean two things to audit and a downgrade surface.
3. This repository — core, server and both apps — is relicensed **AGPL-3.0-only**, matching
   `libsignal`. (`-only`, not `-or-later`, because that is what `libsignal` grants.)
4. What is not libsignal (attachment cipher, message padding, passphrase backup, metadata sealing,
   device linking, the server instance signature) uses audited RustCrypto / dalek crates and is
   listed in `SECURITY.md` so its scope is explicit.

**Consequences.**
- **Wire break.** E2EE protocol generation 2. v1 sessions cannot be converted: upgraded clients
  register a fresh libsignal identity, keep locally decrypted history and space keys, and raise
  "safety number changed" notices; v1 clients are refused with an explicit "update required"
  (HTTP 426). Server migration `0008` drops v1 key material.
- **Copyleft.** Anyone who distributes the apps, or runs a modified server for others, must offer
  the corresponding source under AGPL-3.0. The apps carry a licence/acknowledgements screen with
  the source location.
- **App-store distribution.** We are not the copyright holder of `libsignal`, so we cannot grant
  the additional permissions a copyright holder can. Whether distributing AGPL-licensed code that
  one does not own through Apple's App Store (whose terms impose usage restrictions on recipients)
  is compatible with the AGPL is a long-standing, unsettled question: the FSF's position is that
  it is not; other AGPL/GPL software is nonetheless distributed there, some by parties who are not
  the sole copyright holders. This ADR records the question; it does not resolve it. The owner
  should take advice before a public App Store release. Direct distribution (macOS notarised
  download, Android APK, self-built iOS) does not raise it.
- **Toolchain.** `libsignal` needs Rust ≥ 1.93.1 and `protoc` at build time; both are now pinned /
  documented (`rust-toolchain.toml`, README, Dockerfile).
- **What an audit still has to cover.** Not the protocol, but our use of it: the store
  implementation, identity-trust policy, sealed mailbox and delivery keys, device linking and
  reset, sender-key distribution/rotation, voice key exchange, backup. See `SECURITY.md`.

---

## ADR-012 — Membership is decided by members, not by the server (interim: signed approvals; target: a member-signed membership log) — **Accepted (interim implemented in build 43)**

**Context.** ADR-004 says the server is untrusted. Up to build 42 that held for *content* but not
for *membership*: every client asked the server "who is in this server, and what are their
devices?" and handed its channel sender key, the space key and per-call voice keys to whatever
came back. A malicious or compromised host could add a ghost member — or a ghost device to a real
account — and read everything from then on. A user seen for the first time raised no notice at all
(audit finding C1; H1/M2 are the same hole for contacts' devices).

**Decision (interim, shipped).** Two client-side gates, in `core/skwod-sync/src/engine/trust.rs`:

1. *Devices of an account.* A contact's devices are pinned the first time the account is seen.
   After that a device counts only if a **link signature** (the one an account's own devices
   already verify for each other) chains it to a pinned device. Traffic goes to, and is accepted
   from, chain-verified devices only; a listed-but-unvouched device is held and reported; a
   *verified* contact whose device set changes blocks the whole send. One safety number per
   account, over the sorted device-identity set.
2. *Members of a server.* Each device keeps a **roster** per server. Its first look at a server
   takes the listed members as the baseline. After that, a user the server lists is accepted only
   with a **member approval**: `sign(approver device identity key, "skwod-member-approval-v1" ‖
   server ‖ member ‖ approver ‖ ts)`, where the approver is the pinned owner or someone already in
   the roster, verified against the approver's *chain-verified* device identity, and `ts` is newer
   than the last time this device saw that member removed (so a kept record cannot be replayed).
   The server only stores and relays approvals (`member_approvals`); it cannot forge one. Keys for
   a channel go to a newly accepted member — or to a new device of an accepted member — only after
   a persistent "X joined (approved by Y)" / "X added a device" row has been written into that
   channel. A user who is merely listed stays **held**, is flagged in the channel, and gets
   nothing.

   An approval is signed only by an explicit user action (approving a join request, or "Let in" on
   a held member). A provision request never causes one: a server can insert a ghost and have it
   ask. Consequently an *auto-join* invite (token / username) no longer hands out keys by itself —
   the joiner shows up as a join request for the owner. That is a deliberate regression in
   convenience; the full design below restores one-tap joins safely.

   The owner a device trusts is **pinned with a provenance** (`created`, `invite`, `sibling`,
   `legacy-unknown`): never copied from a server listing. Pins from before provenance was recorded
   are `legacy-unknown`; they authorize nothing and are not passed to sibling devices until
   re-confirmed.

**What the interim does not do.**
- The baseline is trust-on-first-use: ghosts present when a device first looks at a server (or
  when it upgrades to build 43) are grandfathered. So is whatever owner the join response named.
- Any accepted member's approval is honoured, not only an admin's: roles live on the server and
  are not yet authenticated to clients. The approver is shown, so abuse is visible, and a server
  acting alone still cannot admit anyone.
- Removal is still the server's word (a kick the server invents only *removes* access; a kick the
  server hides is caught when keys rotate on the next real membership change, not before).
- Approvals are per (server, member, approver) records with no ordering between them.
- An owner attestation signed by the *instance* key authenticates "the server we pinned says so",
  nothing more. It protects a pin against being rewritten later; it is not evidence against a host
  that was malicious from the start.

**Target design — a member-signed membership log (Signal's group state, adapted).**
- Per server, an append-only **log** of membership operations: `create(owner)`, `add(member, by)`,
  `remove(member, by)`, `link-device` is *not* in it (device sets stay with the account, gate 1),
  `set-role(member, role, by)`, `transfer(owner → owner')`. Each entry carries
  `{seq, prev_hash, op, ts}` and a signature by a device of `by`; `prev_hash` chains the entries.
- **Authority is evaluated from the log itself**: entry *n* is valid iff its signer had, in the
  state produced by entries `0..n-1`, the role the operation needs. Roles and the owner therefore
  become client-verifiable, and "an admin approved" can replace "a member approved".
- The **genesis entry** is the trust anchor. It is bound into invites: the invite carries
  `H(genesis)` (and, for auto-join invites, a **link secret** the server never sees, with which the
  joiner proves to the approver's device that it holds *this* invite — that is what makes one-tap
  joins safe again, and it is the piece the interim lacks).
- The server stores the log and serves it; clients verify the chain, refuse forks (two entries
  with the same `seq`) and refuse rollbacks (they remember the highest `seq`/hash they accepted).
  The log head is included in what devices of one account sync to each other (`OwnerPins` becomes
  "log head"), so a relinked device starts from a sibling's view, not the server's.
- **Key distribution reads the log**: the set of users who may hold a channel key is the log's
  member set at its head, nothing else. Rotation on `remove` is driven by the log entry.

**Migration path.** `Engine::admit` is the only place key distribution asks "who may have this
key", and `Roster` + `apply_approvals` are the only things behind it. The log replaces those two;
the callers (`sync_channel_key`, `voice_sync`, provisioning) and the UI events (`SystemEvent`) do
not change. Existing approvals become the first `add` entries of a log whose genesis the owner's
device signs on upgrade; the `member_approvals` table is then dropped.

**Consequences (build 43).** New persistent rows in channels and DMs; held sends for unvouched
devices; blocked sends to verified contacts after a device change; auto-join invites need the
owner's tap; build-42 clients keep working against a build-43 server except that they cannot
refill prekeys (device proof now required) and cannot read wire-v3 channel messages — they must
update.
