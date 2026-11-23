# Architecture

The technical blueprint for the native Skwod rewrite. Every later phase builds to this document.

## 1. Principles

1. **E2EE everything.** The server is untrusted infrastructure even though the user owns it. It sees
   ciphertext, public keys, and routing metadata — never plaintext, never private keys.
2. **One shared core, native UIs.** The hard, security- and correctness-critical code (crypto,
   realtime sync, local cache) lives once in Rust and is bound into each native client. UI is fully
   native per platform. This is the Signal (libsignal) / Telegram (TDLib) pattern — one systems
   core, N native shells — chosen specifically so we never reimplement crypto or the sync/data layer
   in both Swift and Kotlin.
3. **Self-hostable by anyone.** A single static binary + a storage volume. No Kubernetes, no managed
   cloud, no Supabase. Runs on a laptop or a €4 VPS.
4. **Signal's protocol, not ours.** All message-protocol cryptography is Signal's official
   `libsignal` (ADR-011). Skwod adds no protocol crypto of its own; the small non-protocol pieces
   around it are listed in SECURITY.md.

## 2. Locked decisions

| # | Decision |
|---|---|
| Clients | iOS + macOS (SwiftUI, one shared app codebase, two targets) · Android (Kotlin + Jetpack Compose) |
| Shared core | Rust, exposed via UniFFI → Swift + Kotlin bindings |
| Encryption scope | DMs, channel messages, files/media, feed/stories, voice/video — all E2EE |
| Protocol | libsignal v0.108.0: PQXDH (X25519 + Kyber-1024) · Double Ratchet + SPQR · Sender Keys · Sealed Sender |
| Key storage | iOS/macOS: Secure Enclave–gated Keychain · Android: StrongBox/TEE Keystore |
| Server | Rust single binary; SQLite + filesystem blob store default; Postgres + S3 optional |
| Realtime | Authenticated WebSocket; server relays ciphertext + presence/typing |
| Voice/video | LiveKit (self-hosted SFU in the bundle) with insertable-streams E2EE |
| Payments | Planned, not built: Stripe external checkout, $3.99/mo (see §8 — nothing gates on payment today) |
| UI | Liquid-glass native design system |

Open/flagged items live in [`DECISIONS.md`](DECISIONS.md).

## 3. System topology

```
   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │  iOS app   │   │  macOS app │   │ Android app│
   │  SwiftUI   │   │  SwiftUI   │   │  Compose   │
   └─────┬──────┘   └─────┬──────┘   └─────┬──────┘
         │  UniFFI        │  UniFFI        │  UniFFI(JNI)
         └────────┬───────┴────────┬───────┘
                  ▼                 ▼
         ┌─────────────────────────────────┐
         │        Rust SkwodCore           │   (in-process, on every client)
         │  crypto · sync · encrypted cache│
         └───────────────┬─────────────────┘
                         │  TLS: WebSocket + HTTPS (ciphertext only)
                         ▼
         ┌─────────────────────────────────┐
         │      Self-hosted skwod server    │   (single Rust binary + volume)
         │  API · realtime relay · blobs ·  │
         │  key directory · Stripe webhooks │
         └───────┬──────────────┬──────────┘
                 ▼              ▼
          storage volume    LiveKit SFU (self-hosted, E2EE media)
        (SQLite + blobs)
```

## 4. Shared Rust core (`SkwodCore`)

Three crates behind one UniFFI umbrella:

### `skwod-crypto`
A thin layer over **libsignal** (ADR-011) — it contains no protocol cryptography of its own:

- `store` — a persistent implementation of libsignal's six store traits (identity, prekeys, signed
  prekeys, Kyber prekeys, sessions, sender keys), snapshotted into the SQLCipher cache, plus
  synchronous wrappers over libsignal's API and the identity-trust policy.
- `certs` — libsignal sender/server certificates; the trust root is signed by the server's
  invite-pinned instance key.
- `link` — device linking and signed device operations.
- `padding`, `attachment`, `backup`, `aead`, `instance` — the non-protocol pieces (RustCrypto/dalek).

### `skwod-sync`
The client data/sync engine — the part we deliberately do **not** rewrite twice in Swift + Kotlin:

- WebSocket client, reconnection, backfill.
- Local **encrypted** cache (SQLCipher / encrypted sqlite) — the on-device message store.
- Optimistic writes, invalidation, and query subscriptions (the role TanStack Query played on web).
- Realtime handlers: messages, DMs, typing, presence, reactions, read-states, feed, stories,
  whiteboard, chess — all decrypt on ingress, encrypt on egress.

### `skwod-core` + `bindings/`
UniFFI interface definition (`.udl` / proc-macro) → generated `SkwodCore.swift` and Kotlin. Exposes
suspend/async-friendly APIs (login, register device, send/subscribe, key verification, backup).

## 5. Native clients

### Apple (`apps/apple`) — iOS + macOS
- SwiftUI, one app, two targets sharing views/models; `#if os(macOS)` for platform chrome.
- Liquid-glass UI via `.ultraThinMaterial` / `Material` + custom translucency, vibrancy, and depth
  layers; SF Symbols; Dynamic Type.
- Keys in **Secure Enclave**–gated Keychain; biometric unlock.
- Voice/video via **LiveKit Swift SDK** with the core's E2EE key provider.
- Push: APNs; payloads are content-available wakeups — **no plaintext in notifications** (core
  fetches + decrypts). macOS uses the same shared code + AppKit shims (tray, window vibrancy).

### Android (`apps/android`)
- Kotlin + Jetpack Compose; Material 3 restyled into the liquid-glass system (blur/translucency).
- Keys in **StrongBox/TEE Keystore**; BiometricPrompt unlock.
- Voice/video via **LiveKit Android SDK** + core key provider.
- Push: FCM data-only messages, same decrypt-on-device rule.

## 6. Self-hostable server (`server`)

Single Rust binary (axum + tokio). Responsibilities — all ciphertext-only:

- **API**: auth, servers/channels/roles, membership, invites/join codes, message + attachment
  relay (opaque blobs), feed/stories metadata, presence.
- **Realtime relay**: authenticated WebSocket fan-out of encrypted envelopes + presence/typing.
- **Key directory**: device identity keys, signed prekeys, one-time EC + Kyber prekeys and the
  last-resort Kyber key (libsignal formats, signatures verified on upload); prekey bundles only
  for accounts that share a server/DM and are not blocked; sealed-sender certificates; device
  linking, signed deletion and guarded reset.
- **Sealed mailbox**: a per-device queue of sealed-sender envelopes. Deposits carry no
  credentials, so the server learns the recipient device and nothing about the sender. All
  pairwise traffic (DMs, sender-key hand-offs, space keys, provisioning, voice keys) goes here.
- **Blob store**: resumable encrypted uploads (TUS-style) to the volume (filesystem) or S3.
- **Entitlement**: verifies Stripe subscription status via webhooks; gates server creation/usage
  per region policy.
- **Bundled LiveKit SFU**: token minting + a self-hosted SFU in the deploy bundle.

**Storage — "point it at a volume":**
- Default: **SQLite** file on the chosen volume + encrypted blobs in a directory on the same volume.
  Zero-config, ideal for the <10-user groups Skwod targets.
- Optional: `--database postgres://…` and `--blobs s3://…` for larger deployments.
- The volume is the entire state; back it up by copying it.

Because everything is ciphertext, the DB schema is mostly opaque blobs + routing columns + public
keys, so SQLite scales fine for the target size.

## 7. Data model

Ported from the original 40-table Postgres schema (see original `supabase/migrations/00001_schema.sql`),
with plaintext content columns replaced by ciphertext blobs:

`profiles · servers · roles · server_members · member_roles · channel_categories · channels ·
channel_permission_overrides · messages · message_attachments · message_link_previews · reactions ·
dm_conversations · dm_participants · dm_messages · dm_attachments · dm_reactions · invites ·
notification_preferences · read_states · push_tokens · stories · story_media · story_views ·
feed_posts · feed_post_servers · feed_comments · feed_likes · feed_comment_likes ·
feed_comment_reactions · user_devices · one_time_prekeys · sender_key_distributions ·
e2ee_key_backups · e2ee_backup_shares · device_attestations · identity_key_log · e2ee_retry_requests ·
canvas_states · chess_games`

Permissions keep the original bigint bitmask (15 permissions). Link previews are generated
**client-side** and encrypted (the server must not fetch URLs on users' behalf → metadata leak).

## 8. Payments & entitlements

> **Status (build 41): not in effect.** No Stripe checkout, entitlement service or webhook exists
> in this tree, and no build gates on payment: the server has no billing columns
> (`server/migrations/0001_init.sql`) and the apps ship with the paywall switch off
> ([APPLE.md](APPLE.md) → "Paywall flag"). Pricing for the official mobile builds is undecided.
> The text below is the original decision, kept for the record.

- **Web-only signup (Stripe), apps are login-only** (ADR-003). All payment happens on `skwod.io` via
  Stripe; the native apps contain **no purchase UI and no IAP**. A user subscribes on the web, then
  signs in. This "reader app" model is compliant in every country with **zero Apple/Google
  commission**, and rides on the existing out-of-app join-code onboarding.
- **Gate.** App usable only with (a) an active $3.99/mo Stripe entitlement AND (b) a valid join code.
  Entitlement is verified server-side via Stripe webhooks; the client holds a short-lived signed
  entitlement token.
- **Self-host note.** Entitlement checks are a client/app-store concern, not a server-privacy one —
  a self-hosted server can run with entitlement gating off for its own members if the operator
  chooses (open-source, their box, their rules).

## 9. Feature-parity map

| Feature | Native plan |
|---|---|
| Servers / channels / categories | Core models + server API; SwiftUI/Compose views |
| Text chat (reactions, mentions, pins, replies, edits, typing, read states) | `skwod-sync` + native chat UI |
| Attachments / files | Encrypted resumable upload (core) + native pickers |
| DMs (1:1 + group) | Double Ratchet / Sender Keys via core |
| Voice / video | LiveKit native SDKs + core E2EE key provider |
| Stories / feed / comments | Encrypted content model + native feed UI |
| Media editor (filters, trim, music overlay) | Native: Core Image/AVFoundation (Apple), Media3/RenderEffect (Android); MusicKit/server-brokered audio |
| Whiteboard | Encrypted canvas state over realtime + native canvas |
| Chess | Encrypted game state over realtime + native board |
| Roles / permissions (bitmask) | Ported to core + server enforcement of *metadata* only |
| Invites / join codes | Server-issued codes; join flow gated by entitlement |
| Search | **Client-side** over the local encrypted cache (server can't read content) |
| Push notifications | APNs/FCM data-only wakeups; decrypt on device |
| News bot | Runs as a server-side member that posts; content encrypted to the channel sender key |
| Key backup / recovery / safety numbers | Core `KeyBackup` + `KeyTransparency`; native verification UI |

## 10. Cross-cutting

- **Build**: Rust core → UniFFI → XCFramework (Apple) + AAR (Android), wired via SwiftPM and Gradle.
- **Testing**: crypto test vectors + property tests in Rust; cross-binding conformance tests; native
  UI snapshot tests.
- **CI**: build all three clients + server; run the crypto conformance suite on every change.
