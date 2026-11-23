# FFI surface changes — E2EE protocol v2 (libsignal)

Everything below is `skwod-core`'s UniFFI surface (`SkwodClient` unless marked *free function*).
Names are Rust; Swift/Kotlin get the usual camelCase. Anything not listed is unchanged.

## Removed

| Function | Replacement |
|---|---|
| `encrypt_dm(user_id, device_id, plaintext)` / `decrypt_dm(user_id, device_id, envelope)` | none — raw envelopes are no longer exposed; use `send_dm` / `fetch_dm` |

## Changed behaviour, same signature

| Function | What changed |
|---|---|
| `attach_cache(path, key_hex) -> bool` | Returns `false` also for a device **upgrading from protocol v1** (history + space keys kept, fresh identity). Callers already register on `false`. |
| `register_device() -> String` | Only an account's **first** device. Otherwise throws `CoreError.LinkRequired` → run the linking flow. Throws `CoreError.UpdateRequired` against a pre-libsignal server. |
| `send_dm(conversation_id, user_id, device_id, text)` | Fans out to **every device** of the user (+ synced copy to our verified siblings). `device_id` is a hint. Message id is client-generated. May throw `CoreError.IdentityChanged`. |
| `fetch_dm(conversation_id, user_id, device_id, my_user_id)` | Syncs the sealed mailbox; `user_id`/`device_id`/`my_user_id` are ignored. |
| `share_group_key(channel_id, user_id, device_id)` | Keys **all** devices of that member. Rarely needed: `sync_channel_membership` already keys every device of every member. |
| `provision_member`, `request_provision` | Address every device of the user; `device_id` is a hint. |
| `sync_channel_membership`, `sync_server_membership` | Also distribute our sender key to every member device (incl. verified siblings). Rotation is per holder **device**. |
| `process_control_inbox(my_user_id) -> u32` | Now the sealed-mailbox sync (+ prekey upkeep). Files inbound DMs into the cache. |
| `safety_number(my_user_id, user_id, device_id)` | Signal's numeric fingerprint. Values differ from v1. |
| `voice_keys(channel_id, my_user_id, call_salt)` | `call_salt = None`: pre-join readiness check only (one placeholder entry, or empty ⇒ refuse to join). With a salt: `voice_sync` without participant tracking. Prefer `voice_sync`. |
| `enable_key_backup(passphrase)` | Rejects weak passphrases (< 14 chars, numeric PINs). |
| `restore_key_backup(passphrase)` | Restores identity onto the backed-up device id and re-keys it; v1 backups are refused with an explicit message. |
| `block_user`, `unblock_user` | Also rotate this device's delivery key / maintain the local drop list. |
| `compute_safety_number(local_id, local_identity_key_hex, remote_id, remote_identity_key_hex)` *free* | Takes `"user:device"` ids and libsignal identity keys. |

## Added

| Function | Purpose |
|---|---|
| `set_pinned_server_key(server_public_b64)` | Pin the invite's instance key; the sealed-sender trust root must be signed by it. Call after constructing the client. |
| `take_security_notices() -> [SecurityNotice]` | Drain notices: `identity_changed`, `protocol_upgraded`, `new_device`, `device_linked`, `unverified_device`. |
| `set_peer_verified(user_id, device_id, verified)`, `is_peer_verified(user_id, device_id) -> bool` | Mark a safety number verified. |
| `accept_identity_change(user_id, device_id)` | Unblock sending after a verified peer's key changed. |
| `begin_device_link() -> String` | New device: get the code to display. |
| `complete_device_link() -> String?` | New device: poll; returns the device id once linked. |
| `approve_device_link(code) -> bool` | Existing device: approve the device showing `code`. |
| `pending_device_links() -> u32` | Existing device: are any link requests waiting. |
| `reset_devices(pin: String?) -> String` | Wipe the account's devices and register this one (lost-everything recovery). Needs the registration-lock PIN; without one the first call throws `ResetPending` (7-day hold, cancellable by any existing device) and a later call completes it. |
| `voice_sync(channel_id, my_user_id, call_salt, participant_user_ids) -> [VoiceKey]` | Per-call random keys, sent to participants, rotated when one leaves. |
| `disable_key_backup()` | Delete the server copy. |
| `set_registration_pin(pin: String?, current_pin: String?)` | Set/change/remove the registration-lock PIN (device-signed). A PIN waives the reset hold only after 7 days in place. |
| `encrypt_attachment(plaintext) -> EncryptedAttachment` *free* | Signal's attachment scheme. |
| `decrypt_attachment(ciphertext, key, digest, plaintext_len) -> bytes` *free* | |
| `generate_recovery_key() -> String` *free*, `backup_passphrase_problem(passphrase) -> String?` *free* | Key-backup UX. |
| `e2ee_protocol_version() -> u32` *free* | `2`. |

## Errors

`CoreError` gained `UpdateRequired { detail }`, `IdentityChanged { detail }`, `LinkRequired { detail }`,
`ResetPending { detail }`. `unregister_device(device_id)` now signs the request with this device's
identity key (the server refuses token-only deletion). Notice kinds also include `reset_blocked`.

## Server API (for anyone touching networking)

New/changed under `/api/e2ee`: `devices/register` (libsignal fields, `protocol_version`, optional
`link`), `devices/{id}/rekey`, `devices/{id}/delivery-key`, `users/{id}/devices`, `member-devices`,
`prekey-bundle`, `prekeys/replenish`, `prekeys/count`, `spk/rotate`, `trust-root` (no auth),
`devices/{id}` DELETE and `devices/reset/cancel` (device proof), 
`certificates`, `sealed/send` (**no auth — must not carry the token**), `sealed/inbox`,
`sealed/ack`, `link-requests[...]`, `key-backup` (`PUT`/`DELETE` need a device proof),
`registration-pin` (`pin` not `pin_hash`; device proof + `current_pin`), `devices/{id}/delivery-key`
(device proof). Removed: `sender-keys`, `retry-requests`. `GET /api/instance/identity` reports
`e2ee_protocol`. Realtime events on the user topic: `sealed`, `device_added`, `link_request`.

**Device proofs.** Account-security writes (`devices/{id}` DELETE, `devices/reset/cancel`,
`devices/{id}/delivery-key`, `registration-pin`, `key-backup` PUT/DELETE) carry the header
`X-Skwod-Device-Proof: <unix-ms>.<base64 signature>`: this device's identity-key signature over
(op, account, target, timestamp, SHA-256 of the request payload). The server checks freshness, that
the key is on the account, that the payload matches, and accepts each signature once. Never put a
proof in a URL.

## Host/server changes app clients should know (no FFI change made)

- `POST /api/push/register` also accepts `{ "provider": "gateway", "gateway", "apns_token", "voip_token", "topic" }`
  (+ optional `"device_id"`); 409 if the token belongs to another account. `POST /api/push/unregister`
  with `{}` removes this session's registration. Register again on every launch.
- `POST /api/channels/{id}/ring` (optional `{ "user_ids": [...] }`): rings members — a `ring`
  realtime event on `user:<id>` for connected devices, a `call` wake for sleeping ones. Without
  a `voip_token` a call degrades to a `message` wake.
- `GET /api/instance/p2p` may carry `lan_key`; invites may carry `?l=<hex>`. To use same-LAN
  discovery a member sets `NetConfig.local_discovery = true` and `lan_key`. `p2p_connect` does
  not do this yet.
- The API answers `503 {"error":"this skwod is stopped"}` while the host has pressed Stop.

## Build 43: verification, instance owner, contact status

- **Removed: `set_peer_verified`.** It marked a contact verified for whatever devices were listed
  at the moment of the call. Use `verify_contact(user_id, safety_number)` with the number EXACTLY
  as displayed: the core re-reads the directory, recomputes, and fails with `IdentityChanged` if
  the device set is no longer the one that number covers (show the new number; nothing was
  marked). `unverify_contact(user_id)` removes the mark.
- **Safety QR is directional.** `safety_qr(user_id)` is the payload this device shows
  (`skwod-safety:2:` + my fingerprint + theirs). `check_safety_qr(user_id, scanned)` returns the
  60-digit number when the OTHER party's code matches, `None` for anything that is not a current
  safety code, and fails with `IdentityChanged` on a mismatch (including this device's own
  code). Feed it live camera scans only — never an image file or anything received in a message.
- `contact_status(user_id)` → `{ verified, sends_held, devices, unvouched_devices }`, local state
  only. `sends_held` is when a DM send fails with `IdentityChanged`.
- `instance_owner()` → the account that owns the instance, verified under the pinned instance
  key (`GET /api/instance/owner-attestation`) and pinned on first use in the workspace cache.
  For the skwod icon only; `None` without a pinned instance key.
- `account_fingerprint(user_id)` → the contact's 30-digit half of the safety number, as this
  device holds it. Show its first two blocks next to anyone the user is asked to decide about.
- **"Waiting to join" labels are claims.** The usernames from `list_members` /
  `list_join_requests` come from the server. Before offering "Let in", resolve the name with
  `find_user` and require the same user id; treat a name that already belongs to an accepted
  member or a DM contact under another id as an impersonation; re-check at the moment of the tap.
  (`WaitingTrust` in both apps.) Which invite a request came through is not exposed by the
  server, so the apps cannot show it yet.
- Avatar pointers: accept `server:<id>` only from a channel of server `<id>` whose pinned owner
  (`space_owner`) wrote it, and `skwod:<id>` only when `<id>` is the workspace's instance id and
  the author is `instance_owner()`.
- Server: the owner now outranks administrators (`member_rank`); administrators cannot act on
  each other or on the owner.

## Build 43b: the basics (attachments, DMs, sessions, history, feed, joins)

Nothing was removed and no existing signature changed. *free* = free function.

### Attachments — other people can open them now

The server only serves a blob to (a) its uploader, (b) readers of a channel message it is
**linked** to, (c) whoever presents its **download token**. Build 42 clients did neither (b) nor
(c), so an attachment opened for the uploader only.

| What | How |
|---|---|
| Channel message with attachment(s) (chat photo/file, feed post, story) | Upload as before, then send with `send_channel_message_with(channel_id, text, reply_to_id?, blob_ids)`. The server links the blobs in the same transaction. `send_channel_message` / `reply_channel_message` are now thin wrappers with no blobs. |
| DM attachment | `new_blob_download_token() -> { token, hash_hex }` *free*. Create the blob with `POST /api/blobs { total_size, download_token_hash: hash_hex }`, put `token` in the attachment descriptor (JSON key `token`), send the DM as usual. |
| Download | Descriptor has a `token` → `GET /api/blobs/:id` with header `x-skwod-blob-token: <token>` and **no** `Authorization` header. No token → `Authorization: Bearer …` as before. |
| Delete | Deleting a channel message deletes its (otherwise unreferenced, own) blobs server-side. For a DM attachment the uploader calls `DELETE /api/blobs/:id`. |
| New upload errors | `POST /api/blobs` may answer `403` (account is in no space), `413` (per-account quota; body `error` is a sentence to show), `507` (host disk nearly full; sentence to show), `429`. |

### Direct messages — incoming ones appear, and own devices stay in sync

| Function | Purpose |
|---|---|
| `sync_dms() -> [DmEvent]` | Sync the sealed mailbox now; returns the DMs it brought. Call on the realtime `sealed` event (topic `user:<me>`), on a push wake, at launch and on a slow timer. |
| `take_dm_events() -> [DmEvent]` | Same list without touching the network — DMs drained by any other call (`fetch_channel_messages`, `process_control_inbox`, …). Call after those. |
| `list_dms() -> [DmConversation]` | Every 1:1 conversation of the **account** (`conversation_id`, `peer_user_id`, `peer_username`), including ones started on another own device. Call at launch and when a `DmEvent` names an unknown conversation. |

**`peer_username` is the server's word and nothing more.** A host can list a conversation with a
ghost account under a friend's name. `DmEvent.peer_user_id` is authenticated (it is the decrypted
sender); a `list_dms` row may only add to a conversation with the same `peer_user_id`. Show a
name only from a trusted source (someone the user already knows under that user id, or
`find_user(name)` returning exactly that id), run the waiting room's look-alike check on a new
peer's name, and flag anyone else as unknown / unverified.

`DmEvent { conversation_id, peer_user_id, message_id, from_self, text, created_at }`. For each:
upsert the conversation into the sidebar; notify unless `from_self` (a copy of something we sent
from another device). The message is already in the cache (`history("dm:<conversation_id>")`).

### Sessions

| Function | Purpose |
|---|---|
| `session_state() -> Valid \| SignedOut \| Unreachable` | `SignedOut` = the server answered 401: clear the stored session and show login (macOS host owner: sign in again from the Keychain `ownerLogin`). `Unreachable` = keep the session, show the reconnecting state. Ask it wherever the app used to conclude "unreachable". |
| `rotate_session(base_url, token) -> AuthSession` *free* | New token for the same sign-in. Call at launch when the stored token is older than ~7 days, **before** building `SkwodClient`; store the result. The old token works for 5 more minutes. The server moves the push registration to the new token. |

Server side: a session now lives 30 days after its **last use** (any request, or an open
WebSocket), at most 1 year after sign-in.

### Channel history — catch-up, older pages, reactions, the game lane

| Function | Purpose |
|---|---|
| `fetch_channel_messages(channel_id, my_user_id)` | Same signature. Now a cursor-driven catch-up: brings **everything** that changed since the last call (new messages, edits, deletes), paging as needed; cheap when nothing changed. A first sync pages back until it holds ~100 **chat** messages. Still returns the newest 500 cached. Call it when the WebSocket says something happened in the channel (events `message`, `message_update`, `message_delete`, `reaction`, `channel_cleared`), on (re)connect, and on a slow safety timer — not every 1–2 s. |
| `history_page(scope, before_ms, limit) -> [Message]` | Cached messages older than `before_ms` (chronological). The "load older" read. |
| `load_older_channel_messages(channel_id, my_user_id) -> u32` | When the cache has nothing older: fetch older history from the server — as many pages as it takes to add ~50 chat messages. Returns the number of **chat** messages added; `0` = start of the channel. |
| `channel_reactions(channel_id) -> [MessageReaction]` | All reactions of the channel as of the last `fetch_channel_messages`, from the cache — replaces calling `list_reactions` per message. `{ message_id, user_id, emoji_hash, emoji? }`. |
| `fetch_aux_messages(channel_id, my_user_id) -> [Message]` | Game state (bodies starting `\u{2}skwod/game|`). It travels exactly like chat; the core sorts it out **on the device, after decryption**, into its own cache scope (`aux:<channel_id>`), so it no longer pushes chat out of the history window. Whiteboard/chess read from here; sending is unchanged. |
| `message_notifies(text) -> bool` *free* | Should a message with this decrypted body, from someone else, notify? `false` for `skwod/game|`, `skwod/like|`, `skwod/comment|`, `skwod/avatar|`, `skwod/addr|`, `skwod/sys|`. Use it everywhere a notification is decided (in-app realtime, push wake, the iOS notification service extension). |
| `message_is_hidden(text) -> bool` *free* | Game state rather than conversation. |

**The server is told nothing about what a message is.** There is no `silent` flag and no
separate lane: a chat line, a like, a chess move and a sender key are the same opaque envelope to
it — stored alike, announced alike (`message` / `sealed`, with no describing field) and pushed
alike (a contentless wake for every message, coalesced and jittered per device, bounded by the
gateway's per-token limits). What to show is decided by the recipient after decrypting.

A message whose text exceeds 150 KB (or whose envelope would exceed the 256 KB wire limit) now
fails with `CoreError.Invalid { detail }` — `detail` is a sentence to show. Feed/story media must
be an attachment plus a small inline thumbnail, never inline base64 of the full image.

Edits made on another device of the author now arrive (the server records which device sealed
the edit). No client change beyond calling `fetch_channel_messages`.

### Feed

| Function | Purpose |
|---|---|
| `feed_channel(server_id) -> String` | The one channel a server's feed and stories live in: the server's hidden `purpose = feed` channel; the owner's app creates it on first call for a pre-43 server; until then everyone gets the lowest-position text channel. Use it for posting, liking, commenting and reading — never "the first channel on this device". |
| `list_channels(server_id)` | No longer lists the feed channel. (Voice channels are still listed with `kind = "voice"`: filter them out of text lists.) |

### Joining

| Function | Purpose |
|---|---|
| `check_invite(base_url, join_code) -> InviteCheck` *free* | Unauthenticated pre-check, before the name/password screen. `{ valid, reason?: "expired" \| "used" \| "unknown", requires_approval }`. Throws when the host cannot be reached. |

Realtime, topic `user:<me>`: `join_request { server_id, user_id, pending }` to everyone who can
approve (also a push wake) — badge and notify; `join_approved { server_id }` / `join_denied` to
the joiner — finish the join without a relaunch. Topic `server:<id>`: `member_joined`,
`channels_changed`.

### Calls

| Function | Purpose |
|---|---|
| `pending_rings() -> [RingInfo]` | `GET /api/rings`. After a VoIP wake, ask **every** signed-in server and answer the one that is ringing. `{ channel_id, server_id, from_user_id, ring_id, expires_at }` — drop a ring past `expires_at`. Realtime `ring_cancel { channel_id, ring_id }` on `user:<me>` ends the incoming-call UI. |

Which skwod rang (no FFI): when registering for push through the gateway
(`POST /api/push/register`, gateway shape) a device may add `"wake_tag"` — 16–32 chars of
`[A-Za-z0-9_-]` it made up for THAT skwod and keeps locally. The server and the gateway hand it
back as a top-level `"tag"` in the APNs payload of every wake (VoIP and alert). Only the
workspace that owns the tag may supply the ring for that push; never choose by a
server-reported `expires_at`. A gateway that predates the field delivers the wake without it.

### Trust

| Function | Purpose |
|---|---|
| `peek_account_fingerprint(user_id) -> { fingerprint, pinned }` | Read-only: never pins. Use it wherever people are merely listed (Waiting to join). `pinned = false` → label "unverified". `account_fingerprint` (which pins on first sight) is for explicit actions only. |

### Server behaviour apps rely on

- WebSocket: the server pings every 20 s and drops a socket silent for 50 s. A `presence`
  frame with `offline` makes the install push-wakeable while the socket lingers; any other
  status makes it in-band again. iOS must close the socket when it enters the background.
- Host invites (`/admin`, QR, `skwod init`) are `https://skwod.io/join#…` share links.
- Usernames: `[a-z0-9_]`, 3–32 (unchanged, now tested).

## Build 44a: accounts, devices, recovery

**Status: both apps are converted** (Apple: `AccountSecurity.swift`,
`DeviceAndRecoveryViews.swift`, `AppLock.swift`; Android: `AccountSecurity.kt`,
`ui/DeviceRecoveryScreens.kt`, `AppLock.kt`). "What the apps must do" below is kept as the
checklist it was written as.

**How 44a and 44b were merged** (neither shipped alone): the `Content` wire tags are build
43's, then 44a's, then 44b's; `ChatResend` carries `reply_to`; the engine state's build-44
additions are two tagged sections (accounts `0xA1`, content `0xC1`); `send_dm` runs through
`send_dm_as` with 44a's sent store, persist-before-send and per-device owed deliveries;
migrations are `0012_accounts` then `0013_content`.

### The model the apps have to follow

- **A session speaks for one device.** The server records which device (and which *install* of
  it) a session was bound to. Two clients must never share a session token. The core binds
  lazily (`ensure_bound`, inside every device-scoped call): a signature by the device's identity
  key plus the *install secret* — 32 random bytes kept in the encrypted cache, never backed up.
- **Sign out ≠ erase.** Signing out drops the session token and nothing else: keep the cache
  file, the cache key and the workspace record. Signing back in = build `SkwodClient` with the
  new token, `attach_cache` (returns `true`), carry on — same device, no link.
  **Never delete the cache or its key on sign-out.** `erase_device` is the separate, explicit
  wipe.
- **A copy of the identity key is not the device.** Anything that changes the account (remove a
  device, PIN, backup, password, approving a link or a member) needs the device proof AND a
  session bound to the signing device's current install.
- **The recovery key is what restores.** A restore proves the recovery key to the server (a
  signature by a key derived from the backup key, over a server nonce; nothing secret leaves
  the device) and completes **at once** — also after the device was erased, in which case the
  identity comes back as a fresh device row. Two conditions: the backup must have been written
  by build 44 (it carries the verifier), and the recovery key must have been in place for
  **7 days** (`recovery_key_instant_from`). Otherwise — and for anyone holding only a copy of
  the identity key — a restore is a *recovery request*: another device's approval, the PIN, or
  7 days.
- **How a recovery key stops working** (there is no undo):
  - *Changed* (a new key saved, backup turned off): the old key, if it was 7 days old, still
    restores at once for 7 more days — ONCE. That restore uses it up, cancels the newer key and
    leaves the account with no recovery key (`recovery_key_needed` notice: ask for a new one).
    This is how an owner takes the account back from a key somebody planted.
  - *Compromised*: removing another device, `erase_device_as_lost`,
    `mark_erased_device_removed`, or `report_recovery_key_compromised` retire the key **at
    once**, with no overlap. It never works again. Every device gets `recovery_key_changed`
    and `recovery_key_needed`.
- **Why a device left matters.** One that erased itself (`erase_device`) may be restored later
  and is recognised by siblings and contacts (they show `account_restored` / `new_device`).
  The device says so before it goes, but that is only a claim: it counts once the SERVER's
  record agrees (the device is no longer registered and is recorded as self-erased), which a
  peer learns the next time it re-reads that account's devices — so call `refresh_devices_of`
  / `refresh_own_devices` on `device_removed`. A peer that never did sees the restored device
  as unverified and has to accept it by hand. One that another device removed — or that was erased as
  lost — is tombstoned for good: the server refuses to register its identity again except
  through a link approval, and no sibling or contact re-trusts it.
- **A current, unlocked device is fully authoritative** (as a linked device is in Signal). The
  protocol does not defend against one from the inside; the app lock and removing it from
  another device are the mitigations.

### Changed behaviour, same signature

| Function | What changed |
|---|---|
| `attach_cache(path, key_hex) -> bool` | A cache that does not open under the key is **moved aside** (`<path>.unreadable`, one generation kept) and a fresh one started; returns `false`. Ask `cache_was_reset()` and tell the user once. Never loops on `Cache` errors for a wrong key any more. |
| `register_device`, `begin_device_link`, `complete_device_link`, `reset_devices` | Fail with `CoreError.Cache` when no cache is attached. Attach first, always. |
| `reset_devices(pin)` | With a registration-lock PIN on the account and `pin = null` → `CoreError.PinRequired` (show the PIN screen). Wrong PIN → `CoreError.PinIncorrect { attempts_left }` (0 = locked 15 min). |
| `restore_key_backup(passphrase) -> bool` | Completes at once when the recovery key is seasoned (see above); the install the device was on before stops (`DeviceSuperseded`) and the account's other devices get an `account_restored` notice. Otherwise throws `CoreError.RecoveryPending`: the restored state is kept; show `recovery_fingerprint()` and "approve on another device", then `retry_restore(pin?)`. After an erase the device id is new. Restores owner pins with their provenance and contacts with their verified marks. |
| `enable_key_backup(passphrase)` | Also stores the recovery verifier. Replacing an existing backup under a different key is a **change of recovery key**: every device gets `recovery_key_changed`; the new key is not instant for 7 days and the old one keeps working once for 7 days (see above). |
| `disable_key_backup()` | The same kind of change: announced; the old key keeps its one overlap use. |
| `unregister_device(device_id)` (another device) | Also retires the recovery key at once and turns backup off on this device: prompt for a new recovery key. |
| `unregister_device(device_id)` | Removing another device also drops its keys locally and rotates every sender key it held. Removing this device marks the install `Removed`. |
| `send_dm(...)` | Delivery is per device: devices that did not take the message are owed it and retried (30 s doubling to 6 h, 30 days). The message row and the ratchet state are written to the cache in one transaction BEFORE the send; a failed send removes the row again. |
| `send_channel_message_with`, `edit_channel_message` | Same persist-before-send. Fail with `DeviceRemoved` / `DeviceSuperseded` when the server no longer accepts this install. |
| `fetch_channel_messages`, `load_older_channel_messages` | A message this device cannot decrypt is no longer skipped: a **placeholder row** (content prefix `\u{2}skwod/undecryptable\|` + JSON `{"from": <user id>, "final": <bool>}`, author = the real author) takes its place, and its author's device is asked to send it again. When it does, the row's content is replaced in place. `final: true` = it cannot be sent again. Render: "Couldn't decrypt this message — asking X to resend" / "Couldn't decrypt this message". `message_notifies` is `false` for it. |
| `sync_dms`, `fetch_dm`, `history("dm:…")` | Same placeholder (message id `retry:<hash>`) for an undecryptable direct message; removed when the resend arrives. DMs are ordered by **arrival** (`created_at`); `Message.sent_at` carries the sender's time. |
| `take_security_notices` | New kinds: `recovery_requested` (a restore WITHOUT a usable recovery key is waiting: `device_id`, `request_id`, `fingerprint` — show the code and Approve / Block, never auto-answer; a request that replaces another is a NEW notice with a new id), `account_restored` (`device_id` was restored onto a new install, or came back after an erase: "Your account was restored on a new device"), `recovery_key_changed` (the key was changed, removed or retired — if it wasn't the user: restore with the old key within 7 days, or report it compromised), `recovery_key_needed` (no recovery key is in force: ask the user to save a new one), `owner_changed` (after a restore the instance attests a different owner for server `device_id`; the pin was demoted). An account reset is still vetoed automatically (`reset_blocked`). |
| `request_provision(server_id, host…)` | Also records `host` as the expected provisioner when this device has no trusted owner pin — as `legacy-unknown`, trusted only once the pinned instance key attests that same owner. This is what lets servers come back after an account reset. |
| `approve_device_link(code)` | Also hands the new device this device's sibling set, the account key, every space key and the trusted owner pins — encrypted to the new device's identity key and authenticated by the code. The new device no longer needs `request_provision` to read names. |

### Added

| Function | Purpose |
|---|---|
| `device_state() -> Unregistered \| Active \| Removed \| Superseded \| RecoveryPending` | Where this install stands. Route UI from it after `attach_cache` and after any typed failure. |
| `set_device_label(name)` | What this device calls itself. Call right after constructing the client, before registering. Uploaded sealed (`device_name_ciphertext`); only the account's devices can read it. |
| `rename_device(name)` | The user edited the name. |
| `list_devices() -> { devices: [{ device_id, name?, created_at, last_active_at, is_this_device, verified }], max_devices }` | The devices screen. `verified = false` = listed by the server, approved by none of our devices: show it flagged. Show `devices.count / max_devices`. |
| `refresh_own_devices()` | Export of the existing engine call. Call on realtime `device_added`, `device_removed`, `link_request`, `device_recovery_requested`, `device_rekeyed` (topic `user:<me>`), then `take_security_notices`. |
| `refresh_devices_of(user_id)` | Call on realtime `device_removed { user_id, device_id }` about someone else (topics `server:<id>`, `user:<me>`). |
| `change_password(old, new)` | Old password + this device's signature. Ends every other session of the account. |
| `approve_recovery(device_id, request_id)`, `cancel_recovery(device_id, request_id)` | Answer a `recovery_requested` notice with **the `request_id` from that notice**. Throws `RecoveryChanged` (nothing approved) if another request has replaced it; that one arrives as a fresh notice. Approving a restore of THIS device stops this install once it completes. |
| `recovery_fingerprint() -> String` | On the install waiting for a restore: the code of its request (`XXXX-XXXX` in build 44; `XXXX-XXXX-XXXX-XXXX` from build 45, see below). The approving device's notice shows the same code. |
| `recovery_key_instant_from() -> i64?` | When a restore with the recovery key becomes instant (7 days after it was saved). Say so when the user saves the key. |
| `report_recovery_key_compromised()` | "My recovery key is compromised": retired at once, backup off on this device; prompt for a new key. |
| `erase_device_as_lost(even_if_offline)` | Erase this device as LOST: a removal (identity never restorable, recovery key retired at once). |
| `erased_devices() -> [{ device_id, identity_key_hex, erased_at }]`, `mark_erased_device_removed(identity_key_hex)` | An erased device later found to be lost or stolen is converted to removed. |
| `retry_restore(pin?) -> bool`, `restore_key_backup_with_pin(passphrase, pin?)` | Complete a waiting restore. |
| `reset_devices_forgot_pin() -> String` | Reset when the PIN is lost: the 7-day hold (`ResetPending`), no shortcut. |
| `erase_check() -> { has_key_backup, other_devices, safe }` | Gate "Erase this device": when `safe` is false, erasing leaves only the 7-day reset and the history is gone for good. Explain that. |
| `erase_device(even_if_offline)` | Unregister this device (signed) and delete the cache file. The client is unusable afterwards. The app deletes the cache KEY and the workspace record itself. |
| `forget_registration()` | A `Removed` / `Superseded` install is about to be linked again as a new device: drops the old identity, keeps space keys, pins, contacts. |
| `cache_was_reset() -> i64?` | When an unreadable cache was set aside. |
| `retry_deliveries() -> u32` | Try owed per-device DM deliveries now; returns how many remain. |
| `Message.sent_at: i64?` | See above (defaulted: existing constructors keep compiling). |

| `recovery_completes_at() -> i64?` | On the install waiting for a restore: when the 7-day hold ends (unix ms), for the countdown. `None` while the request is contested, and after a launch until the server has answered (`retry_restore`). |
| `recovery_contested() -> bool` | The waiting request was contested (another install asked to restore the same device; server `contested_at`): it completes only by an approval or the PIN. Show "Waiting for approval on one of your devices." in place of the countdown. |
| `retry_restore` after a relaunch | A restore that was waiting to be handed the backup asks the server how it stands (so the contest is known again); once granted it throws `Invalid` with `RESTORE_APPROVED_KEY_AGAIN`: enter the recovery key again (`restore_key_backup`) to finish. |
| `Message.is_system`, `Message.is_undecryptable` | What a row IS, recorded by the core when it wrote it (cache column `kind`). **Decide on these, never on the text or the author**: any member can send a message whose body starts with `\u{2}skwod/sys\|` or `\u{2}skwod/undecryptable\|`. Such a body is stored with the control character removed (it reads as plain text) and is an ordinary message; the reserved `__system__` author cannot be written as a message at all. |
| `undecryptable_placeholder(message) -> { from_user_id, is_final }?` *free* | The placeholder row's fields — `None` unless `message.is_undecryptable`. Both apps render the row from this. |

### Errors

`CoreError` gained `PinRequired`, `PinIncorrect { detail, attempts_left }`, `DeviceSuperseded`,
`DeviceRemoved`, `RecoveryPending`, `RecoveryChanged`, `DeviceLimit` (all carry a user-facing
`detail`). `SecurityNotice` gained `request_id?` and `fingerprint?` (defaulted).

### Server API

New migration `0012_accounts` (SQLite + Postgres).

- `POST /api/e2ee/devices/register`: **`install_hash` required** (32 bytes, base64). Optional
  `device_name_ciphertext`, `forgot_pin`. A linked device registers only on an approval the
  linker's install recorded through `link-requests/:id/approve` (an inline signature alone is
  refused). Reset: `403 {"error":"registration pin required"}` /
  `{"error":"registration pin incorrect","attempts_left","locked_until"}`.
- `POST /api/e2ee/devices/:id/bind` `{ install_secret }` + device proof (op `bind-session`,
  payload = `op_payload(session token hash, sha256(secret))`).
- `POST /api/e2ee/devices/:id/rekey`: `install_hash` AND `install_secret` required (the hash is
  covered by the proof; the secret must hash to it). From an install that is not the device's
  current one it completes at once with `recovery_auth` (a seasoned recovery-key proof), else
  `403 {"error":"device recovery pending","completes_at"}` until approved / PIN (`pin`) / the
  hold is over. `devices/register` takes `recovery_auth` too (purpose `register`, target = the
  identity key) and answers `recovered: true`.
- `POST /api/e2ee/key-backup/challenge` → `{ nonce }` (per session, 10 min, consumed only by a
  valid proof). `PUT /api/e2ee/key-backup` takes `auth_verifier` (covered by the device proof).
  `POST /api/e2ee/key-backup/compromised` (device proof, op `backup-compromised`).
  `GET /api/e2ee/key-backup` also returns `alternates` (backups under keys still in their
  overlap, and earlier contents under the same key): a restore tries its key against each.
  `DELETE /api/e2ee/devices/:id?lost=1` (proof payload `lost`).
  `POST /api/e2ee/devices/tombstones/remove` `{ identity_key }` (op `tombstone-remove`).
- `POST /api/e2ee/devices/:id/recovery/{approve,cancel}` `{ request_id }` + device proof over
  that id; `409 {"error":"recovery request changed"}` if it was replaced. The install hash of a
  request is never returned by any route.
- `GET /api/e2ee/devices` also returns `current`, `generation` per device, `max_devices`,
  `recoveries: [{ device_id, request_id, fingerprint, requested_at, completes_at, approved }]`,
  `recovery_key_instant_from`, `recovery_key_changed_at`, `recovery_key_needed`, `erased`.
  Rekey / register answers carry `recovery_key_consumed`.
- `PUT /api/e2ee/devices/:id/name`.
- `POST /api/auth/password` `{ old_password, new_password }` + device proof (op `password`).
- `link-requests/:id/approve` takes `bundle`; `GET link-requests/:id` returns it.
- Channel posts and edits: `author_device_id` must be a registered device of the author and the
  session must be bound to it. `403 {"error":"device removed"}`, `409 {"error":"device
  superseded"}`, `403 {"error":"device bind required"}`.
- Every route that took a device proof now also requires the session to be bound to the signing
  device's current install.
- Realtime: `device_removed { user_id, device_id }` (own devices, every server of the account,
  DM partners); on `user:<id>`: `device_recovery_requested`, `device_rekeyed`,
  `account_restored`, `recovery_key_changed`, `backup_updated`, `sessions_revoked`.
  All are nudges: call `refresh_own_devices` and read the notices.
- A device row from before this build (`legacy_unbound`) keeps its ordinary traffic working for
  a build-43 client, has no authority, and is bound once by a session that existed at upgrade.

### What the apps must do (done in the build-44 apps batch)

1. Stop sharing nothing: one token per install is already the case. Call `set_device_label`
   before `register_device`.
2. **Sign-out**: drop the token only (Apple `signOut()` and `leaveCurrent()` currently delete
   the cache and the cache key — that is the lock-out). Add "Erase this device" (`erase_check`,
   `erase_device`, then delete the cache key).
3. Never fall through to `register_device` when `attach_cache` threw; on `false` + an account
   that has devices, show the recovery sheet (link / restore / reset).
4. Route `PinRequired` / `PinIncorrect` to the PIN screen; "Forgot PIN" → `reset_devices_forgot_pin`.
5. Route `DeviceSuperseded`, `DeviceRemoved`, `RecoveryPending` (see `device_state`): the
   waiting-restore screen shows `recovery_fingerprint()` and retries with `retry_restore`; the
   `recovery_requested` prompt shows the notice's `fingerprint` and passes its `request_id`.
   When saving a recovery key, show "Instant restore from <recovery_key_instant_from>".
6. Devices screen (`list_devices`, `rename_device`, `unregister_device`), password change.
7. Render the undecryptable placeholder row; show `sent_at` secondarily in DMs.
8. Handle the new realtime events and the `recovery_requested` notice.
9. Wire tests that create several clients: each needs its own login.
## Build 44b: content — blocks, reports, the outbox, DM parity, clears, stories, uploads

Nothing was removed. One record gained a field (`DmEvent.kind`). *free* = free function. Both apps
are converted; this is the reference for anyone touching them.

### Blocks — one list, applied by the core

| Function | Purpose |
|---|---|
| `refresh_blocks() -> [BlockInfo]` | Bring the list up to date from the server (a block made on another device applies here). Call at launch and on every reconnect. |
| `blocked_user_ids() -> [String]`, `is_blocked(user_id) -> bool` | The list as this device knows it. **Synchronous, no network.** |
| `block_user`, `unblock_user` | Unchanged signatures. **Use these, never `PUT /api/blocks/…` directly** (the Apple app did): only the core rotates this device's delivery key and keeps the drop list. |

**What the core now does for you.** Everything read from the cache — `history`, `history_page`,
`fetch_channel_messages`, `fetch_aux_messages`, `fetch_dm`, `channel_reactions`, `dm_reactions`,
`list_dms` — leaves out rows authored by a blocked user. That is chat, feed posts, stories,
comments, likes, game moves and DMs at once, on both platforms, and unblocking brings them back
(nothing is deleted). **What the app must still filter with `is_blocked`:** notifications for a
live `message` event (check `author_id` before fetching), presence, typing, and anything it
draws from the server's member list.

While a block lasts the two people cannot read each other's NEW channel messages either (the
server hides each one's devices from the other, so neither keys the other in). After an unblock
that heals by itself on the next `sync_channel_membership` — nobody has to be let in again.

### Reports

| Function | Purpose |
|---|---|
| `report_message(category, note?, message_text?, subject_user_id?, server_id?) -> ReportReceipt` | File a report. `message_text` is the reported message **only if the reporter chose to include it** — ask. `ReportReceipt { report_id, sealed_to_owner }`: show "Report sent" when it returns. |
| `received_reports() -> [AbuseReport]` | For the skwod's owner: reports that reached this device (they arrive with `sync_dms`). `{ report_id, reporter_user_id, subject_user_id?, server_id?, category, note?, excerpt?, received_at }`. `reporter_user_id` is authenticated; `excerpt` is the reporter's claim of what was said. |
| `dismiss_report(report_id, reporter_user_id)` | Remove one from this device's list. |

`report_message_at(category, note?, message_text?, subject_user_id?, server_id?, channel_id?, message_id?)`
is `report_message` for a channel message that also tells the owner WHERE it is. `AbuseReport`
carries `channel_id?` / `message_id?`: the reporter's claim, sealed to the owner only (the
server's queue gets neither). The reports inbox looks the message up in the owner's own copy
of the channel before offering "Remove message".

The note and the quoted message are sealed (like a DM) to the instance owner's devices — or,
on an instance nobody claimed, to the pinned owner of `server_id`. The server's report queue
gets who / whom / category and **no text**. With no owner to seal to (`sealed_to_owner = false`)
the note goes to the queue as text, as before, and a quoted message is not sent at all.
`report_abuse` still exists (plaintext `body` to the queue); prefer `report_message`. Both apps
have a reports inbox. **Everything in a report except its reporter is a claim**: the inbox
acts only on what the owner's device confirms (the cached message under that id, its real
author, the server that channel is in on this device) and shows a mismatch instead of acting
when the report names someone or somewhere else.

### The outbox — nothing a person sends is lost offline

Queueing is local and instant: the operation is stored in the encrypted cache, an own message
is in `history` at once (author `__me__`), and `flush_outbox` delivers when it can — **once**
(a channel message's id is chosen at queue time and the server answers a repeat with the
original; a DM's id is filed once by the receiver).

| Function | Purpose |
|---|---|
| `queue_channel_message(channel_id, text, reply_to_id?, blob_ids, upload_ids) -> String` | Chat, a feed post, a story, a comment, a game move, a forward — whatever `text` encodes. Returns the message id. |
| `queue_channel_edit(channel_id, message_id, text)`, `queue_channel_delete(channel_id, message_id)`, `queue_reaction(channel_id, message_id, emoji, remove)` | The same for edits, deletes (also posts / stories / comments) and reactions (also likes). Deleting something that was never sent just takes it back. |
| `queue_dm(conversation_id, peer_user_ids, text, reply_to_id?, upload_ids) -> String`, `queue_dm_edit`, `queue_dm_delete`, `queue_dm_reaction` | The DM counterparts. |
| `flush_outbox() -> OutboxReport { sent, pending, failed }` | Deliver what is queued. Call after queueing, on reconnect, at launch, on a slow timer. Safe to call concurrently. |
| `pending_sends(scope?) -> [PendingSend]` | `{ local_id, scope, message_id, kind: send\|edit\|delete\|reaction, state: sending\|failed, error?, attempts, created_at }`. Overlay on history: a row whose id has a `send` here is "Sending…" or, when `failed`, "Not sent — `error`" with Retry / Discard. |
| `retry_send(local_id)`, `discard_send(local_id)` | A discarded send disappears from history. |

Order is kept per conversation: while one operation waits for the network, the ones behind it
wait too. One the server REFUSED (`failed`) steps aside with a sentence and does not block the
rest. The direct calls (`send_channel_message…`, `send_dm`, `edit_…`, `delete_…`,
`add_reaction`) still exist and still fail offline; the apps no longer use them for anything a
person types.

### Direct messages — reply, edit, delete for everyone, reactions, small groups

| Function | Purpose |
|---|---|
| `reply_dm(conversation_id, peer_user_ids, text, reply_to_id) -> String` | (Or `queue_dm` with `reply_to_id`.) The row's `reply_to_id` is set on every device. |
| `edit_dm`, `delete_dm`, `react_dm(…, emoji, remove)` | Direct versions of the queued ones. Only the author's own messages can be edited or deleted — enforced on the RECEIVING device against the authenticated sender. |
| `dm_reactions(conversation_id) -> [MessageReaction]` | From the cache. `emoji` is always set; `user_id` is the real id, also for this account. |
| `open_group_dm(member_user_ids) -> String`, `list_group_dms() -> [GroupDm]`, `send_group_dm(conversation_id, member_user_ids, text) -> String` | 3–10 people, each message sealed pairwise to every device of every member. Both apps have group screens. **The server's member list is never adopted**: an app fixes a group's members when the user starts or accepts it, stores that set, seals only to it, flags a listing that differs, treats an unseen conversation as an invitation, and drops whatever a non-member sends into the group. The apps' 1:1 DM lists must not be fed group conversations (`list_dms` still leaves them out). |

`peer_user_ids` is who the message is sealed to: the one other person, or the members of a
group **as the user chose them** — never a list taken from the server.

`DmEvent` gained `kind`: `"message"` (notify unless `from_self`) or `"edit"` / `"delete"` /
`"reaction"` (redraw only — **do not notify**). These travel as new sealed `Content` variants:
a build-43 peer cannot decode them and silently ignores them (it keeps showing the original).

### Channel clear

| Function | Purpose |
|---|---|
| `channel_cleared(channel_id, cleared_at?)` | Call on the realtime `channel_cleared` event (its payload now carries `cleared_at`): empties this device's cache of the channel — chat, game state, reactions, queued sends — at once. |

A device that missed the event needs nothing: every history page carries the channel's
`cleared_at`, and `fetch_channel_messages` purges everything cached from before it.

### Time

Own messages are filed under the SERVER's `created_at` (from the send response), not the device
clock — ordering, the whiteboard's clear cutoff and chess move order now agree across devices.
A queued message carries the device's time until it is delivered. `server_now_ms() -> i64` is
the server's clock as this device estimates it; compare `created_at` against that.

Own messages sent from ANOTHER device of this account now read back with author `__me__` too
(they used to carry the real user id). `author == "__me__"` is sufficient everywhere.

### Stories, posts, comments

| Function | Purpose |
|---|---|
| `expire_stories(channel_id, story_tag, ttl_ms) -> u32` | End stories older than `ttl_ms` by SERVER time: other people's leave this device's cache; this account's own are deleted for everyone (queued). Call when the feed is read. |
| `cached_message(scope, message_id) -> Message?` | One row. |

A story's or post's time is `Message.created_at`. The `ts` inside the body is the sender's claim
and is no longer read. Delete = `queue_channel_delete` (the server removes the linked photo).

### Uploads — streamed, resumable, queueable

| Function | Purpose |
|---|---|
| `prepare_upload(source_path, work_dir, for_dm) -> PreparedUpload` | Encrypt file-to-file (no whole file in memory; up to ~1.9 GiB). No network. `{ upload_id, placeholder_blob_id, key, digest, plaintext_len, blob_len, download_token? }`. |
| `finish_upload(upload_id) -> String` | Upload now, resuming from the server's offset; returns the blob id. Call again after a failure. |
| `pending_uploads() -> [UploadProgress]`, `resume_uploads() -> u32`, `release_upload(upload_id, delete_blob)` | Uploads survive an app restart: resume them at launch and on reconnect. |
| `decrypt_attachment_file(blob_path, out_path, key, digest, plaintext_len)` *free* | Verify-then-decrypt file to file. |

To send an attachment offline: build the descriptor with `placeholder_blob_id` as its blob id
and queue the message with `upload_ids: [upload_id]`. At flush the upload is finished and the
real id is put in. **The body must be `<tag>` + a JSON object in which the placeholder is a
whole string value** — the id is set structurally, never pasted into text, and a blob id from
the server is accepted only as a canonical UUID.

Both apps send chat and DM attachments this way (Apple `StreamedUpload.swift`, Android
`Uploads.kt`) and decrypt downloads file to file. Still in memory: a photo while its metadata
is stripped (it has to be decoded), feed/story photos and avatars. Video metadata is not
stripped.

### Server behaviour apps rely on

- `POST /api/channels/:id/messages` **requires** `message_id`. The author repeating a send under
  its own id gets `200 { message_id, created_at, duplicate: true }`; anyone else's id is `409`.
  A send without an id is a build ≤ 42: `426`, and that device's `GET /api/e2ee/sealed/inbox`
  answers `426` from then on with a sentence those builds show verbatim.
- Every authenticated request from the core carries `x-skwod-build: 44`.
- `GET /api/channels/:id/messages` returns `cleared_at`; `channel_cleared` carries it.
- New CLI: `skwod backup`, `skwod restore`, `skwod move-data` (docs/SELF-HOSTING.md).

## Build 45: security-audit fixes

Bindings must be regenerated (`build-core.sh`) for the two additions; the rest is behaviour.

### Added

| Method | Notes |
|---|---|
| `delete_account(user_id: String)` (async, throws `CoreError`) | Swift `try await client.deleteAccount(userId:)`, Kotlin `client.deleteAccount(userId)`. Deletes an account for good: the signed-in one, or — for the instance owner — any other. The request is signed by this device (op `delete-account`, target = the user id) on a session bound to it. **Apps must call this instead of sending `DELETE /api/auth/users/{id}` themselves**: once the calling account has a device, the server answers a bare-token delete `403`. Errors are the usual ones (`Forbidden` for a non-owner deleting someone else, `NotFound`, the owner's account cannot be deleted). |

| `process_notification_inbox()` (async, throws `CoreError`) | Swift `try await client.processNotificationInbox()`. **The notification extension calls this instead of `process_control_inbox`.** It syncs and decrypts the sealed mailbox and puts the client in notification-extension mode for the rest of its life: no device registration, no prekey refill, no signed-prekey or delivery-key rotation, no new sender key, no key upload — in this call and in every later one on that client. Provision requests that arrive are persisted and fulfilled by the app's next sync. Android has no such extension and does not call it. |

### Changed behaviour, same signature

- **Channel wire v2 (build ≤ 42 history) is still read, without server-supplied metadata.** The
  version byte is outside the ciphertext, so the plaintext decides: a body that is a v3 body is
  treated as v3 whatever its label (sealed id / reply target / edit flag); any other body under
  a v2 label is shown as plain text with `reply_to_id = nil` and `is_edited = false` — the
  server's values for those are ignored. Once a sender device has been seen writing v3 in a
  channel, a v2 body it sealed later (by its own signed sender-key counter) is skipped: no row,
  no placeholder, no re-ask. Rows already in the cache are untouched. docs/SECURITY.md
  "Channel messages from build 42".
- **A contact's device that is gone vouches for nobody.** Once a contact's device is absent from
  the directory listing (or the contact's own device said it removed it) it can no longer vouch
  for a new device, and it does not come back by being listed again: both show up as
  `unverified_contact_device` notices and the device is held (`contact_status(..).unvouched > 0`).
  This includes the listing in which the old device first goes missing: a new device that
  appears together with its linker's disappearance is HELD. (An honest "link the new phone,
  then remove the old one" is unaffected for contacts who saw the link while the old phone was
  still listed; one who only looks afterwards sees the new phone as unvouched until another
  live device of the contact links it or the contact is verified again.)
- **Restore with a young recovery key waits for approval before the backup is even fetched.**
  A build-45 server does not hand a backup under a recovery key younger than 7 days to a new
  sign-in. `restore_key_backup` then files a restore request (`POST /api/e2ee/key-backup/request`)
  and fails with `RecoveryPending` exactly as before; the account's other devices get the same
  `recovery_requested` notice (`approve_recovery` / `cancel_recovery` unchanged), and
  `retry_restore(pin)` completes it once approved, with the seasoned PIN, or after the 7-day
  hold. The recovery key is kept in memory for `retry_restore`; after an app relaunch call
  `restore_key_backup` again with it (same request, nothing is lost). Only when the server
  cannot tell which device the backup restores does it fail with the `RECOVERY_KEY_TOO_NEW`
  explanation (`Invalid`).
- **A send that reaches no recipient device always fails.** A contact whose only listed device
  is held (e.g. they replaced their phone and this device only looked afterwards) makes
  `send_dm` fail with `IdentityChanged` and raises `unverified_contact_device`, verified or
  not: show "their devices changed" and offer `accept_identity_change`. Provisioning a member
  none of whose devices can be sent to now returns an error instead of succeeding quietly.
- **The mailbox delivery key rotates by itself**: after a member or a contact's device is
  removed, after this account leaves or is removed from a server (noticed from `GET /api/servers`,
  asked at most every 5 minutes), within minutes and at most once per 10 minutes — and at least
  every 7 days. Until now only `block_user` did. It happens inside `process_control_inbox` /
  `maintain_keys`; apps call nothing new. A state written by build ≤ 44 rotates once on its
  first sync after the update. The engine state gains two sections (`0xD1`, `0xB5`) that older
  builds skip.

### Build 45, second batch: the core audit (C1 and the engine/crypto findings)

Bindings must be regenerated (`build-core.sh`) for the additions (four methods, one record field); the rest is behaviour the
apps should know about. docs/SECURITY.md "Identity keys never change by themselves" and "What
the server cannot do to local state".

#### Added

| Method | Notes |
|---|---|
| `forget_space(server_id: String)` (async) | Swift `await client.forgetSpace(serverId:)`. Drops everything this device trusts about one space (pinned owner, space key, roster, channel sender keys). The only way to let a later join pin a different owner. Call it from a deliberate, confirmed user action ("leave and forget", "this skwod has a new owner — join again"), never in response to a server event. |

| `channel_opened(server_id: String, channel_id: String) -> Bool` (async) | Swift `await client.channelOpened(serverId:channelId:)`. **Apps must call this when the user opens a channel from a server's channel list.** It confirms, on this device, which server the channel belongs to — the thing a later clear (or deletion of someone else's message) by that server's owner is checked against. A channel the user never opened, created or joined through keeps its cached history when the owner clears it; and an owner can only announce a clear for a channel their own device has confirmed. Writing in a channel confirms nothing. Returns `false` (and a `channel_remap_refused` notice follows: `device_id` = the channel, `server_id` = where it is confirmed) when the channel is already confirmed in another server. Never call it for every channel a listing returns: the point is that a listing confirms nothing. |

| `dm_is_group(conversation_id: String) -> Bool?` (async) | Swift `await client.dmIsGroup(conversationId:)`. Whether a direct conversation is a group, as fixed on this device the first time it was used — by the group marker sealed inside the first message received in it, or by the user's own first send. `nil`: never used here. **Use this (and `DmEvent.is_group`) to decide how a conversation is presented, not the server's `is_group`.** |
| `DmEvent.is_group: Bool` (new record field) | Set on every DM event from the same binding. |
| `safe_instance_id(raw: String) -> String` (sync, free function) | The server's instance id when it is 1–64 characters of `[A-Za-z0-9-]`, otherwise `h-` + 32 hex characters (a stable hash). `fetch_server_identity` now returns its `instance_id` through this, so the value is always safe as a key, file name or path component. Apps that read an instance id from anywhere else (an invite, a stored record) should pass it through this instead of their own check, so both sides agree. |

#### Changed behaviour, same signature

- **Group or 1:1 is sealed by the sender (apple A5).** A direct-message payload for a group
  conversation is wrapped with the group's member list inside the ciphertext; a 1:1 payload is
  bare. A bare payload is never filed in a group conversation, a wrapped one never in a 1:1, and
  a group message only in the group of exactly the members it names; on first use the server's
  participant list must agree with the marker. Consequences: a build-44 device's group messages
  are not delivered to build-45 devices (they arrive bare) and build-44 devices drop build-45
  group messages (an unknown payload) — 1:1 messages are unaffected; and group membership is
  fixed at first use on each device.
- **`ChannelPage` no longer carries the server's `cleared_at`** (apple A3 / engine M1): the engine
  itself drops the field, so no caller can purge on it.
- **`list_channels` leaves out a channel the server lists under one space while this device has
  it placed in another**; a confirmed placement is never moved by a listing.
- **`join_space` / `join_by_code` can now fail** when the server answers with the id of a space
  this device already has an owner pinned for and names a different host. The error is
  `Protocol`; a `security_notices` entry `owner_change_refused` follows (`user_id` = the host the
  server named, `server_id` = the space). Nothing was changed. Apps should say that the invite
  claims a different owner and offer `forget_space` only as an explicit choice. A join never
  replaces a space key the device already holds.
- **`identity_changed` notices now also mean "someone presented another key for this device and
  it was refused".** `device_id` is set, `was_verified` says whether that contact was verified.
  Sends are not held and the contact's safety number is unchanged. The notice has the same kind
  and shape as a real change, so an app cannot tell the two apart from the notice alone; what
  distinguishes them is `contact_status(user_id)`: after a refused impersonation `sends_held`
  is false and the safety number is the one already shown. Wording that fits both: "someone
  presented a different key for X's device". At most one per device per hour.
- **`device_removed` notices** are now also raised when another of the account's devices tells
  this one that a device was removed (it stops being trusted here at once).
- **`channel_cleared(channel_id, cleared_at)` no longer deletes anything by itself.** It reads the
  mailbox; the cache is emptied only if a sealed clear from the server's owner (or one of the
  user's own devices) is there. Keep calling it on the realtime event. `fetch_channel_messages`
  likewise ignores the server's `cleared_at`. A clear by a moderator who is not the owner does
  not empty other members' caches.
- **A message another member deleted disappears when their device's sealed deletion arrives**
  (through any mailbox sync), not when the server serves a tombstone. An author's deletion
  applies to their own messages everywhere; deleting someone ELSE's message reaches other
  devices only from the pinned owner — a moderator who is not the owner removes it from the
  server and from their own devices only. `delete_channel_message`
  and `clear_channel_messages` / `clear_server_messages` send those sealed messages themselves.
- **Channel rows and reactions from someone this device does not accept as a member are not
  returned** (held members included: let them in first).
- **Reactions**: only reactions that open for that message and that user are returned, so
  `MessageReaction.emoji` is always present. Reactions written by build 44 are no longer shown
  (they could be re-attributed), and the server-visible tag now differs per message.
- **`refresh_blocks` / `list_blocks`** can return entries with an empty `username`: people this
  device drops whom the server does not (or no longer) list. The server's list never unblocks
  anyone; an unblock made on another device has to be repeated here.
- **Direct messages**: a send into a conversation that is bound to other people fails with
  `Protocol` ("that conversation is with someone else"). Apps already keep one peer per direct
  id; group conversations are bound to the members they were first used with.
- **`recovery_fingerprint()` and the `fingerprint` of a `recovery_requested` notice are now
  `XXXX-XXXX-XXXX-XXXX`** (19 characters, was 9). Server and clients compute it with the same
  function, so both must be build 45; a build-44 device shows a code that never matches.
- **`passphrase_problem` / `enable_key_backup` refuse guessable passphrases** (common passwords
  with digits, keyboard runs, repeats), not only short ones. Show the returned sentence.
- **`restore_key_backup` can fail** with `Protocol` ("this backup is older than one this device
  has already seen") on an install that has uploaded or restored a newer backup: the server is
  serving a stale blob.
- **Engine state** gains two sections (`0xE1`, `0xE2`) and the backup blob one (`0xE3`); older
  builds skip them. Two `Content` variants are appended (`ChannelClear`, `ChannelDelete`); a
  build-44 device drops them unread, so its cache is not emptied by a build-45 owner's clear.

### Build 45, third batch: what the build-45 server requires of a client

Bindings must be regenerated (`build-core.sh`) for four additions.

#### Added

| Method | Notes |
|---|---|
| `bind_session() -> Bool` (async, throws `CoreError`) | Swift `try await client.bindSession()`. **Apps call this right after `attach_cache` (and `set_pinned_server_key`), before their own first authenticated request and before opening the realtime socket.** A build-45 server refuses a session that is bound to no device everything but linking, restoring and binding once the account has a device (`403 device bind required`). `false`: this install is not a device of the account yet (unregistered, or a restore still waiting) — nothing to bind; registering, completing a link and restoring bind the session themselves. Throws `Superseded` / `DeviceRemoved` (read `device_state()` afterwards) and transport errors (call again when the server is reachable). One request per client; later calls return at once. |
| `delete_account_and_ban(user_id: String)` (async, throws `CoreError`) | The instance owner's "delete and ban": like `delete_account`, and the username and the identity keys of the account's devices cannot sign up or register on this instance again; the invite it signed up with is revoked. Not for one's own account. |
| `purge_server_messages(server_id: String, older_than_ms: Int64)` (async, throws `CoreError`) | Retention purge, signed by this device (`purge-messages`). No app screen uses it yet; an app that adds one must go through this. |
| `delete_space(server_id: String)` (async, throws `CoreError`) | Delete a space on the server (its owner), signed by this device (`delete-server`). Local trust state is untouched — `forget_space` is a separate, deliberate step. No app screen uses it yet. |

#### Changed behaviour, same signature

- **`clear_channel_messages`, `clear_server_messages` and `set_voice_config` are signed by this
  device** (ops `clear-channel`, `clear-server`, `voice-config`) and bind the session first.
  They can therefore now fail with `Superseded` / `DeviceRemoved`. An install with no device
  (a host that has not registered one) still sends the token alone. `set_voice_config` trims
  its three values before signing, as the server does before storing.
- **A device restored onto another install makes what it held rotate.** When the directory
  lists a device — a contact's or one of the account's own — at a higher `generation` (the
  server's `device_rekeyed`), the delivery key and the sender keys that device was a holder of
  are replaced on the next maintenance / send. Apps call `refresh_devices_of(user_id)` on the
  realtime `device_rekeyed` event for someone else (payload `user_id`), as they do for
  `device_removed`; nothing else is new.
- **The realtime event `backup_fetched`** (topic `user:<me>`, payload `{ "at": ms }`) is the
  server saying the account's key backup was downloaded by a session that is not one of its
  current devices. It carries nothing the core can check; apps show it as a notice ("if this
  was not you, change your password and save a new recovery key").

- **Fixed at integration:** the `fingerprint` of a `recovery_requested` notice was cut to 16
  characters; it is now the full `XXXX-XXXX-XXXX-XXXX` that `recovery_fingerprint()` shows on
  the restoring install. And a new sign-in can file its restore request
  (`POST /api/e2ee/key-backup/request`) with bound sessions required — before, the server's
  new default refused it and restore by approval failed with `403 device bind required`.

#### What the apps do with it (build 45 apps)

- Bind in the workspace bind, after `attach_cache` / `set_pinned_server_key` and before the
  client goes up (lists, socket, push), and again before each inbox sync until it succeeds;
  link, restore and register re-run the bind through the normal "device became active" path.
- A direct conversation's banner comes from `contact_status` and from queued sends that failed
  on the contact's keys — never from an `identity_changed` notice alone. Accept calls
  `accept_identity_change`, then retries those sends; failed sends read "Not delivered".
- `DmEvent.is_group` decides group or direct when an event is filed; an unclaimed direct entry
  gives way to a group-marked event, a claimed one keeps its id (audit A16).

### Build 45, final review (M1, M2, L1, L2)

#### Changed signatures

| Function | What changed |
|---|---|
| `accept_identity_change(user_id, device_id, shown)` | **New `shown: String`** (audit L2): the `accept_fingerprint` of the `ContactStatus` the banner (or notice, or safety-number screen) was drawn from. Only that exact device-and-key set is accepted. If the directory lists anything else by the time of the tap — a device added, removed or re-keyed — nothing is accepted and `CoreError.IdentityChanged` comes back: read `contact_status` again and show the banner for the new set. An empty or made-up `shown` accepts nothing. |
| `ContactStatus` | **New field `accept_fingerprint: String`**: hex SHA-256 over the live devices with their keys and the held (unvouched) devices with theirs — what "Accept" would take on. |

#### Added

| Function | Purpose |
|---|---|
| `unconfirmed_restored_devices() -> [String]` | Devices of this account a backup restore brought back that are not confirmed yet (audit M2). The backup may be older than the account (the host can serve an earlier blob that still opens) and list a device removed since. Nothing is sent to these devices, nothing they vouch for is admitted, nothing they send is read, and **none of them can confirm itself or another**. One is confirmed by the sibling set of an ALREADY-CONFIRMED device of the account, or by the user. **A restored install with no confirmed device keeps every restored device unconfirmed until the user confirms it.** A confirmed sibling's removals drop a stale device. The Devices screen asks "Is this your device?" for each. |
| `confirm_restored_device(device_id)` | The user's "yes, this is my device" for one of them. It is sent a session reset, and answers with the account's current set and removals. A removed device is never brought back by this (error). |

#### Changed behaviour, same signature

- **Restore** (`restore_key_backup`, `retry_restore`): restored siblings start UNCONFIRMED (above).
  A live build-45 sibling queues its sibling set and removals for a sibling whose generation rose
  or that came back restored; the restored install acts on them once that sibling is confirmed.
- **Backups** carry the contacts' removed devices (`contact_tombstones`) in a section of their
  own; older backups restore as before. A device answers a CONTACT's session reset (a restore)
  with its own account's removals.
- **Restore requests** (server, audit L1): several installs may each have a request for the
  same device (up to three live); each is listed in the device listing's `recoveries` with its
  own `request_id` and code. Apps keep each one as its own prompt; approving one ends the
  others. A request completes by the 7-day hold only if it was never contested; a contested
  one needs an approval, the PIN or the recovery key. New realtime event
  `device_recovery_multiple` (`{device_id, waiting, at}`): more than one install is trying —
  apps show "More than one install is trying to restore your account". A new filing while a
  request is granted, or while three are live, answers `409`.

#### Apple only (no FFI)

- Push (audit M1): no raw-token registration any more; a skwod that refuses wake credentials
  gets none and Settings says its host needs updating. A VoIP or alert wake without a
  `skwod_cred` this install registered is never rung and never dials a host.

## Build 46

### Added

| Function | Purpose |
|---|---|
| `instance_name() -> String?` | The skwod's name as its owner set it on the host (`GET /api/instance/name`, signed in). `None` when unset, and from an older host (404). A LABEL the host supplies: apps hold it to the shared host-name rule (`apps/shared-test-vectors/skwod-names.json`) and always show the host key beside it. |
| `set_instance_name(name) -> String?` | The instance owner names the skwod (`PUT /api/instance/name`). Device-signed, op `instance-name`, target `""`, payload = the name's bytes exactly as sent (the host checks the signature over the raw string, then trims it and refuses control/invisible characters and more than 64 characters). Empty clears it. Returns the name the host keeps. A non-owner gets `Engine` with "http status 403"; a refused name "http status 400". Apps check the name against the shared rule first. |

### Not in the core (decided by the apps, same rule on both)

- **Whose @everyone counts** (`EveryoneRule` / `Mentions.everyoneSenders`): the pinned owner
  (`space_owner`), plus members whose roles grant Administrator or Manage Server. Roles are the
  server's word, so an admin counts only when listed as a member, not held (`held_members`) and not
  blocked. The iOS notification extension gets the resulting ids per channel from the app (in the
  sender sets, key `everyone:channel:<id>`); it asks the server nothing about roles.

## Build 48 — p2p connect never hangs; relay hint in links

| Function | What changed |
|---|---|
| `p2p_connect_hinted(node_id, public_fallback, relay_url)` *free, new* | `p2p_connect` plus the host's home relay (`P2pInvite.relay_url`). The hint is dialed only with `public_fallback` and only if it is an allow-listed n0 relay. |
| `p2p_connect(node_id, public_fallback)` *free* | Same signature. The WHOLE call (bind, lookup, dial, admission proof, loopback proxy start) is now bounded by 20 s and fails with `Engine { "could not reach the host: timed out" }`. A failed endpoint is closed off the caller's path. |
| `p2p_connect_timeout_secs() -> u32` *free, new* | The budget above, for the apps' own backstop timer. |
| `p2p_format_share_link(node_id, join_code, fallback_url, relay_url)` *free* | **New 4th argument** `relay_url`: kept as `&r=` only if allow-listed (`*.relay.n0.iroh.link`). |
| `P2pInvite.relay_url` | New field: the `&r=` / `?r=` hint, or `None`. |
| `GET /api/instance/p2p` (server) | Adds `relay_url`: the host's current home relay (only with public fallback, only allow-listed). |

## Build 48 — "Add a device" by QR (`pairing.rs`, docs/SECURITY.md "Adding a device by QR")

| Function | What it does |
|---|---|
| `pairing_new_offer(node_id, relay_url, username, user_id, now)` *free, new* | Existing device: a fresh offer (new 80-bit link code, expires `now + 300`, and `commitment`: 32 hex chars committing to a nonce kept inside this process's core). `PairingOffer` has a `commitment` field. |
| `pairing_qr_encode(offer)` / `pairing_qr_decode(text, now)` *free, new* | The strict, versioned QR text `skwod-pair:1:…` (seven fields, the last the commitment); decode refuses expired / over-long offers. |
| `pairing_offer_link(offer)` *free, new* | The share link (node id + relay hint) to dial the host. |
| `SkwodClient.instance_p2p() -> InstanceP2p?` *new* | `GET /api/instance/p2p`: node id, current home relay, and `qr_pairing` (the host set `SKWOD_QR_PAIRING=1`). Offer QR pairing only when `qr_pairing` is true. |
| `SkwodClient.register_pairing_offer(offer)` *new* | Existing device, BEFORE showing the QR: registers the offer (device-signed). A new device can only pair with a registered offer. |
| `SkwodClient.pair_begin(offer, now)` *new* | New device, NO session (client made with the p2p loopback base URL and an empty token, cache attached first), only after the person said yes to "Join … as …?": opens a session-less pair request. Returns nothing: the emoji come from `pair_poll`. |
| `SkwodClient.pair_poll(offer) -> PairProgress` *new* | New device: `Waiting`; `Confirm { emoji }` (five) once the existing device revealed its nonce (checked against the offer's commitment); `Paired { device }` once approved — ONE session claimed (signed by its identity key), linked and registered. Show "Approved on your other device · <short key>" before signing in with `device.session`. Errors when the offer expired, was denied or contested, or the nonce does not match ("did not match"). `PairedDevice { session, device_id }`. |
| `SkwodClient.pairing_candidate(offer, now) -> PairingCandidate?` *new* | Existing device: `PairingCandidate { choices, identity_key, request_id }` — four shuffled five-emoji sets, one real, stable per offer — approving nothing; `None` while nobody has asked. The first call that sees a request pins its key and reveals the nonce for it. Errors once expired / used, when the offer is contested, when another key appears after the reveal, or when the app restarted since making the offer (the nonce is gone: make a new code). |
| `SkwodClient.approve_pairing(offer, candidate, picked, now) -> bool` *new* | Existing device: `picked` is the set the person chose. A wrong pick denies the request and burns the offer (error). A right one waits ~2 s, re-checks the request is uncontested and the same key, then approves. Single use, refused after expiry or when contested. |
| `SkwodClient.deny_pairing(offer, candidate)` *new* | Existing device ("None of these"): refuse the candidate; the offer is burned. Needs a session bound to this device (the core binds first). |
| Server `POST /api/e2ee/pair-offers` (device-signed), `POST /api/e2ee/pair-requests` (no session), `GET /api/e2ee/pair-requests/by-offer/:offer_id`, `POST …/:id/reveal` (bound session; the nonce for the key seen, once), `POST …/:id/approve` (only after the reveal), `DELETE …/:id` (deny; bound session, limited), `POST …/:id/claim` (signed by the request's identity key; carries the nonce once revealed) | All 404 unless `SKWOD_QR_PAIRING=1`. An unknown / expired / consumed / other-username offer gets a decoy request id and nothing is stored. Offers are stored for at most 5 minutes and consumed on approve, deny, contest and register; every step checks the offer's expiry; a claimed but unregistered session is revoked on contest or expiry. Migration 0019 adds `device_pair_offers` and `device_pair_requests` (separate from `device_link_requests`); 0020 adds `consumed`, `nonce`, `registered`, `session_hash`. |
| p2p proxy (`skwod-net/src/proxy.rs`) | Also stamps `POST /api/e2ee/pair-requests` with proof of work, as for signup/login (the host answers 428 without it). The polled `…/claim` is not stamped; the host asks no work for it. |
| Apps | Apple: `NewDevicePairing.swift` (join question → waiting → five emoji → approved → enter), `PairingViews.swift` (pick among four, "None of these"), `PairingCopy.swift`; `signIn(…, pairedLocalId:)`. Android: `AppModel.pairingStart/pairingPoll/pairingEnter/pairingDrop`, `adopt(…, pairedLocalId)`, `PairNewDeviceDialog`, `AddDeviceDialog`, `PairingCopy.kt`. The Mac reads a QR from an image (no camera scan). |
