# Security model

> Skwod's message protocol is **Signal's official `libsignal`** (v0.108.0, ADR-011). The protocol
> itself is audited and widely deployed. How Skwod *uses* it — everything described below that is
> not libsignal — has **not** had an independent audit. "Remaining gaps versus Signal" at the end
> is part of the model, not a footnote.

## Threat model

The server is **untrusted infrastructure**, even though the operator owns it. We defend message
content, private keys and (as far as described below) sender identity against: the server operator,
the hosting provider, anyone who compromises the server or its backups, and a network attacker.
Self-hosting decides *whose box*; E2EE decides *whether the box can read the messages*.

## What libsignal provides (and what we configure)

| Property | Mechanism |
|---|---|
| Session setup | **PQXDH**: X25519 + Kyber-1024. Every bundle carries a KEM key: a one-time Kyber prekey while they last, the signed **last-resort** key after. A device cannot register without one, so there is no classical fallback. |
| 1:1 sessions | **Double Ratchet + SPQR** (the "triple ratchet"; mandatory in this libsignal release). A session counts as usable only if PQXDH-established and SPQR-ratcheting. |
| Channels | **Sender Keys**. One sender key per device per channel, handed to every device of every member over pairwise sessions. |
| Sender anonymity | **Sealed Sender v1** for all pairwise traffic (see "Metadata"). |
| Identity verification | Signal's **numeric safety number** (version 2, 5200 iterations), per device pair. |
| Prekey hygiene | Signed prekey + last-resort Kyber key rotate weekly (old ones kept 30 days for in-flight setups); one-time keys are refilled below a low-water mark; one-time keys are deleted on use; a replayed last-resort setup message is rejected. |

### Identity keys never change by themselves (build 45)

Until build 45 the policy here was "a changed key is accepted on receive with a notice, refused on
send for a verified peer". That was wrong for Skwod, and it was the critical finding of the
build-44 audit (C1): the **host issues sender certificates**, so it could mint one naming a
contact's device under a key of its own, deposit a PQXDH PreKey message, and libsignal would make
that the active session for the contact and record the host's key as theirs. The engine noticed
the key was not the pinned one and dropped the *content* — but kept the session and the identity,
so the next thing sent to that contact (a DM, a channel sender key, a voice key, the account key
for a sibling device) was encrypted to the host. It worked against verified contacts, and the
safety number did not change. Builds ≤ 44 are exposed to this against a malicious host.

What holds now (`skwod-crypto/src/store.rs`, `skwod-sync/src/engine.rs`):

- **The pin is the authority.** The key this device holds for a peer comes from its own trust
  decisions only — the vouched key of a sibling, the pinned or link-chain-verified key of a
  contact's device. Not from a certificate, a bundle or a session.
- **Receive.** A sealed envelope is opened in two steps. The outer layer and the certificate are
  checked first, which changes nothing. Before libsignal sees the inner message, the certificate's
  key and (for a PreKey message) the identity inside it must both equal the pin. Otherwise the
  envelope is dropped there: no session is started or replaced, no identity is recorded, no
  prekey is consumed, no sender key is handed out again, no session repair is triggered. There is
  no trust on first use on receive: a pinned device with nothing yet in the libsignal store is
  protected the same way.
- **The store refuses on its own.** A key on record is never replaced by a message or a bundle,
  in either direction, verified or not. The only path that changes one is an explicit decision
  (`accept_identity`: the user accepted a contact's changed devices, or the device's own trust
  chain names another key), and that retires the session made with the old key.
- **Rollback.** Whatever fails after the checks (a bad MAC, bad padding) leaves the store exactly
  as it was — session, identity, one-time prekeys, last-resort replay memory.
- **Send.** A session counts only if both it and the recorded key are for exactly the pinned key,
  checked when the session is chosen and again inside the store at the moment of encryption. A
  session that got there any other way — including one planted on a build ≤ 44 install — is
  retired and rebuilt from a bundle, which is checked against the same pin.
- **What the user sees.** An envelope under a certificate that names a known device with another
  key raises an `identity_changed` notice (the device, and whether that contact was verified), at
  most once an hour per device. Sends are **not** held because of it: the pins did not change, so
  what is sent still goes only to the keys the user trusted, and holding sends would hand the host
  a way to mute any conversation by injecting one envelope. A contact's key really changing still
  goes through the device-set rules below (held as unvouched; a verified contact is blocked until
  verified again).
- **Devices nobody vouched for.** A message from a device the server lists for a contact but that
  no trusted device linked is read without accepting its sender (`sealed_peek`: nothing is kept)
  and held for the user. The envelope is remembered by hash so it is held, and later delivered,
  once; and what is held is dropped if the key the directory lists for that device changes.

What this does not change: the first time an account is seen its listed devices are pinned (trust
on first use of the *account*, gap 4 below), and the host can still drop or delay envelopes.

## What is not libsignal

Each of these uses audited RustCrypto / dalek crates and is small on purpose.

| Piece | Scheme | Why it exists |
|---|---|---|
| Message padding | Signal's: `plaintext ‖ 0x80 ‖ 0…` to 160-byte buckets, on every pairwise and channel message | libsignal leaves padding to the application |
| Attachments | Signal's attachment scheme: fresh 64-byte key per file, **AES-256-CBC + HMAC-SHA256**, plaintext zero-padded to Signal's size buckets, SHA-256 digest of the blob carried inside the E2EE message | libsignal has no attachment API. CBC+HMAC rather than AES-GCM-SIV because it is what Signal ships, it binds the blob by digest, and it has no single-shot size ceiling |
| Channel/space names, beacon note, backup payload | ChaCha20-Poly1305, random nonce, static key | metadata that is not a message |
| Key backup | Argon2id (64 MiB, t=3) wraps a random backup key; see below | no enclave exists on a self-hosted server |
| Device linking | libsignal identity-key signature + HMAC-SHA256 under a one-time code; see below | libsignal has no multi-identity account model |
| Server instance identity | Ed25519 (the key invites pin) | authenticates the *server*, and signs the sealed-sender trust root |
| Local cache | SQLCipher | holds the libsignal store and decrypted history |

## Metadata

All **pairwise** traffic — direct messages, sender-key distributions, space keys, provisioning,
voice keys, device-sibling updates — is sealed-sender encrypted per recipient device and deposited
in that device's **sealed mailbox**. The deposit request carries no credentials and is made on a
separate connection that never carries the account token; authorization is the recipient's
*delivery key*, which the server hands out only with that device's directory entry (i.e. to accounts
allowed to contact it). The mailbox table has no sender column.

Sender certificates are libsignal `SenderCertificate`s (6 h — `CERTIFICATE_TTL_MS` in `server/src/keydir.rs`; a removed device can deposit "as" its account for at most that long) issued by the host server. Their
trust root is signed by the server's Ed25519 instance key — the key the invite pins — so the
server cannot swap in another authority later.

**Blocks** work without the server knowing senders: a block makes the server refuse the blocked
party any directory entry or bundle for the blocker (on every path, including the per-server
member-device list), the blocker's device rotates its delivery key, and whatever still arrives
from a blocked user is dropped on the device.

The delivery key is a bearer capability: whoever was handed it can deposit until it changes. A
device therefore replaces it (device-signed; `rotate_delivery_key`) when someone who holds it
should not — a block, a member removed from a server we share, a contact's device removed, and
**when this account leaves or is removed from a server** (found by comparing the server's list of
our servers with the last one, at most every 5 minutes) — at most once per 10 minutes, and in any
case every 7 days. The notification extension never does this; the app does on its next sync.

## Story music (what Apple and the host learn)

A story can carry a song from Apple's catalogue. The song itself, and which part of it plays,
are inside the end-to-end-encrypted story: the server never reads them from the message. What
plays is Apple's ~30 second preview of the song, an audio file on Apple's CDN — and fetching a
file tells whoever serves it who asked.

**Viewers never fetch it from Apple.** If they did, Apple would see the IP address of every
person who opens the story, and when. Instead the viewer's app asks its own Skwod host
(`POST /api/music/preview`, members only), the host fetches the file and hands it back.

Who learns what, honestly:

- **Apple** sees the host's address ask for a preview (once per ten minutes per song — the host
  keeps a short in-memory cache). It does not see viewers.
- **The host** learns that *this signed-in session* asked for *this preview* at *this time*:
  which song, when, which account. It is not told which story or whose — that stays in the
  encrypted message — but a host that also watches message timing can often guess. The server
  writes none of this down: the request is not logged, the URL travels in the request body (so
  it is in no access log, the server's or a reverse proxy's), and the cache is memory only.
  A host running modified software could record it. This is the same trust a host already has
  for attachment downloads: it serves them, so it knows who fetched which blob.
- **"Play story music only when I tap"** (Profile → Privacy; off by default) is for members who
  would rather the host not learn it unasked: with it on, opening a story fetches nothing, and
  the song is requested — still through the host — only when the viewer taps it.

**Song cards in chats and feed posts follow the same rule.** Tapping play on a card fetches
the preview through the host, exactly as a story does, and the card's cover is fetched through
the host too (`POST /api/music/artwork`) instead of loading from Apple when the card scrolls
into view. So the host additionally learns which covers a session's app displayed — in
practice, which song cards were on that person's screen and when — and with tap-to-play on,
nothing about a card (cover or audio) is requested until its play button is tapped; it shows a
placeholder until then.

Playing the **whole track** in-app is the viewer's own opt-in: "Play full songs with my Apple
Music account" (Apple apps, Profile → Privacy, off by default). It uses the viewer's Apple
Music subscription on that device, so Apple sees which songs that person plays — which is what
the setting says. Apple Music access is asked for only when the setting is switched on. With
it off, without access, or without a subscription, a card plays the preview through the host.
Stories are not affected: they always play the part their author chose, through the host. (The Android app's song cards show no cover and play nothing
in-app; they only open Apple Music on a tap.)

The artwork endpoint has its own, equally narrow rules: only
`https://is1…is5-ssl.mzstatic.com/image/thumb/…` (those five exact names; `is1` is the one the
catalogue was seen to return), only `image/jpeg`, `image/png` or `image/webp` (never SVG),
300 kB, 600 requests an hour per account, the same address checks and redirect rule, its own
small cache, nothing logged.

The preview endpoint is not a proxy either. It fetches only `https://audio-ssl.itunes.apple.com/itunes-assets/…`
audio files (exact host, checked on the parsed URL), connects only to public addresses it
resolved itself, follows at most two redirects and only to that same host, relays only audio
content types, stops at 4 MB and 15 seconds, and allows an account 120 requests an hour.

What still goes straight to Apple, from the device of the person doing it:

- **Picking a song.** Searching (MusicKit on Apple devices when authorised, otherwise Apple's
  public iTunes Search API; always the latter on Android), the artwork in the search results,
  and hearing the part while choosing it is the *poster* using Apple Music — except that the
  audio they hear while choosing also comes through the host. The poster chose to use Apple
  Music; viewers did not. Search is not sent through the host: it would hand the host every
  keystroke of what a member looks for, which is worse than Apple seeing a search.
- **"Open in Apple Music"** opens Apple's app or site, on a tap.

## Multiple devices

Each device has its own libsignal identity. A device is added to an account only by **linking**:
the new device shows an 80-bit one-time code; the user types it into a device already on the
account; that device signs the new device's identity key. The code keys an HMAC in each direction,
so neither side can be handed a device of the server's choosing. The server refuses to register an
unlinked extra device — and clients do not rely on that: each keeps a **verified sibling set**
derived from link-signature chains, sends sync copies and keys only to verified siblings, and
grants "my own device" privileges (synced messages, space keys, provisioning) only to them, and
only over a session whose identity key is the vouched one. A stolen session token cannot enrol a
device. "This account has had a device" is a durable server record, not the current device count,
so emptying the device list does not reopen first-device registration. Removing a device needs a
signature from a device on the account. Lost every device: restore the key backup (same identity,
new prekeys), or **reset** the account's devices (new identity; contacts see a new device and
safety number) — which waits 7 days, during which any device still on the account cancels it
automatically and warns its user. A registration-lock PIN waives that wait, but only a PIN that has
itself been in place for 7 days; setting or changing the PIN needs a device signature (and the
current PIN, if any).

**Rule: a session token alone never changes account security.** Every such mutation needs a
signature from a device on the account, an identity-key proof, or the hold: device linking
(link signature), device deletion, PIN set/change/disable, key-backup write/delete, delivery-key
rotation, **deleting the account** — one's own, or anyone's as the owner (device signature); prekey upload/rotation/rekey (signed by the stored identity key);
reset (seasoned PIN or the cancellable hold, claimed atomically). Device signatures cover the
request's contents (the new PIN, the backup blob/salt/KDF cost, the new delivery key), travel in a
header rather than the URL, expire after 10 minutes and are accepted once — so observing one does
not let a token holder replay it or swap the payload. Reading the encrypted backup
blob still needs only the token — that is what makes recovery on a new device possible — which is
why its passphrase must withstand offline guessing.

### Adding a device by QR (build 48)

The same linking, with the code going the other way, and **no password on the new device**.
A device already on the account shows a QR (Profile → Devices → Add a device):
`skwod-pair:1:<node id>.<relay region|->.<username>.<user id>.<code>.<expires>.<commitment>`
(`core/skwod-core/src/pairing.rs`, strictly versioned and parsed). The server side is
`server/src/pairing.rs`; its tests are `server/src/pairing_tests.rs`, and
`core/skwod-core/tests/linked_devices_live.rs` runs the whole exchange against a real server.

- **Off unless the host turns it on.** The routes answer 404 unless the operator sets
  `SKWOD_QR_PAIRING=1`; `GET /api/instance/p2p` reports it as `qr_pairing`, and the apps offer
  "Add a device" / "Scan from your other device" only when it is on.
- **The QR is not a credential, and never a reason to type a password.** Anyone can print one,
  so it might name a host and an account the person never chose. The new device therefore asks
  for nothing secret. Before it dials anything it asks **"Join <skwod> as @<username>?"**, naming
  the skwod only by a workspace this device already has, otherwise by the host's short key (never
  by a name from the QR or the host), and saying that a code from someone else would add this
  device to *their* account. Only on Continue does it dial the node id (the transport proves the
  host holds that key) and open its encrypted store. Cancel, denial or expiry delete the store
  and key it created.
- **What a forged QR can still do (the residual).** Someone who hands the person a QR of their
  own (their host, their account, their offer) can approve the resulting request on their own
  device. The new device then joins **the attacker's account**: it holds nothing of the person's
  (no keys, contacts or messages of the person's account ever reach it), but whatever the person
  goes on to type there is the attacker's to read. The two questions are the defence: "Join … as
  …?" before dialling, and **"Approved on your other device · <host short key>"** before entering,
  so a host or account the person does not recognise can be cancelled (Cancel there deletes the
  local store; the device row the attacker's server created is left with nothing behind it).
- **Only offers the existing device registered can be asked for.** Before showing the QR the
  existing device registers the offer with a device-signed `POST /api/e2ee/pair-offers` (offer id
  = a hash of the QR's code, the username, an expiry the server stores as at most 5 minutes; a
  minute of clock skew is cut back, not refused). The new device's session-less
  `POST /api/e2ee/pair-requests` (offer id, username, identity key, an HMAC under the code, the
  hash of a poll secret only it knows) is stored only for a registered, unexpired, unconsumed
  offer for that username. Anything else gets an identical 200 with a decoy request id that never
  completes, and nothing is stored: no oracle for usernames or offers, and nobody without the QR
  can fill an account's requests or block its pairing.
- **Its own table.** Pair requests live in `device_pair_requests` (migrations 0019, 0020), not in
  `device_link_requests`: nothing in the typed-code `/link-requests` flow can list, approve or
  replace one.
- **Commit, then reveal.** The QR carries a 128-bit commitment (`skwod_crypto::link::pair_commitment`)
  to a 32-byte nonce that stays inside the existing device's core. When that device first reads a
  request whose proof verifies, it **pins** the requester's identity key and only then releases
  the nonce for exactly that key (`POST …/:id/reveal`, once; a different nonce or key is refused,
  and a different key showing up later burns the offer on the device). The claim hands the nonce
  to the request's own (key- and secret-proving) device, which checks it against the QR's
  commitment and stops if it does not match.
- **Five emoji, picked among decoys.** Both devices compute five emoji (30 bits) as an HMAC under
  the code over the account, the requester's key and the nonce
  (`skwod_crypto::link::pair_confirm_indices`). Because the key is fixed before the nonce exists for
  anyone but the existing device, someone holding the code (a photographed QR) **and** the server
  can no longer grind a key until its emoji match: each attempt is a single 2^-30 guess, and the
  offer allows one. The existing device does not show the real set to approve with a tap: it shows
  **four sets** (one real, three random decoys that each differ from it in at least two places,
  shuffled, stable for the offer) and the person picks the one the new device shows, or "None of
  these". A wrong pick denies the request and burns the offer. A right pick waits about two
  seconds, checks once more that the request is uncontested and still that key, and approves only
  that identity key (its link signature over the key is verified by the server, which also refuses
  an approval before the reveal). Residual: if someone who photographed the QR is the only one to
  ask (the person has not scanned it yet), the person has no new device to read from and should
  choose "None of these"; a blind pick would still be right 1 time in 4.
- **Two devices presenting one code: nobody is approved.** A second request for the same offer
  never replaces the first; it silently marks the offer contested (and consumed), and a contested
  offer is never revealed, approved or claimed. The existing device then says "Someone else also
  scanned this code…".
- **The session goes only to the approved key, and is never left loose.** After approval the new
  device claims ONE session (`POST /api/e2ee/pair-requests/:id/claim`), signing with the approved
  identity key over the request, the offer and the poll secret; the poll secret alone gets nothing.
  The session is created first and the row is claimed and records it in one conditional UPDATE; a
  claim that loses deletes its session. Registering the device takes the row in its own
  transaction with one conditional UPDATE (uncontested, claimed, not yet registered, by that very
  session, offer unexpired) and refuses otherwise; binding fails if the session is gone. A session
  claimed but not yet registered is **revoked** when the request is contested or expires. The link
  bundle stays sealed to the new device's identity key and authenticated under the code, exactly
  as for a typed code.
- **Consumed, expiring, single use.** The server consumes the offer on approve, deny, contest and
  register; register marks the request instead of deleting it, so a later request for the same
  offer opens nothing. Every step (read by offer, reveal, approve, claim, register) checks the
  offer's own expiry. Contested, denied and expired are told only to the request's own
  key-proving device. The new device refuses an expired offer (or one claiming a longer life), and
  the existing device refuses to look up or approve with it after the expiry or after one use.
  Pairing raises no "a device wants to join" alert.
- **Rate limits.** The session-less create is gated like signup and login: over p2p it needs a
  proof-of-work stamp (the app's local proxy attaches it), then per-caller and per-population
  limits. The claim is polled every couple of seconds, so it asks no work: a per-caller window,
  then the cheap check (the 256-bit poll secret matches) before anything else, then a ceiling of
  60 signature checks a minute **per request** — only the request's holder can reach it, so a
  flood of wrong guesses never blocks the real device. Deny needs a session bound to a current
  device and is limited per account; offer registration, reveal and reads are limited per account.
- **Platforms.** iOS and Android scan with the camera. The Mac shows the QR and can read one from
  an image; it has no camera scan.

## Key backup (opt-in)

Signal protects PIN recovery with an enclave that rate-limits guesses. A self-hosted server has no
such thing and its operator is in the threat model, so anything stored there can be attacked
**offline**. Therefore: backup is off by default; it requires a generated 160-bit recovery key or a
passphrase of ≥ 14 characters that is not a PIN; the passphrase is stretched with Argon2id and the
parameters travel with the backup (weak or absurd parameters returned by a server are refused:
below 19 MiB / 2 passes, above 256 MiB / 6 passes). The backup holds the identity key, pinned peer
identities, verified siblings and space keys — never sessions, sender keys or prekeys.

**A passphrase is the weak option, and the host can attack it offline.** The host holds the salt,
the parameters, the wrapped key and a verifier, so every guess costs it one Argon2id run and
nothing else. Since build 45 a passphrase must also pass a guessability estimate
(`backup::passphrase_guess_bits`, at least 2^50 guesses): common password stems, keyboard and
alphabet runs, repeats and years are priced as the few choices they are, so `password123456` and
`qwertyuiop1234` are refused. It is a pattern check, not a dictionary: an ordinary phrase it does
not recognise passes, and may still be guessable by someone who knows the user. The generated
160-bit recovery key is the option that does not depend on any of this.

**Freshness.** A backup carries a sequence number inside what the recovery key seals. An install
refuses to restore a backup older than one it has itself uploaded or restored. A *fresh* install
has nothing to compare with, so a host can still serve it an older blob that opens under the same
key; what such a rollback would bring back is contained (audit M2):

- **Restored siblings are unconfirmed.** Every device the backup lists as a sibling comes back
  unconfirmed: nothing is sent or synced to it, nothing it vouches for is admitted, nothing it
  sends is read, and it can never confirm itself or another device — so a stolen device a
  stale backup still lists gets nothing, whatever the host lists. A restored device is
  confirmed only by the sibling set of an already-confirmed sibling, or by the user ("Is this
  your device?" on the Devices screen). **With no confirmed sibling at all, every restored
  sibling stays unconfirmed until the user confirms it.** The user is the residual: confirming
  a device that was in fact removed brings it back (unless its removal is on record here).
- Removals win: a confirmed sibling sends its removal record, and a removed device is never
  re-admitted. Backups also carry the contacts' removal records (a section of their own; older
  backups still restore), and a device answers a contact's restore (its session reset) with
  its own account's removals.
- Every restored contact is re-read from the directory under the usual link rules.

The server keeps serving the earlier contents of the same recovery key for the hold period on
purpose (they are what the owner restores from if a current device buries a good state), so
the client cannot rely on it to serve only the newest.

**The approval code** shown for a restore that waits for another device is 80 bits (16
characters) since build 45; at the 32 bits it had, someone able to file a competing request could
grind a look-alike in seconds.

The registration-lock PIN is a separate, purely server-side gate on an account reset (online,
5 tries then a lockout). It protects no key material and is stored as an Argon2id hash.

**Restoring with a young recovery key.** A backup under a recovery key younger than 7 days is
served only to a session that is one of the account's current devices. A new sign-in instead
files a restore request (`POST /key-backup/request`: the device the backup was written by — the
server's record — and the hash of the install's secret). It is the same request as any recovery:
every device is told and shown the same short code, one of them approves or refuses exactly that
request with a device signature, the seasoned registration PIN grants it, and un-cancelled it
completes after 7 days. Only then is the backup served, and only to the install presenting the
secret behind the request; the re-key that follows uses the same grant. A request by itself
opens nothing, and one made without the recovery key gets — even if approved — a ciphertext it
cannot open and a re-key it cannot sign.

**Several restore requests for one device (build 45, audit L1).** A restore request used to be
replaced by the next one filed from another install, which reset its approval: anyone with the
password could keep the owner's restore from ever completing. Now:

- Every install files a request of its own, beside the others — up to three live at once per
  device (pending, approved, or past an uncontested hold and not yet used); a fourth is refused
  until one is cancelled, used or expires. No filing replaces, voids or resets another.
- Every device of the account sees each request with its own code and approves or cancels each
  one on its own; it is told, and woken, on every filing, and told in so many words when more
  than one install is trying ("more than one install is trying to restore your account").
- **The hold grants only an uncontested request.** When a second request is filed for the same
  device, every request still waiting is marked contested. A contested request completes only by
  an explicit approval from a current device, the seasoned PIN or the recovery key — never by
  waiting. So an attacker's request filed beside the owner's never completes by itself.
- Approving one request (or the PIN granting one) ends every other request for that device in
  the same transaction, and while a request is granted and not yet used no new request is filed.
  Filings and approvals are serialized per device (a lock row written first in each
  transaction), so the cap holds under concurrent requests, on SQLite and Postgres alike.
- Limits: three new filings per day per server-issued session (a sign-in costs a rate-limited
  password check), and ten per account per day counting only filings that were made — a refused
  attempt costs nobody anything. The PIN and the recovery key file no request and are outside
  every limit and cap.

*Accepted residual:* someone who has the password can keep a request contested (file one beside
it), which blocks the hold-only path. They cannot take the device over or cancel the owner's
request, and every filing is announced to every device. The owner completes the restore by
approving it on a current device, with the PIN, or with the recovery key; an owner with none of
the three and an attacker who keeps filing has no way back but changing the password (which ends
the attacker's sessions).

## Voice / video

Each device generates a **random** media key per call and sends it, over sealed libsignal sessions
only, to the devices of the people in the call. When someone it was sent to leaves the call (or
stops being a member), a new key is generated at the next key index and sent only to those who
remain. If keys cannot be set up the client refuses to join (ADR-007).

**Who is in a call is visible to the server's members (build 47).** The host
always knew it: it mints the room tokens and runs (or configured) the SFU. The server now reads
each voice room's participants from LiveKit's room service (loopback for the managed SFU;
nothing is written to the database) and publishes them — user id, microphone muted, camera and
screen share on, join time — as `voice_state` events on the `server:<id>` topic. Each one is
handed only to a member who may see that voice channel (Read Messages and Connect on it),
checked before every delivery; the same rule filters the rosters handed to a socket when it
subscribes and `GET /api/servers/:id/voice-state`. A private voice channel's participants are
therefore never sent to members who cannot see it. A permission change applies from the next
event and the next subscribe: a client that just lost access keeps what it was already shown
until it reconnects. Media, media keys and who is speaking never pass through the server.
Identities the SFU lists that are not members of the server are dropped.

## Key storage

- **Apple:** the SQLCipher key is a `ThisDeviceOnly` Keychain item (not synced, not in backups),
  one per workspace. Its class is decided by `KeyAccess` (unit-tested):
  - **`WhenUnlockedThisDeviceOnly`** (unreadable while the screen is locked) on macOS always,
    and on iOS whenever **app lock is on** or **"Show message text in notifications" is off** —
    i.e. whenever nothing has to decrypt on a locked phone. This is what build 44 did everywhere.
  - **`AfterFirstUnlockThisDeviceOnly`** only on an iPhone with app lock off and previews on.
    **Trade-off (build 45, the one Signal makes, with the same classes):** the key is unreadable
    from boot until the device is first unlocked, and readable after that even while the screen
    is locked — so that a notification arriving on a locked phone can say who wrote and what
    (decrypted on the device by the notification extension). The cost: someone who takes a
    locked, running phone and can extract data from it gets the key, and with it the cache —
    the libsignal identity, sessions and history. A user who does not accept that turns
    previews off or app lock on, and the key goes back to `WhenUnlocked` at that moment.
  - The class is moved in place (`SecItemUpdate`; never delete-and-re-add) at launch and
    whenever one of the two settings changes, in both directions. Nothing is ever `Always`.
  - The cache files are `NSFileProtectionCompleteUntilFirstUserAuthentication` (the container
    default, now stated explicitly); what gates them is the key.
  - The **workspace list** (server addresses and session tokens) is `AfterFirstUnlock`, as in
    every build so far: a call push that starts the app on a locked phone has to ask the skwod
    who is ringing. It cannot be split into a token-less record for the extension — the
    extension needs the session token to sync before it can decrypt anything.
  - **What the notification extension is told about conversations** — their titles and whose
    rows may be announced under each — are Keychain items under the cache key's rule (build 45
    kept them in the app-group preferences, a plain plist), and are deleted while app lock is on
    or previews are off, when nothing reads them. The app-group preferences hold settings,
    message ids and timestamps only.
  - **One value is readable before first unlock**: until when *every* signed-in skwod is muted
    as a whole (a time in an unprotected file — no skwod, no conversation). Only while it runs
    does a restarted phone nobody has unlocked show the passive line; a single muted skwod or
    conversation never hides another's notification (docs/PUSH.md, "What a wake may make the
    device do").
  - **Mutes** (which conversations, or which whole skwod, the user muted and until when) never
    leave the device. They are Keychain items too: the conversation list follows the cache
    key's rule; the skwod's own mute — a time and nothing else — is `AfterFirstUnlock` on iOS,
    so the extension can make a muted skwod's wakes passive even with app lock on. (Android:
    in the encrypted preferences, next to the session.)
  - **A narrower notification key (assessed, not built).** Ideally the extension would hold a
    key that opens notifications only, and the identity and history would stay `WhenUnlocked`.
    With the cache as it is that is not possible: decrypting a message advances a libsignal
    session (or a sender key), which lives in the same SQLCipher database as everything else,
    under one key — which is also why Signal opens its whole database from its extension.
    Two ways to get there, neither small: (a) split the cache into two databases — ratchet and
    sender-key state under an after-first-unlock key, history and contacts under a
    when-unlocked one — with the extension queueing what it decrypted for the app to file
    later; the identity key still has to be readable (prekey messages), so this protects
    history, not the identity. (b) a protocol change: senders additionally seal a short preview
    to a per-device notification public key; only that private key is after-first-unlock. That
    protects identity and history fully, but adds a ciphertext per recipient device per message
    and gives previews weaker forward secrecy unless the key is rotated; it touches the core,
    the FFI and all three apps. (a) is the realistic next step.

  The key lives in the data-protection keychain on both
  iOS and macOS (see gap 9 for unsigned Mac builds). On iOS the cache and its key sit in an App
  Group / keychain group shared with the notification service extension, and nowhere else.
- **Android:** the SQLCipher key lives in `EncryptedSharedPreferences` under an Android Keystore
  master key (StrongBox when available, else TEE).

## Upgrading from builds ≤ 40

The in-house protocol those builds used cannot be converted. On first launch of an upgraded build:
locally decrypted history and space keys are kept; a fresh libsignal identity is generated; the
device registers again (the first device of an account freely, further ones by linking); the user
is told encryption was upgraded; and the first contact with each previous peer raises a "safety
number changed" notice. Old builds get an explicit "update required" from the server.

## Push notifications

Operators with their own Apple/Google keys can still use the **direct** mode (`APNS_*`, `FCM_*`
env; silent data-only pushes; no shipped app registers for it). A direct token is checked when
it is registered and again before it is used (Apple: hex only — it becomes part of a URL
path), belongs to the session that registered it, and an account holds at most eight. Everyone else's iOS installs are woken through the **blind push
gateway** (`push-gateway/`, the only thing the app publisher runs):

- The app first registers with the **gateway** (proving by a silent push that the APNs token
  is its own) and gets a *wake credential* for this one skwod; it hands the server only that:
  `{ provider: "gateway", gateway, wake_credential, device_id }` (`POST /api/push/register`).
  The server never sees an APNs or PushKit token, the credential is useless anywhere else, and
  the device can revoke it at the gateway without the server's cooperation. `docs/PUSH.md` is
  the contract. The row is tied to the session: logout, session expiry, account deletion
  (cascade) and device removal delete it. Removing a device removes that device's rows only.
- **Transition (builds ≤ 45).** Older apps hand the server their raw tokens
  (`apns_token`, `voip_token`, `topic`, optional `wake_tag`) and the server wakes with them.
  Both shapes are accepted until the steps in `docs/PUSH.md` "Plan to drop raw tokens" are
  done. While that lasts, three things from the 2026-11 audit stay true for raw rows: the same
  token is known to every skwod the phone is in (they can link the accounts by comparing); a
  raw token already registered to another account on this server is refused with 409, which
  tells the caller that token has an account here; and the first account to register a token
  holds it until its session ends. None of the three applies to a credential.
- The gateway URL is hostile input: https only, default port, a public DNS name (no IP literals,
  no internal suffixes), re-resolved at send time with every answer required to be globally
  routable, the connection pinned to the checked address, redirects never followed. And a
  member cannot pick the host: the server calls only the hosts on its allowlist
  (`SKWOD_PUSH_GATEWAYS=host1,host2`, else the publisher's gateway baked into the build), or,
  with neither, the one host the instance **owner's** app registered first. The rule is applied
  at registration, at startup and again each time a wake is about to be sent.
- A wake is `POST <gateway>/v1/wake {"credential","kind"}` and nothing else: no server
  identity, sender, channel, message id or content, no identifying header. (For a raw row:
  `{"token","kind","topic"}` plus the optional `tag` the device chose.) A failed wake is
  retried once after a jittered pause.
- **Who is woken.** For a channel message: the members who may *read* that channel, minus
  anyone who has blocked the author. For a direct message: the other participants, minus
  blockers. Sealed mail names no sender, so it cannot be filtered that way: any deposit the
  recipient's delivery key admits wakes them (bounded by the mailbox limits and the
  coalescing below). Mutes are not known to the server — a muted conversation still wakes the
  device, which then stays quiet.
- Every message wakes alike. The server is not told which messages deserve a notification (see
  "What a message looks like to the server"); the device decides after decrypting.
- A session that is about to expire takes its push registration with it; that install gets one
  last wake first, so the app can tell its owner it was signed out instead of going silent.
  Those last wakes are sent one by one, each a random 0–4 minutes after the sweep that found
  the expired session, not together. A rotated session token carries the registration over.
- Wakes are scheduled per registration. The first message wake of a burst waits a random
  0–750 ms (a call: 0–150 ms); then comes a quiet period (20 s / 5 s), and whatever arrived
  during it is ONE more wake after a random 1.5–6 s (a call: ≤ 0.4 s). So one registration is
  woken at most about every 21–26 s while a chat is busy — some 23–28 times in ten minutes —
  which is under the gateway's budget for one credential (30 per ten minutes).
- **A device is not woken for an event it is handed in-band and reads.** *Handed*: a socket
  of that install is subscribed to the event's topic — an open socket that is not (a
  conversation it has not subscribed to yet, or a socket that subscribed to nothing) silences
  nothing. *Reads*: an install is woken when it says it left the foreground, and when it does
  not answer the probe that follows an event on its connection within 3 s ± 750 ms
  (`SKWOD_WS_ACK_MS`). A socket that fell behind and had events dropped is woken for them,
  including a call wake if a ring was among them. What the server cannot tell apart: whoever
  holds an install's session token, subscribes and answers the probes *is* that install to
  it, and that install is then not woken.

**What the gateway, Cloudflare and Apple still learn.** Stated plainly:

- *That* a credential (and so a device) was woken and *when* — to within a second for the
  first wake of a burst, ± the jitter after it. Members of one channel are woken within a
  second of each other, so someone who could watch wakes arrive could cluster devices into
  groups. The gateway does not log, and stores only HMACs (keyed by a secret,
  `RATE_KEY_SALT`, which it requires) for rate limiting.
- *Who calls.* Cloudflare's edge sees the calling server's IP address with every wake, next
  to the credential. For a self-hosted skwod that is the host's home address, and the set of
  credentials one address wakes is that skwod's exact list of iOS devices — not their
  accounts, names or tokens, but a stable membership list. The Worker uses the address only for
  a per-caller rate limit (an HMAC of it, kept one minute, not linked to the credential); the
  network operator sees it regardless.
- *How many skwods a phone is in, and which wake came from which.* Each credential is a
  separate budget row, and the push payload carries the registration id (`skwod_cred`) and
  the per-skwod `tag` the device chose. Both are stable for as long as the registration
  lives — the tag survives signing in again — so the gateway and Apple can count a device's
  skwods and tell their activity apart. Neither value says which skwod, who, or what.
- *The device's own address*, at Cloudflare's edge, when it registers or revokes
  (`docs/PUSH.md` "Limits").

## The host admin page

A separate listener (default `127.0.0.1:3477`), not part of the API router — it cannot be reached
over p2p or through a reverse proxy in front of the API. In containers it listens on the LAN
behind a one-time token printed to the container log. It can start/stop hosting, show and mint
invites (friend invites it mints still need the owner's approval in the app), switch local
discovery, and show counts. It cannot read content (nobody can) and shows no member identities.
On a LAN it is plain HTTP: someone sniffing that LAN while you type the token could take over the
page — and with it, before the owner has signed up, the owner invite. Claim the server right away.

### What a message looks like to the server

Every channel message is one opaque envelope, and the server is given **no field that says what
kind it is**: a chat line, a like, a comment, an avatar update and a chess move are stored the
same way, announced the same way (`message`, with no describing field) and wake devices the same
way — one contentless push per message, coalesced and jittered per device, bounded by the
gateway's per-token limits. The same holds for sealed mail: a direct message, a sender key and a
call key are indistinguishable deposits. Which of them deserves a notification, and which belong
in the visible history (game state is kept in a separate cache scope so it cannot crowd chat out),
is decided by the recipient **after decrypting** (`message_notifies`, `message_is_hidden`). A
"silent" flag and a separate server-side lane for game traffic were considered for build 43 and
rejected for exactly this reason.

What the server can still tell about channel traffic, beyond the routing metadata in gap 2:

- **Size and timing** of each envelope. Pairwise and channel messages alike are padded to
  160-byte buckets before encryption (`skwod-crypto/src/padding.rs`, applied in `store.rs` to both
  the sealed-sender and the sender-key path), so a length reveals a bucket, not a message length.
- **That a message has attachments, how many, and their sizes.** A channel send names the blob
  ids it refers to so the server can link them — that link is what lets other members download
  the file, lets access follow channel permissions, and lets the file be deleted with the
  message. Not avoidable without making every channel attachment a bearer capability that
  survives a member's removal. DM attachments do not have this: the uploader registers only the
  hash of a random download token, the token travels inside the encrypted message, and the
  download carries no session — the server sees an upload by an account and, later, an anonymous
  fetch.
- **Edits, deletions and reactions** are separate API calls and visible as such (the emoji is
  sealed; its keyed tag lets the server count equal reactions without learning which emoji).
- **Which device of the author** sealed a message or an edit (`author_device_id`; readers need
  it to pick the sender key).

### Channel messages from build 42 (wire v2) and the downgrade rule

A channel message is `version byte || sender-key ciphertext`. Since build 43 (wire v3) the
plaintext carries the message id, the reply target and the edit flag, so the server cannot move
content between rows or invent a reply or an edit. Build 42 (wire v2) sealed the bare text; almost
all older history is v2 and stays readable. The version byte is **outside** the ciphertext — it
is the server's claim — so nothing is decided by it (`Engine::open_channel_message`):

1. A plaintext that is exactly a v3 body **is** a v3 message, whatever label it was served
   under. Relabelling a v3 message as v2 changes nothing: its sealed id, reply target and edit
   flag are used, and served under another message's id it is dropped (never shown as text).
2. Any other plaintext under a v2 label is a build-42 message. It is shown as plain text and
   the server-supplied `reply_to_id` and `is_edited` are **ignored**: no reply link, no edit
   marker.
3. Per channel and sender device: once that device has been seen writing v3, a build-42 body it
   sealed **later** is refused (no row, no placeholder, no re-ask). "Later" is the sender's own
   statement, not the server's and not a clock: every sender-key message carries, under the
   sender's signature, its distribution id, chain id and a counter that only increases. When
   the first v3 from a device is seen, the distributions it had announced so far are recorded
   (persisted in the engine state, section `0xB5`); a v2 body is accepted only under one of
   those, and only at a counter value below the lowest v3 seen on that chain. Old rows fetched
   after newer v3 ones (scrolling up) really are earlier on that counter, so history stays
   readable in whatever order pages arrive.

What a malicious server can still do with build-42 bodies: serve one that this device has not
opened yet (a sender key opens each message once) in any row — under any message id, position or
date — or withhold it. It cannot change the text, show it twice, attach a reply or an edit marker
to it, create one, or do any of this to a v3 message. Rule 3 is defence in depth on top of rule
1: no honest build writes v2 after v3, so the only bodies it refuses come from a sender that
itself went back to v2. Rows already in the local cache keep what was stored with them.

## What the server stores, and for how long

| Data | Kept until |
|---|---|
| Channel/DM message ciphertext, attachments (ciphertext), reactions | deleted by author/moderator, purged by a moderator, or the space/account is deleted |
| Sealed mailbox envelopes | the device acknowledges them (deleted at once); undelivered: 30 days |
| Sessions (token hash) | logout, or expiry: 30 days after the last use, at most 1 year after sign-in — swept every 5 minutes. A rotated token's predecessor: 5 minutes |
| Attachment uploads never finished, or finished and never referenced (no channel link, no download token) | 24 hours |
| Push registrations / tokens (gateway credentials, raw tokens of builds ≤ 45, direct tokens) | logout, session expiry, removal of that device, account deletion, or the gateway reporting the credential or token dead. Direct tokens: at most 8 per account |
| Presence (`status`, `last_seen_at`) | the last socket closing sets offline at once; a heartbeat older than 3 minutes is cleared by the sweep and the timestamp erased |
| Typing indicators | never stored (relayed in memory) |
| Read states | while the user is in that space; orphaned rows are swept |
| Device-proof replay records | 10 minutes |
| Device-link requests | 10 minutes |
| Used one-time prekeys | next sweep |
| Dead invites (expired/revoked) | 7 days after they died |
| Resolved join requests and abuse reports | 90 days |
| Rate-limit keys (IP or node id) | in memory only, ≤ 1 hour, never logged |
| Membership, roles, channel structure, public keys, usernames | while they exist (the social graph is server-visible — gap 2 below) |

**Logs.** At the default level the server logs lifecycle events and errors only: no IP address,
node id, user id, channel id or message id. (The one line that used to name the channel of every
pushed message was removed.) The p2p stack's own logs, which contain addresses, are suppressed
unless `SKWOD_P2P_DEBUG=1`.

## App updates

Skwods are mostly peer-to-peer and have no web address, so the apps do not update from the Skwod
they are connected to. Releases are published in one public place, the GitHub repository
`FlayrLabs/skwod-releases` (binaries and feeds only), and every install reads the same feed:
`…/releases/latest/download/appcast.xml` on macOS (Sparkle) and `…/manifest.json` on Android. iOS
updates through TestFlight / the App Store.

**What GitHub is trusted for: availability, nothing else.** An update installs only if it carries
the publisher's signature, made on the release machine with keys GitHub never holds:

- macOS: an EdDSA signature over the archive, checked against `SUPublicEDKey` in the app before
  anything is unpacked, plus Developer ID signing and Apple notarization.
- Android: an Ed25519 signature over the build number and SHA-256(apk), checked against the key
  pinned in `Updater.kt`; the system then also insists on the same apk signing certificate and a
  higher version code. Installing always takes the user's tap.

**The feeds are signed too** (from the first release that includes them; older installs still read them
unsigned until they update):

- macOS: the appcast must carry Sparkle's EdDSA feed signature (`SURequireSignedFeed`, with the
  fallback to an unsigned feed switched off), so the version, release notes and links in the
  update window are the publisher's. The feed address is fixed in code and cannot be redirected
  through the app's preferences.
- Android and iOS: `manifest.json` contains a statement signed by the same publisher key —
  build numbers, release notes, the apk's address and digest, and the TestFlight / App Store
  link the iOS banner opens — and the apps read nothing else from the file. An unsigned or
  altered manifest offers no update at all. The iOS link is additionally opened only if it is
  https on `testflight.apple.com` or `apps.apple.com`.

Whoever controls the repository, GitHub's CDN or the network can therefore withhold an update, but
cannot get one installed, cannot put text or links into the update prompt, and cannot point an
iPhone at a look-alike beta. The Android app talks to GitHub over https only, starts every
request at `github.com` under the release repository, and follows redirects only to `github.com`,
`release-assets.githubusercontent.com` and `objects.githubusercontent.com`, checking the scheme,
host and port again on every hop.

**What this does not give you** (details and the plan: `RELEASE-SIGNING.md`):

- *Freshness is bounded, not proven.* An old signed build that is still newer than yours can be
  served again ("you are being held back" looks like "nothing new"). On Android and iOS the
  signed statement expires after 120 days, and a manual check then says it cannot confirm you
  are up to date; Sparkle has no such expiry on the Mac. Android below 13 cannot verify the
  statement at all and is only told that a newer build exists.
- *The signing keys are online.* They are files on the release machine and values in a secret
  store, not a hardware token or an offline signer; whoever steals them can sign an update.
- *Builds are not reproducible.* A release names the commit it was built from inside the signed
  statement, but nobody else can rebuild it and compare.
- *Self-hosted Docker images are not published or signed yet.* Build the image yourself, or pin
  a published one by digest and verify it (`docs/SELF-HOSTING.md`); never run a `:main` tag.

**What an update check reveals.** A check is one anonymous download of a public file. It sends no
account, device identifier, Skwod address or anything about what the app is used for — but, like
any request, it shows GitHub (and whoever watches the network path) **the device's IP address and
that it runs Skwod**, with the app's user agent, which on macOS includes the installed version.
With automatic checks on this happens **once a day** (plus, on Android, when the app is opened
while a newer build is already known). Downloading an update is a second request of the same kind.

**Turning it off.** "Check for updates automatically" (Profile on macOS, Settings on Android) is
on by default; switching it off stops all background contact with GitHub. Nothing is then fetched
until the user chooses "Check for updates". Someone who does not want GitHub to see their address
at all should switch it off and fetch releases over a VPN or Tor; a build that is never updated
does not get security fixes, so this is a trade to make deliberately.

## Non-negotiable invariants

1. No code path sends plaintext content or private key material to the server.
2. Voice/video fails closed.
3. No session without a post-quantum KEM.
4. Notifications never carry plaintext.
5. Search and link previews run on-device.
6. A device is never trusted as "mine" because the server says so.
7. An identity key on record is never replaced by anything a message, a certificate or a bundle
   carries. Only an explicit decision on this device changes it.
8. Nothing is encrypted to a key this device did not pin, and nothing the server alone says
   deletes what this device holds or changes whom it trusts.

## What the server cannot do to local state (build 45)

Each of these was possible in build 44 (the audit's High and Medium findings):

- **Make a non-member speak in a channel.** A sender key is bound, and a row shown, only for an
  author on the roster THIS device keeps for the channel's server — the same roster that decides
  who is handed keys. A ghost account, or a member who was removed, cannot be given a voice.
  One limit: WHICH server's roster applies follows where the channel is placed, and for a channel
  the user has not confirmed (see "Move a channel" below) that placement is the first listing
  the device saw. A host can therefore still present a not-yet-confirmed channel under another
  space the user is in, and that space's accepted members — never an account on no roster —
  would be the ones allowed to speak in it and handed keys for it.
- **Replace a trusted owner or a space key by answering a join.** The first join pins the host it
  names. A later invite-accept response naming someone else for a space that is already pinned is
  refused (`owner_change_refused` notice) and a held space key is never overwritten. Only the
  user's explicit `forget_space` clears a space's trust state.
- **Bring back a removed device.** A removal is enforced when it arrives: the device stops being a
  sibling (or a contact's live device) at once, and its identity is not re-admitted by a re-listed
  row, a replayed link signature, a sibling's old set or a link bundle. Removals are re-sent to
  every sibling until acknowledged. (To a contact they are sent once; a host that drops that
  deposit leaves the contact relying on the directory rules — the device is held as unvouched
  once its row has been seen missing.)
- **Erase channel history.** A channel clear, and the deletion of a message a device already
  holds, count only as sealed messages from someone entitled: the pinned owner of the server, the
  message's author, or one of the user's own devices. The server's `cleared_at` and its tombstone
  rows delete nothing (a tombstone is shown only for a message the device never had), and a
  clear never removes the membership and security rows the core wrote. Cost: a clear, or the
  deletion of someone else's message, made by a moderator who is not the owner takes effect on
  the server and the moderator's devices, not in the other members' caches; and a device that
  never receives the sealed message keeps its copy.
- **Move a channel to get a clear accepted.** Which server a channel belongs to decides whose
  owner may clear it. A clear or deletion names its server inside the ciphertext and is accepted
  only against a placement this device CONFIRMED through something the user did (created the
  channel in that server, joined through an invite to it, opened it from that server's list;
  writing in a channel confirms nothing). What a server listing says is kept in
  memory only, bounded per server, never moves a confirmed channel and authorises nothing — so
  listing a channel under a space the host controls, or flooding listings, gains nothing. Cost:
  a channel the user never touched keeps its cached history when the owner clears it.
- **Invent or re-attribute a reaction.** A reaction is shown only if it opens under the space key
  for that message and that user. Reactions written by build 44 (bound to the message only) are
  no longer shown. The server still sees who reacted to what, and can still hide reactions.
- **Unblock someone.** The server's block list can add to the local one (a block made on another
  device) and can never shrink it. Cost: an unblock made on one device does not reach the others
  — each shows the person as still blocked and can unblock them itself. The server can also still
  *add* an entry, which silences that contact on this device; the entry is visible in the list.
- **File a message in someone else's conversation.** A direct conversation is bound to the people
  it was first used with; the participant list is not asked again.
- **Present a group message as a 1:1 message, or the reverse.** Whether a direct-message payload
  belongs to a group, and who is in that group, is sealed by the sender inside the ciphertext.
- **Choose an unsafe instance id.** The id a server reports for itself is used only when it is
  1–64 characters of `[A-Za-z0-9-]`; anything else is replaced by a hash of it.

## Remaining gaps versus Signal

Stated plainly; none of these is hidden by the design above.

1. **Channel messages are not sealed-sender.** They are posted with the author's account and
   device id so the server can enforce permissions, edits, deletes, bans and moderation. The server
   therefore knows who posted in which channel and when (never what). Signal's groups hide this.
2. **The server knows the social graph.** Server membership, channel structure, DM conversation
   records, reactions (by user), read states and presence are server-visible by design here.
   Signal's server knows almost none of this (private groups, sealed sender, no contact graph).
3. **IP addresses.** Sealed deposits hide the account, not the network address; a server can
   correlate a deposit with an authenticated request from the same IP. Signal has the same
   limitation without a proxy; Skwod does not yet route deposits over Tor.
4. **No enclave-backed anything.** No SVR (hence passphrase-only backup), no private contact
   discovery (not needed: there is no phone-number discovery), no key transparency log that
   clients audit — a malicious server can serve a wrong identity key for a *new* contact or a
   contact's *new* device, and the defence is the safety number and the "new device" notice.
5. **Per-device identities.** Signal has one identity key per account shared by linked devices;
   Skwod has one per device, so a safety number verifies a device pair and a contact adding a
   device shows as "new device" rather than being covered by an existing verification. Contacts
   DO verify link signatures (`skwod-sync/src/engine/trust.rs`): a new device of a known contact
   is accepted only when a device they already trust **and that the same directory listing
   still names** signed it. A device that is absent from the listing is treated exactly like a
   removed one, in the very listing where it first goes missing: otherwise a host working with
   whoever holds a discarded device's key could drop the old row and list a new device "linked
   by" it in one answer. Such a device is held and flagged (`unverified_contact_device`). The
   cost: a contact who first looks after an honest "link the new phone, remove the old one" sees
   the new phone as unvouched until another live device links it or the contact is verified
   again. First sight of a contact is still trust-on-first-use. This is never silent: a send
   that would reach no device of the recipient fails with a reason (`IdentityChanged`), for
   contacts the user never verified too — the engine has no pairwise send that returns
   success having reached nobody. (Carrying the vanished device's signature forward was
   considered and not done: the signature is genuine in both the honest and the stolen-key
   case and carries no time, so a contact who had not yet seen the removal cannot tell them
   apart; blocking with a visible reason asks the user instead of guessing.)
6. **No history sync to a newly linked device**, no disappearing messages, no message
   retry/resend receipts (a failed session is reset, the lost message is not re-requested).
7. **Sealed Sender v1 only** (one envelope per recipient device). Fine at this group size; it
   means delivery cost grows with devices.
8. **Decrypted attachments are cached as files** while they are being viewed, not re-encrypted at
   rest like Signal's attachment store. On Apple platforms the copies live in a backup-excluded
   cache folder, under `NSFileProtectionComplete` on iOS (owner-only permissions on macOS, where
   at-rest protection is FileVault's), are removed at every launch, on sign-out, and after a day.
9. **macOS data-protection keychain needs a properly signed build.** The Mac app keeps its secrets
   in the data-protection keychain (`kSecUseDataProtectionKeychain`) when the build carries the
   `keychain-access-groups` entitlement; a locally built, unsigned copy cannot, falls back to the
   login keychain, and says so under Profile → Encryption (docs/APPLE.md).
10. **Voice key rotation is polled** (2 s): a participant who leaves can decrypt for up to that
    long afterwards, and the SFU (LiveKit) sees who is in a call and when.
11. **Not audited as integrated**, and no reproducible builds.
12. **The last-resort key's replay memory is bounded per sender.** One sender may start at most
    64 sessions on one last-resort key pair; past that it is refused on its own (its one-time-key
    sessions still work) and nobody else is affected. When many senders have used a pair the
    device rotates it early, at most once an hour.
13. **Channel sender-key distribution ids are bound first come, first served.** A member who gets
    another member's distribution id onto a device first (with the host delaying the real one)
    keeps that member's key from binding until they rotate. It costs readability, not
    confidentiality.
14. **One-time prekeys can be drained by a contact.** Anyone allowed to contact a device may
    fetch 60 bundles an hour for it, so an offline device's 100 one-time keys can be used up in
    two hours. Sessions started after that use the signed prekey and the last-resort Kyber key
    — still PQXDH, without the one-time-key contribution. This is the same class of weakness
    Signal has, and since build 45 only accounts that share a server with the device's owner
    (never an account in the waiting room) can do it.

## Who may reach whom (build 45)

- **The waiting room.** An account that no server has admitted — it signed up with an invite
  and the host has not approved it, or it was removed from everywhere — reaches only its own
  account and devices, its own mailbox, invite redemption and the instance's public identity
  (`server/src/admission.rs`, deny by default). No lookup, no conversations, no key directory,
  no sender certificate, no push registration, no storage.
- **Invites are used up by signups.** One account per use; and at most
  `SKWOD_INVITE_PENDING_SIGNUPS` (10) accounts created with one invite may be unadmitted at once.
- **Lookup, conversations and keys need a relationship**: a shared server, or a conversation in
  which both sides have written. A conversation row alone proves nothing. The one exception is
  whoever decides on a pending join request, who may look up and fetch the keys of the
  requester — not the reverse. Consequence: two people who no longer share any server can no
  longer start new sessions with each other on that host.
- **What the apps do with a stranger's direct message** (reviewed, not changed in build 45): a
  group conversation from non-contacts is held as an invitation; a 1:1 message from any account
  the host delivers is listed (name marked unverified) and notified. On an honest host the
  rules above mean such a message can only come from someone who shares a server with you.

## Second audit pass (build 45): what changed, and what needs the apps

Findings are named as in the per-area audit reports (server, p2p transport, release).

**A superseded install gets nothing (server H-1).** A session is bound to a device at a
generation; a restore raises the generation, a removal deletes the device. A session bound to
an older generation, or to a device that is gone, is refused on **every** authenticated route
(`409 device superseded` / `403 device removed`), on the WebSocket (at the upgrade, at every
re-check, and at once when the account's devices change), for blob downloads, voice and p2p
standing. It reaches only what explains or repairs: `GET /api/auth/me`, its own device list,
`bind`, `rekey` (which is then a recovery request), the link-request routes and `register`
(`server/src/auth.rs`, `stopped_install_allows`, deny by default). On a re-key the old
install's push registrations are deleted, and `device_rekeyed` (with the new `generation`,
which the device directory now lists) goes to the account's devices, the members of its
servers and its DM partners.

- *The peers' side (core, build 45):* a device whose `generation` in the directory rose —
  a contact's or one of the account's own — has what it held of ours rotated: the mailbox
  delivery key, and the sender key of every channel and call it was a holder of (the next send
  distributes a new one). The apps re-read a contact's devices on `device_rekeyed`. Until a
  peer has looked, the old install holds keys it can no longer fetch ciphertext for from an
  honest host; a dishonest host is not stopped by this from serving it old ciphertext.
- *On by default:* a session bound to **no** device is refused once the account has one (a
  password alone then reaches only link / restore / bind). Build-45 apps bind before their
  first request (`bind_session`). `SKWOD_REQUIRE_BOUND_SESSIONS=0` is the operator's way out
  while members are on older builds: update the host first, then everyone, then remove it.

**The approval gate (server H-2).** A denial is final for that invite (asking again answers
409 and notifies nobody). Join requests and approvals count against `max_uses` and the
waiting-room cap. The instance owner can delete an account with `?ban=1`: the username and the
identity keys of its devices are banned on the instance and the invite it signed up with is
revoked — the only identifiers a server that stores no addresses has. A determined person
comes back with a new name, new keys and a new invite; that needs the host to hand out one.
The waiting room no longer sees `/api/instance/p2p` (the LAN-discovery key) and hears no DM
topic on the socket.

**Destructive actions need a current device (server M-3).** Clearing a channel, purging or
clearing a space, deleting a space and setting the voice (SFU) configuration are refused to a
session that is not a current install of one of the account's devices. When the request carries
a device proof it must hold: ops `clear-channel` (target: channel id), `purge-messages`
(server id; payload `older_than_ms` as 8 big-endian bytes), `clear-server`, `delete-server`
(server id) and `voice-config` (payload: `op_payload[url, key, secret]`).
The proof is mandatory by default: the build-45 core signs all five (`clear_channel_messages`,
`clear_server_messages`, `purge_server_messages`, `delete_space`, `set_voice_config`).
`SKWOD_REQUIRE_DEVICE_PROOFS=0` accepts an unsigned request from a current install again.

**Key backup download (server M-4) — mitigated, not closed.** The proof of the recovery key
cannot be demanded before the download: the key that makes the proof is sealed inside the blob
(`skwod-crypto/src/backup.rs`). So the blob can still be fetched by a session that only knows
the password, once the recovery key has seasoned. What changed: a superseded install cannot
fetch it at all; a fetch by a session that is not a current device is limited to 24 a day and
is announced to every device of the account (`backup_fetched`, with a push wake; the apps
show it as a notice and keep it in the security activity — a device that is offline then
does not learn of it later, the event is not stored). What protects the blob offline is the recovery key itself: a
generated 160-bit key, or a passphrase of at least 14 characters under Argon2id.

**Registration PIN (server M-5).** An attempt is taken with one conditional UPDATE before the
PIN is verified, so parallel guesses cannot outrun the five-attempt counter.

**Resource bounds (server M-1, M-2).** Auth bodies are capped at 16 KiB; a username is
validated before it becomes a rate-limit key; limiter keys are bounded and expired windows are
swept every minute. An upload chunk is refused from its headers before its body is read. A DM
attachment needs a live message, participation and no block. Backup history keeps the newest
8 contents per recovery key and at most 24 MiB per account (over that an upload is refused,
never evicting an older key's blobs). An unauthenticated sealed deposit stops looking up after
16 misses.

**Sign-in lockout (p2p P6).** The per-account window (10 a minute) counts failed attempts
only, so the owner's own sign-ins never use it up. *Accepted residual:* ten wrong passwords a
minute against a name still hold that name's NEW sign-ins off for that minute — the brake that
protects the password; existing sessions are unaffected. The proof-of-work difficulty rises
one bit per doubling of the spent-stamp record beyond 1/64 full (20 → 26 bits); the host says
how much in `x-skwod-pow-bits`. A build that cannot do more than 20 bits cannot sign in over
p2p while a flood lasts.

**p2p admission (P1–P3).** See [P2P.md](P2P.md#abuse-limits-without-ips).

**A host cannot reach outside its skwod through the loopback proxy (P5).** The proxy drops
`Set-Cookie` and `Cookie` and keeps a `Location` only when it is a path on the same skwod.
*The apps* should still use a cookie-less, non-redirecting HTTP session.

**The host's data directory (server M-7)** is 0700, the database 0600, and the process runs
with umask 077; an existing directory is tightened at every start.

**Host-backup restore (server M-6).** See SELF-HOSTING.md, "Backing up, restoring and moving".

