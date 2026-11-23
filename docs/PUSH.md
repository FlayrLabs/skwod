# Push notifications — the blind gateway (iOS)

The publisher runs no chat infrastructure, and a self-hosted Skwod has no Apple push credentials.
iOS wake-ups therefore go through a **gateway that is told as little as possible**. This document
is the contract between the three parties (app, Skwod server, gateway) and what the Apple app does
with it. Client code: `apps/apple/Sources/PushManager.swift`,
`apps/apple/NotificationService/NotificationService.swift`.

## Contract

A wake is authorized by a **credential the device registered**, not by the device's push token.
The skwod never holds the token; the gateway never learns which skwod holds the credential.
Gateway side: `push-gateway/` (its README has every field rule and status code).

| Step | Who → whom | What |
|---|---|---|
| 0 | app → gateway → APNs → app | `POST <gateway>/v1/challenge` `{ "apns_token": "<hex>", "topic": "<bundle id>" }` → `202`; the gateway sends a **background push** (silent) to that token with `"skwod_challenge": "c1.…"` in the payload. `410`: Apple does not know the token (remembered for 10 minutes) |
| 1 | app → gateway | `POST <gateway>/v1/register` `{ "apns_token": "<hex>", "voip_token": "<hex or null>", "topic": "<bundle id>", "challenge": "c1.…" (or "revoke": "r1.…" when renewing), "tag": "<optional>" }` → `{ "ok": true, "credential": "w1.…", "revoke": "r1.…", "id": "<registration id>", "expires_at": <unix s> }` |
| 2 | app → its Skwod (authenticated) | `POST /api/push/register` `{ "provider": "gateway", "gateway": "<url>", "wake_credential": "w1.…", "device_id": "<the install's device id, 1–64 chars; optional>" }` |
| 3 | Skwod → gateway | `POST <gateway>/v1/wake` `{ "credential": "w1.…", "kind": "message" \| "call" }` — and nothing else |
| 4a | gateway → APNs (`kind: "message"`) | alert push, generic text **"New message"**, default sound, `mutable-content: 1`, plus `"skwod_cred"` and (if the device registered one) `"tag"` |
| 4b | gateway → APNs (`kind: "call"`) | PushKit VoIP push: `{"aps":{},"kind":"call"}` plus `"skwod_cred"` and `"tag"` — no caller, no room |
| 5 | app → gateway | `POST <gateway>/v1/revoke` `{ "revoke": "r1.…" }` on sign-out and on leaving the Skwod |
| 6 | app → gateway | `POST <gateway>/v1/revoke-all` `{ "apns_token", "topic", "challenge" or "revoke" }` on erase and for "cut off every Skwod": every credential minted under that APNs token so far is dead (alerts and rings); credentials minted under another APNs token are untouched |

The gateway never learns which Skwod is calling, who sent what, or any content. The Skwod never
talks to Apple and never sees an APNs or PushKit token. Apple sees a generic alert.

- **Registration is proven by push.** The challenge reaches only the device that owns the APNs
  token, is bound to that token, lasts 10 minutes and works once. Someone who merely *knows* a
  token — a Skwod that was handed it by an older build, a copy of its database — cannot
  register it. The app needs the `remote-notification` background mode and reads
  `skwod_challenge` in `application(_:didReceiveRemoteNotification:fetchCompletionHandler:)`;
  it asks for a challenge while it is in the foreground (iOS throttles background pushes to
  apps in the background and does not deliver them to a force-quit app). Limits: 3 challenges
  per 10 minutes and 10 per day per token.
- **One outstanding challenge; keep what arrives.** While a pushed challenge is unused, more
  requests for that token answer `202` and send nothing. Anyone who knows a token can request
  one, so the app must **keep the latest `skwod_challenge` it receives, whether it asked or
  not**, and use it: then a flood of requests by someone else cannot stop it registering.
- **Renewal and revoke-all without a challenge.** A device that holds a credential proves
  itself with that credential's `revoke` token instead (`"revoke"` in place of `"challenge"`).
  The wake credential is never proof — the Skwod has it.
- **The VoIP token is not proven and not owned.** A VoIP push rings, so it cannot carry a
  challenge. A credential is the pair (proven APNs token, VoIP token as given); the gateway
  refuses nobody for the VoIP token they name, so nobody can lock a phone out of its own, and
  revoking only ever reaches credentials minted under the revoker's own APNs token. Two things
  bound a credential that names someone else's VoIP token: its rings count against its OWN
  proven device's share (below), never the owner's, and `skwod_cred`.
- **`skwod_cred`: the app checks every ring.** `/v1/register` returns `id`; every push sent
  for that credential carries it as `"skwod_cred"` (VoIP payload and alert payload, next to
  `tag`). The app keeps the ids it registered — per Skwod, with the credential — and **ends a
  VoIP call with an unknown `skwod_cred` immediately** (report to CallKit, end). Raw legacy
  wakes carry none. From build 45 the app rings ONLY for a `skwod_cred` it registered: a ring
  without one is ended, and an alert without one stays the generic banner and dials no host
  (`WakeOrigin`, audit M1) — whatever `LEGACY_RAW_WAKES` says. When the APNs
  token changes, the app calls `/v1/revoke-all` for the old one with an old `revoke` token and
  registers again; it forgets the old ids.
- **One registration per Skwod and install.** The app registers with the gateway separately for
  every Skwod it is signed in to and keeps `(credential, revoke, expires_at)` per Skwod on the
  device. Two credentials for the same phone are unrelated strings to the Skwods that hold
  them, and each has its **own rate budget** at the gateway: one Skwod flooding (or someone who
  copied its database) cannot use up another Skwod's wakes. Every wake also counts against a
  **per-device ceiling**, shared by all credentials of the same *proven* device and nobody
  else: four times one credential's message budget for alerts (keyed by the proven APNs
  token), and for rings **6 a minute and 20 an hour per (proven APNs token, VoIP token)
  pair**. Nothing is keyed on a VoIP token alone, so a stranger's credentials naming a phone's
  VoIP token cannot spend that phone's ring budget. More credentials never mean more rings.
  (The raw path has its own per-token rows, apart from every pair.)
- **At most 16 credentials are live per APNs token.** Registering a 17th evicts the oldest
  (its wakes answer `410`). Only the device can register, so eviction cannot be used against
  it, and a phone that lost its stored credentials can always get back in.
- **The credential is opaque.** It is the tokens, topic, tag and expiry sealed (AES-256-GCM)
  under a key only the gateway has. A Skwod stores it as given and can do exactly one thing
  with it: ask the gateway for a contentless wake.
- **`revoke` never leaves the device** except to the gateway. A credential holder cannot derive
  it. After a revoke the credential answers `410 gone` forever, and the Skwod deletes the
  registration. Revoking is what makes "leave" and "sign out" final for a server that keeps
  its rows: its credential is dead, and it never had the token.
- **Rotation is re-registration.** A credential lasts 30 days (`expires_at`). The app registers
  again — new credential to the Skwod, old one revoked — when a token changes, when the VoIP
  token arrives after the APNs token, and silently when under a third of the lifetime
  remains. The gateway allows 24 registrations per APNs token per day. Renewal never extends
  anything: it is a new credential (new `id`, new `expires_at`); the old one ends at its own
  expiry or when revoked.
- **Calls without a VoIP token.** The Skwod cannot see what is sealed in a credential, so it
  sends `kind: "call"` when it means a call. If the registration has no VoIP token, the
  gateway delivers it as a message wake (the generic alert, counted as a message) and answers
  `202`.
- **What `410` means to the Skwod.** On a *message* wake: the registration is over — revoked,
  evicted, expired, cut off, or the APNs token is dead — and the Skwod deletes its row. On a
  *call* wake it may be only the VoIP token that died, so the Skwod changes nothing.
- **`tag`** (16–32 chars of `[A-Za-z0-9_-]`) is a random value the device makes up per Skwod.
  It is sealed into the credential at registration and comes back in the push payload, so a
  phone in several Skwods knows which one woke it. The Skwod never sees it and cannot change it.
- **`device_id` ties the registration to a device.** Removing a device from the account
  (`keydir.rs`) deletes the registrations that name it and those of the sessions bound to it —
  and no others. (Before this, a registration without `device_id` was deleted whenever *any*
  device of the account was removed, which silenced the account's other phones until they
  were next opened.) A session that is bound to a device registers as that device whatever the
  body says; the field matters for a session that is not bound yet. The raw shape below may
  carry `device_id` too.
- **Which host the Skwod will call.** Not any host a member names: the hosts on the server's
  allowlist (`SKWOD_PUSH_GATEWAYS`, else the one baked into the server build with
  `SKWOD_DEFAULT_PUSH_GATEWAY`), or with neither the host the instance owner's app registered
  first. Anything else is refused at step 2 with `400`.
- **Gateway URL.** Build setting `SKWOD_PUSH_GATEWAY` (`apps/apple/project.yml`), surfaced as
  `SkwodPushGateway` in Info.plist. Default **empty = remote push disabled** (a release sets it on the `xcodebuild` command line,
  `SKWOD_PUSH_GATEWAY=https://…`; `apps/apple/upload-ios.sh` does): no remote-notification
  permission prompt, no token, no registration. Only an `https://` URL is accepted.
- **Step 2** goes to the *active* Skwod over the same channel as everything else (through the
  loopback p2p proxy for a p2p host), once per Skwod + credential, and again when another Skwod
  becomes active. Step 1 and step 5 go **straight to the gateway** — see "Limits" below for
  what that exposes.
- **`topic`** is the app's bundle id (`com.skwod.app`). For the VoIP push the APNs topic is
  `<topic>.voip` — appending that suffix is the gateway's job.

### Transition: raw tokens (build 44)

Build-44 apps sent their raw tokens to the Skwod, and build-44 servers wake with them:

| | Legacy shape |
|---|---|
| app → Skwod | `POST /api/push/register` `{ "provider": "gateway", "gateway": "<url>", "apns_token": "<hex>", "voip_token": "<hex or null>", "topic": "<bundle id>", "wake_tag": "<optional>" }` |
| Skwod → gateway | `POST <gateway>/v1/wake` `{ "token": "<hex>", "kind": …, "topic": "<bundle id>", "tag": "<optional>" }` |

Both sides stay supported for now:

- The gateway accepts the raw wake shape while its `LEGACY_RAW_WAKES` var is not `"0"`. Raw
  wakes are budgeted per token in rows **no credential shares**, so a raw-token holder can no
  longer starve anyone — but can still deliver generic alerts and ring at the raw budget's rate.
- A new server accepts both registration shapes and wakes each row the way it was registered.
- A build-45 app registers with the gateway first and sends only the credential. **It never
  falls back to raw tokens** (`allowLegacyRawPushRegistration = false`, audit M1): a Skwod
  that answers 4xx to the credential shape gets no push registration at all (the app asks it
  to drop any raw row it holds and tells the user that host needs updating), and a gateway
  without `/v1/challenge` means no push until it is updated. A raw token cannot be revoked,
  and a malicious host could refuse credentials on purpose to get one and ring after it was
  left.
- A build-45 app never rings for, nor dials a host because of, a wake without a `skwod_cred`
  it registered — so a raw token a host kept from a build-44 app is useless against it.

**Raw wakes stay on at the gateway for build-44 phones.** While `LEGACY_RAW_WAKES` is on, a
raw token still reaches the phone (within the raw budget and the device ceiling). For a
build-44 phone that is the old behaviour. For a build-45 phone it is at most a generic banner
or a call that is reported and ended at once — never a ring and never a dial.

**Order of rollout:** gateway (with `WAKE_CRED_SECRET` set) → servers → apps. Nothing breaks in
any other order; credentials simply are not used until all three are in place.

**Plan to drop raw tokens.** (1) Done in build 45: the app has no raw fallback and does not
ring for raw wakes. (2) Servers stop accepting the raw registration shape and delete their raw
rows. (3) **Turn off once no build-44 clients remain:** set `LEGACY_RAW_WAKES = "0"` in
`push-gateway/wrangler.toml` and deploy — raw wakes then answer `410`, which makes any
remaining server drop the row. Until (3) a build-44 phone can still be rung through a raw token
a host kept; only after it is a token that leaked during the legacy era useless for waking.

### Who is woken, and when not

Server side (`server/src/push.rs`, `gateway.rs`, `ws.rs`):

- **Recipients.** A channel message wakes the members who may *read* that channel, a direct
  message the other participants; in both cases nobody who has **blocked the author**. Sealed
  mail carries no sender the server can see, so it wakes its recipient regardless. Mutes live
  on the device only: a muted conversation still wakes the phone, and the app keeps quiet.
- **Coalescing.** Per registration: the first wake of a burst after a random 0–750 ms (call:
  0–150 ms), then a 20 s quiet period (call: 5 s), then at most one trailing wake after a
  random 1.5–6 s. One busy Skwod therefore wakes a phone at most ~23–28 times in ten minutes,
  inside one credential's budget of 30.
- **Not woken when handed the event in-band.** A wake is skipped only if a socket of that
  install is subscribed to the event's topic *and* counts as reading (it has not said
  `push: background`, and answered the last probe). An open socket that is not subscribed to
  that conversation — or to nothing — does not suppress the wake. If the socket is handed the
  event and does not answer the probe within 3 s ± 750 ms, the wake goes out then; if events
  were dropped for a slow socket, it is woken for them (with a call wake when a ring was
  among them and is still live).
- **Signed out by expiry.** The registration goes with the session; the install gets one
  last message wake, a random 0–4 minutes after the sweep that found it (never all expired
  sessions at once).

### Limits and what is next

Stated plainly, because they are the difference between this and the full design:

1. **The VoIP token is not proven: a stale server can flash the phone.** A Skwod that stored a
   phone's VoIP token (build ≤ 45) and has a device of its own can mint credentials that name
   it, or use the raw path while that is on. It cannot stop the phone registering, cannot
   revoke or cut off anything of the phone's, and **cannot use up the phone's call budget**:
   its rings are counted under its own (proven APNs token, VoIP token) pair. What it can do is
   make the phone's CallKit flash: each stranger needs a real proven device, each such device
   gets **6 rings a minute and 20 an hour**, and the app ends at once any VoIP push whose
   `skwod_cred` it did not register. So the residual, once raw wakes are off
   (`LEGACY_RAW_WAKES=0`), is: *a stale server can flash-and-end at most 20 times an hour per
   proven device it controls* (`RL_DEST_CALL_PER_HOUR`). There is deliberately no cap across
   devices keyed on the VoIP token — that would be the owner's budget for a stranger to drain.
   While raw wakes are on, a raw-token holder can additionally ring at the raw budget's rate
   (6 a minute, 20 an hour per token; no `skwod_cred`, which the app cannot tell from a
   build-44/45 Skwod's real call). It ends when PushKit issues a new VoIP token. **Next:** a
   proof for VoIP tokens; there is no push to a VoIP token that does not ring, so it needs an
   app-side handshake, which is not built.
   A raw-token holder can also request challenges (one silent push per ten minutes reaches the
   phone, up to 10 a day). A phone that keeps the delivered challenge, or already holds a
   credential, is unaffected; a first-time registration that missed it waits for the window.
   Each caller is also limited by source address, in the Worker (10 device-route requests a
   minute; `push-gateway/README.md` "Per-source limit").
2. **The device contacts the gateway directly** for register and revoke, so the gateway's edge
   (Cloudflare, and the publisher as account owner) sees the device's IP address next to its
   push token at those moments. The Worker uses the address only for its per-caller rate limit
   (an HMAC of it, kept one minute, never stored beside a token); the network operator sees
   the connection. The gateway can also count how many registrations a token made in a day
   — an upper bound on how many Skwods the phone joined or re-registered with — and can tell
   that two wakes used the same credential. It still learns nothing about which Skwod, who, or
   what. **Next:** seal the registration to a gateway public key and relay it through the
   Skwod (which then sees only ciphertext, and the gateway only the Skwod's address), with
   revocation relayed through a *different* Skwod or sent directly.
3. **A malicious Skwod could force the raw-token fallback** (build 44) by answering 4xx to the
   credential shape. Closed in build 45: there is no fallback (that Skwod gets no
   registration), and a wake without a registered `skwod_cred` is never rung. A host that
   already holds a build-44 phone's raw tokens keeps them until `LEGACY_RAW_WAKES = "0"`.
4. **Revocation needs the gateway to be reachable.** A revoke that fails (offline at sign-out)
   must be retried by the app; until it lands, the credential works. A credential also dies on
   its own at `expires_at`.
5. **A revoked credential stops wakes, not knowledge.** The Skwod still knows the account
   existed and when it was woken. That was always so.
6. **Stable pseudonyms in the push.** `skwod_cred` (per registration) and `tag` (per Skwod,
   chosen by the device and kept when the user signs in again) travel in the push payload, and
   each credential has its own budget row. The gateway and Apple can therefore count how many
   Skwods a device is registered with and tell their wakes apart — not which Skwods, who, or
   what. Rotating the tag on every registration would shorten that to a credential's lifetime
   (30 days); the apps do not do it yet.
7. **The gateway's edge sees which server wakes which credentials.** Every wake arrives from
   the Skwod's IP address. For a self-hosted Skwod that is the host's home address, and the
   credentials it wakes are that Skwod's exact set of iOS devices. The Worker uses the address only
   for its per-caller rate limit (an HMAC, kept one minute, not linked to the credential) and
   logs nothing; Cloudflare, and the publisher as account owner, could see more.
   **Next:** nothing planned; an onion-routed or batched wake would be a different design.
8. **Strangers can still make the gateway ask Apple about made-up tokens** on the two routes
   that accept a bare token: `/v1/challenge`, and the raw wake shape until
   `LEGACY_RAW_WAKES=0`. A repeated token costs nothing (10-minute dead mark); distinct ones
   are bounded per source address by the Worker (120 wakes and 10 device-route requests a
   minute, checked before the body is read) — so by how many addresses the stranger has. The
   publisher's gateway stays on `workers.dev`, because that address is baked into builds
   44/45; a Cloudflare edge rule on top needs a custom domain, and moving is a staged change
   (`push-gateway/README.md` "Moving off workers.dev").
   All requests still pass through one limiter object. A wake by credential is not exposed
   this way: a credential the gateway did not seal is refused before the limiter or Apple.
9. **Raw rows keep the old weaknesses** (the first table under "Transition"): the same token
   at every Skwod, `409` on `/api/push/register` revealing that a raw token already has an
   account on that server, and first-holder-keeps-it. They end with the raw shape.
10. **A session token is the install.** Whoever holds an install's session token can open a
   socket, subscribe and answer probes; the server then treats the install as reading and
   does not wake it. (They can also read everything that session can.) An idle or
   unsubscribed socket no longer has that effect.

## `message`: generic alert, rewritten on-device when possible

The Notification Service Extension (`SkwodNotificationService`) receives the generic alert and
tries to replace its text locally: connect to the user's Skwod(s) (dialing a p2p host by its key),
sync the sealed mailbox, decrypt, and show "‹name›: ‹message›". Nothing decrypted leaves the
device. It is strictly best effort; in every one of these cases the generic "New message" is
what the user sees:

- the build has no App Group / shared keychain group (simulator builds with signing off);
- the device has not been unlocked since it was started — the cache and its key are readable
  after first unlock (docs/SECURITY.md "Key storage"), so a restarted phone shows "New message"
  until then; a phone that is merely locked gets the sender and the text;
- the app is running and holds the cache (it notifies by itself over its live connection, and a
  remote alert that arrives while the app is in front is suppressed);
- the host is unreachable, or the extension runs out of time or memory (the system then delivers
  the original content);
- the user turned previews off (`NotificationState.showPreviews`).

Rules the extension follows: it never registers a device or creates keys (`attach_cache` must
report an existing identity, and it syncs with `process_notification_inbox`, which puts the core
in a mode where nothing is registered and no key is created, rotated or uploaded — no prekey
refill, no signed-prekey or delivery-key rotation, no new sender key; a member's request to be
provisioned is kept for the app; enforced in the engine where keys are made,
`Engine::set_passive`); it only *tries* the cross-process cache lock and gives up if the app
has it; it bumps a generation counter when it has written to the cache so the app re-opens it on
return.

### What a wake may make the device do (`WakeRule`, `WakeRules.swift`)

Decided before anything is dialed, opened or decrypted, from the wake's `tag` and the mutes:

- **Whose wake.** A tag one signed-in Skwod chose: that Skwod alone is contacted. A tag nobody
  here chose, or no tag once every Skwod has registered one: it is nobody's — **no host is
  contacted** (someone who only holds the push token cannot make the phone dial every Skwod),
  and the generic "New message" stays, with its sound. No tag at all is followed up only for
  Skwods that never registered one (an install upgraded from a build before tags).
- **A missed notification is worse than an extra one.** A wake is the passive "New activity"
  line (no banner, no sound) only when **every** Skwod it could be from is muted as a whole.
  One muted candidate among several does not silence the others (it is simply not looked
  at); a mute that cannot be read is not a mute. A muted *conversation* silences only itself,
  once a decrypted message is known to be in it: where the extension may not decrypt (previews
  off, app lock on) that Skwod's banners stay generic **and audible**.
- **Before the first unlock** after a restart the Keychain is unreadable — not the mutes, not
  even which Skwods there are. One thing is kept readable for that case: a single time, until
  when *every* signed-in Skwod is muted as a whole (a file with no file protection; it names
  no Skwod and no conversation). Only while it runs is a wake passive; otherwise it is the
  generic banner with its sound.
- **A wake that finds no message** ends in the passive line only when every Skwod that was
  asked answered and had nothing that needs the user. If one could not be reached, ran out
  of time or had its dial budget spent, the generic banner stays, and sounds.
- Every audible banner is subject to the burst limit (one sound per conversation — or per
  Skwod for a generic banner — per 5 s).
- **Dial budget** (`WakeBudget`): wakes make the extension connect to one Skwod's host at most
  60 times an hour. Past that the wake is not followed up and the generic banner stays, with
  its sound — so in a very busy hour (or with a host that sends wakes while posting nothing,
  to learn when and where the phone is reachable) banners go generic. "Relay only" for extension connections is
  not offered yet (it needs the transport's support).
- **Time** (`BoundedCall`): 12 s per Skwod and 22 s in all, at most 3 Skwods. A call into the
  core is not interruptible, so a Skwod that has not answered in its time is *left*: it records
  and claims nothing from then on, and the cache lock is kept until it has really ended.
- **What is announced.** New rows are told by id, never by the server's date. One banner per
  conversation with something new: the newest becomes the push itself, up to 8 more are
  posted beside it, and an id is claimed in the announced ledger only for a banner that is
  made (anything beyond is found again by the next wake). Rows that could not be shown
  (undecryptable, a sender nobody vouched for) are remembered in a list of their own, so
  flooding a conversation with garbage cannot push real ids out of the ledger.
- **What the extension is given.** Conversation titles and the per-conversation sender sets
  are Keychain items under the cache key's class (not the app-group plist), and are not kept
  at all while app lock is on or previews are off. The app-group defaults hold settings,
  message ids (announced / seen / unsure) and timestamps.

The VoIP path (`call`) is not decided by `WakeRule`: PushKit obliges the app to report every
call push. It ends a push whose `skwod_cred` it did not register, and one for a muted Skwod.

## `call`: PushKit → CallKit, immediately

Every VoIP push is reported to CallKit inside the PushKit callback, before anything else (Apple
terminates apps that don't). Because the push names no caller and no room, the system call screen says "Skwod call";
the app re-establishes its connection while the phone rings. An unanswered call is ended after
45 s. Calls are kept out of the system Recents list (`includesCallsInRecents = false`), which would
otherwise sync to iCloud.

While the app is **running**, the ring arrives on the live connection instead — a `ring` event on
the user's own topic with `server_id`, `channel_id` and `from` — and is reported to CallKit the
same way, with "‹caller› · ‹server›" as the name (built on the device). If both arrive for one
call, the second is folded into the first: a `ring` event fills in the name of a push-announced
call, and a push for a call already on screen is reported against the same call.

**Which room.** Answering a call that a `ring` event described joins that event's server. A call
known only from the push has no room (the wake never carries one): after answering, the app waits
for its connection, gives a `ring` event four seconds to arrive, and otherwise opens the voice
room of the server in view.

**The server keeps the ring for late devices.** A ring stays active for 45 s per voice channel
(in memory only). A device that connects in that time — woken by the push — gets it two ways:

- when its socket subscribes to its own `user:<id>` topic, the server replays the `ring` event
  right after `subscribed`;
- `GET /api/rings` returns `{ "rings": [ … ] }` — the same payloads — for a client that wants the
  room before its WebSocket is up.

Payload: `{ channel_id, server_id, from, ring_id, expires_at, replay }` (`replay: true` on a
replayed one; `ring_id` is the same for the live event and its replays, so a client that saw both
can fold them). The replay is re-authorized when it is delivered: a member who lost voice access
or was blocked by the caller since gets nothing. A ring ends early when the callee joins (asks
for the room's voice token — their other devices get `ring_cancel`, reason `answered`) or the
caller gives up (`DELETE /api/channels/{id}/ring` → `ring_cancel`, reason `cancelled`). The wake
itself stays empty. Server side: `server/src/voice.rs` (`Rings`), tests
`a_late_socket_gets_the_active_ring_on_subscribe` and
`a_ring_is_kept_for_late_devices_until_answered_cancelled_or_expired`. **The apps do not use the
replay yet** — they still wait four seconds and fall back to the server in view; `ring_id`,
`replay`, `ring_cancel` and `GET /api/rings` are there for them to adopt.

`POST /api/channels/{id}/ring` is for members who may connect to that voice channel only, and is
limited to 3 per minute per caller and channel and 6 per minute per caller overall.

1. `voip_token` may be `null` (PushKit has not delivered a token yet); the client registers
   again once it arrives — a new credential, or in the legacy shape the same `apns_token` — so
   the Skwod's registration is an upsert per signed-in install.
2. Tokens are lowercase hex.
3. The alert must carry `mutable-content: 1`, or the extension never runs.
4. The wake carries no hint of *which* voice room is ringing. The client learns the room from the
   `ring` event, which the server replays to a device that connects while the call is still
   ringing (see "Which room" above). The room is learned from the Skwod after connecting — never
   added to the wake.
5. `{ "token", "platform" }` on `/api/push/register` is a third, older shape for operators with
   their own APNs/FCM keys (`server/src/push.rs`); it has nothing to do with the gateway, and
   no shipped app sends it. The token is validated (Apple: 64–200 hex characters; FCM: 32–512
   of `[A-Za-z0-9_:-]`), tied to the registering session (it ends with it), limited to 30
   registrations an hour and 8 tokens per account, and checked again before it is used.

## Not verified

The credential flow (register, wake by credential, revoke) is covered by the gateway's tests
against a stubbed APNs and has **not been exercised against Apple or on a device**. The VoIP push
and the on-device rewrite have likewise **not been exercised end to
end** here. They need a signed build on a real device with the gateway and APNs credentials in place.
What the iOS 26.2 Simulator did show (2026-11-17):

- **`ring` event → CallKit.** With the app running, a ring from another client was reported to
  CallKit and accepted, with the caller and server as the name. The Simulator has no system call
  screen and ends the call about a second later; answering through a CallKit transaction in that
  window reached the answer handler and opened the ring's server. The incoming screen itself, the
  lock screen and the audio-session hand-over could not be exercised.
- **The service extension cannot be run with `xcrun simctl push` there.** The extension is built,
  embedded and registered (`pluginkit` lists `com.skwod.app.NotificationService` under
  `com.apple.usernotifications.service`; bundle id, principal class
  `SkwodNotificationService.NotificationService`, App Group and keychain group are as intended),
  notifications were authorized and the payload carried `mutable-content: 1` — and the system
  still delivered the alert unchanged within 90 ms. The log shows why: `simctl push` has
  CoreSimulatorBridge *add a notification request* on the app's behalf; it never goes through the
  remote-notification path, which is where service extensions are invoked. Nothing in the app is
  wrong or fixable for this; it needs a real APNs push.
