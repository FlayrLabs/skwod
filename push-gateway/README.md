# Skwod push gateway

A blind APNs wake gateway for Skwod, as a single Cloudflare Worker.

Skwod servers are self-hosted, but only the app publisher holds the Apple push
key for the iOS app. This Worker is the one piece of infrastructure the
publisher runs: a self-hosted server asks it to wake a device, and it forwards
a content-free push to Apple. A device registers its push tokens here and gets
a sealed **wake credential** to hand to one server; the server presents that
credential and a kind. The gateway is never given a server identity, sender,
channel or message content, and a server is never given the device's tokens.

iOS only. Android clients keep a persistent connection and do not use this.

License: AGPL-3.0-only.

## Contract

Five routes, all `POST`, `content-type: application/json`, body at most 2 KB,
exact key sets (an unknown key is `400`). The full flow between app, server and
gateway is in `docs/PUSH.md`.

### `POST /v1/challenge` (device → gateway)

`{ "apns_token": "<hex>", "topic": "<bundle id>" }` → `202 {"ok":true}`. The gateway sends a
**background** push to that token (`apns-push-type: background`, priority 5, body
`{"aps":{"content-available":1},"skwod_challenge":"c1.<base64url>"}` — nothing shown, nothing
sounded). The value is never in the HTTP response: only the device that owns the token gets
it, which is what makes presenting it proof of possession. It is good for 10 minutes, for
that token only, once. Stateless to issue (nonce ‖ expiry ‖ HMAC over nonce, expiry and token
under a key derived from `WAKE_CRED_SECRET`); the gateway stores an HMAC of the nonce once it
is used, until it would have expired. Limits per token: `RL_CHALLENGE_PER_10MIN` (3) and
`RL_CHALLENGE_PER_DAY` (10); `429` beyond, `410` for a dead token — remembered for 10 minutes
(the same mark a wake leaves), so asking again for a token Apple does not know costs no further
request to Apple.

**One outstanding challenge per token.** While a pushed challenge is unused and unexpired,
further requests for that token answer `202` and do nothing: no push, no budget. Anyone can
request a challenge for a token they know, so this is what keeps a flood harmless — it costs
the device one silent push per ten minutes and none of its allowance, and the owner already
holds the delivered value (the app keeps the latest `skwod_challenge` it received, asked for
or not). Using a challenge clears the mark. Stored: `(HMAC of token, expiry)`.

### `POST /v1/register` (device → gateway)

```json
{ "apns_token": "<hex>", "voip_token": "<hex>" , "topic": "<bundle id>", "challenge": "c1.…" }
{ "apns_token": "<hex>", "voip_token": null, "topic": "<bundle id>", "revoke": "r1.…", "tag": "<16–32 chars of A-Z a-z 0-9 _ ->" }
```

`voip_token` is required and may be `null`; `tag` is optional. **Exactly one proof** that the
APNs token is the caller's (none or both is `400`; a bad one is `403`):

- `challenge` — the value pushed to that token. Forged, expired, used or pushed to another
  token is refused. Used up by the call.
- `revoke` — the revoke token of a credential that is still outstanding **for that same APNs
  token**. This is renewal without a challenge, for a device whose challenge allowance someone
  else used up. Not consumed; counts against the registration caps like any registration.

A wake credential (`"credential"`) is **not** accepted as proof here or on `/v1/revoke-all`
(`400`): the skwod holds it, and a skwod that could mint or revoke with it could keep itself
alive after the user left, or cut off the user's other skwods.

**The credential is a pair.** It seals the proven APNs token together with the VoIP token as
given. The VoIP token cannot be proven — a VoIP push rings the phone — and **nobody owns one
here**: any number of devices may register the same VoIP token, none is refused for it, and
none can affect another's credential. There is nothing to squat. Everything that ends a
credential (revoke, revoke-all, eviction, expiry) hangs off the APNs token it was minted
under, for both of its halves. What bounds rings through a VoIP token its holder did not ask
for is that each proven device has its own ring share ("Rate limits") and the app
("`skwod_cred`", below). Answer:

```json
{ "ok": true, "credential": "w1.<base64url>", "revoke": "r1.<base64url>", "id": "<22 chars base64url>", "expires_at": 1790000000 }
```

- `credential` is AES-256-GCM over `{registration id, tokens, topic, tag, expiry}` under a key
  derived (HKDF-SHA256) from the `WAKE_CRED_SECRET` secret. Only this gateway can open it.
  The device gives it to **one** server. Registering the same tokens again gives a different,
  unlinkable credential with its own budget.
- `revoke` is for the device alone: the registration id and expiry with an HMAC under a second
  derived key. The credential's holder cannot read the id or forge the MAC.
- `id` is the registration id (16 random bytes, base64url) — the same id the revoke token
  carries. **Every push the gateway sends for this credential carries it as `"skwod_cred"`**
  (the VoIP payload and the alert payload, next to `tag`). The app keeps the ids it registered
  and **ends at once a VoIP call whose `skwod_cred` it does not know** (report to CallKit, then
  end — PushKit requires the report). Raw legacy wakes carry no `skwod_cred`; once
  `LEGACY_RAW_WAKES = "0"` a ring without one cannot come from this gateway's credential path
  and is ended too. The skwod never sees the id: it is inside the sealed credential.
- `expires_at` (unix seconds) is `CRED_TTL_DAYS` (default 30) from now, and it is final: nothing
  extends a credential. Renewal is registering again — a **new** credential with its own id and
  expiry, under a challenge or the held revoke token, within the caps below. The old one runs
  out at its own `expires_at` unless revoked first.
- The gateway stores no token and no credential for a registration. It stores: a counter row per
  token HMAC — at most `RL_REGISTER_PER_DAY` (24) registrations per proven APNs token per day,
  `429` after (the VoIP token is not counted: a cap on it would be something anyone who knows
  it could use up) — and a row `(HMAC of APNs token, HMAC of registration id,
  minted, expiry)` per outstanding credential.
- **At most `LIVE_CREDENTIALS_PER_TOKEN` (16) credentials are outstanding per APNs token.** One
  more evicts the oldest, whose wakes then answer `410`. Evicting rather than refusing is safe
  because only the device can register (the challenge), and it means a phone that lost its
  stored credentials can always register again.
- A request refused for a cap writes nothing: its challenge is still good.

### `POST /v1/revoke-all` (device → gateway)

`{ "apns_token": "<hex>", "topic": "<bundle id>", "challenge": "c1.…" }` or
`{ …, "revoke": "r1.…" }` → `200 {"ok":true}`. Exactly one proof, as for register (`400` for
none, both, or a wake credential; `403` for a bad one).
Every credential minted for that APNs token up to this moment answers `410`, whoever holds it;
ones registered afterwards work. That is both halves of each such credential — its alerts and
its rings. A credential minted under **another** APNs token is not touched, whatever VoIP
token it names: no cutoff is keyed on a VoIP token, so nobody can cut off someone else's
calls. For erase and "cut off every skwod". Stored: `(HMAC of APNs token, cutoff time)`.

### `POST /v1/revoke` (device → gateway)

`{ "revoke": "r1.…" }` → `200 {"ok":true}`, idempotent. From then on the credential answers
`410 gone`. Stored: one row `(HMAC of registration id, credential expiry)`, deleted at expiry.
A token that is not this gateway's is `403`.

### `POST /v1/wake` (server → gateway)

```json
{ "credential": "w1.…", "kind": "message" }
{ "credential": "w1.…", "kind": "call" }
```

The token, topic and tag come out of the credential; the caller supplies none of them.
`call` uses the registered VoIP token. The server cannot see whether one was sealed in, so a
`call` for a registration made without one is **delivered as a message wake** (alert to the
APNs token, counted against the message budgets) and answers `202`.

`410` on a **message** wake means the registration is over (revoked, evicted, expired, cut off
by revoke-all, or the APNs token is dead): the server deletes its row. `410` on a **call** wake
can also mean only the VoIP token is dead, so a server changes nothing on it.

**Legacy shape (transition).** Build-44/45 servers hold raw tokens and send exactly these
three keys — or these three plus `tag`:

```json
{ "token": "<hex APNs device token>", "kind": "message", "topic": "<bundle id>" }
{ "token": "…", "kind": "call", "topic": "…", "tag": "<16–32 chars of A-Z a-z 0-9 _ ->" }
```

`tag` is an opaque value the **device** made up for one of its servers when it registered for
pushes there. The server hands it back with each wake and the gateway passes it to the device
unchanged (`"tag":"…"` appended to the payload below), so a phone signed in to several servers
knows which one woke it — and cannot be told otherwise by another of them. It means nothing to
the gateway or to Apple, and its shape (short, fixed alphabet) keeps it from being a message
channel. What it does give the gateway: two wakes for one token with the same tag came from the
same registration.

| Field | Rule |
|---|---|
| `token` | hex, even length, 64 to 200 characters (lower-cased by the gateway) |
| `kind` | `"message"` or `"call"` |
| `topic` | `^[A-Za-z0-9][A-Za-z0-9.-]{0,154}$` and listed in `ALLOWED_TOPICS`. Always the app's base bundle id, also for calls. |

What is sent to `POST <apns>/3/device/<token>`:

| | `message` | `call` |
|---|---|---|
| `apns-push-type` | `alert` | `voip` |
| `apns-topic` | `<topic>` | `<topic>.voip` |
| `apns-priority` | `10` | `10` |
| `apns-expiration` | now + 1 h | `0` |
| body | `{"aps":{"alert":{"body":"New message"},"sound":"default","mutable-content":1}}` | `{"aps":{},"kind":"call"}` |

`mutable-content` lets the app's Notification Service Extension fetch and
decrypt the real message from the user's own server and rewrite the text.

Auth to Apple is token-based: an ES256 JWT (`kid` = key id, `iss` = team id,
`iat`), cached per isolate and re-minted after 45 minutes. If production APNs
answers `400 BadDeviceToken`, the request is retried once against the sandbox
host (tokens from development-signed builds).

Responses (JSON, no CORS headers, `cache-control: no-store`):

It is accepted while `LEGACY_RAW_WAKES` is not `"0"`, and budgeted per **token** in rows no
credential shares — so whoever holds a raw token can spend the raw budget and nothing else.
The tag is not part of the budget key (a caller could invent tags for fresh budgets). With
`LEGACY_RAW_WAKES = "0"` the shape answers `410 gone`.

| Status | Body | Meaning for the caller |
|---|---|---|
| 200 | `{"ok":true,…}` | registered / revoked |
| 202 | `{"ok":true}` | APNs accepted the push (wake or challenge) |
| 400 | `{"ok":false,"error":"bad_request"}` | malformed body, unknown key, bad field |
| 403 | `{"ok":false,"error":"forbidden"}` | topic not on the allowlist; a credential / revoke token this gateway did not issue (tampered, or sealed under another secret); a challenge that is forged, expired, already used or for another token; a revoke token offered as proof whose credential is not outstanding for that token |
| 404 / 405 | `not_found` / `method_not_allowed` | wrong path / method (`OPTIONS` is always 405) |
| 410 | `{"ok":false,"error":"gone"}` | credential revoked, evicted, expired or cut off; token dead (APNs 410, or `BadDeviceToken` on both hosts); or raw wakes are switched off. On a message wake: delete the registration |
| 413 / 415 | `too_large` / `unsupported_media_type` | body over 2 KB / not JSON |
| 429 | `{"ok":false,"error":"rate_limited"}` + `retry-after` | per-credential, per-raw-token or per-device limit hit; registration or challenge cap hit |
| 503 | `{"ok":false,"error":"upstream"}` | APNs 429/5xx, unreachable, or APNs rejected the gateway's own request; the APNs reason is never passed on |
| 503 | `{"ok":false,"error":"unavailable"}` | gateway not configured (missing or short `RATE_KEY_SALT`: every route; missing APNs secret; or, for the credential routes, missing `WAKE_CRED_SECRET`) or internal failure |

`GET /health` returns `{"status":"ok"}` and nothing else.

## Rate limits

All configurable in `wrangler.toml` `[vars]`. "Per credential" below means per registration —
one device in one server. The legacy raw shape gets the same rules per token, counted
separately: a credential's budget and a raw token's budget never draw on each other, and two
credentials for the same phone never draw on each other.

On top of that every wake by credential counts against a **per-device ceiling**, shared by all
credentials of the same **proven device** and by nobody else:

- alerts — keyed by the proven APNs token: the three message rules × `RL_DEST_MESSAGE_FACTOR`
  (4 per 5 s / 120 per 10 min / 720 per hour). Several times one budget, so no one credential
  can fill it and starve the others; what it stops is multiplication.
- rings — keyed by the **pair (proven APNs token, VoIP token)**: 6 a minute and 20 an hour.
  One credential's minute (6) equals its device's minute, so one skwod ringing flat out does
  use up that device's rings for the minute.

A wake is refused when *either* its own budget *or* its device's ceiling is full. **Nothing is
keyed on a VoIP token alone**, so there is no budget a stranger can spend for someone else: a
credential minted under another APNs token that names the same VoIP token counts under its
own pair. That is the bound on a stale server with a device of its own and a VoIP token it
once stored: per proven device it controls, 6 rings a minute and 20 an hour, each ended by the
app at once (`skwod_cred`) — and the real owner's calls are untouched.

The raw path has no proven device; it keeps its own per-token rows (its budget, plus a
per-token ceiling row that adds the 20-an-hour ring rule), separate from every pair.

**Every check-then-write is one step.** All state lives in one SQLite-backed Durable Object,
and each decision is a single method of it whose reads and writes run in one
`transactionSync`, with no `await` between them: the Worker never asks "may I?" in one call
and writes in another.

| Decision | Method | What is atomic |
|---|---|---|
| a wake's budgets (credential/raw, per-device, global), revoked / cut off / dead | `take` | all checks + the `hits` and `dest` rows |
| challenge: outstanding? within allowance? count it and mark it outstanding | `challengeBegin` | check + `mints` + `pending` rows (taken back by `challengeFailed` if APNs refuses) |
| register: proof (challenge single use, or revoke token still outstanding), mint cap, live-credential cap + eviction | `register` | proof check + `spent`, `mints`, `live`, `revoked` rows; refused → nothing written |
| revoke-all: proof + cutoff | `revokeAll` | proof check + `spent`, `cutoff`, `live` rows |
| revoke | `revoke` | `revoked`, `hits`, `live` rows (no check; idempotent) |
| dead token | `markDead` | un-count + `dead` row |

The minting moment and the revoke-all moment are both the Durable Object's clock, and a
credential admitted after a revoke-all is stamped strictly later than it, so "before" and
"after" cannot be confused within a millisecond. The credential is sealed after admission; if
the Worker died in between, a `live` row would exist for a credential nobody holds (it counts
toward the cap until evicted or expired, and wakes nothing).

| Var | Default | Meaning |
|---|---|---|
| `RL_MESSAGE_BURST` / `RL_MESSAGE_BURST_WINDOW_S` | `1` / `5` | message wakes per token per window (max window 3600 s) |
| `RL_MESSAGE_PER_10MIN` | `30` | message wakes per token per sliding 10 minutes — the sustained rate; sized so one busy server (≤ ~28 coalesced wakes per 10 min) is never refused |
| `RL_MESSAGE_PER_HOUR` | `180` | message wakes per token per sliding hour — a ceiling for a token several servers wake at once |
| `RL_CALL_PER_MINUTE` | `6` | call wakes per token per sliding minute |
| `RL_GLOBAL_PER_MINUTE` | `0` (off) | optional last-resort brake: wakes per minute across all tokens |
| `RL_DEST_MESSAGE_FACTOR` | `4` | per-device message ceilings = the three message rules × this |
| `RL_DEST_CALL_PER_MINUTE` | `6` | rings per (proven APNs token, VoIP token) pair per sliding minute, all of that device's credentials together; also per raw token |
| `RL_DEST_CALL_PER_HOUR` | `20` | the same per sliding hour |
| `RL_REGISTER_PER_DAY` | `24` | credentials minted per proven APNs token per day |
| `LIVE_CREDENTIALS_PER_TOKEN` | `16` | outstanding credentials per APNs token; one more evicts the oldest |
| `RL_CHALLENGE_PER_10MIN` / `RL_CHALLENGE_PER_DAY` | `3` / `10` | registration challenges pushed per APNs token |
| `CRED_TTL_DAYS` | `30` | credential lifetime (max 400) |
| `LEGACY_RAW_WAKES` | `1` | `0` refuses the raw-token wake shape with `410` |

Message and call limits are independent. Refused wakes are not counted and
store nothing. A wake APNs answers "dead token" to (410, or `BadDeviceToken`
on both hosts) is taken back out of the counters, and the token's HMAC is
remembered as dead for 10 minutes: repeats get 410 straight away without
another APNs request.

### Why there is no global cap

Callers are unauthenticated. A hard cap shared by all of them is a switch any
one of them can flip: send enough wakes for made-up tokens and nobody's
notifications get through. So `RL_GLOBAL_PER_MINUTE` defaults to off. What
bounds abuse instead: per-token limits (a real token can be woken only so
often), dead tokens costing one APNs round trip and then nothing for 10
minutes, and a per-source limit in the Worker (next section). The
trade-off: without the cap, a flood of *distinct made-up* tokens is limited
only per source, so each source can cause that many APNs requests per minute
(Apple answers them with `BadDeviceToken`; sustained junk can get a provider
throttled). That holds for the two routes that take a token from a stranger:
the raw wake shape (until `LEGACY_RAW_WAKES = "0"`) and `/v1/challenge`. Both
leave and obey the same 10-minute dead mark, so *repeating* a made-up token
costs nothing; a wake by credential never gets this far, because a credential
this gateway did not seal is refused (`403`) before the limiter or Apple is
involved. **Distinct made-up tokens are bounded by the per-source limit
below** (per source: someone with many addresses gets that many allowances). If you set the brake, set it far above your real peak and accept
that reaching it blocks everyone.

### Per-source limit (in the Worker; a Cloudflare rule on top if you can)

One caller naming many *different* made-up tokens is bounded by none of the
per-target limits. So the Worker limits each **source address** itself, before
it reads the request body — before any request to Apple and before a made-up
token is looked at:

| Var | Default | Counts |
|---|---|---|
| `RL_SOURCE_WAKE_PER_MINUTE` | `120` | `POST /v1/wake` per source per sliding minute (a busy self-hosted server sends a few) |
| `RL_SOURCE_DEVICE_PER_MINUTE` | `10` | `/v1/challenge`, `/v1/register`, `/v1/revoke`, `/v1/revoke-all` together (a phone makes a handful a day) |

Over the limit: `429` with `Retry-After`; refused requests are not counted.
`0` switches a limit off. The source is `CF-Connecting-IP` (set by Cloudflare,
not by the caller); an IPv6 caller is counted by its /64. A request without
that header (local development) is not limited.

**What this costs in privacy.** Until this change the Worker never read the
caller's address at all. It now reads it in one function (`sourceLimited`,
`src/index.ts`), only to compute `HMAC-SHA256(RATE_KEY_SALT, route class ‖
address)`, and stores `(that HMAC, timestamp)` for one minute in the limiter.
The address is never logged, never returned, and never stored next to a token
or a credential — the per-caller rows and the per-target rows share no key.
Someone who holds both the stored rows and `RATE_KEY_SALT` (the operator)
could test whether a given address called in the last minute; IPv4 is small
enough to try them all. The reason for the change: the alternative, a
Cloudflare rule, cannot be put in front of a `workers.dev` address, and the
publisher's gateway has to stay on one while builds 44/45 are in use.

On your own host you can add the edge rule as well — it stops a flood before
it costs Worker requests (zone, Security, WAF, Rate limiting rules):

- Rule A — wakes. Match
  `(http.host eq "push.example.org" and http.request.uri.path eq "/v1/wake")`,
  characteristics IP, `120` per `1 minute`, Block for 1 minute (the free plan
  allows one rule with a 10 second period: `20` per `10 seconds`).
- Rule B — device routes (needs a plan with more than one rule; on the free
  plan fold them into rule A with `starts_with(http.request.uri.path, "/v1/")`).
  Match `(http.host eq "push.example.org" and http.request.uri.path in {"/v1/challenge" "/v1/register" "/v1/revoke" "/v1/revoke-all"})`,
  characteristics IP, `10` per `1 minute`, Block for 10 minutes.

Why a Durable Object and not KV: KV is eventually consistent (two edge
locations would each allow the "one" wake), has no atomic increment and caps
writes to the same key at one per second. A SQLite-backed Durable Object
(available on the free plan) gives a single, strongly consistent place to
check-and-record in one step. There is one limiter instance; it holds one row
`(HMAC of token, kind, timestamp)` per accepted wake and one `(HMAC, expiry)`
row per recently dead token. An alarm deletes hit rows older than one hour and
expired dead marks every minute while any exist. The trade-off is that one
object serialises every wake; if that ever becomes the bottleneck, shard by
key prefix.

The row key is `HMAC-SHA256(key = RATE_KEY_SALT, msg = token)`, computed in
the Worker. The Durable Object never receives the token. `RATE_KEY_SALT` is
**required** (16 characters or more): there is no fallback key, and without it
every route except `/health` answers `503 unavailable` before anything is
parsed, counted or sent.

## Privacy properties and threat model

**Servers are not identified; a wake is authorized by what the caller holds.**
Any self-hosted Skwod server may call the gateway, and there is no registry of
servers. A wake needs a credential the device itself registered and handed to
that server, and the device can revoke it (sign-out, leaving, erasing): a server
the user left has nothing that still works. Registering needs a challenge the
gateway pushed to the token, so knowing a token is not enough to mint one. The
other controls: the topic allowlist (the key can only push to the publisher's
own app), per-credential budgets under a per-device ceiling, caps on
registrations and live credentials per token, a per-source limit, and strict
input validation. No caller can set any content.

**Known limits (see `docs/PUSH.md` "Limits and what is next").** While
`LEGACY_RAW_WAKES` is on, a server that was handed a raw token by a build-44/45
client can still send generic alerts and call wakes at the raw budget's rate —
but can no longer starve the credentials, and cannot mint any. **Credentials
are only mandatory once `LEGACY_RAW_WAKES = "0"`.** Two things a holder of
someone's tokens can still do:

- *Request challenges for the APNs token.* One silent push per ten minutes
  reaches the phone and the rest do nothing; over a day that can use up the
  token's 10 challenges. A phone that already holds a credential is unaffected
  (it renews and revokes by revoke token). A phone registering **for the first
  time** is not locked out as long as the app keeps the challenge that was
  delivered — but if it missed it, it waits for the window.
- *Ring through a VoIP token they know.* A server that stored a phone's VoIP
  token (build ≤ 45) and has a device of its own can mint credentials naming
  it, or use the raw path while that is on. The phone's own registrations,
  credentials **and ring budget** are unaffected — the stranger's rings count
  under the stranger's (APNs token, VoIP token) pair — and the phone's
  revoke-all does not reach those credentials (they are not its own). What
  bounds it: each stranger needs a real proven device; **each such device gets
  6 rings a minute and 20 an hour**; and the app ends any ring whose
  `skwod_cred` it did not register, immediately. The residual is a brief
  CallKit flash, at most 20 times an hour per proven device the stranger
  controls (there is no cap across devices — a cap keyed on the VoIP token
  would be the owner's budget for a stranger to spend). Once
  `LEGACY_RAW_WAKES = "0"` the raw path is gone and that is all that is left.
  It ends when PushKit issues a new VoIP token.
There is deliberately no shared cap one caller could exhaust for everyone (see
"Why there is no global cap").

**What the gateway operator can see** (anyone with access to the Cloudflare
account, and Cloudflare itself):

- the APNs device token, the topic, the kind, and the time of each wake and
  each registration, in memory for the duration of the request;
- how many registrations and challenges a token made in the last day, how many
  credentials are outstanding for it, and that two wakes used the same
  credential — not which server holds it;
- at Cloudflare's edge, outside this Worker's control: the caller's IP address
  and TLS metadata — a server's for a wake, and **the device's own** for
  `/v1/register` and `/v1/revoke`, which the app calls directly. The code reads `cf-connecting-ip` in one place, for the
  per-source limit ("Per-source limit": an HMAC of it, kept one minute, never beside a token),
  never reads `request.cf` and forwards no inbound header to Apple; Cloudflare as the
  network operator necessarily sees the connection.
- persistently: `(HMAC of token or of registration id, kind, timestamp)` rows
  for at most about an hour; `(HMAC of token, timestamp)` registration counters
  for a day; `(HMAC of token, HMAC of registration id, minted, expiry)` per
  outstanding credential; `(HMAC of registration id, expiry)` per revoked one
  until it would have expired; `(HMAC of nonce, expiry)` per used challenge for
  ten minutes; `(HMAC of token, expiry)` per outstanding challenge;
  `(HMAC of APNs token, time)` per revoke-all. A VoIP token appears only inside
  the HMAC of a (APNs token, VoIP token) pair its rings are counted under, as
  the raw path's own row, and as a dead mark. Every one of those HMACs is keyed by `RATE_KEY_SALT`, so
  testing whether a *known* token woke, registered or revoked recently takes the stored rows
  **and** that secret — which the operator (and anyone who can read the Worker's secrets) has.
  It protects the rows against someone who obtains them alone; it is not protection against
  the operator.

**What it cannot see:** which server, community, channel or user a wake is
for; who sent the message; any message content, ciphertext or metadata; who is
calling. None of that is in the request.

**What Apple sees:** the device token, topic, push type and timing, coming from
Cloudflare. Cloudflare adds its own headers to Worker subrequests (for example
`cf-worker`, naming the Worker's zone); the Worker cannot remove those.

**No logging.** The code contains no `console.*` call and catches errors
silently. `wrangler.toml` sets `[observability] enabled = false` and
`logpush = false`. As the owner, keep it that way: do not enable Workers Logs,
Logpush, Tail Workers or Analytics Engine for this Worker, and do not leave
`wrangler tail` running, since invocation logs include request metadata.

## Deploy (owner)

Prerequisites:

- A Cloudflare account (the free plan is enough; SQLite-backed Durable Objects
  are available on it).
- Apple Developer account: Certificates, Identifiers & Profiles > Keys > create
  a key with **Apple Push Notifications service (APNs)** enabled. Download the
  `AuthKey_XXXXXXXXXX.p8` (only downloadable once), note its **Key ID** and your
  **Team ID**. This one key serves both alert and VoIP pushes, for production
  and sandbox.
- Node 22 and npm.

Steps, from this directory:

```sh
npm ci
```

Edit `wrangler.toml`: set `ALLOWED_TOPICS` to the app's bundle id (comma-separate
several). The placeholder `com.example.skwod` must be replaced.

```sh
npx wrangler login
npx wrangler secret put APNS_KEY_P8 < AuthKey_XXXXXXXXXX.p8   # multi-line PEM via stdin
npx wrangler secret put APNS_KEY_ID                           # paste the 10-character Key ID
npx wrangler secret put APNS_TEAM_ID                          # paste the Team ID
openssl rand -hex 32 | npx wrangler secret put WAKE_CRED_SECRET  # seals wake credentials (>= 32 chars)
openssl rand -hex 32 | npx wrangler secret put RATE_KEY_SALT  # REQUIRED: keys every stored row (>= 16 chars)
npx wrangler deploy
```

**A new gateway:** before `deploy`, give the Worker its own address. In `wrangler.toml`
uncomment the route with your host (the zone must be on the same Cloudflare account), set
`workers_dev = false`, and (optionally) create the edge rules of "Per-source limit" for that host:

```toml
routes = [{ pattern = "push.example.org", custom_domain = true }]
workers_dev = false
```

**Moving off workers.dev** (a gateway that is already in use). The `workers.dev` address is
baked into every app (`SKWOD_PUSH_GATEWAY`) and server build (`SKWOD_DEFAULT_PUSH_GATEWAY`, an
operator's `SKWOD_PUSH_GATEWAYS`, an owner-pinned host) released with it; setting
`workers_dev = false` ends push for all of them at the next deploy. So, in this order:

1. Add the `routes` line and deploy with `workers_dev = true` still set: both addresses work.
2. Optionally create the edge rate-limiting rules for the new host (the Worker's own
   per-source limit applies on both addresses either way).
3. Release apps and servers that name the new host. A server only calls hosts on its list (or
   its owner's pinned host), so servers must accept the new host **before** apps register
   with it: list both hosts in `SKWOD_PUSH_GATEWAYS` during the move. An owner-pinned server
   (no list) keeps its old pin and refuses the new host until it is given a list.
4. When the old builds are gone, set `workers_dev = false`.

**Upgrading a gateway that ran without `RATE_KEY_SALT`.** It answers `503` on every route
until the secret is set, and setting it re-keys every stored row: the rate counters start
afresh (harmless), and so do the *revocations, revoke-all cut-offs and the list of outstanding
credentials* — a credential a device revoked would work again until it expires. If any
credentials are in the field, set `RATE_KEY_SALT` and a new `WAKE_CRED_SECRET` **together**:
every old credential then answers `403`, servers treat that as a failed wake, and the apps
register again. (With no credentials issued yet, just set the salt.)

If the Worker does not exist yet, `wrangler secret put` offers to create it;
accept. The PEM may also be stored as one line with `\n` escapes.

**Your host (`https://push.example.org`) is what gets baked into the app as the
default gateway**, and into the server build as its allowlist
(`SKWOD_DEFAULT_PUSH_GATEWAY`).

Smoke test:

```sh
GW=https://push.example.org
curl -s $GW/health
# {"status":"ok"}
curl -s -X POST -H 'content-type: application/json' \
  -d '{"token":"nothex","kind":"message","topic":"com.example.skwod"}' $GW/v1/wake
# {"ok":false,"error":"bad_request"}
curl -s -X POST -H 'content-type: application/json' \
  -d "{\"token\":\"$(openssl rand -hex 32)\",\"kind\":\"message\",\"topic\":\"not.your.app\"}" $GW/v1/wake
# {"ok":false,"error":"forbidden"}
```

Then send a wake with a real device token and your bundle id and expect
`{"ok":true}` and a notification. `{"ok":false,"error":"unavailable"}` means a
secret is missing; `"upstream"` means Apple refused the request (check Key ID,
Team ID, the key, and that the topic is your app's bundle id).

The credential flow cannot be smoke-tested with curl alone: `/v1/register` needs the challenge
that `/v1/challenge` pushes to the device, so it takes the app (or a device log showing the
`skwod_challenge` value of the background push):

```sh
curl -s -X POST -H 'content-type: application/json' \
  -d "{\"apns_token\":\"$TOKEN\",\"topic\":\"<bundle id>\"}" $GW/v1/challenge
# {"ok":true}   — and a silent push on the device
```

Rotating the APNs key: create a new key in the Apple Developer portal, then

```sh
npx wrangler secret put APNS_KEY_P8 < AuthKey_NEWKEYID00.p8
npx wrangler secret put APNS_KEY_ID
```

back to back (each takes effect immediately; wakes in between get 503, which
calling servers treat as retryable), confirm a wake works, then revoke the old
key at Apple. Changing `RATE_KEY_SALT` simply starts the limiter counters afresh
(and forgets revocations — rotate it together with `WAKE_CRED_SECRET`, or not at all).

`WAKE_CRED_SECRET` is generated once and kept: it is never shown to anyone, and
**changing it invalidates every credential in the field** (wakes answer `403`
until each device registers again on its next launch). Change it only to cut
off all outstanding credentials on purpose. Upgrading an existing deployment:
put the secret first, then deploy; until the secret exists the new routes answer
`503` and the legacy shape keeps working, so the order is safe either way.

## Development

```sh
npm run typecheck      # tsc --noEmit, strict
npm test               # vitest in workerd; APNs is a stubbed fetch, the P-256 key is generated per run
npm run e2e            # test/e2e-local.sh: wrangler dev --local against test/fake-apns.mjs on 127.0.0.1
npm run dev            # needs a .dev.vars with the three APNS_* secrets
```

`APNS_HOST` / `APNS_SANDBOX_HOST` (full origins) replace Apple's endpoints; they
exist for tests and must stay unset in production.

`package-lock.json` was generated with npm 12 because npm 10.9's resolver
crashes on vitest 4's peer set; `npm ci` works with npm 10.9.

### Not verified

Nothing here has been deployed, and Apple's real APNs endpoints have never been
contacted: the tests and the local end-to-end check use stand-ins over
HTTP/1.1. APNs requires HTTP/2, which depends on Cloudflare's outbound `fetch`
negotiating it. The first wake with a real device token after deploying is the
check for that, for the Apple credentials, and for the deploy steps above.
