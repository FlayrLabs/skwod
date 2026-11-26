# The Apple apps (iOS + macOS)

One SwiftUI codebase in `apps/apple/` builds `Skwod-iOS`, `Skwod-macOS` and the iOS notification
service extension. This is the operator's guide: how to build, what the switches are, how joining
and hosting work, what the app does for privacy, and what a release needs.

## Build

```sh
cd apps/apple
./build-core.sh all          # Rust core → Generated/SkwodCore.xcframework + Swift bindings,
                             # then the Mac host tools (bundle-host-tools.sh)
xcodegen generate
xcodebuild -project Skwod.xcodeproj -scheme Skwod-macOS CODE_SIGNING_ALLOWED=NO build
xcodebuild -project Skwod.xcodeproj -scheme Skwod-iOS \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' CODE_SIGNING_ALLOWED=NO build
```

The Swift packages (Sparkle, LiveKit and LiveKit's WebRTC and FFI binaries) are pinned:
`project.yml` names exact versions (LiveKit's SDK: a commit, in `fetch-livekit-swift.sh`, with
`livekit-swift.patch` on it; `xcodegen generate` fetches it) and installs the committed
`Package.resolved` into the generated project. Add `-onlyUsePackageVersionsFromResolvedFile` to
`xcodebuild` to make it fail instead of re-resolving.

`build-core.sh` fails if the host tools fail (it used to hide that). `SKWOD_SKIP_HOST_TOOLS=1`
skips them on purpose (iOS-only work).

**Running in the simulator needs local signing.** A simulator build made with
`CODE_SIGNING_ALLOWED=NO` has no keychain, so it can sign in but never gets an encryption identity.
To *run* it, let Xcode sign for the simulator (`CODE_SIGN_IDENTITY=-`, i.e. "Sign to Run Locally");
that involves no certificate and no profile.

### Switches

| Setting | Default | Meaning |
|---|---|---|
| `SKWOD_PUSH_GATEWAY` | empty | Blind push gateway base URL (`https://…`). Empty = remote push off. See [PUSH.md](PUSH.md). |
| `SKWOD_FLAGS=SKWOD_PAYWALL` | off | Compiles the StoreKit paywall in (iOS). See "Paywall flag". |
| `SKWOD_APP_GROUP` | `group.com.skwod.app` | Container shared by the iOS app and its notification extension. |
| `SKWOD_KEYCHAIN_GROUP` | `com.skwod.shared` | Keychain group shared by the same two (prefixed with the team id). |
| `SKWOD_SKIP_HOST_TOOLS=1` (env) | unset | `build-core.sh` does not rebuild/bundle the Mac host tools. |
| `SKWOD_LIVEKIT_FROM_SOURCE=1` (env) | unset | `bundle-host-tools.sh` builds LiveKit from the pinned source tarball instead of the pinned bottle. |

### Bundled host tools (macOS)

`bundle-host-tools.sh` puts two binaries in `Resources/host-tools/`: `skwod-server` (built from
`server/`) and `livekit-server` **v1.13.11**. LiveKit publishes no macOS release binaries, so the
pinned artifact is the Homebrew bottle addressed by its digest; the script verifies the SHA-256
before unpacking, extracts exactly one file, and checks it is an arm64 Mach-O reporting that
version. Nothing is fetched from a "latest" URL and nothing is downloaded at run time. Apple
Silicon only. The release script must sign both binaries (`package-release.sh` does).

## Joining

- The app registers the `skwod://` URL scheme. An invite is
  `skwod://join/<52-char host key>#<join code>` (optionally `?u=https://…` for a host that also has
  a domain). Classic `https://host#code` links and bare `https://` addresses still work for VPS
  hosts; plain `http://` is accepted for this machine's loopback only.
- A tapped link, a scanned QR code (iOS camera; on macOS "QR from image…") and pasted text all go
  through `Sources/Invites.swift`: length cap, no control characters or whitespace, exactly one of
  the two accepted shapes, join-code charset check. An invite only ever **prefills the connect
  screen** — the user still types a name and password and presses the button. If the invite is for
  a Skwod the user is already in, the app switches to it and uses the code to join one more of its
  servers.
- Connecting dials the host by its key (`p2p_connect`) and uses the returned loopback URL wherever
  a server URL went (REST, WebSocket, LiveKit). **The loopback URL is never persisted, shown or
  logged**; the workspace stores the host key. The app reconnects on launch, on returning to the
  foreground and on network changes; a host that is not answering does not block launch — the app
  opens on its local cache, says "Host is offline", and keeps trying.
- Connection state is shown in plain words: *Connected directly*, *Connected through a relay*,
  *Connecting…*, *Reconnecting…*, *Host is offline* (title bar pill on macOS, the you-bar on iOS,
  Profile → Privacy on both; tapping the pill explains what a relay can and cannot see).
- **Transport security.** The only ATS exception is `NSAllowsLocalNetworking` (loopback http/ws for
  the in-process proxy and a Mac host's own server). No arbitrary loads, no domain exceptions.
- The old address beacon (Nostr over Tor) and the "my address moved" announcement are no longer
  used by the app: a p2p address is a key and does not move. Old links' `~b.…` suffix is ignored.
  The core's beacon functions are still exported (Android may use them) but nothing here calls them.

## Hosting (macOS)

See [SELF-HOSTING.md](SELF-HOSTING.md) for the user-facing flow. Implementation notes
(`Sources/HostManager.swift`, `Sources/HostWizardView.swift`):

- One button runs `skwod-server run --data <folder> --listen 127.0.0.1:<port> --public-fallback <bool>`
  with `SKWOD_LIVEKIT_BIN` pointing at the bundled SFU. The server initializes a fresh folder
  itself, prints the one-time owner code and the invite; the app reads the host key from that
  output (either link form; later from `GET /api/instance/p2p` if the p2p endpoint came up late)
  and redacts codes in the on-screen log.
- The port is the first free one of 4820–4839 (4820 first), remembered per `SKWOD_PROFILE`
  (`HostPort`). When it has to move, the owner's stored workspace address moves with it
  (`AppState.hostAddressMoved`). All twenty taken → a sentence, no arbitrary port.
- A loopback port proves nothing, so every spawn gets a fresh random local-proof secret on its
  standard input (`run --local-proof-stdin`; not its environment, which other processes of
  the same user can read) and the listener must answer `GET /api/instance/local-proof?nonce=…` with
  the HMAC under it. The server counts as running only after `/health` AND that proof, and no
  credential — setup code, saved owner password, the owner's session token, a typed "This Mac"
  login — is sent to a host-range loopback address without a fresh proof
  (`HostManager.verifiedLocalURL` / `gatedBase`). While the child is down the owner's workspace is
  bound offline.
- Supervision (`Sources/HostReliability.swift` holds the decisions as pure functions, with
  `HostReliabilityChecks` in `selfcheck`): a child that ends by itself is restarted after
  2/5/15/30/60 s (reset after 3 healthy minutes); exit 75 (port in use) moves to another port;
  74/78 (data folder, disk) stop with the server's own last `[skwod] …` sentence from stderr.
- "Keep this Mac awake while hosting" holds `ProcessInfo.beginActivity(.idleSystemSleepDisabled)`
  while hosting is on (default: on AC power). "Start Skwod when I log in" is
  `SMAppService.mainApp`; a login-item launch that has hosted before hides the app and starts the
  server from the app delegate, without a window.
- `HostAppDelegate.applicationShouldTerminate` asks before a quit while hosting (member count
  read with the owner's session); a system quit (logout/restart/shutdown) is never held up.
- Sparkle: while hosting, `willInstallUpdateOnQuit` / `shouldPostponeRelaunchForUpdate` hold the
  install until the user says "Install now" (`SparkleUpdater`).
- DEBUG host hooks (`HostE2E`): with `SKWOD_E2E_OUT=<dir>` the app writes `<dir>/host.json` and
  runs `SKWOD_E2E_HOSTCMD` / `<dir>/hostcmd.txt` commands — `selfcheck`, `start:<owner name>`,
  `stop`, `signin`, `activate`, `rings`, `signedout`, `quitmsg`, `awake:on|off`, `shot`.
- The host is signed in as owner over the local path: first run creates the account with the
  one-time code and a generated 24-character password kept in the Keychain; later runs reuse the
  saved workspace or log in again with the saved login.
- The firewall prompt is explained on the Start card before the button is pressed.
- A server left behind by a crash is stopped on the next start only if the recorded pid really is
  the bundled binary; stopping the server also stops its LiveKit child.
- Cloudflare is gone: no `cloudflared`, no quick/named tunnels, no API client.

## Calls (voice + video)

Code: `Sources/CallView.swift` (the call and its screen), `Sources/Calls.swift` (ringing, the macOS
banner), `Sources/PushManager.swift` (`CallManager`: CallKit on iOS), `Sources/Realtime.swift`
(the `ring` event).

- **One call per server** — its "General" voice room. The Voice row (or answering a ring) opens the
  call sheet; closing the sheet for any reason disconnects (`AppState.activeCall` → `CallSession.end`).
  The room is created by whoever opens the call first. The server lets any member who may
  connect to voice create a server's *first* voice channel (and hands back the existing one
  otherwise — `server/src/structure.rs`, `open_first_voice_room`).
- **A failed join says where it stopped** (`VoiceFailure.swift`, one table with Android:
  `shared-test-vectors/voice-failures.json`): voice off or starting on the skwod, host not reached,
  may not join, media path blocked on this device, media not getting through. Host not reached and
  voice starting are tried once more first, with a fresh token.
- **Media.** Microphone on join; camera on request; on iOS also switch camera and speaker/earpiece.
  Remote cameras show in a grid. Picture-in-picture is **not** implemented (LiveKit's Swift SDK has
  no ready-made one; it needs an `AVPictureInPictureVideoCallViewController` fed from a sample-buffer
  layer, and it cannot be checked in the Simulator).
- **Encryption.** The room has one `BaseKeyProvider`; LiveKit seals every track this device
  publishes — microphone and camera — with it, and opens every track it receives with it. Keys are
  per call and random, handed out over libsignal by `voice_sync`, re-read every 2 s.
  - Our outgoing frames are pointed at our own newest key **explicitly**
    (`setCurrentKeyIndex`). Registering a per-participant key does not do that by itself; before
    this fix a rotated key was never used for sending, and re-joining a call within the same room
    session sent nothing.
  - **Nothing unencrypted is ever received.** The app connects with auto-subscribe off and
    subscribes only to tracks the SFU lists as end-to-end encrypted; a track published in the clear
    is not subscribed to (never played, never drawn) and the call shows "Someone in this call
    isn't encrypting". A track that claims encryption but isn't sealed with a key we hold fails to
    decrypt and yields nothing.
  - **No third-party STUN.** LiveKit hands clients Google's and Twilio's public STUN servers by
    default. When the SFU is on this device's loopback (the p2p tunnel, or a Mac host's own SFU)
    there is nothing they could add, so the app replaces the list with an entry that never leaves
    the device. An external SFU keeps the list its server sends (it may include TURN).
- **Ringing.** "Ring everyone" (shown while nobody else is in the call) calls
  `POST /api/channels/{id}/ring`. A running app gets a `ring` event on its own `user:<id>` topic
  with the server and channel; a sleeping iPhone gets an empty VoIP push ([PUSH.md](PUSH.md)).
  - iOS: both are shown by **CallKit and nothing else** — no notification, no in-app banner — so
    the lock screen shows only the system call UI. Answering opens the ring's server.
  - macOS: a banner in the main window with a repeating system sound; nothing is posted to
    Notification Center. It rings for 45 s.
- **Permissions.** `NSMicrophoneUsageDescription` / `NSCameraUsageDescription` say what each is
  for (`project.yml`). Refusing the microphone fails the join with an explanation; refusing the
  camera leaves the call running, audio only.

## Devices and account safety

- **Add a device:** the new device logs in and shows a one-time 80-bit code as text and as a QR
  (`skwod-link:<code>`); an existing device scans it (iOS) or types it under Profile → Encryption →
  Link a device. The existing device can also show the Skwod's address as a QR so the new device
  lands on the right log-in screen. (The code originates on the *new* device — that is how
  `begin_device_link` / `approve_device_link` work — so the code QR is on the new device.)
- **Notices** from `take_security_notices` (new device, device linked, safety number changed,
  unrecognised device, blocked reset, protocol upgrade) are shown as alerts, queued one after
  another. Events about a conversation are also persistent system rows in it.
- **Waiting to join.** Join requests and members the core is holding (listed by the server,
  approved by nobody this device trusts) are a section at the top of the member list with
  *Let in* / *Decline*, and a badge on the members button — not alerts. *Let in* is the only
  place a member approval is signed. The name on an entry comes from the server, so it is
  checked first (`WaitingTrust`): it must resolve to that very account, and must not be the name
  of someone the user already knows under another account (shown as a possible impersonation).
  Each entry shows the account id and key fingerprint; *Let in* is off unless the name checks
  out, and the check is repeated at the moment of the tap.
- **Safety number.** One per account pair (`SafetyNumberView`). Verifying hands the number on
  screen to `verify_contact`, so it can only ever cover the devices that were compared. iOS
  verifies by a live camera scan of the other person's (directional) code; on macOS, and as the
  fallback on iOS, the digits are compared by eye and confirmed explicitly. There is no "check a
  picture": anything sent through the conversation is chosen by whoever might be in the middle.
- **Icons.** A server icon is accepted only from a channel of that server and its pinned owner;
  the skwod icon only from the instance owner pinned under the instance key.
- **Errors:** `UpdateRequired` → "update required" alert / message; `LinkRequired` → the link
  screen; `ResetPending` → the "Reset is waiting" screen (explains the 7-day hold, takes the PIN,
  offers linking instead); `IdentityChanged` on send to a verified contact → the message is held
  and the user chooses between comparing safety numbers and accepting the new keys.
- **Account PIN** (registration lock) and **key backup** (passphrase or generated recovery key,
  with turn-off) live under Profile → Encryption.

## Privacy and security behaviour

| Area | What the app does |
|---|---|
| Keychain | iOS: data-protection keychain, shared group with the extension. macOS: data-protection keychain (`kSecUseDataProtectionKeychain`) when the build is entitled, with a one-time move of older login-keychain items; an unentitled local build falls back to the login keychain and says so in Profile. |
| Attachments | Decrypted copies only exist while viewed: backup-excluded cache folder, `NSFileProtectionComplete` on iOS, 0700/0600 on macOS; wiped at launch, sign-out, leave, and after 24 h. |
| Photos | Re-encoded from pixels before encryption: no EXIF, GPS, camera model or capture time is sent (`SafeImage.stripped`). Animated images go as they are; video/audio metadata is NOT stripped. |
| Image decoding | Every image from someone else must be JPEG, PNG, HEIC/HEIF, GIF or WebP (no other ImageIO parser is fed), is size-checked from its header (50 MP / 64 MB) and decoded straight to a bounded size. Avatars above 512 kB or 2048 px are not stored. |
| Downloads (macOS) | Decrypted attachments carry `com.apple.quarantine`, so Gatekeeper checks anything opened from "Show in Finder". |
| Links | A markdown link whose label is not its address shows the real address beside it; only http/https/mailto are links; opening asks first with the full address. |
| App switcher | Content is covered by the logo whenever the app is not active (iOS) / hidden (macOS). On by default. |
| Screen security | Optional: blocks screenshots, recording and screen sharing (`NSWindow.sharingType = .none` on macOS; secure-layer container on iOS). |
| Logging | `os.Logger` with fixed strings and counts only; no content, names, ids, codes, tokens, host keys, addresses or IPs. No analytics, crash reporter or other third-party SDK (dependencies: LiveKit client, Sparkle on macOS). |
| Pasteboard | Invites, codes, recovery keys and the owner password are copied as local-only items that expire after 60 s (system expiry on iOS; concealed type + timed clear on macOS). |
| Updates | macOS: Sparkle with one fixed public feed (`SUFeedURL` = build setting `SKWOD_UPDATE_FEED`, the `FlayrLabs/skwod-releases` GitHub repo) — never a Skwod server; archives must verify against `SUPublicEDKey`. Checked once a day, installed on quit, can be switched off in Profile ([SECURITY.md](SECURITY.md) → App updates). Debug builds never update themselves. iOS: only `testflight.apple.com` / `apps.apple.com` links are ever opened. |

## Paywall flag

There is no paywall in this build: nothing checks StoreKit and nothing gates the app, on any
platform. The gate is a compilation condition, `SKWOD_PAYWALL`, that is off by default; every
reference to it in the app is inside `#if SKWOD_PAYWALL`, so the app builds and runs without the
two files that implement it (`Sources/IAP.swift`, `Sources/PaywallView.swift`). **Those two files
are not in the public repository**, and building with the flag needs them:

```sh
xcodebuild … SKWOD_FLAGS=SKWOD_PAYWALL      # only where IAP.swift and PaywallView.swift exist
```

With the flag on, iOS shows a subscription screen when the on-device StoreKit check finds no
active subscription; macOS is never gated. The pricing model is not settled — leave it off.
Android has the same switch (`-Pskwod.paywall=true`, source set `app/src/paywall`, likewise not
published; `app/src/nopaywall` is what a normal build compiles).

## Proving it (end to end)

Debug builds can be driven without taps through environment variables
(`Sources/E2EHooks.swift`; `SIMCTL_CHILD_<NAME>` in the simulator). The real paths run — the
invite arrives through the URL handler, sign-up goes through the connect screen's code. On a Mac
that has a real Skwod install, **always** pass `SKWOD_PROFILE=<name>` and a different bundle id so
the test build keeps its keychain items and data apart. All of this is compiled out of Release.

```sh
# 1. a host: either a bare server …
apps/apple/Resources/host-tools/skwod-server run --data /tmp/skwod-e2e --listen 127.0.0.1:38411
#    … or the Mac app's Start server button (SKWOD_PROFILE=e2e).
# 2. the simulator joins by deep link, signs up and sends a message
SIMCTL_CHILD_SKWOD_E2E_USER=member SIMCTL_CHILD_SKWOD_E2E_PASSWORD=… \
SIMCTL_CHILD_SKWOD_E2E_SEND='hello' xcrun simctl launch booted com.skwod.app
xcrun simctl openurl booted 'skwod://join/<host key>#<code>'
# 3. each client writes what it could DECRYPT to <out>/messages.json
```

Trust flows have commands too (dropped into `<out>/cmd.txt`, one per line; listed at the top of
`Sources/E2EHooks.swift`): `letin` / `decline` for "Waiting to join", `send:` / `edit:` /
`react:`, `safety:<user>`, `verify:<user>` (confirms the number last computed),
`verifynumber:<user>:<digits>`, `safetyqr:<user>`, `scanqr:<user>:<payload>`, `dm:<user>:<text>`
(reports `held` when a verified contact's devices changed), `accept:<user>`, `approvelink:<code>`,
`selfcheck` (metadata stripping, decode bounds, link policy, avatar authority, quarantine). Each
outcome lands in `<out>/e2e.json` with who is waiting, the pinned owners and each contact's
status. `core/skwod-core/examples/e2e_tool.rs` supplies the other actors: `link` (a second device
for an account) and `ghost` (an uninvited account that asks everyone for keys once the test has
inserted it into the server's database).

Build 43b ("the basics") added commands for what that build fixed, each through the same
service calls the buttons use: `photo` / `dmphoto:<user>` (a generated photo as an attachment —
linked to the channel message, or carrying a download token in a DM), `openatt` /
`opendmatt:<user>` (download + decrypt the newest attachment from someone else), `open:feed`,
`feedpost:<text>` / `feedphoto:<text>` (through the Feed screen's own model), `flood:<n>`,
`loadolder`, `listdms`, `rings` (ask every signed-in skwod what is ringing), `background` /
`foreground` (what the scene-phase observer calls) and `join:<code>`. `SKWOD_E2E_ROTATE=1` treats
the stored token as a week old, so the launch rotates it. `e2e.json` gained a `live` section (also
written to `live.json` before the client is in any server): realtime events seen by name, DMs that
arrived and whether each was a copy of our own, every local notification the app asked for, how
many announced channel messages turned out to deserve one, join requests, the invite pre-check
(`invite-check.json` too), session state, the sidebar's DM list, the join status and which channel
each server's feed is in. `selfcheck` covers the "Waiting to join" name checks (zero-width,
Cyrillic look-alike, full-width, plain different name).

Build 44 added a second driver for the ACCOUNT flows, which happen exactly where the main shell
is not on screen (signed out, waiting for a restore, removed): commands go into
`<out>/acct-cmd.txt`, state and outcomes into `<out>/account.json` (`Sources/E2EAccountHooks.swift`
lists them: `devices`, `removedevice:`, `signout`, `erase`, `recoverykey`, `restore:<key>`,
`retryrestore`, `link`, `approverecovery:<code>`, `reset[:pin]`, `forgotpin`, `show:<screen>`,
`selfcheck`, …). The app lock has its own (`lock-cmd.txt` → `applock.json`), since nothing of the
app is mounted while it is locked. `SKWOD_E2E_NSE_HOLD=<seconds>` plays the notification
extension's part of the cache-lock hand-over inside the app process; `account.json → storelock`
then lists the steps in order (the app waiting, the stand-in releasing, the app holding the lock,
the cache opened). `SKWOD_E2E_RELOGIN=1` logs back in after a `signout` command, and
`SKWOD_E2E_LOOPBACK_PROOF=1` lets a bare loopback test server prove its pinned key (the proof
itself is the real one). New chat-side commands: `groupdm:<a>+<b>:<text>`, `acceptgroup`, `groups`,
`upload:<path>`, `uploads`, `resumeuploads`, `fetchatt`, `placeholders`, `reportat:<user>`, `inbox`,
`reportaction:<remove|kick|ban|dismiss>`.

Two things this run taught us about a Mac build driven this way: the very first launch of a
freshly copied `.app` bundle comes up without a window (and then nothing of the app runs) —
launch it once and quit it before the real run; and each concurrent instance needs its own
bundle id (a copy with `CFBundleIdentifier` changed), or they share one preferences domain.

One thing to know when re-running: an ad-hoc-signed Mac build keeps its keys in the login
keychain, and macOS ties those items to the build that wrote them. After a rebuild the same
`SKWOD_PROFILE` can block at launch on a keychain prompt — use a fresh profile name per build.

### Proving a call

Extra switches and commands for calls are listed at the top of `Sources/E2EHooks.swift`. Each
client keeps `<out>/call.json` current: its tracks, their encryption, the frame cryptor's state per
track and the decode counters; and `remote-video-<sid>.png`, the newest frame it could decrypt and
decode from each remote camera. A Mac build also keeps `window-<n>.png`, a picture of its own
windows drawn from the view tree (no screen-recording permission involved; video surfaces and glass
come out empty there).

```sh
# one Mac: a server with its own SFU, no p2p listener
SKWOD_LIVEKIT_BIN=apps/apple/Resources/host-tools/livekit-server \
  skwod run --data /tmp/skwod-call --listen 127.0.0.1:38611 --admin-listen off
# both clients join it over loopback: http://127.0.0.1:38611#<code>
SIMCTL_CHILD_SKWOD_E2E_SYNTHETIC_MEDIA=1 SIMCTL_CHILD_SKWOD_E2E_LOOPBACK_ICE=1 … xcrun simctl launch …
echo call   > <out>/cmd.txt     # then: camera, ring, answer, hangup
lk room participants get --room skwod-<voice channel id> <user id>   # "encryption": "GCM" per track
```

Things this setup taught us:

- **One Mac cannot carry two p2p members in a call.** A member's media forwarder binds
  `127.0.0.1:<the SFU's UDP port>`; the Simulator shares the Mac's network stack, so a second
  member (or the SFU itself) is already on that port. Calls on one machine therefore use the
  loopback address of the server (the "host's own app" path); the p2p tunnel leg is covered by the
  Android run and by `skwod-net`'s tests, not by the Apple run.
- **A call on cellular (or with a full-tunnel VPN).** The media path of a p2p call is
  `127.0.0.1:<port>` on this device (the tunnel's forwarder). WebRTC ignores the loopback interface
  by default and binds one UDP socket per OTHER interface the system path monitor lists. On Wi-Fi
  that socket is answered; on a point-to-point interface it is not: its packets do arrive at
  `127.0.0.1`, but the system routes its own address out of that interface, and a packet from
  127/8 may not leave one (XNU `ip_output.c`, "127/8 must not appear on wire"), so the forwarder's
  reply fails with EADDRNOTAVAIL. Wi-Fi's own address is routed through `lo0`, which is why the
  same call works there. Measured on a Mac with a utun interface; cellular (`pdp_ip0`) is
  point-to-point too, but the phone itself was not measured. Binding the forwarder's socket to
  `lo0` (IP_BOUND_IF) does not help; TCP from such a socket is not answered either.
  - So a call whose server is on loopback ALSO gathers candidates on loopback:
    `LiveKitSDK.setGathersLoopback`, added to the pinned SDK by `livekit-swift.patch` (a public WebRTC
    option the SDK does not expose; `fetch-livekit-swift.sh` fetches the commit and applies it
    before `xcodegen generate`). That socket is bound to 127.0.0.1, reachable from this device
    alone; WebRTC prefers it (network cost 0), and it stays when the phone moves between Wi-Fi and
    cellular. The other interfaces' candidates are what they were, and an external call server
    keeps the SDK's own behaviour. Checked with the pinned WebRTC on a Mac, in one process, against
    a single 127.0.0.1 candidate: `en0` answered 5 of 5 checks, `utun` 0 of 8, `lo0` 5 of 5 and
    chosen. Not checked on a phone.
  - The forwarder counts answers it could not hand over (`P2pVoiceStats.undelivered`), which is
    how the app tells this from a host that does not answer (`VoiceFailure.swift`).
  - Moving between networks during a call: the p2p connection migrates by itself, or the session
    reconnects; then the media port goes to the new connection at once (it used to stay with the
    old one for its 15 s grace).
- **The Simulator has no system call screen.** CallKit accepts an incoming call and ends it about
  a second later. `SKWOD_E2E_AUTOANSWER=1` requests the answer through CallKit at once, which is
  enough to see the answer path open the ring's room.
- **`simctl push` does not run a notification service extension** on the iOS 26 Simulator: the
  push is added as an ordinary notification request by CoreSimulatorBridge and never goes through
  the remote-notification path where extensions run ([PUSH.md](PUSH.md)).

### Not verified (calls)

- Real camera and microphone capture, camera switching, speaker/earpiece routing (the runs used
  generated media; the Simulator has no camera).
- CallKit's incoming screen, answering from the lock screen, the audio-session hand-over
  (`didActivate`), and the VoIP push — all need a signed build on a device and the gateway.
- A call over the p2p tunnel from an Apple client on cellular, with a full-tunnel VPN, and moving
  between Wi-Fi and cellular during a call.

## Release checklist (what only the owner can do)

**iOS / TestFlight**

1. App IDs: `com.skwod.app` and `com.skwod.app.NotificationService`, both with **App Groups**
   (`group.com.skwod.app`) and **Keychain Sharing** (`com.skwod.shared`); the app also with **Push
   Notifications**. Regenerate provisioning profiles (automatic signing does this).
2. Push: an APNs auth key (.p8) for the **gateway** (not for Skwod servers), valid for topic
   `com.skwod.app` and `com.skwod.app.voip`. `SKWOD_PUSH_GATEWAY` is empty in `project.yml`;
   `upload-ios.sh` takes the gateway's URL from the environment or `signing.env`, passes it to
   `xcodebuild`, and refuses to upload an archive that does not carry it. `aps-environment` is `production` in `Skwod-iOS.entitlements`.
3. Background modes `remote-notification`, `voip`, `audio` are declared; App Review expects the
   VoIP mode to be justified by real calls (CallKit is used).
4. Privacy strings are in `project.yml` (camera, microphone, photos, Apple Music, local network).
   `ITSAppUsesNonExemptEncryption` is currently `NO`; the app ships Signal-protocol E2EE, so
   re-check the export-compliance answer.
5. The paywall flag stays off until pricing is decided.

**macOS / Developer ID**

1. `Skwod-macOS.entitlements` carries `keychain-access-groups`, a restricted entitlement: a
   Developer ID build that claims it must **embed a provisioning profile** for `io.skwod.mac` that
   authorizes it, or the signed app will not launch. No such profile exists yet and one cannot be
   created from the command line, so `package-release.sh` **drops the entitlement** for the
   Developer ID build and the released app uses the login-keychain fallback. To ship with the
   data-protection keychain: create a Developer ID profile for the app id (Keychain Sharing) in
   the developer portal and run `SKWOD_MAC_PROFILE=/path/to.provisionprofile ./package-release.sh`
   (that path is written but has never been exercised — test the first build made with it).
2. `package-release.sh` builds the app ad-hoc and makes every shipping signature itself, inside
   out: host tools (`skwod-server`, `livekit-server`), Sparkle's helpers, the frameworks, then the
   app **with** `--entitlements` (microphone, camera). It fails if the signed app lost them.
3. Sparkle: the private EdDSA key stays out of the repo. The feed is the public release repo, so
   p2p-only communities update like everyone else ([RELEASE-SIGNING.md](../RELEASE-SIGNING.md)).
