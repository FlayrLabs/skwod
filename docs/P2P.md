# P2P transport — the host's key is the address

Status: **stage 3 on Apple** (core + server + headless proof + the iOS/macOS apps: invites, deep
links, hosting, reconnect — see [APPLE.md](APPLE.md)). Android is wired the same way; Tor onion hosting
is stage 4.

A host starts the server and gets an invite. Friends open it and are in. No domain, no port
forwarding, no third-party account — and the publisher runs no infrastructure.

```
skwod://join/<node id>#<join code>
             │          └ presented at signup (fragment: never sent by URL handling code)
             └ the host's iroh public key, z-base-32, 52 chars — address AND pinned identity
```

Optional: `?u=https://…` (a VPS address of the same Skwod), `?l=<hex>` (the LAN-discovery key, only when the host turned local discovery on). Unknown query params are ignored.

**The share form (apps from build 42).** What the apps' Copy, Share and QR code hand out is the
same invite spelled as an `https://` link, so that it is tappable in any messenger:

```
https://skwod.io/join#<node id>.<join code>
                      └ all of it is the URL fragment: never sent to skwod.io
```

Optional, after the code: `&u=https://…` and `&l=<hex>`, with the same meaning as above. A link
with a query string, another host, or another path is refused. It opens a static page that
forwards to the `skwod://` form, or the app directly where universal links / app links are set
up (iOS `applinks:skwod.io`, Android `autoVerify`). Every build still accepts `skwod://join/…`;
builds up to 41 accept only that when a link is pasted. The server's admin page and logs still
print the `skwod://` form. Grammar and tests: `core/skwod-net/src/invite.rs`; the page is the
`/join` page of the skwod.io site.

## How it works

| Piece | What | Where |
|---|---|---|
| Identity | Persistent iroh key in `<data>/p2p.key` (0600). Losing it changes the address. | `skwod-net/src/endpoint.rs` |
| Discovery | pkarr record signed by that key, published to the **BitTorrent Mainline DHT** (global addresses + relay URL only); members resolve it there. Optional same-LAN discovery over mDNS, opt-in. | `endpoint.rs`, `lan.rs` |
| Connectivity | iroh QUIC, hole punching, UPnP/NAT-PMP/PCP on the host. | iroh `=1.4.1` (pinned) |
| API | The unchanged axum router, served in-process on each QUIC bi-stream. No extra listener. | `server/src/p2p.rs` |
| Apps | A loopback HTTP proxy inside the app process: `http://127.0.0.1:<port>/<128-bit secret>` replaces the server URL everywhere (Rust core, URLSession, OkHttp, WebSocket). | `skwod-net/src/proxy.rs` |
| Voice/video | LiveKit signaling on a stream (served by hyper, bound to the room named in the LiveKit token); media as QUIC datagrams into a loopback forwarder. LiveKit advertises one ICE candidate, `127.0.0.1:<udp port>`. | `host.rs`, `voice.rs`, `server/src/livekit.rs` |

Stream kinds on ALPN `skwod/1` (one preamble byte): `1` HTTP, `2` LiveKit signaling, `3` voice hello.

### Pinned identity: node id vs. the existing server signing key

Both are carried; they are **independent keys**. The node id is the root pin — the QUIC handshake
fails unless the peer holds its private key, so nothing else needs verifying to know you reached
the right host. The older Ed25519 instance key (`/api/instance/identity`, used for sender
certificates) is fetched *through* that authenticated channel and pinned as before. Deriving one
from the other was rejected: the instance key lives in the database and belongs to the E2EE
layer, which is being replaced independently.

### The host's own app

Uses the **local direct path** (`http://127.0.0.1:<listen port>`, as today) and talks to LiveKit
on loopback directly. Only remote members go through the tunnel.

## `public_fallback`

| | Mainline DHT | n0 relays | n0 DNS/pkarr |
|---|---|---|---|
| `true` (default) | yes | yes — when no direct path exists | yes |
| `false` | yes | **never** | **never** |

Host: `skwod run --public-fallback false` / `SKWOD_PUBLIC_FALLBACK=false`. Member: second argument
of `p2p_connect`. With it off, a connection needs a direct path: same LAN, a public/IPv6 address,
a UPnP mapping, or a hand-forwarded port (`--p2p-port` + `--p2p-external-addr`). Behind a NAT
without any of those, the host is unreachable — that is the price of strict independence.

Other switches: `--no-p2p`, `--local-discovery`, `--admin-listen`, `--wait-for-start`, `SKWOD_NO_MANAGED_LIVEKIT=1`, `SKWOD_TRUSTED_PROXIES`, `SKWOD_OPEN_SIGNUP=1`, `SKWOD_LIVEKIT_BIN`,
`SKWOD_LIVEKIT_UDP_ADDR`, `SKWOD_P2P_DEBUG=1` (lifts the address-free logging — troubleshooting only).

## Who can see which IP

| Observer | `public_fallback=false` | `public_fallback=true` |
|---|---|---|
| Anyone holding the invite / node id | The host's **public** IP:port via the DHT, and when it last published (≤ 1 h granularity). Never a LAN/private/CGNAT/ULA address. | Same, plus the host's relay URL (which n0 relay region it is near). |
| Devices on the host's LAN | nothing, unless the host opted in to local discovery; then a service name that changes hourly and is meaningless without the invite's LAN key, plus the host's private addresses. | same. |
| DHT nodes queried | The querier's IP and the record it asked for. The host's record is stored under — and carries — its public key, so the nodes that store or serve it learn the node id and the host's IP without ever seeing an invite; nodes near that key can log the IP of everyone who looks it up. | Same. |
| The host | Each member's IP on a direct path. Never logged; held in memory only for the per-source connection limiter (≤ 1 min). | Direct: same. Relayed: the relay's address, not the member's. |
| n0 relay | nothing — never contacted. | Both IPs of a relayed connection + packet sizes/timing. Never content (QUIC end to end). |
| n0 DNS (pkarr over HTTPS) | nothing. | The IP of whoever resolves/publishes, and the node id — n0's server only. Since the build-45 audit the member no longer ALSO asks for `_iroh.<node id>.dns.iroh.link` through the system resolver, which put the node id in plaintext DNS for every Wi-Fi operator and ISP on the way. |
| Other members | nothing — all traffic goes via the host. | nothing. |
| LiveKit (on the host) | loopback only; never a member address. | same. |
| The publisher | nothing. No telemetry, no update ping in this layer. | nothing. |

A member uses a fresh throwaway key per session, so the host cannot link sessions by node id.
Message and media content stay E2EE as before; this layer never sees plaintext.

## What the DHT record contains

Signed by the host key, readable by anyone who knows the node id: the node id, up to 8
**globally routable** `ip:port` pairs (a public address, a UPnP mapping, `--p2p-external-addr`),
the relay URL when `public_fallback` is on, and a publish timestamp. No user data, no LAN
addresses, no hostname. n0's DNS (fallback on) gets the node id + relay URL only, never an IP.
The public IP is inherent to being directly reachable; a host that must hide it has to wait for
Tor (stage 4) — running with fallback on and no direct path still reveals the IP to n0's relay.

## Local network discovery (opt-in)

Off by default: a host on café, hotel or office Wi-Fi must not announce itself. The admin page
toggle "Let people on this Wi-Fi find my server faster" (or `--local-discovery` /
`SKWOD_LOCAL_DISCOVERY=true`) turns it on. Then the host answers mDNS as
`<tag>._skwod1._udp.local`, where `tag = HMAC-SHA256(lan key, "skwod-lan-v1" ‖ node id ‖ hour)[..16]`
rotates hourly, and announces only private addresses. The lan key (`<data>/lan.key`) reaches
members in the invite (`?l=`) and from `GET /api/instance/p2p` (`lan_key`, authenticated).
Members announce nothing; they listen and match the tag for the current and previous hour.

Not done: remembering the choice per trusted network (it is one switch per server — fine for a
NAS, not for a laptop that roams; leave it off there). App side: `NetConfig.lan_key` +
`local_discovery` must be set by the caller; `skwod-core`'s `p2p_connect` does not pass them yet,
and iOS/Android need the local-network permission first.

## Abuse limits without IPs

Node ids are free, so nothing rests on counting them alone (`server/src/client_key.rs`,
`core/skwod-net/src/host.rs`):

- **Sign-up / sign-in:** a proof-of-work stamp on every p2p attempt (the loopback proxy adds
  it; ~0.1–0.4 s), per-caller and per-account windows, separate ceilings for direct and
  relayed callers. The difficulty rises while the host is flooded (20 → 26 bits).
- **New connections — admission:**
  1. A direct dial from an address nobody has proven they can receive at is answered with a
     QUIC Retry and counted nowhere: spoofed packets cannot fill the source table, hold
     handshake permits or use up a member's allowance.
  2. 30 new connections a minute per validated IPv4 / IPv6 /64, a token bucket for relayed
     dials, 12 a minute per relayed node id.
  3. Beyond the free allowance a connection is admitted **for work**: its first stream must be
     a connection stamp (2^18 hashes, bound to host, node id and time; single use). Members
     send one on every connection, so a member behind a busy NAT or a drained relay bucket
     still gets in. A build from before this cannot, while its allowance is exhausted.
- **Slots:** 256 of 1,024 are reserved for members; among strangers, one that proved work
  gives way only to another that did; a connection becomes a member's at its first
  authenticated request (not after a 10–60 s timer); when the table is full of members, the
  most recently admitted member gives way to one who has been a member for longer.
- **Per connection:** a stream budget (600 streams per 10 s — streams, not requests), and a
  stream that does not say what it is within 10 s is dropped.

## Seams left open

- **Tor (stage 4).** `proxy::Upstream` is the transport interface the loopback proxy talks to.
  An onion upstream implements `open_http` and everything above keeps working; `NetError::Unreachable`
  is where the caller falls through to it. No onion hosting exists yet, so there is nothing to
  fall back *to* today except an invite's `?u=https://…`.
- **Stable base URL.** The proxy port/secret change every launch. Apps must persist the node id,
  not the URL.

## Reproduce the proof

```sh
# tests (in-process host + member, no network)
(cd core   && cargo test -p skwod-net)
(cd server && cargo test p2p)

# real network: start a host, connect a headless member by invite
server/target/debug/skwod run --data /tmp/skwod-demo --listen 127.0.0.1:38411   # prints Invite: skwod://join/…#…
(cd core && cargo run -p skwod-core --example p2p_member -- 'skwod://join/…#…' --messages 30)
#   --no-fallback      DHT + direct only
#   --addr IP:PORT     skip discovery (same machine / LAN)
#   --voice --hold 120 open the voice tunnel, print the loopback LiveKit URL, show media counters
```

Against the Docker image none of the manual LiveKit setup below is needed (the container runs
its own): see "What was verified" in [SELF-HOSTING.md](SELF-HOSTING.md) for that call test.

Call test: run LiveKit with `rtc.udp_port: P`, `rtc.node_ip: 127.0.0.1`, `rtc.use_external_ip: false`;
store `livekit_url=ws://…`, `livekit_api_key`, `livekit_api_secret`, `livekit_udp_port=P`; then
`lk room join --url <printed LIVEKIT_URL> --identity <user id> --publish-demo <room>`.
On ONE machine LiveKit's UDP port must not sit on `127.0.0.1:P` (the member forwarder owns that):
put it behind a port mapping and point `SKWOD_LIVEKIT_UDP_ADDR` at it. For the same reason only
one member per network stack can be in a call — the iOS Simulator shares the Mac's, so a Mac app
and a Simulator cannot both be p2p members of one call (APPLE.md → "Proving a call").
