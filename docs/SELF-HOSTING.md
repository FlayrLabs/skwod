# Self-hosting Skwod

Skwod hosts nothing centrally. Every server is run by someone in the group, on their own machine.
The server only ever stores **ciphertext, public keys, and routing metadata** — never your
messages or private keys.

Every form below ends the same way: press **Start server**, get an invite
(`skwod://join/<your server's key>#<code>`), open it on your own phone first (the first person in
is the owner), then invite your friends. No account, no domain, no port forwarding: the server's
key is its address ([P2P.md](P2P.md)).

| Where | What you run | Voice + video | Status |
|---|---|---|---|
| [1. A Mac](#1-a-mac-the-app) | the Skwod Mac app | bundled | built and run (see [APPLE.md](APPLE.md) for what was and was not checked) |
| [2. Docker, Unraid, Synology](#2-docker-unraid-synology) ([Unraid guide](UNRAID.md)) | one container | bundled | **verified** on Docker (linux/arm64) — details below |
| [3. A Windows PC](#3-a-windows-pc) | the Skwod host tray app | bundled | **not yet built or run on Windows** — see the section |
| [4. A Linux PC](#4-a-linux-pc) | the Skwod host tray app | bundled | **package not yet built; never run on Linux** — see the section |
| [5. A VPS](#5-a-vps-always-on-your-own-domain) | Docker + Caddy, your domain | not checked on this path | not re-run for this guide |

---

## 1. A Mac (the app)


1. Open the Skwod Mac app → **Start a server**.
2. Type the name you want in your Skwod and click **Start server**. The app runs the bundled server
   and the bundled voice/video server (LiveKit, loopback only), and signs you in as the owner —
   there is no code to copy and no password to invent (one is generated and kept in your Keychain;
   the invite panel can show it if you want to sign in on your phone too).
3. The **Invite your friends** panel opens: a link (`skwod://join/<your server's key>#<code>`) with
   **Copy**, **Share** and a **QR code**. Send it to your friends.
4. They tap the link (or scan the QR), pick a name, and ask to join. You see them under **Waiting
   to join** and click **Let in**. Their app then receives everything it needs, end to end.
   For one person you fully trust, **Create a one-time link** instead: whoever opens it is in at
   once, and it stops working.

**The macOS firewall question.** If the macOS firewall is on, the first start makes macOS ask
whether "skwod-server" (and "livekit-server") may accept incoming connections. Click **Allow**: it
is what lets friends connect straight to your Mac. With **Deny**, Skwod still works but every
connection goes through a relay (slower). Change it later in System Settings → Network → Firewall.

**Your address never changes.** It is the server's key, stored in the data folder (`p2p.key`).
Invites stay valid across restarts, network changes and moving house. Back up the data folder if
you want to keep the same address on a new Mac; losing it means a new address and new invites.

**When your Mac is off or asleep, your Skwod is offline.** Members see "Host is offline", can still
read what is already on their device, and reconnect by themselves when the Mac is back. Under
**Start a server → Keep it running** (the same screen is **Server settings** once it runs):

- **Keep this Mac awake while hosting** — on by default while the Mac is plugged in, off on
  battery unless you switch it on. It stops the Mac going to sleep by itself; the screen can still
  turn off, and closing a MacBook's lid still puts it to sleep.
- **Start Skwod when I log in** — after a restart of the Mac, Skwod starts in the menu bar and
  brings the server up without opening a window. macOS may ask you to allow it in System Settings >
  General > Login Items; the screen says so when it is waiting for that.

**If the server stops by itself, the app starts it again** — after 2, 5, 15, 30 and then every 60
seconds, showing "Restarting…" with the reason. It only gives up, with a sentence saying what to
do, when the problem is one you have to fix (the storage folder cannot be written, the disk is
full, the data is damaged).

**Quitting Skwod stops your server**, so it asks first: "Quit Skwod? 4 members will go offline
until you start it again." — **Keep running** or **Quit**. Logging out or shutting down the Mac is
never held up by that question.

**Updates ask while you are hosting.** Skwod normally installs a downloaded update when you quit.
While the server is running it never relaunches for an update on its own: you get "An update is
ready. Installing it restarts your Skwod server — members will be offline for about a minute." with
**Install now** / **Later**, and the server comes back by itself after the relaunch.

**The port.** The app talks to its own server on this Mac at `127.0.0.1:4820`. If another program
already uses 4820, Skwod takes the next free port up to 4839, remembers it, and you stay signed
in; if all twenty are taken it says so instead of starting. Friends never use this port — they
connect with your invite. Before the app sends your login to that port it checks that the program
answering there is the server it started itself.

**Direct or relayed.** Members connect straight to your Mac when a direct route exists and through
an independent relay otherwise; the app shows which ("Connected directly" / "Connected through a
relay"). A relay sees that two devices are talking, never what is said. To forbid relays entirely,
turn off **Use a relay when a direct connection isn't possible** under Options before starting —
then only friends who can reach your Mac directly can connect (docs/P2P.md, `public_fallback`).

> Earlier builds reached a Mac host through a Cloudflare tunnel (a `trycloudflare.com` address, or
> your own domain). That is gone: the app no longer bundles or talks to anything from Cloudflare.
> Members of such a Skwod keep their account — the host sends them a new `skwod://` invite, they
> paste it under **Log in**, and the app recognises the Skwod by its pinned key and switches over
> without signing in again.

---

## 2. Docker, Unraid, Synology

For a box that is always on. One container holds the server and a pinned LiveKit (voice and
video); there is nothing else to run and nothing else to expose.

> **On Unraid?** Follow **[UNRAID.md](UNRAID.md)**, a step-by-step guide for people who have never
> used Docker. The rest of this section is the short version.

**Get the image.** Either use the published one, `ghcr.io/flayrlabs/skwod-server` (linux/amd64
and linux/arm64, signed; see "Which image" below), or build it yourself. Building works with plain
`docker build`, and BuildKit is not required:

```bash
git clone https://github.com/FlayrLabs/skwod.git && cd skwod
docker build -t skwod-server .          # about 2 GB of RAM and 5 GB of disk while it builds
```

**Docker / Synology Container Manager / Portainer** — copy
[`deploy/docker-compose.yml`](../deploy/docker-compose.yml) into a project (Synology: Container
Manager → Project → Create), then:

```bash
SKWOD_IMAGE=skwod-server docker compose up -d
docker compose logs skwod     # "One-time admin token: XXXXX-XXXXX-XXXXX-XXXXX"
```

`SKWOD_IMAGE` is required; the compose file has no default and refuses to start without it.
`skwod init` writes and starts this same file, so it needs `SKWOD_IMAGE` in its environment too.

**Which image, and why by digest.** The server holds your skwod's keys, so the image is as
trusted as the server itself. Two safe choices:

- **The image you built** (above). You are the publisher; nothing more to check.
- **A published image, pinned by digest and verified.** For compose, do not use a tag: a tag is
  a name the registry can point at different content tomorrow. A digest (`name@sha256:<64 hex>`)
  is the image's own hash, and Docker refuses anything that does not match it.

  ```bash
  IMAGE=ghcr.io/flayrlabs/skwod-server@sha256:<digest from the release notes>
  deploy/verify-image.sh "$IMAGE"        # digest-pinned AND cosign-signed by the release workflow
  SKWOD_IMAGE="$IMAGE" docker compose up -d
  ```

  `verify-image.sh` runs `cosign verify` (cosign 3 or newer). It pins the signer to the source
  repository's image workflow, run on a `skwod-v<n>` release tag (keyless
  Sigstore; the signature is in the public Rekor log). Each release's notes carry the digest, and
  so does the image workflow's run summary. The publishing and signing procedure is in
  `RELEASE-SIGNING.md`, under *The Docker image*. To update, change the digest on purpose; nothing
  updates behind your back.
- **`:latest`, for Unraid's "check for updates".** The Unraid template uses
  `ghcr.io/flayrlabs/skwod-server:latest`. The image workflow moves that tag only after the new
  build has passed its smoke test on both architectures and its signature has been verified. You
  still trust whoever can run that workflow, so if you want to decide each update yourself, pin a
  digest in the template instead ([UNRAID.md](UNRAID.md#updating)).

**The admin page is on this machine only.** The compose file publishes port 3477 on
`127.0.0.1`, not on your LAN. The page is plain HTTP, and until the skwod has an owner it shows
the owner setup code — anyone who could watch your Wi-Fi (or a compromised gadget on it) could
read that and become the owner first. On the box itself open `http://127.0.0.1:3477`. From
another computer, tunnel over SSH and use the same address:

```bash
ssh -L 3477:127.0.0.1:3477 you@the-box      # keep it open; then browse http://127.0.0.1:3477
```

Synology: enable SSH (Control Panel → Terminal & SNMP) for the setup and switch it off again.
`SKWOD_ADMIN_BIND=0.0.0.0` puts the page back on the LAN; do that only on a network where you
trust every device, and never on a VPS (Docker's published ports bypass `ufw`).

**Unraid**: see **[UNRAID.md](UNRAID.md)**. In short: download
[`deploy/unraid/skwod.xml`](../deploy/unraid/skwod.xml) to
`/boot/config/plugins/dockerMan/templates-user/my-skwod.xml`, then Docker tab → Add Container →
Template **skwod** → Apply (or install it from Community Applications once it is listed). The token
is in the container's **Logs**. The template publishes the admin page on the Unraid box's
`127.0.0.1` only, so reach it with `ssh -L 3477:127.0.0.1:3477 root@<unraid>`.

Then, on the box or through the SSH tunnel:

1. Open `http://127.0.0.1:3477` and type the token. Each token works once; restart the container
   for a new one.
2. Press **Start server**. You get an invite with a QR code.
3. Open the invite on **your own phone first** — the first person in becomes the owner.
4. Create a space in the app, then press **New invite** on the page (or invite from the app) for
   each friend. Friends ask to join; you approve them in the app.

Good to know:

- **Back up the data folder/volume.** It holds the keys that *are* your server's address.
- **Do not forward port 3477** on your router, and leave it on `127.0.0.1` (above).
- Friends reach the server by its key. When a direct connection is impossible they go through a
  public relay that sees only encrypted traffic (`SKWOD_PUBLIC_FALLBACK=false` forbids that).
  Forwarding UDP 47474 on your router is optional and should make direct connections more likely.
- The container is hardened: read-only root filesystem, no capabilities, non-root, no privilege
  escalation. An existing root-owned data folder is repaired once, automatically: the compose
  file's `init-permissions` step does it; the Unraid template starts as root with three
  capabilities, repairs the folder, and drops to an unprivileged user with none before it opens a
  socket.

### What was verified (2026-11-17, Docker in a linux/arm64 VM on a Mac)

Image built with the classic builder; `docker compose up -d` from `deploy/docker-compose.yml`
with a fresh volume.

| Check | Result |
|---|---|
| Admin page | token from the log signs in once (second use 401); without it 401; a POST without the page's header 403; **Start** → `phase: running`, `p2p: true`, `voice: true`, an owner invite and its QR code; the API answers 503 until Start |
| p2p | `core/skwod-core/examples/p2p_member.rs` connected by the invite from the Mac, signed up as owner, created an E2EE space, sent 5 messages and read all 5 back decrypted. Path: **n0 relay** (the VM's UDP port is not reachable from the Mac, so a direct path could not form) |
| Call | through the container's own LiveKit: a publisher on the Mac via the member's p2p voice tunnel, a second participant on the container's loopback. `lk room join --publish-demo` video arrived at the second participant. Then an Opus track published with LiveKit's GCM frame encryption (Go SDK): the SFU lists it as `encryption: GCM`; the receiver opened 680 frames with the call key, 0 with a wrong key, and the plaintext marker was never visible on the wire |
| Upgrade | a volume written by a root-run server: the default non-root start refuses with the fix-it message; `skwod fix-ownership` (compose's init step) re-owns it and is a no-op the second time; the Unraid-style start (`--user 0:0`, caps `CHOWN,SETUID,SETGID`) re-owns it and then runs `skwod` **and** `livekit-server` as uid 1000 with `CapPrm/CapEff/CapInh/CapAmb = 0` and `NoNewPrivs: 1`; healthcheck `healthy` |

**Mac → Docker move (2026-11-22, linux/arm64 VM).** A data folder made by the Mac app's bundled
server (owner, member, server, channel, messages, an approval invite) was exported with
`skwod backup`, restored with the root-run `docker run … skwod restore` from
[UNRAID.md](UNRAID.md#moving-your-skwod-from-a-mac-to-unraid) and started with the Unraid
template's flags. The result had the same instance identity and the same p2p node id. The old
invite still checked valid, both accounts signed in again, the old ciphertext came back
byte-identical, a new message went through, LiveKit ran with a freshly written loopback
`livekit.yaml`, and everything ran as 99:100. The test found, and this build fixes, a
`fix-ownership` bug: it re-owned a 0700 directory before its contents, which locked the walk
(root with only `CAP_CHOWN`) out of `blobs/`. Not checked here: decryption by the real apps
after the move. The server stores the same bytes, and the apps keep their own keys.

Not verified: an **amd64** build (the Dockerfile has no architecture-specific step other than the
LiveKit download, whose amd64 archive and checksum were fetched and verified, but the image was
only built for arm64; the image workflow builds and smoke-tests amd64 on its first run); a real Unraid or Synology box (the template's flags were run with plain
`docker run`); a **direct** p2p path to a container (published UDP port / router forward); the
call test with the Skwod apps as clients (the encrypted-call check used LiveKit's SDK with a
shared test key, not the apps' libsignal-distributed keys).

---

## 3. A Windows PC

The **Skwod host** app (`host/`): a tray icon that runs the bundled server and a pinned LiveKit,
opens the admin page in your browser, and has **Start server**, **Stop server**, **Launch at
login** (off until you tick it) and **Quit**.

> **Status: not built for Windows and never run on Windows.** The app's Windows code
> type-checks and lints (`cargo clippy --target x86_64-pc-windows-gnu`), and the same app was run
> on macOS against the real server. What remains: run `host/packaging/docker-build.sh windows`
> (cross-compiles the server and the app with mingw-w64, downloads the pinned
> `livekit-server.exe` — its checksum was verified — and builds the NSIS installer; the script
> and `installer.nsi` have not been executed yet), then on a real Windows 10/11 PC check: the
> installer, the tray icon and menu, the firewall prompt, voice through the bundled LiveKit, Launch
> at login, uninstall. The installer is unsigned; SmartScreen will warn until it is code-signed.

How it is meant to go, once built:

1. Run `skwod-host-setup-<version>-x64.exe` (installs for your user only; no administrator
   rights). Start **Skwod host**; its icon appears next to the clock and the admin page opens.
2. A one-time note explains the firewall question. Press **Start server**. Windows may ask
   whether "skwod" may communicate on your networks: choose **Allow** (Private is enough). With
   **Cancel**, Skwod still works, through a relay.
3. Open the invite on your own phone first; then **New invite** for each friend.

The server's data (database, keys — your server's address) is in `%LOCALAPPDATA%\skwod-host`;
back it up. Uninstalling leaves it in place. When the PC is off or asleep, your Skwod is offline.

---

## 4. A Linux PC

The same **Skwod host** tray app as on Windows.

> **Status: the package has not been built, and the app has never run on Linux.** Its Linux
> code type-checks and lints (`cargo clippy --target x86_64-unknown-linux-gnu`), its tests pass
> on macOS, and it was run there headless against the real server: it started the server, the
> admin page answered, **Start** produced an invite, a second launch did not start a second
> server, Ctrl-C shut the server down cleanly, and the next launch resumed hosting. What remains:
> run `host/packaging/docker-build.sh linux` (not executed yet), install the `.deb` on a
> desktop, and check the tray icon, the first-run note, voice through the bundled LiveKit and
> Launch at login. On a server without Docker the Docker image (section 2) is the tested path.

How it is meant to go, once built:

```bash
sudo apt install ./skwod-host_<version>_<arch>.deb     # Debian 12+, Ubuntu 24.04+
skwod-host                                             # or "skwod host" in the app menu
```

- The tray icon needs AppIndicator support: KDE, XFCE, Cinnamon and MATE have it; on GNOME install
  the "AppIndicator and KStatusNotifierItem Support" extension (Ubuntu ships it). Without a tray
  the server and its page still work; the page is at `http://127.0.0.1:3477`.
- No display at all (a headless box): `skwod-host --no-tray --start` runs the server until
  Ctrl-C and prints where the one-time admin token is. A `.tar.gz` with the same three programs
  is built next to the `.deb` for other distributions.
- If you run a firewall (ufw, firewalld) nothing has to be opened; allowing incoming UDP for
  Skwod only makes direct connections more likely.
- Data: `~/.local/share/skwod-host` (mode 0700). Back it up.

---

## 5. A VPS (always-on, your own domain)

You need:

- A Linux VPS with a public IP (any provider — a 1 GB box is plenty to run).
- A domain (or subdomain) with a **DNS A record pointing at the VPS**, e.g. `chat.example.com`.

Then, on the box:

```bash
git clone https://github.com/FlayrLabs/skwod.git
cd skwod
sudo ./deploy/vps-install.sh chat.example.com you@example.com
```

That one command:

1. Installs Docker if it isn't already there.
2. Gets and auto-renews a real HTTPS certificate for your domain (Caddy + Let's Encrypt).
3. Starts the ciphertext-only Skwod server behind the proxy.
4. Prints your **URL** and a **one-time owner setup code**.

Finish setup in the app: **Connect to a server** →

- Server address: `https://chat.example.com`
- Join code: the setup code the script printed

You become the owner, and that setup code stops working. Now invite friends from inside the app.

> Building the image from source wants ~2 GB RAM. On a 1 GB box, either add swap, or set
> `SKWOD_IMAGE=<prebuilt-image-ref>` before running the script to pull an image instead of building.

### Managing the VPS instance

From the `deploy/` directory:

```bash
docker compose -f docker-compose.vps.yml -p skwod ps        # status
docker compose -f docker-compose.vps.yml -p skwod logs -f   # follow logs
docker compose -f docker-compose.vps.yml -p skwod restart   # restart
docker compose -f docker-compose.vps.yml -p skwod down      # stop
```

**Updating:** `git pull` then re-run `sudo ./deploy/vps-install.sh chat.example.com`. It rebuilds and
restarts in place; your data and owner are untouched (the setup code is not regenerated).

**Backups:** all state lives in the Docker volume `skwod_skwod-data`. See
[Backing up, restoring and moving a skwod](#backing-up-restoring-and-moving-a-skwod).

### Using Postgres instead of SQLite (optional)

SQLite (the default) is ideal for small-group self-hosting — one file, nothing else to run. If you'd
rather point the server at a Postgres database (e.g. a managed instance, or to share one DB across
services), pass `--database-url`:

```bash
skwod run --data ./skwod-data --listen 0.0.0.0:3000 \
  --database-url postgres://user:password@db-host:5432/skwod
```

The same flag works on `skwod init` and `skwod migrate`. The server applies its Postgres migrations
automatically on boot. Messages stay end-to-end encrypted either way — Postgres, like SQLite, only
ever stores ciphertext.

---

## Backing up, restoring and moving a skwod

Everything a skwod **is** lives in its data folder: the database (accounts, ciphertext, the
instance key), the attachment ciphertext (`blobs/`) and the key whose public half is the
skwod's address (`p2p.key`). Put that folder on another machine and it is the same skwod — same
address, same invites, same members; nobody has to be invited again.

**What happens by itself**

- **A daily snapshot of the database**, in `<data>/snapshots/daily-YYYY-MM-DD.db` — a consistent
  copy (`VACUUM INTO`, taken while the server runs), the newest seven kept. It covers "yesterday's
  mistake"; it is on the same disk, so it is not a backup against losing the disk, and it does
  not include attachments.
- **A copy before every schema change**: when an update is about to migrate the database, the
  database as it was is kept first, as `snapshots/pre-migrate-v<N>-<date>.db` (newest three). If
  that copy cannot be taken (disk full), the server says so and does not start, rather than
  migrate without a way back.

Files in `snapshots/` (and everything a backup or restore writes) are readable by the server's
user only (`0600`, directories `0700`).

**A real backup: one encrypted file**

```sh
skwod backup  --data <data> --out /somewhere/else/skwod.skwodbackup
skwod restore --in  /somewhere/else/skwod.skwodbackup --data <new data folder>
skwod restore --in  … --data … --verify-only      # check a backup without restoring it
skwod move-data --from <data> --to <new place>    # same skwod, new folder (server stopped)
```

- The passphrase is read from `SKWOD_BACKUP_PASSPHRASE`, from `--passphrase-file <file>` (first
  line), or asked for. It needs 14 characters or more; a short one or a PIN is refused. Argon2id
  (64 MiB, 3 passes) turns it into the key that wraps a random archive key; the archive is
  ChaCha20-Poly1305 in 1 MiB chunks. **Without the passphrase the file cannot be opened** — by
  anyone, you included.
- `backup` is safe while the server is running (the database is copied consistently). It
  refuses to write inside the data folder.
- `restore` changes nothing unless the whole file opens, authenticates and holds a healthy
  database: it unpacks into a private scratch folder next to the target and moves it into place
  at the end. A folder that already holds a skwod is refused; `--replace` sets the existing one
  aside as `<data>.replaced-<time>` (it is never deleted). Stop the server first.
- **A restore is the skwod as it was, including everything revoked since.** So a restore
  signs everyone out (every session and push registration ends; members sign in again and
  their devices prove themselves), drops the one-time prekeys (some were handed out after the
  backup; devices upload fresh ones), and — when it replaces a skwod whose database can still
  be read — prints what it brought BACK: devices that had been removed, members that had left
  or been removed, bans that are gone, deleted accounts that exist again, retired recovery
  keys that are in force again. The same list is saved as `restore-report.txt` in the data
  folder. Nothing on it is undone for you (a restore is also how you recover from a mistaken
  removal): remove, ban and delete again what should stay gone, and tell the people whose
  removed device is listed.
- `restore --verify-only` streams the archive and writes nothing but a temporary copy of the
  database (to check it), which it removes.
- Not covered: a Postgres database (`--database-url`). Back that up with `pg_dump`; the data
  folder still holds the attachments and keys.

**Mac app** — Start server → Options → **Backup**: *Export…* writes that same file (and includes
this Mac's saved host login, so the new Mac can sign you in); *Import…* on another Mac restores
it. **Storage folder → Move…** moves the skwod to the folder you choose; it no longer starts a
new, empty server there.

**Docker / Unraid** — the container's data folder is `/data`. Write the backup to a second
mounted path so it lands on the array, not inside the appdata folder being backed up:

```sh
# Unraid: add a path mapping to the container first, e.g. /mnt/user/backups/skwod → /backup
docker exec -e SKWOD_BACKUP_PASSPHRASE='a long passphrase you wrote down' skwod \
  skwod backup --data /data --out /backup/skwod-$(date +%F).skwodbackup

# Check it
docker exec -e SKWOD_BACKUP_PASSPHRASE='…' skwod skwod restore --in /backup/skwod-2026-11-19.skwodbackup --data /data --verify-only

# Restore onto a new box: with the container STOPPED, into an EMPTY appdata folder
docker run --rm -e SKWOD_BACKUP_PASSPHRASE='…' \
  -v /mnt/user/appdata/skwod:/data -v /mnt/user/backups/skwod:/backup \
  ghcr.io/flayrlabs/skwod-server:latest skwod restore --in /backup/skwod-2026-11-19.skwodbackup --data /data/restored
# …then move the contents of /mnt/user/appdata/skwod/restored up one level and start the container.
```

On Unraid the User Scripts plugin can run the first command nightly. (`restore` needs a target
folder it can create or that is empty, which is why the example restores into a subfolder of
the mounted volume.) These commands were run against a local data folder and through the Mac
app's bundled binary; they were **not** run on a real Unraid box.

## Limits and lifetimes you can tune

All optional environment variables of `skwod run`; the defaults suit a group of friends.

| Variable | Default | What it does |
|---|---|---|
| `SKWOD_REQUIRE_BOUND_SESSIONS` | on | Once an account has a device, a sign-in that has not proved which install it is (the password alone) reaches only linking, restoring and binding. Build-45 apps bind before their first request; an app from before build 45 stops working against this server until it is updated. `0` (or `false`, `no`, `off`) turns it off for hosts whose members cannot update yet — update the host first, the members next, then remove the `0`. A superseded or removed install is refused everything regardless of this. Devices registered before build 44 keep working until their own install has claimed them. |
| `SKWOD_REQUIRE_DEVICE_PROOFS` | on | Clearing a channel, clearing, purging or deleting a space and changing the voice server need a request signed by the device of whoever does it, not just a session of it. Build-45 apps sign them. `0` turns it off (an unsigned request from a current install is then accepted again). |
| `SKWOD_ADMIN_LOCAL_PEERS` | none | Addresses or CIDRs, besides this machine, that the admin page may send the **owner setup code** to. The page is plain HTTP: name only addresses on the host itself (for example a container network gateway that is not detected). |
| `SKWOD_MAX_UPLOAD_MB` | `100` | The largest **single file** a member may send, in megabytes (1 to 1900). The apps read it from the server, refuse a larger file before encrypting it and show this number; the server refuses it too, whatever the app believed. |
| `SKWOD_BLOB_QUOTA_MB` | `5120` | Attachment storage one account may hold (declared sizes of all its uploads). A member who hits it is told to delete messages with attachments or ask you for more. |
| `SKWOD_BLOB_FREE_FLOOR_MB` | `1024` | Uploads are refused while the data volume has less free space than this, so attachments cannot fill your disk. |
| `SKWOD_MESSAGE_QUOTA_MB` | `512` | Message storage one account may hold: the ciphertext of its channel messages, DM rows, reactions and attachment descriptions. `0` = unlimited. One message is at most 256 KiB whatever this says. The same free-space floor applies: below `SKWOD_BLOB_FREE_FLOOR_MB` no new message is stored either. |
| `SKWOD_INVITE_PENDING_SIGNUPS` | `10` | How many accounts created with one invite may be waiting (admitted to no server) at once. Approve the request, or delete the account, to free a place. |
| `SKWOD_TRUSTED_PROXIES` | none | Reverse proxies whose `X-Forwarded-For` is believed, as IPs/CIDRs. **Nothing is trusted by default, not even loopback** (it was, before build 45): if you run your own reverse proxy on the same machine, set `127.0.0.1,::1`, or every member shares one rate-limit bucket. The bundled VPS compose file already names its Caddy. |
| `SKWOD_PUSH_GATEWAYS` | the build's | Push-gateway hosts this skwod will call. Official builds carry the publisher's gateway as the default; a build without one lets the instance owner's own app choose the host, and nobody else. |
| `SKWOD_SESSION_TTL_SECS` | 30 days | A sign-in ends this long after its **last use**. People who open the app now and then stay signed in. |
| `SKWOD_SESSION_MAX_SECS` | 1 year | …and at the latest this long after signing in, however active. |
| `SKWOD_WS_PING_SECS` | `20` | How often open app connections are pinged; one that is silent for 2½ intervals is closed (a phone that went to sleep then gets push wakes again). |
| `SKWOD_WS_ACK_MS` | `3000` | How long (± a random 0–750 ms; minimum 1000) an open app connection has to answer the probe sent after a message, sealed-mail or ring event before the device is push-woken anyway. |

**Changing the upload limit.** Three ways, the same setting:

- Docker and other self-hosting: set `SKWOD_MAX_UPLOAD_MB` (for Compose, in the `environment:`
  of the `skwod` service) and restart.
- The Mac app: Profile → Server settings → **Largest file a member can send**. It applies at
  once, without a restart.
- Any host, as the owner account: `PUT /api/instance/limits` with `{"max_upload_mb": 250}`
  (`null` clears it). `GET /api/instance/limits` shows the value in force.

A value chosen by the owner (the Mac app or the `PUT`) is stored in the database and **wins over
the environment variable** until it is cleared. It must fit on the disk as it is: the server
refuses a limit larger than the free space above `SKWOD_BLOB_FREE_FLOOR_MB`. It is a limit per
file; `SKWOD_BLOB_QUOTA_MB` still caps what one account holds in total, so a limit above the
quota is not usable. Members on app builds before 45 keep their built-in 100 MB cap for
sending, and are told the host's number when the server refuses a file. Raising the limit was
tested against the server only; sending a file of several hundred megabytes from a phone over a
relayed connection was **not** tested.

Uploads that were never finished, or never attached to a message, are removed after 24 hours.
Only accounts that are a member of a space can upload. Startup problems (the port is taken, the
disk is full, the data file is damaged or in use) are reported as a sentence on stderr, prefixed
`[skwod]`, with exit code 75 (port) or 74 (data).

## Story music: your server fetches the previews

When a member opens a story that has a song, their app does not fetch the song's preview from
Apple (Apple would see every viewer's IP address). It asks **your server**, which fetches the
~1 MB audio file from Apple's preview CDN and hands it back (`POST /api/music/preview`).

What that means for you as the host:

- The same goes for **song cards in chats and posts**: their audio, and their cover images
  (`POST /api/music/artwork`, from `is1…is5-ssl.mzstatic.com`), are fetched by your server.
- **Outbound HTTPS to `audio-ssl.itunes.apple.com`** (and `is1-ssl.mzstatic.com` … `is5-ssl.mzstatic.com` for covers) must be allowed from the server. Behind a
  firewall or in a container with no outbound access, stories still show their song but play
  no sound ("couldn't load the song"). Nothing else on the server needs the internet for this.
- **Apple sees your server's address**, not your members'. A song is fetched at most once per
  ten minutes (a small in-memory cache, at most ~100 MB, emptied on restart).
- **You could learn what your members listen to**: the request comes with the member's
  session, so the server knows which account asked for which preview, and when. Skwod does not
  log it and keeps no record; the URL is in the request body, so a reverse proxy's access log
  does not contain it either. Please keep it that way — do not add body logging in front of
  the server. Members who would rather you not learn it unasked can turn on **Play story
  music only when I tap**; see `docs/SECURITY.md`, "Story music".
- **It is not an open proxy.** Only members of a space can use it, only for Apple's preview
  files (exact host, `https`, audio only, 4 MB, 15 s), never to private or local addresses,
  120 requests per member per hour. There is nothing to configure and no way to widen it.
- Members on a server older than build 45 get no story sound (the apps never fall back to
  fetching from Apple directly); update the server.

This was tested against a stand-in for Apple's CDN (redirects, oversize, non-audio, private
addresses) and one real preview URL's headers were checked; playing a story's song end to end
through a real host on real phones was **not** tested.

## Inviting people

The owner setup code is a **one-time bootstrap** — it claims the server for you and then dies. It is
**not** how friends join. Everyone else joins with a proper invite:

1. In the app, open your space → **Invite**.
2. Create a **shareable code** (needs your approval — the safe default) or a **one-time link**
   (auto-joins). Codes expire in 7 days by default and you can **revoke** any of them instantly.
3. Send the code to your friend. They enter it in **Join a server** — nothing else to paste.
4. For an approval code, you'll see them in **Pending requests**; approve, and their app
   automatically receives everything it needs to see the channels. No keys to copy.

Security model in one line: possessing a code doesn't grant message access — approval does, and
every key that lets a new member read channels is delivered end-to-end encrypted, never by the
server. See [SECURITY.md](SECURITY.md) for the full picture.

---

## Content policy & operator responsibilities

Running a Skwod makes you the operator of a small social platform. Be honest with yourself about
what that means before you invite strangers.

**What you cannot do.** The server only ever stores ciphertext — you cannot read, scan, filter, or
moderate the *content* of channels, DMs, or attachments, even with full access to the box. That is
the point of the design, and it is an accepted tradeoff: **no server-side content scanning is
possible**. There is no lawful-intercept switch, no "admin view", and adding one would mean breaking
the encryption for everyone.

**What you can do.** Moderation works on the metadata layer, and the levers are real:

- **Delete a message** — the author (or a moderator with Manage Messages) tombstones it: the row
  stays for ordering, the ciphertext is blanked on the server.
- **Purge** — retention cleanup: hard-delete all channel messages in a server older than a cutoff
  (Manage Server).
- **Kick** — remove a member from a server. They keep their account and can rejoin with a new
  invite.
- **Ban** — kick plus a server-side ban that every join path enforces: no invite (not even a
  pre-existing one) readmits them until you unban. Requires the Ban Members permission.
- **Block** (per-user) — anyone can block another user; the server then refuses DM traffic between
  the pair. Self-serve, no moderator needed.
- **Delete an account** — the instance owner can delete any account outright; all their data
  cascades away.
- **Delete the server/space** — the owner's nuclear option.
- **Invite control** — invites expire (7 days by default), are revocable, and are rate-limited;
  approval-mode codes put a human between a code and membership.

**Your abuse signal: reports.** Because you can't scan content, **user reports are your primary
signal**. Any member can file a report (in the app, or `POST /api/reports`) with a category and —
Signal-style — an excerpt or description *they choose to disclose in plaintext*. Nothing is
decrypted server-side; the reporter shares their own copy. As instance owner you can list and
resolve reports (`GET /api/reports`, owner account only). Check the queue; it is the only inbox
abuse will arrive in.

**The law still applies to you.** E2EE limits what you can see, not what you're responsible for.
Depending on your jurisdiction you may have legal obligations as an operator — for example
**mandatory reporting of child sexual abuse material (CSAM)** you become aware of (in the US,
reports go to NCMEC; other jurisdictions have equivalents), honoring **takedown requests**, and
responding to lawful process. "I couldn't read it" does not excuse ignoring a credible report you
received in plaintext. Know the rules where you operate, act on reports promptly (ban + account
deletion + preserving what you were sent), and don't host communities you aren't prepared to
moderate.

---

## FAQ

**Do I need a join code to connect?** Yes — initialized instances require an invite to sign up. This
is what keeps strangers off your server.

**Is voice/video included?** The Mac app bundles a pinned LiveKit build, and the Docker image
runs a pinned LiveKit inside the container — calls through the container were verified (section
2). The Windows and Linux host packages are built to carry the same pinned, checksum-verified
LiveKit next to `skwod` (`deploy/fetch-livekit.sh`), but those packages have not been built or run
yet. LiveKit listens on loopback only, and members reach it through their p2p connection.

**Can the host read my messages?** No. The server (yours or a friend's) only ever holds ciphertext.
Even with full access to the box, the operator can't read channel or DM contents.

**What if I lose the owner setup code before claiming the server?** Re-run the installer on a fresh
data volume, or `docker compose ... down -v` to wipe and start over (this deletes all data).

## Notes from the build-45 audit for hosts

- **The data folder is private.** The server creates it 0700 (database 0600) and removes group
  and other access from it and from what is directly inside at every start. If another program
  on the machine read files from it, it no longer can — that is the point.
- **The owner setup code is shown on the host only.** The admin page is plain HTTP, so the
  code is sent to a browser on the same machine (in Docker: one reaching the page through the
  port published on `127.0.0.1`) and to nobody else; from another computer the page says a
  code exists. Use an SSH tunnel (`ssh -L 3477:127.0.0.1:3477 you@host`) and open
  `http://127.0.0.1:3477`.
- **Banning someone from the whole instance:** deleting an account from the owner's app
  removes it; with the ban option (`DELETE /api/auth/users/<id>?ban=1`) its name and device
  keys cannot be used here again and the invite it came in with stops working for everyone.
- **A declined join request stays declined** for that invite. Send the person a new invite to
  change your mind.

