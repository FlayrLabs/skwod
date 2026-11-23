# Host Skwod on Unraid

This guide is for people who have an Unraid server and have never used Docker. At the end you
will have your own Skwod running on Unraid: a private, end-to-end encrypted group chat with voice
and video calls, for you and your friends. Plan on about 20 minutes.

**What you are setting up.** Skwod has two parts:

- **The apps** (iPhone, Mac, Android) are what you and your friends chat in.
- **The server** keeps the scrambled messages and passes them between the apps. It can't read
  any of them. This guide puts the server on your Unraid box.

**What you don't need:** a domain name, port forwarding on your router, or an account with
anyone. Your friends' apps find your server by its *key*, which is a long random name it creates
for itself. You share it inside an invite link.

A few words used below:

- **Container**: an app packaged for Unraid's Docker tab. Skwod's server is one container.
- **Template**: a small file that fills in the container's settings for you.
- **appdata**: the folder on your array where containers keep their files
  (`/mnt/user/appdata/...`).
- **Terminal**: a window where you type commands. Unraid has one built in, and so does your
  computer (Terminal on a Mac, PowerShell on Windows).

---

## Contents

1. [What you need first](#1-what-you-need-first)
2. [Add the Skwod template](#2-add-the-skwod-template)
3. [Check the settings](#3-check-the-settings-mostly-leave-the-defaults)
4. [Press Apply](#4-press-apply)
5. [Find the one-time admin token](#5-find-the-one-time-admin-token)
6. [Open the admin page safely](#6-open-the-admin-page-safely)
7. [Start the server and become its owner](#7-start-the-server-and-become-its-owner)
8. [Create a server and invite friends](#8-create-a-server-and-invite-friends)
9. [Voice and video calls](#9-voice-and-video-calls)
10. [Updating](#updating)
11. [Backups](#backups)
12. [Moving to another box](#moving-to-another-box)
    - [Moving your Skwod from a Mac to Unraid](#moving-your-skwod-from-a-mac-to-unraid)
13. [Troubleshooting](#troubleshooting)
14. [For the cautious: pin an exact image](#for-the-cautious-pin-an-exact-image)

---

## 1. What you need first

1. **Unraid 6.12 or newer, or any 7.x**, with the array started.
2. **Docker turned on.** Open **Settings → Docker** and check that **Enable Docker** says **Yes**.
   If you see a **Docker** tab at the top of the web page, it's on.
3. **SSH turned on**, so you can open the admin page safely in step 6. Open
   **Settings → Management Access** and check that **Use SSH** says **Yes**. It is on by
   default.
4. **The Skwod app on your own phone or computer.** Get it from [skwod.io](https://skwod.io).
5. About 1 GB of free space on the drive that holds appdata, and about 800 MB of free memory.
   The container is limited to 768 MB.

Your Unraid box needs normal internet access. Nothing needs to be opened on your router.

## 2. Add the Skwod template

You only download the template once. It then shows up in Unraid's own list.

1. In the Unraid web page, click the **Terminal** icon (`>_`) at the top right. A black window
   opens.
2. Copy this whole line, paste it into that window, and press **Enter**:

   ```sh
   curl -fsSL -o /boot/config/plugins/dockerMan/templates-user/my-skwod.xml https://raw.githubusercontent.com/FlayrLabs/skwod/main/deploy/unraid/skwod.xml
   ```

   It prints nothing when it works. Close the window.
3. Go to the **Docker** tab and click **Add Container** at the bottom.
4. At the top, open the **Template** drop-down and pick **skwod** (it's under *User templates*).
   The page fills in.

> **Once Skwod is in Community Applications** (the **Apps** tab), you can skip the first three
> steps: search for **skwod** in the Apps tab and click **Install**. That opens the same page.

## 3. Check the settings (mostly: leave the defaults)

The template is already set up safely. Here is what each field means. **The defaults are
right for almost everyone.**

**Main settings:**

| Field | Leave it as | What it is |
|---|---|---|
| **Name** | `skwod` | The container's name. The commands in this guide assume `skwod`. |
| **Repository** | `ghcr.io/flayrlabs/skwod-server:latest` | Where Unraid downloads the server from. It's signed by Skwod's public build system. To choose each update yourself, see [the end of this guide](#for-the-cautious-pin-an-exact-image). |
| **Network Type** | `Bridge` | Keep **Bridge**. |
| **Data** | `/mnt/user/appdata/skwod` | Where everything lives: the encrypted messages and attachments, and the keys that *are* your server's address. **Back this folder up** (see [Backups](#backups)). |
| **Connection port (UDP)** | `47474` | The one port your friends' apps use for chat *and* calls. You don't need to forward it on your router. Forwarding it is optional and can make connections faster (see [step 9](#9-voice-and-video-calls)). |

**Under "Show more settings"** (leave all of these alone unless you know you need the change):

| Field | Default | What it is |
|---|---|---|
| **Admin page address** | `0.0.0.0:3477` | The admin page's address *inside* the container. It is **not** opened to your network: Extra Parameters (below) publish it on the Unraid box itself only. |
| **Wait for Start button** | `true` | The server lets nobody in until **you** press **Start server**, so nobody can claim it before you. After that, it starts by itself every time. |
| **P2P port** | `47474` | Must be the same number as **Connection port (UDP)**. If you change one, change both. |
| **Run as (uid:gid)** | `99:100` | The low-privilege user the server runs as (Unraid's usual `nobody:users`). |
| **Use public relays as a fallback** | `true` | If a friend's app can't connect directly (common behind home routers), traffic goes through a public relay. It's still end-to-end encrypted; the relay only sees IP addresses and timing. Setting `false` is more private, but some friends may not be able to connect at all. |
| **Find on local network** | empty (off) | Helps phones on your home Wi-Fi find the server faster. It only works with Network Type **Host**. Leave it off. |

**Extra Parameters** (advanced view): **don't change these.** They are the safety settings:

- `-p 127.0.0.1:3477:3477` puts the admin page on the Unraid box only, not on your network.
- `--read-only`, `--cap-drop=ALL`, `--security-opt no-new-privileges:true` take away
  everything the server doesn't need.
- `--user 0:0` with only `CHOWN`, `SETUID`, `SETGID` lets the container fix the appdata folder's
  owner once at start, then switch to user `99:100` with no special rights at all before it
  talks to the network.
- `--memory=768m` caps its memory.

## 4. Press Apply

1. Click **Apply** at the bottom.
2. Unraid downloads the server (a few hundred MB, so give it a minute) and starts it. When the
   window says **Done**, close it.
3. On the **Docker** tab you'll see **skwod** with a green **started** label. After a minute or
   so the health shows as **healthy**.

## 5. Find the one-time admin token

The admin page is locked with a token that works **once**. The server writes a new one to its
log every time it starts.

1. On the **Docker** tab, click the Skwod icon and choose **Logs**.
2. Find a line like this:

   ```
   [skwod] One-time admin token: ABCDE-FGHJK-LMNPQ-RSTUV
   ```

3. Copy the token (the four groups of letters and numbers). Keep the log window open, or note the
   token down.

You'll also see `Not serving yet: open the admin page and press "Start server".` That's expected.

If the token is used or lost, restart the container (Docker tab → icon → **Restart**). The
log then shows a new one.

## 6. Open the admin page safely

**Why it isn't just a web address on your network.** The admin page uses plain, unencrypted
HTTP. Until someone owns the server, the page shows the *owner invite*, and whoever uses that
invite first becomes the owner. If the page were open to your whole network, any device on your
Wi-Fi could grab it. So the page only answers on the Unraid box itself, and you reach it from
your computer through an **SSH tunnel**.

**What an SSH tunnel is:** a private, encrypted pipe from your computer to the Unraid box. While
it's open, a web address on your own computer (`http://127.0.0.1:3477`) actually shows the page
on the Unraid box.

### On a Mac, Linux, or Windows 10/11 computer on the same network as Unraid

1. Open a terminal on **your computer**: **Terminal** on a Mac, **PowerShell** on Windows (Start
   menu → type *PowerShell*).
2. Type this, replacing `tower` with your Unraid server's name or IP address (shown at the top of
   the Unraid web page, for example `tower.local` or `192.168.1.20`), then press **Enter**:

   ```sh
   ssh -L 3477:127.0.0.1:3477 root@tower
   ```

3. The first time, it asks *"Are you sure you want to continue connecting?"* Type `yes` and press
   **Enter**.
4. Type your **Unraid root password** (the one you use to log in to the Unraid web page). Nothing
   shows while you type; that's normal. Press **Enter**.
5. You're now logged in to the Unraid box in that window. **Leave the window open.** The tunnel
   works only while it is open.
6. In your web browser, open **http://127.0.0.1:3477**. Or, on the Docker tab, click the Skwod
   icon → **WebUI**, which opens that same address.

When you're done with the admin page, type `exit` in the terminal window, or just close it.

### If you use Tailscale

If your Unraid box and your computer are both on your Tailscale network, the same tunnel works
from **anywhere**, not just from home. Use the same command, with the box's Tailscale name (as
shown in the Tailscale app, for example `tower`) or its Tailscale IP address (it starts with
`100.`) after `root@`:

```sh
ssh -L 3477:127.0.0.1:3477 root@TAILSCALE-NAME-OF-YOUR-UNRAID-BOX
```

Then open **http://127.0.0.1:3477** as above. Don't change the template to publish the admin page
on your Tailscale or network address instead. The tunnel is what keeps the owner invite private.

## 7. Start the server and become its owner

**On the admin page** (http://127.0.0.1:3477, through the tunnel):

1. Under **Admin token**, paste the token from step 5 and click **Continue**.
2. The page says *"Your server is off."* Click **Start server**.
3. After a few seconds the status shows **Running**. You'll see **Your invite**: a QR code, a
   link that starts with `https://skwod.io/join#`, and the buttons **Copy invite** and **New
   invite**.

> The owner invite is shown **only once**. If you reload the page or restart before using it,
> the page says *"Nobody has claimed this server yet, and the first invite is only shown once.
> Press New invite to make another."* Press **New invite**. Until someone claims the server,
> that button makes a new owner invite.

**Open that invite on your own phone or computer first.** The first person to sign up with it
becomes the **owner**.

### iPhone or iPad

1. Install Skwod and open it. You'll see **Sign up** / **Log in**. Leave it on **Sign up**.
2. In **Invite link from your host**, tap **Scan QR** and point the camera at the QR code on the
   admin page. Or copy the link (**Copy invite**), send it to yourself, and tap **Paste**.
   Tapping the link itself also opens the app with the link filled in.
3. The app shows **Host key …** and *"Invite is valid."*
4. Choose a **Username** (3–32 characters: a–z, 0–9 and `_`) and a **Password** (at least 8
   characters).
5. Tap **Create account**. It shows *"Finding your host…"* for a moment, then you're in. You are
   now the owner.
6. Next comes **Save your recovery key**. Save it somewhere safe (or **Print** it), tap
   **I've saved it**, type the last 6 characters to check, then tap **Turn on recovery**.
   **Do this.** It's how you get your account back on a new phone.

### Mac

The steps are the same as on iPhone. To read the QR code from a screenshot, use **QR from image…**
instead of the camera. Pasting the link (**Copy invite** → **Paste**) is easiest. Ignore **Start
a server** at the bottom of the Mac app; that's for hosting on the Mac itself, and your server is
on Unraid.

### Android

1. Install Skwod and open it. Leave it on **Sign up**.
2. Under **Invite link from your host**, tap **Scan QR** and point the camera at the admin page,
   or tap **Paste**. It says *"Invite ready. Pick a username and password to join."*
3. Enter a **Username** and **Password**, then tap **Create account**.
4. Save your recovery key when asked, as above.

> On Android, right after you create the owner account, a banner may say *"Couldn't join with
> that invite — it may have expired or been used."* If you're signed in, you are the owner. The
> invite was used, by you, so you can ignore the banner.

### Already using Skwod with someone else's server?

Each Skwod is separate and has its own account. In the app, open your profile and tap **Add a
skwod** (Android: **Add a Skwod**). On a Mac or Android you can also use the **Join or host a
Skwod** tile in the left rail. You get the same **Sign up** form; use your server's invite there.

## 8. Create a server and invite friends

In Skwod, a **server** is a group with its own channels and members, and your Skwod can hold
several. Create one before you invite anyone.

**Create a server:**

- **iPhone:** tap your Skwod's name with the **›** at the top, then **Create a server**.
- **Mac:** click **Create a server** in the middle of the window (or the **+** in the left rail).
- **Android:** tap **Create a server** on the empty screen (or the **+** in the rail).

Give it a **Server name**, keep **general** as the **First channel**, and tap **Create encrypted
server** (Android: **Create**).

**Invite a friend:**

1. Open the server's menu and choose **Invite people**. On iPhone you can also tap the person
   **+** icon next to Search.
2. Pick one:
   - **Shareable code (needs your approval)**: the safe default. The friend asks to join, and
     you let them in.
   - **One-time link (auto-join)**: whoever opens it first is in, with no approval. Send it only
     privately.
3. Send the link to your friend however you like (message, e-mail). It already says where your
   server is.
4. Your friend installs Skwod, taps or pastes the link in **Sign up**, picks a username and
   password, and taps **Create account**. With a shareable code they see *"Waiting for the host
   to let you in."*
5. You let them in: open **Invite people** → **Pending requests** (or the members list →
   **Waiting to join**) and approve them (**✓** or **Let in**). Their app sets itself up on its
   own.

Invites last 7 days, and you can **Revoke** any of them from **Active invites**. The admin page's
**New invite** button also makes a friend invite (needs approval), once you have created a server.

The admin page isn't needed day to day. Everything else happens in the app.

## 9. Voice and video calls

Calls are built in: a voice and video server (LiveKit) runs **inside** the container. It's
bound to the container's own loopback address and is never opened to your network or the
internet. Calls travel through the same encrypted connection as chat, over the one UDP port
**47474**.

- **Port forwarding is optional.** Without it, calls still work. When a direct connection can't
  be made, they go through a public relay, still end-to-end encrypted.
- **For the best call quality**, forward **UDP 47474** on your router to your Unraid box's IP
  address. Look up "port forwarding" in your router's manual. Forward **UDP only**, and **only
  47474**. **Never forward port 3477** (the admin page).
- The admin page shows **Voice and video: On** when calls are ready.

## Updating

1. On the **Docker** tab, click **Check for Updates** at the bottom. If Skwod has a new version,
   it shows **update ready**.
2. Click **apply update**. Unraid downloads the new server and restarts the container. Your data
   in appdata is kept.
3. Each new version is built from the public source code. It's tested on both kinds of processor
   and signed before it becomes `latest`. If an update changes the database, the server first
   keeps a copy of the old one in `appdata/skwod/snapshots/`.

After an update, everyone's apps reconnect by themselves. Nobody needs a new invite.

## Backups

Everything your Skwod **is** lives in `/mnt/user/appdata/skwod`: the encrypted messages, the
attachments, and `p2p.key`, the key that *is* your server's address. **If you lose this folder,
your Skwod is gone,** and every invite and member with it.

**The simplest way:** install **Appdata Backup** from the **Apps** tab and include the `skwod`
folder. It stops the container briefly while it copies, which is the safe way to copy it.

**An encrypted single-file backup (recommended as well).** Skwod can write its whole data folder
into one file locked with a passphrase, which you can safely keep off-site:

1. Stop the container. Then click its icon → **Edit**, and at the bottom click **Add another
   Path, Port, Variable, Label or Device**. Set **Config Type** to `Path`, **Container Path** to
   `/backup`, and **Host Path** to a backup share, for example `/mnt/user/backups/skwod`. Click
   **Add**, then **Apply**.
2. Open the Unraid **Terminal** (`>_`) and run this. Change the passphrase to a long one (at least
   14 characters) and **write it down**:

   ```sh
   docker exec -e SKWOD_BACKUP_PASSPHRASE='a long passphrase you wrote down' skwod \
     skwod backup --data /data --out /backup/skwod-$(date +%F).skwodbackup
   ```

3. To check a backup without restoring it:

   ```sh
   docker exec -e SKWOD_BACKUP_PASSPHRASE='a long passphrase you wrote down' skwod \
     skwod restore --in /backup/skwod-2026-11-22.skwodbackup --data /data --verify-only
   ```

Without the passphrase **nobody** can open the file, you included. The **User Scripts** plugin
(Apps tab) can run step 2 every night.

The server also keeps a daily copy of its database in `appdata/skwod/snapshots/`, with the
newest seven kept. That copy is on the same disk, so it doesn't replace a real backup.

## Moving to another box

Move the data folder and it's the **same** Skwod on the new box: same address, same invites,
same members. Nobody has to be invited again.

**From one Unraid box to another:**

1. On the **old** box, stop the container (Docker tab → icon → **Stop**). **Keep it stopped**
   from now on. Two copies of the same Skwod must never run at the same time.
2. With the container stopped, copy the whole `/mnt/user/appdata/skwod` folder (for example to
   a share, then to the new box). Because the container is stopped, nothing can change while
   you copy. (An encrypted backup also works, but `docker exec` needs the container running:
   ask everyone to stop posting, make the backup, then stop the container.)
3. On the **new** box, add the template ([step 2](#2-add-the-skwod-template)) but **don't
   press Apply yet**. Instead:
   - **If you copied the folder:** put it at `/mnt/user/appdata/skwod` on the new box, then
     click **Apply**.
   - **If you made an encrypted backup:** copy the `.skwodbackup` file to the new box, for
     example to `/mnt/user/backups/skwod/`, and run this in the new box's Terminal. The
     target folder must not exist yet:

     ```sh
     docker run --rm --user 0:0 --network none \
       -e SKWOD_BACKUP_PASSPHRASE='a long passphrase you wrote down' \
       -v /mnt/user/appdata:/appdata -v /mnt/user/backups/skwod:/backup \
       ghcr.io/flayrlabs/skwod-server:latest \
       skwod restore --in /backup/skwod-2026-11-22.skwodbackup --data /appdata/skwod
     ```

     Then click **Apply** on the template. The container fixes the folder's owner by itself at
     start.
4. Open the admin page with a new token ([steps 5](#5-find-the-one-time-admin-token) and
   [6](#6-open-the-admin-page-safely)) and press **Start server** if it's stopped.

A restore signs everyone out once. Members just sign in again, and their apps set themselves up.
If the restore brought back people or devices you had removed since the backup, it lists them in
`restore-report.txt` in the data folder.

**From the Skwod Mac app:** see the next section.

## Moving your Skwod from a Mac to Unraid

Started your Skwod on a Mac and want it on an always-on Unraid box now? You can move it
**without losing anything**. Every message, member, server, channel and invite comes along, and
the move keeps its **address** (its key), so your friends don't need new invites.

> **The one rule: never run both at once.** Your Skwod's address is its key, and the key moves
> with it. If the Mac and the Unraid box both run it, friends' apps reach whichever one answers
> first. Some messages then land on one copy and some on the other, and the two copies never
> merge. So the Mac's server is switched **off** before the Unraid one starts, and stays off.

**Before you start:**

- Tell your group that the Skwod will be down for a few minutes, and that everyone will have to
  **sign in once more** afterwards with their username and password. Make sure they know their
  password. Their messages stay on their phones; nothing else changes.
- **Save your own recovery key** if you haven't yet (in the app: your profile → recovery key).
  Your phone keeps everything, but the Mac app's own entry for this Skwod gets replaced (see
  [What your friends notice](#what-your-friends-notice)).

### On the Mac: switch the server off, then export

Stop first, then export. That way nothing can be posted after the backup is made.

1. Click the Skwod icon in the **menu bar** and choose **Stop server**. From now on, friends
   can't reach the Mac's copy.
2. Open the **Start server** window (from the app's **Start server** button) and click
   **Options**.
3. Under **Backup**, click **Export…**. Choose where to save the file (for example, the Desktop).
4. Choose a **passphrase** of at least 14 characters, type it twice, and **write it down**.
   Without it, nobody can open the file, you included. You get a file ending in
   `.skwodbackup`.
5. Make sure the Mac never starts it again by itself. **Quit Skwod** (menu bar icon → **Quit
   Skwod**). In Finder, choose **Go → Go to Folder…**, type
   `~/Library/Application Support/` and press **Enter**. Rename the folder `skwod-host-data` to
   `skwod-host-data-moved-to-unraid`. If you chose another **Storage folder** in Options, rename
   that folder instead.

   **Why:** Skwod builds up to 45 start the server again at every launch whenever that folder
   exists, even after **Stop server**. Later builds remember **Stop server**, but the rename is
   safe on every build, and the renamed folder is also an extra copy to keep for a while.

### Copy the file to Unraid

6. Copy the `.skwodbackup` file to a share on the Unraid box. In Finder, choose
   **Go → Connect to Server…**, type `smb://tower` (your Unraid box's name) and open a share. If
   you don't have a backups share, create one in Unraid's **Shares** tab, named `backups`. Put
   the file in a folder called `skwod` there, so it ends up at
   `/mnt/user/backups/skwod/` on the box.

### On Unraid: restore into an empty appdata folder, then start

7. Do [steps 1–3](#1-what-you-need-first) of this guide (add the template and look over the
   settings), but **don't press Apply yet**. If you already pressed it, stop the container and
   delete `/mnt/user/appdata/skwod` first (only if you never used that new, empty server).
8. Open the Unraid **Terminal** (`>_`) and paste this. Replace the passphrase and the file name
   with yours. The file name is case-sensitive.

   ```sh
   docker run --rm --user 0:0 --network none \
     -e SKWOD_BACKUP_PASSPHRASE='the passphrase you wrote down' \
     -v /mnt/user/appdata:/appdata -v /mnt/user/backups/skwod:/backup \
     ghcr.io/flayrlabs/skwod-server:latest \
     skwod restore --in /backup/YOUR-FILE.skwodbackup --data /appdata/skwod
   ```

   It downloads the server image the first time (a minute), then ends with a short report. It
   refuses, and changes nothing, if the passphrase is wrong or if `/mnt/user/appdata/skwod`
   already holds a skwod.
9. Back on the template page, click **Apply**. The container takes over the restored folder (it
   fixes the file owner by itself) and **starts serving right away**. A Skwod that already has an
   owner doesn't wait for the Start button.
10. Check it: open the admin page ([steps 5–6](#5-find-the-one-time-admin-token)). It should say
    **Running**, with your **Members** count, **Voice and video: On** and **Reachable by invite:
    Yes**.

### What your friends notice

- The Skwod is unreachable for the few minutes between **Stop server** on the Mac and **Apply**
  on Unraid. Then their apps reconnect by themselves, to the same address.
- **Everyone is signed out once.** A restore deliberately ends every session. Each person opens
  the app, sees the sign-in screen, and signs in with their **username and password**. Their
  chat history, servers and channels are all still there.
- **Invites keep working.** Links you sent before the move point to the same address and still
  work (until they expire as usual).
- **You, on the Mac**: the Mac app reached its own server through a local address, which now
  has nothing behind it. Sign in to the Unraid Skwod from the Mac like any member: open your
  profile → **Add a skwod**, choose **Log in**, paste the server's invite or address (from the
  Unraid admin page, or any invite), and use your owner username and password. The Mac then
  counts as a new device of your account. Keep the old entry until the new one shows your
  history (your recovery key brings it back if it doesn't). Your phones are not affected; they
  already connect by address. *(This Mac-side step has not been tested yet.)*

### The other way: Unraid back to a Mac

1. Ask everyone to stop posting for a few minutes. Make an encrypted backup on Unraid
   ([Backups](#backups), step 2), then **stop** the container right away. On the Docker tab, turn its **Autostart** switch off, so a reboot of the Unraid
   box doesn't start it again.
2. Copy the `.skwodbackup` file to the Mac.
3. In the Skwod Mac app: open **Start server → Options → Backup → Import…**, choose the file, and
   type the passphrase. Then press **Start server**.
4. Once the Mac copy works, remove the Unraid container (or leave it stopped with Autostart off,
   for a while, as a spare). As before, never run both.

## Troubleshooting

**See what the server says.** Docker tab → Skwod icon → **Logs**. Almost every problem is
explained there in plain words. Lines starting with `[skwod]` are the server's own.

**"I can't find the admin token."** It's printed when the container starts, near the top of
the log. Each token works once. Restart the container for a new one.

**The admin page doesn't load (http://127.0.0.1:3477).**
- Is the SSH window from [step 6](#6-open-the-admin-page-safely) still open and logged in? The
  page only works while it is.
- Is the container **started**? Check the Docker tab.
- Did `ssh` say *"bind: Address already in use"*? Something on your computer already uses
  port 3477. Use another local number, for example `ssh -L 13477:127.0.0.1:3477 root@tower`,
  and open http://127.0.0.1:13477.
- Did `ssh` say *"Connection refused"*? Turn on **Use SSH** in **Settings → Management Access**.

**The admin page says *"The owner invite is only shown on the computer that runs the server"*.**
You opened the page some way other than the tunnel. Use the `ssh -L` command from step 6 and
**http://127.0.0.1:3477**.

**Friends can't connect ("Finding your host…" never ends).**
- On the admin page, **Reachable by invite** should say **Yes**. If it says **No**, check the
  log for `p2p endpoint failed to start`; usually the Unraid box has no internet yet. The
  server keeps retrying by itself.
- If it says **Yes (direct only)**, **Use public relays as a fallback** is `false`. Friends behind
  strict routers then can't connect. Set it to `true` (Edit → Show more settings) or forward
  UDP 47474.
- Make sure **Connection port (UDP)** and **P2P port** are the same number.
- Make sure the invite hasn't expired (7 days) or been revoked. Make a new one.

**Calls don't connect, or there's no sound or picture.**
- The admin page should show **Voice and video: On**. If it says **Off**, look in the log for
  `voice disabled` and restart the container.
- Calls use the same connection as chat. If chat works but calls are choppy, forward **UDP
  47474** to the Unraid box ([step 9](#9-voice-and-video-calls)).
- Check that the app has permission to use the microphone and camera (phone **Settings** →
  Skwod).

**Permission errors in the log** (for example *"cannot open"*, *"Permission denied"*, or a
message about the data folder's owner, and the container stops by itself).
- Check that **Extra Parameters** still contains `--user 0:0 --cap-drop=ALL --cap-add=CHOWN
  --cap-add=SETUID --cap-add=SETGID`. The container needs those to fix the appdata folder's
  owner at start. If you removed them, put the template's original value back.
- Check that **Run as** is `99:100`.
- If you copied the folder from elsewhere, restarting the container fixes the owner by itself.

**"Out of memory", or the container keeps restarting.** It's capped at 768 MB. Make sure the box
has that much free memory. You can raise `--memory=768m` in Extra Parameters.

**Starting over (reset).** **This deletes your Skwod for good:** every message, member and
invite. Your friends would need new invites to a new server. Only do this if you're sure, or if
you never invited anyone.
1. Stop the container.
2. In the Unraid Terminal, delete the data folder:
   `rm -rf /mnt/user/appdata/skwod`
3. Start the container, then follow this guide again from [step 5](#5-find-the-one-time-admin-token).

**Still stuck?** Open an issue at
[github.com/FlayrLabs/skwod/issues](https://github.com/FlayrLabs/skwod/issues). Include the log
lines starting with `[skwod]`, but **remove the admin token and any invite links** first.

## For the cautious: pin an exact image

With `:latest`, Unraid offers each new signed release as an update, and you trust Skwod's public
build system for each one. If you want to decide each update yourself, pin the image by its
**digest**, the image's own fingerprint. Docker refuses anything that doesn't match it.

1. Find the digest in the release notes. It looks like `sha256:` followed by 64 letters and
   numbers.
2. Optional: check that it was signed by Skwod's build. On any computer with
   [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3 or newer, run
   `deploy/verify-image.sh ghcr.io/flayrlabs/skwod-server@sha256:<digest>` from a copy of the
   Skwod source.
3. Edit the container and set **Repository** to
   `ghcr.io/flayrlabs/skwod-server@sha256:<digest>`, then **Apply**.

A pinned image never changes, so **Check for Updates** won't show Skwod updates any more. To
update, put a new digest in **Repository** yourself.
