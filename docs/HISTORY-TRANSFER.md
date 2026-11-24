# Message history for a newly linked device (design, build 51)

Status: design only. Build 49 ships the sealed sibling channel (`docs/SECURITY.md` → "Sibling
sync") that this builds on.

## Why a linked device sees no older messages

- **Channels.** Messages use libsignal sender keys, one chain per (channel, sender device). A new
  device gets each sender's distribution at its *current* chain position. libsignal cannot
  derive earlier keys from it, so older ciphertext fails to decrypt. `channel_page` skips those
  rows without a placeholder because they predate `first_key_at`. Resends are deliberately
  fenced to messages sent after the requester got the key (`on_retry_request`).
- **Direct messages.** Each message is sealed per recipient device when it is sent. A device that
  didn't exist then never got an envelope. The host's DM history endpoint is unused.
- **Avatars** are channel messages, so they had the same problem. Build 49 hands the avatar cache
  over the sibling channel instead.

## Goal

When the user approves a new device, the approving device offers **"Transfer message history"**
(on by default; choose the last 30 days, 90 days or everything, capped by size). It seals that
history to the new device. The host relays and stores only ciphertext. The transfer is bound to
the approved pairing and limited in size.

## Design

1. **Trigger.** On the approving device, after `approve_device_link` / `approve_pair` succeeds
   and the new device is a verified sibling (`refresh_siblings` → `device_linked`). Also on the
   new device's `SiblingStateRequest`, if the user chose to transfer and no transfer has
   completed for that sibling.
2. **Export (approving device, core).** Read the local decrypted cache: `cache.messages(scope)`
   for each `channel:<id>` and `dm:<id>` scope this device holds, newest first, within the
   chosen window. Stop at **N MB per conversation** (default 20 MB) and **M MB total** (default
   200 MB). Attachments travel as their existing E2EE descriptors (blob id plus key); the blobs
   aren't copied. Rows are serialized with a versioned, length-prefixed format (not bare
   postcard): scope, message id, author id, created_at, flags (system, edited, deleted,
   reply_to), body.
3. **Encrypt.** A fresh random 32-byte archive key. The archive is split into chunks of at most
   16 MiB, each sealed with AEAD under the archive key. The AAD binds the chunk to the transfer:
   `skwod/history-v1|<transfer_id>|<chunk index>|<chunk count>|<sha256 of manifest>`.
4. **Relay.** Upload the chunks as host blobs (up to 2 GiB per blob, 16 MiB chunks; the host
   sweeps unattached blobs after 24 hours). The host learns the total size and timing, which a
   large upload reveals anyway. Padding to 1 MiB buckets limits that leak.
5. **Bind to the pairing.** Send `Content::HistoryOffer { transfer_id, manifest_hash, chunk
   count, blob ids and download tokens, archive key, window, totals }` over the sibling
   channel, so only the new device can open it. The receiver accepts an offer only from a
   current, non-tombstoned sibling, only for a transfer it asked for or that started within
   10 minutes of its own link, and only once per transfer id.
6. **Import (new device, core).** Download, verify each chunk's AAD and the manifest hash, then
   insert rows with `insert_message_if_absent`. Rows for conversations this device isn't a
   member of are dropped, and rows the device later receives normally are kept as received.
   Imported rows are marked "transferred from <device name>" so the UI can say where they came
   from. A system row in each conversation says how far back history reaches.
7. **Limits and abuse.** Hard caps on archive size, row count, rows per scope and per-row body
   (`MAX_TEXT`). One active transfer per sibling, rate-limited. Import runs in the background
   with progress. A failure leaves whatever was imported and offers "Try again" on the
   approving device.
8. **UI.**
   - Approving device: a "Transfer message history" toggle on the approve screen (on by
     default), the range, an estimated size, and progress.
   - New device: "Getting your history from <device>…" with progress, and a way to skip.
9. **Tests.**
   - An offer from a non-sibling is ignored.
   - A chunk moved between transfers fails its AAD.
   - Truncated or extra chunks are refused.
   - The caps are enforced.
   - Import is idempotent.
   - Two simulators run the link and transfer end to end.

## Out of scope

Transferring history to a device restored from a recovery key (it has its own path), and server
backups of history (never: the host stores ciphertext only, with no history keys).
