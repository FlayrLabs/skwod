//! Attachments that survive a bad connection and a restart.
//!
//! - **Streamed.** `prepare_upload` encrypts file to file (`skwod_crypto::attachment`, the same
//!   blob format as before) and the upload reads the result a chunk at a time: a large video
//!   costs a megabyte of memory, not its size twice over.
//! - **Resumable.** The upload's state (which blob, where the ciphertext is) is written to the
//!   encrypted cache before the first byte goes out. A dropped connection continues from the
//!   offset the SERVER reports (`GET /api/blobs/:id/offset`, or the `409` it answers a
//!   misplaced chunk with) — also after the app was killed: `resume_uploads` at launch, or the
//!   outbox flush of the message that carries the attachment.
//! - **Offline.** A message can be queued with an attachment that has not been uploaded
//!   (`queue_channel_message(…, upload_ids)`): its body names the attachment by a placeholder
//!   blob id, replaced by the real one when the upload completes.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use skwod_sync::{valid_blob_id, ChunkOutcome, ClientError, EngineError};

use crate::{CoreError, SkwodClient};

const UPLOAD_PREFIX: &str = "upload:";
const INDEX_KEY: &str = "uploads-index";
/// One megabyte per request: small enough to lose little when a connection drops, large
/// enough not to crawl. (The server accepts up to 16 MiB.)
const CHUNK: usize = 1024 * 1024;
const MAX_TRACKED: usize = 200;

/// An attachment encrypted and ready to upload.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PreparedUpload {
    pub upload_id: String,
    /// What the message's attachment descriptor names as the blob until the upload is done.
    /// A queued message carrying it gets the real blob id substituted (see `outbox.rs`).
    pub placeholder_blob_id: String,
    /// The 64-byte attachment key, the SHA-256 of the ciphertext, and the plaintext length —
    /// what the descriptor carries.
    pub key: Vec<u8>,
    pub digest: Vec<u8>,
    pub plaintext_len: u64,
    /// Size of the ciphertext that will be uploaded.
    pub blob_len: u64,
    /// For a DM attachment: the download token to put in the descriptor (its hash is
    /// registered with the blob). `None` for a channel attachment.
    pub download_token: Option<String>,
}

/// Where an upload stands.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UploadProgress {
    pub upload_id: String,
    /// The real blob id once the server has created it.
    pub blob_id: Option<String>,
    pub sent: u64,
    pub total: u64,
    pub done: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct State {
    path: String,
    total: u64,
    token_hash: Option<String>,
    blob_id: Option<String>,
    sent: u64,
    done: bool,
}

impl State {
    fn to_json(&self) -> String {
        serde_json::json!({ "path": self.path, "total": self.total, "token_hash": self.token_hash, "blob_id": self.blob_id, "sent": self.sent, "done": self.done }).to_string()
    }

    fn from_json(raw: &str) -> Option<State> {
        let v: serde_json::Value = serde_json::from_str(raw).ok()?;
        Some(State {
            path: v["path"].as_str()?.to_string(),
            total: v["total"].as_u64()?,
            token_hash: v["token_hash"].as_str().map(str::to_string),
            blob_id: v["blob_id"].as_str().map(str::to_string),
            sent: v["sent"].as_u64().unwrap_or(0),
            done: v["done"].as_bool().unwrap_or(false),
        })
    }
}

/// The placeholder a not-yet-uploaded attachment is named by inside a queued message.
pub(crate) fn placeholder(upload_id: &str) -> String {
    format!("{UPLOAD_PREFIX}{upload_id}")
}

const BAD_BLOB_ID: &str = "the server answered with an attachment id this app does not accept; nothing was sent";
const BAD_DESCRIPTOR: &str = "that attachment could not be attached to the message; attach it again";

/// Put real blob ids into a queued message body, STRUCTURALLY.
///
/// A body that carries an attachment is `<tag>` + a JSON object (`\u{2}skwod/attach|{…}`, a feed
/// post, …) whose descriptor names the blob by its placeholder. The body is the sender's words,
/// sealed end to end — and a blob id is the server's. So the id is never pasted into the text:
/// the JSON is parsed, every string value that IS a placeholder (exactly) is set to its blob id,
/// and the object is written out again. A blob id that is not a canonical UUID never gets this
/// far, and even one that did could only ever become the value of that one string.
///
/// Fails when the body is not `<tag>{json}`, or a placeholder is not found as a whole string
/// value — the message is then not sent rather than sent with an attachment nobody can open.
pub(crate) fn substitute(text: &str, ids: &[(String, String)]) -> Result<String, &'static str> {
    if ids.is_empty() {
        return Ok(text.to_string());
    }
    if ids.iter().any(|(_, blob)| !valid_blob_id(blob)) {
        return Err(BAD_BLOB_ID);
    }
    let at = text.find('{').ok_or(BAD_DESCRIPTOR)?;
    let (tag, json) = text.split_at(at);
    let mut value: serde_json::Value = serde_json::from_str(json).map_err(|_| BAD_DESCRIPTOR)?;
    if !value.is_object() {
        return Err(BAD_DESCRIPTOR);
    }
    fn walk(v: &mut serde_json::Value, ids: &[(String, String)], hits: &mut [u32]) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(i) = ids.iter().position(|(placeholder, _)| placeholder == s) {
                    *s = ids[i].1.clone();
                    hits[i] += 1;
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| walk(x, ids, hits)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|x| walk(x, ids, hits)),
            _ => {}
        }
    }
    let mut hits = vec![0u32; ids.len()];
    walk(&mut value, ids, &mut hits);
    if hits.contains(&0) {
        return Err(BAD_DESCRIPTOR);
    }
    Ok(format!("{tag}{value}"))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn invalid(detail: &str) -> CoreError {
    CoreError::Invalid { detail: detail.to_string() }
}

fn read_chunk(path: &Path, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

impl SkwodClient {
    fn upload_state(&self, upload_id: &str) -> Option<State> {
        self.kv(&format!("{UPLOAD_PREFIX}{upload_id}")).and_then(|raw| State::from_json(&raw))
    }

    fn save_upload(&self, upload_id: &str, state: &State) {
        self.kv_put(&format!("{UPLOAD_PREFIX}{upload_id}"), &state.to_json());
    }

    fn upload_index(&self) -> Vec<String> {
        self.kv(INDEX_KEY).and_then(|j| serde_json::from_str::<Vec<String>>(&j).ok()).unwrap_or_default()
    }

    fn set_upload_index(&self, ids: &[String]) {
        if let Ok(json) = serde_json::to_string(ids) {
            self.kv_put(INDEX_KEY, &json);
        }
    }

    /// Stop tracking uploads whose message was delivered (the blobs live on, linked to it).
    pub(crate) fn forget_uploads(&self, upload_ids: &[String]) {
        if upload_ids.is_empty() {
            return;
        }
        for id in upload_ids {
            if let Some(state) = self.upload_state(id) {
                let _ = std::fs::remove_file(&state.path);
            }
            self.kv_put(&format!("{UPLOAD_PREFIX}{id}"), "");
        }
        let kept: Vec<String> = self.upload_index().into_iter().filter(|i| !upload_ids.contains(i)).collect();
        self.set_upload_index(&kept);
    }

    /// The message these uploads belonged to was discarded: drop the local ciphertext. (A blob
    /// already on the server and never linked to a message is swept by the server.)
    pub(crate) fn abandon_uploads(&self, upload_ids: &[String]) {
        self.forget_uploads(upload_ids);
    }

    /// Bring one upload to completion, from wherever it stands. Returns the blob id.
    pub(crate) async fn run_upload(&self, upload_id: &str) -> Result<String, EngineError> {
        self.upload_some(upload_id, u32::MAX).await?.ok_or(EngineError::Protocol("upload interrupted"))
    }

    /// Send at most `max_chunks` more chunks of an upload and stop — what a connection that
    /// drops part-way does. `Some(blob id)` once the upload is complete. (Not part of the FFI:
    /// the tests use it to leave an upload half done.)
    pub async fn upload_some(&self, upload_id: &str, max_chunks: u32) -> Result<Option<String>, EngineError> {
        let Some(mut state) = self.upload_state(upload_id) else {
            return Err(EngineError::Protocol("that attachment is no longer on this device; attach it again"));
        };
        if let (true, Some(id)) = (state.done, state.blob_id.clone().filter(|id| valid_blob_id(id))) {
            return Ok(Some(id));
        }
        // What the cache holds was the server's answer once: it is checked again before use.
        if state.blob_id.as_deref().is_some_and(|id| !valid_blob_id(id)) {
            state.blob_id = None;
            state.sent = 0;
            state.done = false;
        }
        let path = PathBuf::from(&state.path);
        if std::fs::metadata(&path).map(|m| m.len()).ok() != Some(state.total) {
            return Err(EngineError::Protocol("that attachment is no longer on this device; attach it again"));
        }
        // Where does the server stand? (A blob it no longer has is simply started again.)
        let mut offset = 0u64;
        if let Some(id) = state.blob_id.clone() {
            match self.api().blob_offset(&id).await {
                Ok((_, true)) => {
                    state.done = true;
                    state.sent = state.total;
                    self.save_upload(upload_id, &state);
                    return Ok(Some(id));
                }
                Ok((at, false)) => offset = at.min(state.total),
                Err(ClientError::Status { status: 404, .. }) => state.blob_id = None,
                Err(e) => return Err(e.into()),
            }
        }
        let blob_id = match state.blob_id.clone() {
            Some(id) => id,
            None => {
                let mut body = serde_json::json!({ "total_size": state.total });
                if let Some(h) = &state.token_hash {
                    body["download_token_hash"] = serde_json::json!(h);
                }
                let created = self.api().post("/api/blobs", body).await?;
                let id = created["blob_id"].as_str().ok_or(EngineError::Protocol("no blob_id"))?.to_string();
                // The server chooses this string. It is only ever accepted as a plain UUID —
                // before it is stored, used in a path, or named in a message.
                if !valid_blob_id(&id) {
                    return Err(EngineError::Protocol(BAD_BLOB_ID));
                }
                // On disk BEFORE the first chunk: a restart continues this blob, not a new one.
                state.blob_id = Some(id.clone());
                state.sent = 0;
                self.save_upload(upload_id, &state);
                offset = 0;
                id
            }
        };
        let mut corrections = 0;
        let mut budget = max_chunks;
        while offset < state.total {
            if budget == 0 {
                return Ok(None);
            }
            budget -= 1;
            let len = ((state.total - offset) as usize).min(CHUNK);
            let chunk = {
                let path = path.clone();
                tokio::task::spawn_blocking(move || read_chunk(&path, offset, len)).await.map_err(|_| EngineError::Protocol("upload interrupted"))?
            }
            .map_err(|_| EngineError::Protocol("that attachment is no longer on this device; attach it again"))?;
            match self.api().blob_chunk(&blob_id, offset, chunk).await? {
                ChunkOutcome::Accepted { offset: at, complete } => {
                    offset = at.min(state.total);
                    state.sent = offset;
                    state.done = complete;
                    self.save_upload(upload_id, &state);
                    corrections = 0;
                }
                // A chunk whose answer was lost: the server is ahead of (or behind) us.
                ChunkOutcome::Mismatch { offset: at } if corrections < 3 => {
                    offset = at.min(state.total);
                    corrections += 1;
                }
                ChunkOutcome::Mismatch { .. } => return Err(EngineError::Protocol("the upload could not be resumed")),
            }
        }
        state.done = true;
        state.sent = state.total;
        self.save_upload(upload_id, &state);
        Ok(Some(blob_id))
    }

    /// Upload everything `uploads` names and put the real blob ids into `text`. Returns the
    /// finished text and the blob ids to link to the message.
    pub(crate) async fn resolve_uploads(&self, text: &str, uploads: &[String]) -> Result<(String, Vec<String>), EngineError> {
        let mut ids = Vec::new();
        for id in uploads {
            let blob_id = self.run_upload(id).await?;
            if !valid_blob_id(&blob_id) {
                return Err(EngineError::Protocol(BAD_BLOB_ID));
            }
            ids.push((placeholder(id), blob_id));
        }
        let text = substitute(text, &ids).map_err(EngineError::Protocol)?;
        Ok((text, ids.into_iter().map(|(_, blob)| blob).collect()))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SkwodClient {
    /// Encrypt the file at `source_path` for upload, without loading it into memory. The
    /// ciphertext is written into `work_dir` (a directory of the app's, excluded from backups;
    /// the core removes the file when the upload is done or dropped). `for_dm` makes it a DM
    /// attachment (a download token is generated and its hash registered with the blob).
    ///
    /// Nothing is sent yet. Build the attachment descriptor from the result, then either
    /// `queue_channel_message(…, upload_ids: [upload_id])` / `queue_dm(…)` — works offline —
    /// or `finish_upload(upload_id)` to upload now and get the blob id.
    pub async fn prepare_upload(&self, source_path: String, work_dir: String, for_dm: bool) -> Result<PreparedUpload, CoreError> {
        if self.with_cache(|_| ()).is_none() {
            return Err(invalid("Attachments are not ready yet. Try again in a moment."));
        }
        if self.upload_index().len() >= MAX_TRACKED {
            return Err(invalid("Too many attachments are waiting to upload. Let them finish first."));
        }
        let upload_id = skwod_crypto::new_distribution_id().to_string();
        let dest = PathBuf::from(&work_dir).join(format!("{upload_id}.blob"));
        let token = for_dm.then(crate::new_blob_download_token);
        let sealed = {
            let (source, dest) = (PathBuf::from(&source_path), dest.clone());
            tokio::task::spawn_blocking(move || -> Result<skwod_crypto::attachment::StreamedAttachment, String> {
                std::fs::create_dir_all(dest.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
                let file = std::fs::File::open(&source).map_err(|e| e.to_string())?;
                let len = file.metadata().map_err(|e| e.to_string())?.len();
                let out = std::fs::File::create(&dest).map_err(|e| e.to_string())?;
                let result = skwod_crypto::attachment::encrypt_stream(std::io::BufReader::new(file), std::io::BufWriter::new(out), len).map_err(|e| e.to_string());
                if result.is_err() {
                    let _ = std::fs::remove_file(&dest);
                }
                result
            })
            .await
            .map_err(|_| invalid("Could not read that file."))?
            .map_err(|e| invalid(&format!("Could not read that file ({e}).")))?
        };
        let state = State { path: dest.to_string_lossy().to_string(), total: sealed.blob_len, token_hash: token.as_ref().map(|t| t.hash_hex.clone()), blob_id: None, sent: 0, done: false };
        self.save_upload(&upload_id, &state);
        let mut index = self.upload_index();
        index.push(upload_id.clone());
        self.set_upload_index(&index);
        Ok(PreparedUpload {
            placeholder_blob_id: placeholder(&upload_id),
            upload_id,
            key: sealed.key,
            digest: sealed.digest,
            plaintext_len: sealed.plaintext_len,
            blob_len: sealed.blob_len,
            download_token: token.map(|t| t.token),
        })
    }

    /// Upload a prepared attachment now (resuming if part of it is already there) and return
    /// its blob id. Throws when it could not finish; call again to continue from where it
    /// stopped. After the message that carries it was sent directly, call `release_upload`.
    pub async fn finish_upload(&self, upload_id: String) -> Result<String, CoreError> {
        if !valid_id(&upload_id) {
            return Err(invalid("unknown upload"));
        }
        Ok(self.run_upload(&upload_id).await?)
    }

    /// Every attachment this device has prepared and not finished with — after a restart too.
    pub async fn pending_uploads(&self) -> Vec<UploadProgress> {
        self.upload_index()
            .into_iter()
            .filter_map(|id| {
                let s = self.upload_state(&id)?;
                Some(UploadProgress { upload_id: id, blob_id: s.blob_id, sent: s.sent, total: s.total, done: s.done })
            })
            .collect()
    }

    /// Continue every unfinished upload (call at launch and on reconnect). Returns how many
    /// are complete afterwards. Uploads that belong to a queued message are also continued by
    /// `flush_outbox`.
    pub async fn resume_uploads(&self) -> u32 {
        let mut done = 0;
        for id in self.upload_index() {
            if self.run_upload(&id).await.is_ok() {
                done += 1;
            }
        }
        done
    }

    /// Stop tracking an upload and delete its local ciphertext: its message was sent (the blob
    /// stays, linked to the message), or the user removed the attachment before sending
    /// (`delete_blob = true` also deletes what reached the server).
    pub async fn release_upload(&self, upload_id: String, delete_blob: bool) {
        if !valid_id(&upload_id) {
            return;
        }
        if delete_blob {
            if let Some(blob_id) = self.upload_state(&upload_id).and_then(|s| s.blob_id) {
                let _ = self.api().blob_delete(&blob_id).await; // refuses anything but a UUID
            }
        }
        self.forget_uploads(&[upload_id]);
    }
}

/// Verify and decrypt a downloaded attachment file to file (no size limit in memory). Nothing
/// is written to `out_path` unless the whole blob verifies against `digest` and `key`.
#[uniffi::export]
pub fn decrypt_attachment_file(blob_path: String, out_path: String, key: Vec<u8>, digest: Vec<u8>, plaintext_len: u64) -> Result<(), CoreError> {
    let blob = std::fs::File::open(&blob_path).map_err(|e| invalid(&format!("Could not open the attachment ({e}).")))?;
    let len = blob.metadata().map_err(|e| invalid(&e.to_string()))?.len();
    let partial = format!("{out_path}.partial");
    let out = std::fs::File::create(&partial).map_err(|e| invalid(&format!("Could not save the attachment ({e}).")))?;
    let result = skwod_crypto::attachment::decrypt_stream(std::io::BufReader::new(blob), len, std::io::BufWriter::new(out), &key, &digest, plaintext_len);
    match result {
        Ok(()) => std::fs::rename(&partial, &out_path).map_err(|e| invalid(&e.to_string())),
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(CoreError::Engine { detail: e.to_string() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB: &str = "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b";

    #[test]
    fn only_a_canonical_uuid_is_a_blob_id() {
        assert!(valid_blob_id(BLOB));
        for bad in [
            "",
            "3F2B8C1E-9A4D-4E6F-8B7A-0C1D2E3F4A5B",
            "3f2b8c1e9a4d4e6f8b7a0c1d2e3f4a5b",
            "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b ",
            "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b/../x",
            "../../auth/sessions",
            "x\",\"key\":\"attacker",
            "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5\"",
            "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5g",
            "3f2b8c1e?9a4d-4e6f-8b7a-0c1d2e3f4a5b",
        ] {
            assert!(!valid_blob_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_blob_id_is_set_as_a_value_never_pasted_into_the_text() {
        let ph = placeholder("up-1");
        let body = format!("\u{2}skwod/attach|{{\"blobId\":\"{ph}\",\"key\":\"SENDERKEY\",\"name\":\"a \\\"quoted\\\" name {ph}\",\"size\":3}}");
        let out = substitute(&body, &[(ph.clone(), BLOB.to_string())]).unwrap();
        let json: serde_json::Value = serde_json::from_str(out.strip_prefix("\u{2}skwod/attach|").unwrap()).unwrap();
        assert_eq!(json["blobId"], BLOB);
        assert_eq!(json["key"], "SENDERKEY", "the sender's fields are untouched");
        // A string that merely CONTAINS the placeholder is the sender's text and stays as written.
        assert_eq!(json["name"], format!("a \"quoted\" name {ph}"));
        assert_eq!(json.as_object().unwrap().len(), 4, "no field was added");

        // Nested (a feed post carries its descriptor under `att`), and two attachments at once.
        let (a, b) = (placeholder("a"), placeholder("b"));
        let other = "00000000-0000-4000-8000-000000000001";
        let post = format!("\u{2}skwod/feed|{{\"text\":\"hi\",\"att\":{{\"blobId\":\"{a}\"}},\"more\":[{{\"blobId\":\"{b}\"}}]}}");
        let out = substitute(&post, &[(a, BLOB.to_string()), (b.clone(), other.to_string())]).unwrap();
        let json: serde_json::Value = serde_json::from_str(out.strip_prefix("\u{2}skwod/feed|").unwrap()).unwrap();
        assert_eq!((json["att"]["blobId"].as_str(), json["more"][0]["blobId"].as_str()), (Some(BLOB), Some(other)));

        // Not `<tag>{json}`, or no descriptor names the upload: the send fails.
        assert!(substitute("plain text", &[(ph.clone(), BLOB.to_string())]).is_err());
        assert!(substitute(&format!("\u{2}skwod/attach|[\"{ph}\"]"), &[(ph.clone(), BLOB.to_string())]).is_err());
        assert!(substitute("\u{2}skwod/attach|{\"blobId\":\"something else\"}", &[(ph.clone(), BLOB.to_string())]).is_err());
        assert!(substitute(&post, &[(b, other.to_string()), (placeholder("missing"), BLOB.to_string())]).is_err());
        // Nothing to substitute: the text is returned exactly as it was.
        assert_eq!(substitute("just text {not json", &[]).unwrap(), "just text {not json");
    }

    /// The security review's case: a hostile "blob id" that closes the string and adds fields.
    #[test]
    fn a_hostile_blob_id_fails_the_send_and_alters_nothing() {
        let ph = placeholder("up-1");
        let body = format!("\u{2}skwod/attach|{{\"blobId\":\"{ph}\",\"key\":\"SENDERKEY\"}}");
        for hostile in [
            "x\",\"key\":\"ATTACKERKEY\",\"digest\":\"ATTACKER",
            "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b\",\"key\":\"ATTACKERKEY",
            "\"}},{\"blobId\":\"evil",
            "../../../api/auth/logout",
            "",
        ] {
            assert_eq!(substitute(&body, &[(ph.clone(), hostile.to_string())]), Err(BAD_BLOB_ID), "{hostile:?}");
        }
    }
}
