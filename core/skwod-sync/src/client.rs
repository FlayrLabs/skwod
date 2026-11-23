//! Server API + realtime client.
//!
//! [`ApiClient`] is a thin typed wrapper over the Phase-2 REST API (opaque ciphertext in/out —
//! this layer never sees plaintext; the [`crate::engine`] encrypts before calling it).
//! [`RealtimeClient`] owns the WebSocket: connect, auth, (re)subscribe, and yield events; the
//! caller reconnects and backfills over REST after a gap.

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// Hard cap on a response body we will buffer (bytes). The server is untrusted; without a cap a
/// hostile or buggy server could stream an unbounded body and exhaust memory. 8 MiB comfortably
/// covers any JSON response this client expects (message pages are ciphertext-bounded).
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// Read a response body into a `String`, aborting if it exceeds `max` bytes. Streams chunk-by-chunk
/// so a chunked/unknown-length body can't blow past the cap (the `Content-Length` fast-path only
/// catches servers that honestly advertise the size).
async fn read_body_capped(mut res: reqwest::Response, max: usize) -> Result<String, ClientError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| ClientError::Transport(e.to_string()))? {
        if buf.len() + chunk.len() > max {
            return Err(ClientError::Transport("response body exceeds maximum size".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| ClientError::Shape)
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("transport error: {0}")]
    Transport(String),
    #[error("unexpected response shape")]
    Shape,
}

/// The app build this core ships in. Named on every authenticated request (`x-skwod-build`) so
/// a server can tell a build that can no longer take part to update, in words — instead of the
/// guessing it has to do for builds ≤ 43, which named nothing. Bump with the wire format.
pub const CLIENT_BUILD: u32 = 44;
const BUILD_HEADER: &str = "x-skwod-build";

/// Is `id` a blob id as a server mints them — a canonical, lowercase, hyphenated UUID?
///
/// A blob id comes from the SERVER, and it ends up in two places a server must not be able to
/// write into: a request path, and the attachment descriptor inside an end-to-end encrypted
/// message (which recipients take as the sender's words). Anything that is not exactly a UUID
/// is refused wherever one is received or used.
pub fn valid_blob_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// What a chunk upload was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// Accepted; the blob now holds this many bytes, and is (or is not) complete.
    Accepted { offset: u64, complete: bool },
    /// The server holds a different number of bytes than the chunk assumed: continue from here.
    Mismatch { offset: u64 },
}

/// Typed REST client. Cheap to clone (shares the reqwest pool).
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

/// Reject plaintext `http://` to a NON-loopback host — the bearer token + E2EE routing metadata
/// would travel in the clear to a passive network attacker. Only loopback LITERALS
/// (`localhost`/`127.0.0.1`/`::1`) stay allowed — the host's own connection to its bundled server.
/// `.local` (mDNS) names are NOT exempt: they resolve over a real LAN a passive attacker can watch,
/// so they must use TLS like any other remote address.
fn is_insecure_remote(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
    !(host == "localhost" || host == "127.0.0.1" || host == "::1")
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        // connect + idle-read timeouts, NOT a total-request timeout: a request to a dead address
        // must fail fast (the moved-skwod recovery path counts failures — a hung request means the
        // beacon lookup never triggers), but a slow, still-flowing blob download must not be cut off.
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .read_timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http, base: base_url.into().trim_end_matches('/').to_string(), token: None }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// A credential-less sibling of this client for **sealed-sender deposits**: no bearer token,
    /// and its own connection pool, so a sealed envelope never travels on a connection that has
    /// carried this account's token. (The server still sees the source IP — see SECURITY.md.)
    pub fn anonymous(&self) -> Self {
        Self::new(self.base.clone())
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// A request carrying a device proof header (account-security operations; see the engine).
    pub async fn signed(&self, method: reqwest::Method, path: &str, body: Option<Value>, proof: &str) -> Result<Value, ClientError> {
        self.request_with(method, path, body, Some(proof)).await
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, ClientError> {
        self.request_with(method, path, body, None).await
    }

    /// `GET` with one extra request header (the install secret a granted backup request is
    /// fetched with; see `Engine::fetch_key_backup`).
    pub async fn get_with_header(&self, path: &str, name: &'static str, value: &str) -> Result<Value, ClientError> {
        self.request_headers(reqwest::Method::GET, path, None, &[(name, value)]).await
    }

    async fn request_with(&self, method: reqwest::Method, path: &str, body: Option<Value>, proof: Option<&str>) -> Result<Value, ClientError> {
        match proof {
            Some(p) => self.request_headers(method, path, body, &[("x-skwod-device-proof", p)]).await,
            None => self.request_headers(method, path, body, &[]).await,
        }
    }

    async fn request_headers(&self, method: reqwest::Method, path: &str, body: Option<Value>, headers: &[(&'static str, &str)]) -> Result<Value, ClientError> {
        if is_insecure_remote(&self.base) {
            return Err(ClientError::Transport(
                "refusing to send credentials over plaintext http to a remote host (use https)".into(),
            ));
        }
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            // Never on the credential-less sealed-sender client: that path says nothing about us.
            req = req.bearer_auth(t).header(BUILD_HEADER, CLIENT_BUILD);
        }
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status();
        // Fast reject: if the server advertises a Content-Length over the cap, don't even buffer it.
        if res.content_length().is_some_and(|len| len > MAX_RESPONSE as u64) {
            return Err(ClientError::Transport("response body exceeds maximum size".into()));
        }
        let text = read_body_capped(res, MAX_RESPONSE).await?;
        if !status.is_success() {
            return Err(ClientError::Status { status: status.as_u16(), body: text });
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| ClientError::Shape)
    }

    fn guarded(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder, ClientError> {
        if is_insecure_remote(&self.base) {
            return Err(ClientError::Transport("refusing to send credentials over plaintext http to a remote host (use https)".into()));
        }
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            req = req.bearer_auth(t).header(BUILD_HEADER, CLIENT_BUILD);
        }
        Ok(req)
    }

    /// How many bytes of blob `blob_id` the server holds, and whether it is complete
    /// (`GET /api/blobs/:id/offset`). `Status { 404 }` when the blob is gone.
    pub async fn blob_offset(&self, blob_id: &str) -> Result<(u64, bool), ClientError> {
        if !valid_blob_id(blob_id) {
            return Err(ClientError::Shape); // never interpolated into a path
        }
        let res = self.guarded(reqwest::Method::GET, &format!("/api/blobs/{blob_id}/offset"))?.send().await.map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status();
        let header = |name: &str| res.headers().get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        if !status.is_success() {
            return Err(ClientError::Status { status: status.as_u16(), body: read_body_capped(res, MAX_RESPONSE).await.unwrap_or_default() });
        }
        Ok((header("upload-offset").ok_or(ClientError::Shape)?, header("upload-complete") == Some(1)))
    }

    /// Upload one chunk of a blob at `offset` (`PATCH /api/blobs/:id`).
    pub async fn blob_chunk(&self, blob_id: &str, offset: u64, chunk: Vec<u8>) -> Result<ChunkOutcome, ClientError> {
        if !valid_blob_id(blob_id) {
            return Err(ClientError::Shape);
        }
        let res = self
            .guarded(reqwest::Method::PATCH, &format!("/api/blobs/{blob_id}"))?
            .header("upload-offset", offset)
            .header("content-type", "application/offset+octet-stream")
            .body(chunk)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status();
        let header = |name: &str| res.headers().get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        match (status.as_u16(), header("upload-offset")) {
            (204 | 200, Some(offset)) => Ok(ChunkOutcome::Accepted { offset, complete: header("upload-complete") == Some(1) }),
            // The resume answer: a 409 that names where the server actually is.
            (409, Some(offset)) => Ok(ChunkOutcome::Mismatch { offset }),
            _ => Err(ClientError::Status { status: status.as_u16(), body: read_body_capped(res, MAX_RESPONSE).await.unwrap_or_default() }),
        }
    }

    /// Delete a blob this account uploaded (`DELETE /api/blobs/:id`).
    pub async fn blob_delete(&self, blob_id: &str) -> Result<(), ClientError> {
        if !valid_blob_id(blob_id) {
            return Err(ClientError::Shape);
        }
        self.delete(&format!("/api/blobs/{blob_id}")).await.map(|_| ())
    }

    pub async fn get(&self, path: &str) -> Result<Value, ClientError> {
        self.request(reqwest::Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value, ClientError> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: Value) -> Result<Value, ClientError> {
        self.request(reqwest::Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value, ClientError> {
        self.request(reqwest::Method::DELETE, path, None).await
    }

    pub async fn put(&self, path: &str, body: Value) -> Result<Value, ClientError> {
        self.request(reqwest::Method::PUT, path, Some(body)).await
    }

    // ---- typed conveniences used by the engine/tests ----

    pub async fn signup(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        self.signup_with_code(username, password, None).await
    }

    /// Sign up, optionally presenting a join code (required by initialized self-hosted instances).
    pub async fn signup_with_code(
        &self,
        username: &str,
        password: &str,
        join_code: Option<&str>,
    ) -> Result<Session, ClientError> {
        let mut body = json!({ "username": username, "password": password });
        if let Some(code) = join_code {
            body["join_code"] = json!(code);
        }
        let v = self.post("/api/auth/signup", body).await?;
        Session::from_value(&v)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        let v = self.post("/api/auth/login", json!({ "username": username, "password": password })).await?;
        Session::from_value(&v)
    }

    /// POST an opaque ciphertext envelope to a channel; returns (message_id, created_at).
    pub async fn send_channel_message(&self, channel_id: &str, ciphertext_b64: &str) -> Result<(String, i64), ClientError> {
        // Every current build names the message itself (a server refuses a send without an id:
        // that is how it recognises builds 41/42).
        let message_id = skwod_crypto::new_distribution_id().to_string();
        let v = self.post(&format!("/api/channels/{channel_id}/messages"), json!({ "ciphertext": ciphertext_b64, "message_id": message_id })).await?;
        Ok((
            v["message_id"].as_str().ok_or(ClientError::Shape)?.to_string(),
            v["created_at"].as_i64().ok_or(ClientError::Shape)?,
        ))
    }

    /// Backfill channel messages older than `before` (ms); pass i64::MAX for the newest page.
    pub async fn channel_messages(&self, channel_id: &str, before: i64, limit: usize) -> Result<Vec<Value>, ClientError> {
        let v = self.get(&format!("/api/channels/{channel_id}/messages?before={before}&limit={limit}")).await?;
        Ok(v["messages"].as_array().cloned().unwrap_or_default())
    }
}

/// A logged-in session.
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub token: String,
    pub expires_at: i64,
}

impl Session {
    fn from_value(v: &Value) -> Result<Self, ClientError> {
        Ok(Self {
            user_id: v["user_id"].as_str().ok_or(ClientError::Shape)?.to_string(),
            token: v["token"].as_str().ok_or(ClientError::Shape)?.to_string(),
            expires_at: v["expires_at"].as_i64().ok_or(ClientError::Shape)?,
        })
    }
}

/// Deserialize a REST array field (e.g. `body["messages"]`) into typed rows.
pub fn parse_list<T: DeserializeOwned>(v: &Value, field: &str) -> Result<Vec<T>, ClientError> {
    let arr = v[field].as_array().ok_or(ClientError::Shape)?;
    arr.iter().map(|item| serde_json::from_value(item.clone()).map_err(|_| ClientError::Shape)).collect()
}
