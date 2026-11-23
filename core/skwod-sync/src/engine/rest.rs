//! Plain REST passthroughs on [`Engine`]: server structure, roles, invites, moderation, reactions.
//! None of these touch key material — they carry ids, ciphertext produced elsewhere, or public
//! metadata. Split out of `engine.rs` so the E2EE logic there stays readable.

use super::{enc, Engine, EngineError, InviteInfo, JoinOutcome, RoleMeta, MAX_SERVER_ARRAY};

/// Engine-state section holding [`DeliveryRotation`] (build 45).
pub(super) const SECTION_DELIVERY: u8 = 0xD1;
/// The delivery key is replaced at least this often, whatever happened: it is a bearer
/// capability handed to every contact, and nothing else ever takes it back from one who copied it.
pub(super) const DELIVERY_ROTATION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Membership changes within this long of the last replacement wait for it to pass, so a busy
/// (or hostile) server cannot make this device replace its key — and every sender re-fetch it —
/// over and over. Also keeps well inside the server's allowance for rotations.
pub(super) const DELIVERY_ROTATION_MIN_GAP_MS: u64 = 10 * 60 * 1000;
/// How often the list of servers we are in is compared with the last one (M6).
pub(super) const SERVERS_RECHECK: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// How long a failed replacement waits before the next attempt.
pub(super) const DELIVERY_RETRY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// When this device last replaced its sealed-mailbox delivery key, and whether someone who
/// holds the current one should not (a membership change seen since).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct DeliveryRotation {
    /// Unix ms of the last replacement the server accepted; `0` = never (a build ≤ 44 state).
    pub rotated_at: u64,
    /// Unix ms of the first membership change since then, if any.
    pub due_since: Option<u64>,
}

impl DeliveryRotation {
    /// Replace the key now? Periodically, and after a membership change — but never twice
    /// within [`DELIVERY_ROTATION_MIN_GAP_MS`].
    pub fn wanted(&self, now: u64) -> bool {
        let age = now.saturating_sub(self.rotated_at);
        age >= DELIVERY_ROTATION_MS || (self.due_since.is_some() && age >= DELIVERY_ROTATION_MIN_GAP_MS)
    }
}

impl Engine {



    /// Create an invite for a space (server). `kind` is "token" (one-time auto-join), "username"
    /// (auto-join only the reserved name), or "code" (needs host approval). Returns the code.
    pub async fn invite_to_space(&self, server_id: &str, kind: &str, reserved_username: Option<&str>) -> Result<String, EngineError> {
        let mut body = serde_json::json!({ "kind": kind });
        if let Some(name) = reserved_username {
            body["reserved_username"] = serde_json::json!(name);
        }
        let resp = self.api.post(&format!("/api/servers/{}/invites", enc(server_id)), body).await?;
        resp["code"].as_str().map(str::to_string).ok_or(EngineError::Protocol("no invite code"))
    }

    /// Whether `user_id` is a confirmed member of `server_id` (we must have MANAGE access to see it).
    pub(super) async fn is_member(&self, server_id: &str, user_id: &str) -> Result<bool, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/members", enc(server_id))).await?;
        Ok(resp["members"]
            .as_array()
            .is_some_and(|ms| ms.iter().any(|m| m["user_id"].as_str() == Some(user_id))))
    }

    /// The members of a server we belong to, as (user_id, username) pairs. Usernames are the public
    /// login identity (not E2EE), so no key is needed to render the members list.
    pub async fn list_members(&self, server_id: &str) -> Result<Vec<(String, String)>, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/members", enc(server_id))).await?;
        let arr = resp["members"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|m| Some((m["user_id"].as_str()?.to_string(), m["username"].as_str()?.to_string())))
            .collect())
    }

    /// Parse a `/accept` response into a JoinOutcome (server id, pending flag, host identity).
    pub(super) fn parse_join_outcome(resp: &serde_json::Value) -> Result<JoinOutcome, EngineError> {
        let server_id = resp["server_id"].as_str().ok_or(EngineError::Protocol("no server_id"))?.to_string();
        Ok(JoinOutcome {
            server_id,
            pending: resp["pending"].as_bool().unwrap_or(false),
            host_user_id: resp["host_user_id"].as_str().map(str::to_string),
            host_device_id: resp["host_device_id"].as_str().map(str::to_string),
        })
    }

    /// Create a role on a server we hold the space key for (name stays E2EE). Returns the role id.
    pub async fn create_role(&mut self, server_id: &str, name: &str, permissions: i64) -> Result<String, EngineError> {
        let sk = *self.spaces.get(server_id).ok_or(EngineError::Protocol("no space key for server"))?;
        let resp = self
            .api
            .post(
                &format!("/api/servers/{}/roles", enc(server_id)),
                serde_json::json!({ "name_ciphertext": Self::seal_name(&sk, name), "permissions": permissions }),
            )
            .await?;
        resp["role_id"].as_str().map(str::to_string).ok_or(EngineError::Protocol("no role_id"))
    }

    /// The roles on a server, names decrypted with the space key we hold.
    pub async fn list_roles(&self, server_id: &str) -> Result<Vec<RoleMeta>, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/roles", enc(server_id))).await?;
        let arr = resp["roles"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| {
                let role_id = r["role_id"].as_str()?.to_string();
                let name = r["name_ciphertext"].as_str().and_then(|ct| self.decrypt_name(server_id, ct));
                let permissions = r["permissions"].as_i64().unwrap_or(0);
                let is_default = r["is_default"].as_bool().unwrap_or(false) || r["is_default"].as_i64() == Some(1);
                Some(RoleMeta { role_id, name, permissions, is_default })
            })
            .collect())
    }

    /// Delete a role.
    pub async fn delete_role(&self, role_id: &str) -> Result<(), EngineError> {
        self.api.delete(&format!("/api/roles/{}", enc(role_id))).await?;
        Ok(())
    }

    /// Grant a role to a member.
    pub async fn assign_role(&self, server_id: &str, user_id: &str, role_id: &str) -> Result<(), EngineError> {
        self.api.put(&format!("/api/servers/{}/members/{}/roles/{}", enc(server_id), enc(user_id), enc(role_id)), serde_json::json!({})).await?;
        Ok(())
    }

    /// Revoke a role from a member.
    pub async fn remove_role(&self, server_id: &str, user_id: &str, role_id: &str) -> Result<(), EngineError> {
        self.api.delete(&format!("/api/servers/{}/members/{}/roles/{}", enc(server_id), enc(user_id), enc(role_id))).await?;
        Ok(())
    }

    /// The decrypted name of a server we belong to (None until we hold its space key). Used to label
    /// a freshly-joined space in the sidebar.
    pub async fn server_name(&self, server_id: &str) -> Result<Option<String>, EngineError> {
        let resp = self.api.get("/api/servers").await?;
        let arr = resp["servers"].as_array().cloned().unwrap_or_default();
        for s in arr {
            if s["server_id"].as_str() == Some(server_id) {
                return Ok(s["name_ciphertext"].as_str().and_then(|ct| self.decrypt_name(server_id, ct)));
            }
        }
        Ok(None)
    }

    /// List existing invites for a space we host (for showing/revoking them).
    pub async fn list_invites(&self, server_id: &str) -> Result<Vec<InviteInfo>, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/invites", enc(server_id))).await?;
        let arr = resp["invites"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| {
                Some(InviteInfo {
                    code: r["code"].as_str()?.to_string(),
                    max_uses: r["max_uses"].as_i64(),
                    use_count: r["use_count"].as_i64().unwrap_or(0),
                    expires_at: r["expires_at"].as_i64(),
                    status: r["status"].as_str().unwrap_or("active").to_string(),
                    waiting: r["waiting"].as_i64().unwrap_or(0),
                    waiting_full: r["waiting_full"].as_bool().unwrap_or(false),
                })
            })
            .collect())
    }

    /// Revoke an invite by code — it stops working immediately (host rotates by minting a new one).
    pub async fn revoke_invite(&self, code: &str) -> Result<(), EngineError> {
        self.api.delete(&format!("/api/invites/{}", enc(code))).await?;
        Ok(())
    }

    /// List pending join requests for a space we host. Returns (user_id, username) pairs.
    pub async fn list_join_requests(&self, server_id: &str) -> Result<Vec<(String, String)>, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/join-requests", enc(server_id))).await?;
        let arr = resp["requests"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| Some((r["user_id"].as_str()?.to_string(), r["username"].as_str()?.to_string())))
            .collect())
    }

    /// Approve a pending join request (host): the server admits the user, and this device signs
    /// the approval so every other member can verify that a person admitted them.
    pub async fn approve_join_request(&mut self, server_id: &str, user_id: &str) -> Result<(), EngineError> {
        self.api.post(&format!("/api/servers/{}/join-requests/{}/approve", enc(server_id), enc(user_id)), serde_json::json!({})).await?;
        self.approve_member(server_id, user_id).await
    }

    /// Deny a pending join request (host).
    pub async fn deny_join_request(&self, server_id: &str, user_id: &str) -> Result<(), EngineError> {
        self.api.post(&format!("/api/servers/{}/join-requests/{}/deny", enc(server_id), enc(user_id)), serde_json::json!({})).await?;
        Ok(())
    }

    // ---- safety: bans / blocks / reports (all metadata-only, see server safety.rs) ----

    /// Ban a user from a server (kicks them AND bars every rejoin path until unbanned).
    /// Requires `BAN_MEMBERS`; `reason` is an optional moderator note for the audit trail.
    pub async fn ban_member(&self, server_id: &str, user_id: &str, reason: Option<&str>) -> Result<(), EngineError> {
        self.api
            .post(&format!("/api/servers/{}/bans/{}", enc(server_id), enc(user_id)), serde_json::json!({ "reason": reason }))
            .await?;
        Ok(())
    }

    /// Lift a ban (the user still needs a fresh invite to rejoin).
    pub async fn unban_member(&self, server_id: &str, user_id: &str) -> Result<(), EngineError> {
        self.api.delete(&format!("/api/servers/{}/bans/{}", enc(server_id), enc(user_id))).await?;
        Ok(())
    }

    /// The server's ban list (requires `BAN_MEMBERS`): (user_id, username, reason) tuples.
    pub async fn list_bans(&self, server_id: &str) -> Result<Vec<(String, Option<String>, Option<String>)>, EngineError> {
        let resp = self.api.get(&format!("/api/servers/{}/bans", enc(server_id))).await?;
        let arr = resp["bans"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| {
                Some((
                    r["user_id"].as_str()?.to_string(),
                    r["username"].as_str().map(str::to_string),
                    r["reason"].as_str().map(str::to_string),
                ))
            })
            .collect())
    }

    /// Block a user. Three things happen: the server records the block (refusing DM creation, and
    /// refusing to hand the blocked user our prekeys or delivery key); this device rotates its
    /// sealed-mailbox delivery key, so the key the blocked user already holds stops working; and
    /// anything from them that still arrives is dropped unread on this device.
    pub async fn block_user(&mut self, user_id: &str) -> Result<(), EngineError> {
        self.api.put(&format!("/api/blocks/{}", enc(user_id)), serde_json::json!({})).await?;
        self.blocked.insert(user_id.to_string());
        // Best-effort: the server-side refusal and the local drop already hold without it —
        // and a failed attempt is tried again by the next maintenance pass.
        self.delivery_key_exposed();
        self.rotate_delivery_key().await;
        Ok(())
    }

    /// Someone who was handed our delivery key should no longer have it (a member left or was
    /// removed, a contact's device was removed, WE left or were removed from a server):
    /// replace it at the next opportunity.
    pub(super) fn delivery_key_exposed(&mut self) {
        self.delivery.due_since.get_or_insert(super::now_ms());
    }

    /// Replace this device's sealed-mailbox delivery key. Everyone holding the old one gets
    /// "gone" on their next deposit and fetches the new one from the directory — which the
    /// server hands only to people who may still contact us (`send_sealed` retries once after
    /// that fetch, so nothing in flight is lost). Device-signed over the new key: the server
    /// refuses a token-only rotation. `true` when the server took it.
    pub(super) async fn rotate_delivery_key(&mut self) -> bool {
        if self.passive {
            return false; // the notification extension rotates nothing
        }
        let Some(device_id) = self.device_id.clone() else { return false };
        self.delivery_attempt = Some(std::time::Instant::now());
        let fresh: [u8; 32] = skwod_crypto::random_bytes();
        use base64::Engine as _;
        let Ok(proof) = self.device_proof("delivery-key", &device_id, &fresh) else { return false };
        let body = serde_json::json!({ "delivery_key": base64::engine::general_purpose::STANDARD.encode(fresh) });
        let path = format!("/api/e2ee/devices/{}/delivery-key", enc(&device_id));
        if self.api.signed(reqwest::Method::PUT, &path, Some(body), &proof).await.is_err() {
            return false;
        }
        self.delivery_key = fresh;
        self.delivery = DeliveryRotation { rotated_at: super::now_ms(), due_since: None };
        true
    }

    /// M6: have we left a server, or been removed from one, since we last looked? Everyone in
    /// it was handed our delivery key and no longer shares anything with us, so the key is
    /// replaced (subject to the same minimum gap as every other cause). The apps leave over
    /// plain REST and a removal happens elsewhere entirely, so this is found the same way for
    /// both: the server's list of our servers no longer names one it named before. Asked at
    /// most every [`SERVERS_RECHECK`]; an answer that cannot be read changes nothing.
    pub(super) async fn check_own_servers(&mut self) {
        if self.device_id.is_none() || self.servers_checked.is_some_and(|t| t.elapsed() < SERVERS_RECHECK) {
            return;
        }
        self.servers_checked = Some(std::time::Instant::now());
        let Ok(resp) = self.api.get("/api/servers").await else { return };
        let Some(listed) = resp["servers"].as_array() else { return };
        self.note_own_servers(listed.iter().take(MAX_SERVER_ARRAY).filter_map(|s| s["server_id"].as_str().map(str::to_string)).collect());
    }

    /// Fold in the servers we are a member of now. The first listing is only a baseline. (A
    /// server that lies about the list can make us replace the key early — no more often than
    /// the minimum gap allows — and nothing else.)
    pub(super) fn note_own_servers(&mut self, now: std::collections::BTreeSet<String>) {
        if self.b45.servers.as_ref().is_some_and(|before| before.iter().any(|s| !now.contains(s))) {
            self.delivery_key_exposed();
        }
        self.b45.servers = Some(now);
    }

    /// Replace the delivery key when it is time (see [`DeliveryRotation::wanted`]). Quiet: a
    /// failure is retried after [`DELIVERY_RETRY`], never on every sync.
    pub(super) async fn maintain_delivery_key(&mut self) {
        if self.device_id.is_none() || !self.delivery.wanted(super::now_ms()) || self.delivery_attempt.is_some_and(|t| t.elapsed() < DELIVERY_RETRY) {
            return;
        }
        self.delivery_attempt = Some(std::time::Instant::now());
        if self.ensure_bound().await.is_ok() {
            self.rotate_delivery_key().await;
        }
    }

    /// Unblock a user. This device stops dropping them whatever the server answers: the local
    /// list is the user's, and an entry the server has no row for (it only ever lived here, or
    /// the server dropped it) must still be removable. The server's own answer is returned.
    pub async fn unblock_user(&mut self, user_id: &str) -> Result<(), EngineError> {
        let result = self.api.delete(&format!("/api/blocks/{}", enc(user_id))).await;
        self.blocked.remove(user_id);
        match result {
            Ok(_) | Err(crate::ClientError::Status { status: 404, .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// My block list as the SERVER has it: (user_id, username) pairs, newest first. Also adds
    /// to the local drop list (so a block made on another device takes effect here). What this
    /// device actually drops is [`Engine::blocked_users`].
    pub async fn list_blocks(&mut self) -> Result<Vec<(String, String)>, EngineError> {
        let resp = self.api.get("/api/blocks").await?;
        Ok(self.fold_blocks(&resp["blocks"]))
    }

    /// Fold the server's block list into ours and return what to show.
    pub(super) fn fold_blocks(&mut self, blocks: &serde_json::Value) -> Vec<(String, String)> {
        let arr = blocks.as_array().cloned().unwrap_or_default();
        let out: Vec<(String, String)> = arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| Some((r["user_id"].as_str()?.to_string(), r["username"].as_str()?.to_string())))
            .collect();
        // The server's list can ADD to who this device drops (a block made on another of our
        // devices) and can never take anyone off it: an empty or shortened answer must not
        // let a blocked person's messages back in. Only `unblock_user` on this device removes.
        self.blocked.extend(out.iter().map(|(id, _)| id.clone()).filter(|id| id.len() <= 128));
        // Whoever this device drops is on the list it shows, also when the server no longer
        // (or never) lists them — so they can be seen, and unblocked here, by the user.
        let mut out = out;
        let local_only: Vec<String> = self.blocked.iter().filter(|id| !out.iter().any(|(listed, _)| listed == *id)).cloned().collect();
        out.extend(local_only.into_iter().map(|id| (id, String::new())));
        out
    }

    /// File an abuse report with the instance operator. `body` is OUR OWN plaintext description /
    /// excerpt we choose to disclose (Signal-style) — nothing is decrypted server-side. Returns the
    /// report id.
    pub async fn report_abuse(
        &self,
        category: &str,
        body: Option<&str>,
        subject_user_id: Option<&str>,
        server_id: Option<&str>,
    ) -> Result<String, EngineError> {
        let resp = self
            .api
            .post(
                "/api/reports",
                serde_json::json!({
                    "category": category,
                    "body": body,
                    "subject_user_id": subject_user_id,
                    "server_id": server_id,
                }),
            )
            .await?;
        Ok(resp["report_id"].as_str().unwrap_or_default().to_string())
    }

    /// Delete a channel message we authored (server soft-deletes; receivers drop it on next fetch).
    ///
    /// The other members' devices (and our own other devices) are told over the sealed
    /// sessions; that — not the tombstone the server serves — is what removes a copy a device
    /// already holds ([`Engine::take_channel_deletes`]).
    pub async fn delete_channel_message(&mut self, channel_id: &str, message_id: &str) -> Result<(), EngineError> {
        self.api.delete(&format!("/api/messages/{}", enc(message_id))).await?;
        self.announce_delete(channel_id, message_id).await;
        Ok(())
    }

    /// Clear every message in a channel (server-side hard delete, keeping the channel/members/roles).
    /// Owner/moderator only — the server enforces MANAGE_MESSAGES. The caller purges the local cache.
    ///
    /// Other members' devices drop what they cached only when THIS device tells them so over
    /// the sealed sessions ([`Engine::take_channel_clears`]), and they act on it only if it
    /// comes from the owner they have pinned for the server: the server's own `cleared_at`
    /// deletes nothing anywhere. (A clear by a moderator who is not the owner therefore empties
    /// the server's copy and the moderator's own devices, not the other members' caches.)
    pub async fn clear_channel(&mut self, channel_id: &str) -> Result<(), EngineError> {
        self.destructive(reqwest::Method::DELETE, &format!("/api/channels/{}/messages", enc(channel_id)), None, "clear-channel", channel_id, b"").await?;
        // Announced only for a channel this device has CONFIRMED, for the server it is confirmed
        // in. Nothing is looked up, and a placement a listing made is not enough.
        if let Some(server_id) = self.confirmed_server(channel_id) {
            self.announce_clear(&server_id, channel_id).await;
        }
        Ok(())
    }

    /// Clear all content across a server (server-side hard delete): every channel's messages plus the
    /// server's stories and feed posts, keeping channels/members/roles. Server enforces MANAGE_SERVER.
    /// Members' devices are told per channel, as for [`Engine::clear_channel`].
    pub async fn clear_server_content(&mut self, server_id: &str) -> Result<(), EngineError> {
        // (Places channels created since we last looked; never moves one placed elsewhere.)
        let _ = self.list_channels(server_id).await;
        self.destructive(reqwest::Method::POST, &format!("/api/servers/{}/clear", enc(server_id)), Some(serde_json::json!({})), "clear-server", server_id, b"").await?;
        // Only the channels THIS device has confirmed in this server — not whatever ids the
        // server lists under it now.
        for channel_id in self.channels_of(server_id) {
            self.announce_clear(server_id, &channel_id).await;
        }
        Ok(())
    }

    /// A destructive or instance-wide request (server audit M-3): signed by this device, on a
    /// session bound to it, over the operation, its target and `payload` — the same bytes the
    /// server builds from what it received. An install with no device yet (a host setting up)
    /// has nothing to sign with and sends the token alone, which is all the server asks of an
    /// account without a device.
    pub(super) async fn destructive(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        op: &str,
        target: &str,
        payload: &[u8],
    ) -> Result<serde_json::Value, EngineError> {
        if self.device_id.is_none() {
            return Ok(match (method.as_str(), body) {
                ("DELETE", _) => self.api.delete(path).await?,
                ("PUT", body) => self.api.put(path, body.unwrap_or_default()).await?,
                (_, body) => self.api.post(path, body.unwrap_or_default()).await?,
            });
        }
        self.ensure_bound().await?;
        let proof = self.device_proof(op, target, payload)?;
        Ok(self.api.signed(method, path, body, &proof).await?)
    }

    /// Retention purge: hard-delete every channel message of `server_id` older than
    /// `older_than_ms` milliseconds (the server enforces MANAGE_SERVER). Device-signed.
    pub async fn purge_messages(&mut self, server_id: &str, older_than_ms: i64) -> Result<(), EngineError> {
        let body = serde_json::json!({ "older_than_ms": older_than_ms });
        self.destructive(reqwest::Method::POST, &format!("/api/servers/{}/purge", enc(server_id)), Some(body), "purge-messages", server_id, &older_than_ms.to_be_bytes()).await?;
        Ok(())
    }

    /// Delete a space on the server for good (its owner only). Device-signed. What this device
    /// trusts about the space is left alone: forgetting it is the user's own, separate choice
    /// ([`Engine::forget_space`]).
    pub async fn delete_space(&mut self, server_id: &str) -> Result<(), EngineError> {
        self.destructive(reqwest::Method::DELETE, &format!("/api/servers/{}", enc(server_id)), None, "delete-server", server_id, b"").await?;
        Ok(())
    }

    /// Name this skwod on its host (the instance owner only; build 46). Device-signed (op
    /// `instance-name`) over the name's bytes exactly as sent — the server signs-checks the raw
    /// string, then cleans it. An empty name clears it. Returns the name the host now keeps.
    pub async fn set_instance_name(&mut self, name: &str) -> Result<Option<String>, EngineError> {
        let body = serde_json::json!({ "name": name });
        let v = self.destructive(reqwest::Method::PUT, "/api/instance/name", Some(body), "instance-name", "", name.as_bytes()).await?;
        Ok(v.get("name").and_then(|x| x.as_str()).map(str::to_string))
    }

    /// Point voice at an SFU (the instance owner only). Device-signed over the three values as
    /// the server stores them (trimmed).
    pub async fn set_voice_config(&mut self, url: &str, api_key: &str, api_secret: &str) -> Result<(), EngineError> {
        let (url, key, secret) = (url.trim(), api_key.trim(), api_secret.trim());
        let payload = skwod_crypto::link::op_payload(&[url.as_bytes(), key.as_bytes(), secret.as_bytes()]);
        let body = serde_json::json!({ "url": url, "api_key": key, "api_secret": secret });
        self.destructive(reqwest::Method::PUT, "/api/voice/config", Some(body), "voice-config", "", &payload).await?;
        Ok(())
    }

    /// The channels this device has CONFIRMED in `server_id`.
    pub(super) fn channels_of(&self, server_id: &str) -> Vec<String> {
        let mut out: Vec<String> = self.guard.channel_servers.iter().filter(|(_, s)| s.as_str() == server_id).map(|(c, _)| c.clone()).take(MAX_SERVER_ARRAY).collect();
        out.sort();
        out
    }

    /// The space key reactions in `channel_id` are sealed under.
    async fn reaction_key(&mut self, channel_id: &str) -> Result<[u8; 32], EngineError> {
        let server_id = self.channel_server(channel_id).await?;
        self.spaces.get(&server_id).copied().ok_or(EngineError::Protocol("no space key for server"))
    }

    /// What the server sees for a reaction: `HMAC(space key, emoji)`, hex. Equal emoji on the
    /// same server give equal tags (so the server can still count and de-duplicate them) but the
    /// tag says nothing about WHICH emoji it is to anyone without the space key.
    ///
    /// The message id is mixed in (v2), so the same emoji on two messages gives two unrelated
    /// tags: the server cannot count an emoji across a space and guess it by frequency.
    pub(super) fn reaction_tag(key: &[u8; 32], message_id: &str, emoji: &str) -> String {
        hex::encode(skwod_crypto::aead::keyed_tag(key, b"skwod/reaction-v2", format!("{}|{message_id}|{emoji}", message_id.len()).as_bytes()))
    }

    /// What a sealed reaction is bound to: the message AND the person reacting. A sealed emoji
    /// lifted onto another message, or re-attributed to another user, does not open.
    fn reaction_aad(message_id: &str, user_id: &str) -> Vec<u8> {
        format!("skwod/reaction-v2|{}|{message_id}|{user_id}", message_id.len()).into_bytes()
    }

    /// React to a channel message with `emoji`. The server gets the keyed tag and the emoji sealed
    /// under the space key — never the emoji itself.
    pub async fn add_reaction(&mut self, channel_id: &str, message_id: &str, emoji: &str) -> Result<(), EngineError> {
        use base64::Engine as _;
        if emoji.is_empty() || emoji.len() > 64 {
            return Err(EngineError::Protocol("bad reaction"));
        }
        let key = self.reaction_key(channel_id).await?;
        let me = self.account_user_id().await?;
        // The message id and OUR user id are bound in, so a sealed emoji cannot be replayed
        // onto another message or shown as someone else's.
        let sealed = skwod_crypto::aead::seal(&key, &Self::reaction_aad(message_id, &me), emoji.as_bytes());
        self.api
            .post(
                &format!("/api/messages/{}/reactions", enc(message_id)),
                serde_json::json!({
                    "emoji_hash": Self::reaction_tag(&key, message_id, emoji),
                    "emoji_ciphertext": base64::engine::general_purpose::STANDARD.encode(sealed),
                }),
            )
            .await?;
        Ok(())
    }

    /// Remove our own `emoji` reaction from a channel message (also one written by an older
    /// build, under the older tag or the raw emoji).
    pub async fn remove_reaction(&mut self, channel_id: &str, message_id: &str, emoji: &str) -> Result<(), EngineError> {
        let key = self.reaction_key(channel_id).await?;
        let tag = Self::reaction_tag(&key, message_id, emoji);
        self.api.delete(&format!("/api/messages/{}/reactions/{}", enc(message_id), enc(&tag))).await?;
        let old_tag = hex::encode(skwod_crypto::aead::keyed_tag(&key, b"skwod/reaction-v1", emoji.as_bytes()));
        let _ = self.api.delete(&format!("/api/messages/{}/reactions/{}", enc(message_id), enc(&old_tag))).await;
        let _ = self.api.delete(&format!("/api/messages/{}/reactions/{}", enc(message_id), enc(emoji))).await;
        Ok(())
    }

    /// The reactions on a channel message as `(user_id, tag, emoji)` — only those that open:
    /// sealed under our space key for THIS message by THAT user. A row that does not (the
    /// server's own invention, a sealed emoji moved from elsewhere, a row written by a build
    /// before 45) is not a reaction and is left out, so `emoji` is always `Some`.
    pub async fn list_reactions(&mut self, channel_id: &str, message_id: &str) -> Result<Vec<(String, String, Option<String>)>, EngineError> {
        let key = self.reaction_key(channel_id).await.ok();
        let resp = self.api.get(&format!("/api/messages/{}/reactions", enc(message_id))).await?;
        let arr = resp["reactions"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .into_iter()
            .take(MAX_SERVER_ARRAY)
            .filter_map(|r| {
                let user_id = r["user_id"].as_str()?.to_string();
                let tag = r["emoji_hash"].as_str()?.to_string();
                let emoji = Self::open_reaction(key.as_ref(), message_id, &user_id, &tag, r["emoji_ciphertext"].as_str())?;
                Some((user_id, tag, Some(emoji)))
            })
            .collect())
    }

    /// The emoji behind one reaction row, or `None` when the row is not a reaction anyone made:
    /// it must carry an emoji sealed under our space key for THIS message and THIS user, and
    /// its tag must be that emoji's tag for this message (otherwise the server paired them
    /// itself). Nothing the server can write on its own passes — in particular a tag is never
    /// shown as the emoji, which is how any reaction could once be attributed to anyone.
    pub(super) fn open_reaction(key: Option<&[u8; 32]>, message_id: &str, user_id: &str, tag: &str, sealed_b64: Option<&str>) -> Option<String> {
        use base64::Engine as _;
        let key = key?;
        let sealed = base64::engine::general_purpose::STANDARD.decode(sealed_b64?).ok()?;
        let emoji = String::from_utf8(skwod_crypto::aead::open(key, &Self::reaction_aad(message_id, user_id), &sealed)?).ok()?;
        (!emoji.is_empty() && emoji.len() <= 64 && Self::reaction_tag(key, message_id, &emoji) == tag).then_some(emoji)
    }
}
