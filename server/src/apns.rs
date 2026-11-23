//! APNs delivery for the data-only push wakeups built in `push.rs`.
//!
//! Token-based (JWT ES256, .p8 auth key) HTTP/2 sender. The wakeup is a SILENT background push
//! (`content-available: 1`, no alert) carrying only `scope` + `message_id` — never plaintext. The
//! device wakes, fetches + decrypts the referenced message, and posts its OWN local notification
//! with the real (decrypted) title. So the server, even a nosy host, learns nothing of content.
//!
//! Config comes from the environment (all or nothing — absent = push disabled, same as before):
//!   APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC (the app bundle id, e.g. com.skwod.app),
//!   APNS_KEY_P8 (the PEM private key, newlines or \n-escaped) OR APNS_KEY_P8_BASE64.
//! The auth key is team-scoped, so one key serves every app under the team.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

pub struct Apns {
    key_id: String,
    team_id: String,
    topic: String,
    encoding_key: EncodingKey,
    http: reqwest::Client,
    /// Cached provider JWT + the unix-second it was minted (APNs accepts a token for ~1h; we
    /// refresh well inside that).
    cached: Mutex<Option<(String, u64)>>,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: u64,
}

impl Apns {
    /// Build from environment, or None when the config isn't fully present (push stays disabled).
    pub fn from_env() -> Option<Self> {
        let key_id = std::env::var("APNS_KEY_ID").ok().filter(|s| !s.is_empty())?;
        let team_id = std::env::var("APNS_TEAM_ID").ok().filter(|s| !s.is_empty())?;
        let topic = std::env::var("APNS_TOPIC").ok().filter(|s| !s.is_empty())?;
        let pem = std::env::var("APNS_KEY_P8")
            .ok()
            .map(|s| s.replace("\\n", "\n"))
            .or_else(|| {
                use base64::engine::general_purpose::STANDARD as B64;
                use base64::Engine as _;
                std::env::var("APNS_KEY_P8_BASE64").ok().and_then(|b| B64.decode(b).ok())
                    .and_then(|d| String::from_utf8(d).ok())
            })
            .filter(|s| !s.is_empty())?;
        let encoding_key = match EncodingKey::from_ec_pem(pem.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "APNS_KEY_P8 is not a valid EC PEM — push disabled");
                return None;
            }
        };
        let http = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .ok()?;
        tracing::info!(key_id, team_id, topic, "APNs push enabled");
        Some(Self { key_id, team_id, topic, encoding_key, http, cached: Mutex::new(None) })
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// A provider JWT, minted fresh if the cached one is older than ~50 minutes.
    fn provider_token(&self) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Self::now();
        {
            let cache = self.cached.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((tok, iat)) = cache.as_ref() {
                if now.saturating_sub(*iat) < 50 * 60 {
                    return Ok(tok.clone());
                }
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = Claims { iss: self.team_id.clone(), iat: now };
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)?;
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some((token.clone(), now));
        Ok(token)
    }

    /// Send one silent wakeup. Tries production, then sandbox on `BadDeviceToken` (so a dev-signed
    /// and a TestFlight/App-Store token both work without knowing which environment minted it).
    pub async fn send(&self, device_token: &str, scope: &str, message_id: &str) {
        let jwt = match self.provider_token() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "APNs JWT mint failed");
                return;
            }
        };
        // A bare wake-up. Apple must not learn which conversation or message it is about: the
        // app syncs everything on wake, so the scope and message id never leave this server.
        let _ = (scope, message_id);
        // The token becomes part of the URL path: nothing but hex is ever put there.
        if !crate::push::valid_direct_token(device_token, "ios") {
            return;
        }
        let body = wake_body();
        for host in ["api.push.apple.com", "api.sandbox.push.apple.com"] {
            let url = format!("https://{host}/3/device/{device_token}");
            let resp = self
                .http
                .post(&url)
                .header("authorization", format!("bearer {jwt}"))
                .header("apns-topic", &self.topic)
                .header("apns-push-type", "background")
                .header("apns-priority", "5")
                .header("apns-expiration", "0")
                .json(&body)
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => return,
                Ok(r) => {
                    let status = r.status();
                    let reason = r.text().await.unwrap_or_default();
                    // Wrong environment → try the other host. Anything else → give up (logged).
                    if reason.contains("BadDeviceToken") && host == "api.push.apple.com" {
                        continue;
                    }
                    tracing::debug!(%status, reason, host, "APNs push rejected");
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, host, "APNs push transport error");
                    return;
                }
            }
        }
    }
}

/// The complete payload of a direct APNs wake: content-available and nothing else.
pub(crate) fn wake_body() -> serde_json::Value {
    serde_json::json!({ "aps": { "content-available": 1 } })
}

#[cfg(test)]
mod wake_tests {
    #[test]
    fn direct_wake_names_no_conversation_or_message() {
        let body = super::wake_body().to_string();
        assert_eq!(body, r#"{"aps":{"content-available":1}}"#);
    }
}
