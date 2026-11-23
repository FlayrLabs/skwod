//! FCM (Firebase Cloud Messaging) delivery for Android's data-only push wakeups — the Android
//! counterpart to `apns.rs`. Same invariant: the wakeup carries only `scope` + `message_id`, never
//! content; the device fetches + decrypts and posts its own local notification.
//!
//! Auth is FCM HTTP v1 (a service account → OAuth2 access token). Config is all-or-nothing from the
//! environment (absent = Android push disabled): FCM_SERVICE_ACCOUNT_JSON (the service-account key
//! JSON, or FCM_SERVICE_ACCOUNT_JSON_BASE64). project_id / client_email / private_key are read from
//! it. Create the service account in the Firebase project's settings → Service accounts.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

pub struct Fcm {
    project_id: String,
    client_email: String,
    encoding_key: EncodingKey,
    http: reqwest::Client,
    /// Cached OAuth access token + unix-second expiry.
    cached: Mutex<Option<(String, u64)>>,
}

#[derive(Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
}

#[derive(Serialize)]
struct OAuthClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl Fcm {
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("FCM_SERVICE_ACCOUNT_JSON").ok().filter(|s| !s.is_empty()).or_else(|| {
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine as _;
            std::env::var("FCM_SERVICE_ACCOUNT_JSON_BASE64").ok()
                .and_then(|b| B64.decode(b).ok())
                .and_then(|d| String::from_utf8(d).ok())
        })?;
        let sa: ServiceAccount = match serde_json::from_str(&raw) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "FCM service account JSON invalid — Android push disabled");
                return None;
            }
        };
        let encoding_key = match EncodingKey::from_rsa_pem(sa.private_key.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(error = %e, "FCM private_key is not a valid RSA PEM — Android push disabled");
                return None;
            }
        };
        tracing::info!(project_id = %sa.project_id, "FCM push enabled");
        Some(Self {
            project_id: sa.project_id,
            client_email: sa.client_email,
            encoding_key,
            http: reqwest::Client::new(),
            cached: Mutex::new(None),
        })
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// A Google OAuth2 access token for FCM, minted from the service account and cached until ~5
    /// minutes before expiry.
    async fn access_token(&self) -> Option<String> {
        let now = Self::now();
        {
            let cache = self.cached.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((tok, exp)) = cache.as_ref() {
                if now + 300 < *exp {
                    return Some(tok.clone());
                }
            }
        }
        let claims = OAuthClaims {
            iss: self.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".into(),
            aud: "https://oauth2.googleapis.com/token".into(),
            iat: now,
            exp: now + 3600,
        };
        let assertion = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &self.encoding_key).ok()?;
        let resp = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await
            .ok()?;
        let tok: TokenResponse = resp.json().await.ok()?;
        let token = tok.access_token.clone();
        *self.cached.lock().unwrap_or_else(|e| e.into_inner()) = Some((token.clone(), now + tok.expires_in));
        Some(token)
    }

    /// Send one data-only wakeup to an Android device token.
    pub async fn send(&self, device_token: &str, scope: &str, message_id: &str) {
        let Some(access) = self.access_token().await else {
            tracing::warn!("FCM access token unavailable");
            return;
        };
        // A bare wake-up: Google must not learn which conversation or message it is about. The
        // app syncs everything on wake, so the scope and message id never leave this server.
        let _ = (scope, message_id);
        let body = wake_body(device_token);
        let url = format!("https://fcm.googleapis.com/v1/projects/{}/messages", self.project_id);
        match self.http.post(&url).bearer_auth(access).json(&body).send().await {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => {
                let status = r.status();
                let reason = r.text().await.unwrap_or_default();
                tracing::debug!(%status, reason, "FCM push rejected");
            }
            Err(e) => tracing::debug!(error = %e, "FCM push transport error"),
        }
    }
}

/// The complete FCM request for a direct wake: data-only (no `notification` block, so the app's
/// messaging service handles it), carrying a constant marker and nothing about the message.
pub(crate) fn wake_body(device_token: &str) -> serde_json::Value {
    serde_json::json!({
        "message": {
            "token": device_token,
            "data": { "wake": "1" },
            "android": { "priority": "high" },
        }
    })
}

#[cfg(test)]
mod wake_tests {
    #[test]
    fn direct_wake_names_no_conversation_or_message() {
        let body = super::wake_body("tok");
        assert_eq!(body["message"]["data"], serde_json::json!({ "wake": "1" }));
        assert!(body["message"].get("notification").is_none());
    }
}
