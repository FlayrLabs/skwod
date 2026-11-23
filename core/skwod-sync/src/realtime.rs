//! Realtime WebSocket client: connect → auth → resubscribe → yield events, with automatic
//! reconnect and caller-driven REST backfill after gaps.
//!
//! The subscription set is owned here so a reconnect can silently re-subscribe. On any connection
//! drop the client emits [`RtEvent::Reconnected`] once the socket is back and topics are restored,
//! which is the caller's signal to backfill each scope over REST (the relay does not replay missed
//! events — a lagged consumer recovers through the REST history endpoints).

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Events surfaced to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtEvent {
    /// A relay event: (topic, event-name, payload).
    Message { topic: String, event: String, payload: Value },
    /// The socket reconnected and all prior subscriptions were restored; backfill now.
    Reconnected,
    /// The client stopped (caller dropped the handle / shutdown requested).
    Closed,
}

/// Handle to a running realtime client. Dropping it stops the background task.
pub struct RealtimeClient {
    topics: Arc<Mutex<HashSet<String>>>,
    cmd_tx: mpsc::UnboundedSender<Command>,
}

enum Command {
    Subscribe(String),
    Unsubscribe(String),
    Shutdown,
}

/// Backoff schedule for reconnect attempts (ms), capped.
fn backoff_ms(attempt: u32) -> u64 {
    let base = 250u64.saturating_mul(1 << attempt.min(6));
    base.min(15_000)
}

/// Reject plaintext `ws://` to a NON-loopback host (mirrors `client.rs::is_insecure_remote`): the
/// token would otherwise cross a real network in the clear. Only loopback literals stay allowed.
fn is_insecure_ws_remote(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("ws://") else { return false };
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
    !(host == "localhost" || host == "127.0.0.1" || host == "::1")
}

/// Build the WS handshake request carrying the bearer token in the `Authorization` header rather
/// than the URL query string (query strings leak into proxy/access logs). The server accepts either
/// form (see `server/src/ws.rs`), so the header path is compatible.
fn build_ws_request(ws_url: &str, token: &str) -> Option<tokio_tungstenite::tungstenite::handshake::client::Request> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
    let mut req = ws_url.into_client_request().ok()?;
    let value = format!("Bearer {token}").parse().ok()?;
    req.headers_mut().insert(AUTHORIZATION, value);
    Some(req)
}

impl RealtimeClient {
    /// Spawn the client. `ws_url` is the `/api/ws` endpoint; `token` authenticates the socket.
    /// Events (and reconnect signals) arrive on the returned receiver.
    pub fn connect(ws_url: impl Into<String>, token: impl Into<String>) -> (Self, mpsc::UnboundedReceiver<RtEvent>) {
        let ws_url = ws_url.into();
        let token = token.into();
        let topics: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let task_topics = topics.clone();
        tokio::spawn(run(ws_url, token, task_topics, event_tx, cmd_rx));

        (Self { topics, cmd_tx }, event_rx)
    }

    pub fn subscribe(&self, topic: impl Into<String>) {
        let topic = topic.into();
        self.topics.lock().unwrap_or_else(|e| e.into_inner()).insert(topic.clone());
        let _ = self.cmd_tx.send(Command::Subscribe(topic));
    }

    pub fn unsubscribe(&self, topic: &str) {
        self.topics.lock().unwrap_or_else(|e| e.into_inner()).remove(topic);
        let _ = self.cmd_tx.send(Command::Unsubscribe(topic.to_string()));
    }

    pub fn subscriptions(&self) -> Vec<String> {
        self.topics.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }
}

impl Drop for RealtimeClient {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Command::Shutdown);
    }
}

async fn run(
    ws_url: String,
    token: String,
    topics: Arc<Mutex<HashSet<String>>>,
    event_tx: mpsc::UnboundedSender<RtEvent>,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
) {
    // Enforce TLS for remote sockets: cleartext ws:// is only allowed to loopback literals.
    if is_insecure_ws_remote(&ws_url) {
        let _ = event_tx.send(RtEvent::Closed);
        return;
    }
    let mut attempt = 0u32;
    let mut first = true;

    loop {
        // Rebuild the handshake request each attempt (connect_async consumes it); the token rides in
        // the Authorization header, not the URL.
        let Some(request) = build_ws_request(&ws_url, &token) else {
            let _ = event_tx.send(RtEvent::Closed);
            return;
        };
        match tokio_tungstenite::connect_async(request).await {
            Ok((ws, _)) => {
                attempt = 0;
                let (mut sink, mut stream) = ws.split();

                // (Re)subscribe to every remembered topic.
                let current: Vec<String> = topics.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
                for topic in &current {
                    if sink.send(WsMessage::Text(json!({ "type": "subscribe", "topic": topic }).to_string())).await.is_err() {
                        break;
                    }
                }
                if !first && event_tx.send(RtEvent::Reconnected).is_err() {
                    return;
                }
                first = false;

                // Pump until the socket drops or a shutdown arrives.
                loop {
                    tokio::select! {
                        cmd = cmd_rx.recv() => match cmd {
                            Some(Command::Subscribe(t)) => {
                                let _ = sink.send(WsMessage::Text(json!({"type":"subscribe","topic":t}).to_string())).await;
                            }
                            Some(Command::Unsubscribe(t)) => {
                                let _ = sink.send(WsMessage::Text(json!({"type":"unsubscribe","topic":t}).to_string())).await;
                            }
                            Some(Command::Shutdown) | None => {
                                let _ = sink.send(WsMessage::Close(None)).await;
                                let _ = event_tx.send(RtEvent::Closed);
                                return;
                            }
                        },
                        incoming = stream.next() => match incoming {
                            Some(Ok(WsMessage::Text(text))) => {
                                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                                    if v["type"] == "event" {
                                        let ev = RtEvent::Message {
                                            topic: v["topic"].as_str().unwrap_or_default().to_string(),
                                            event: v["event"].as_str().unwrap_or_default().to_string(),
                                            payload: v["payload"].clone(),
                                        };
                                        if event_tx.send(ev).is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            Some(Ok(WsMessage::Close(_))) | None => break,
                            Some(Ok(_)) => {}
                            Some(Err(_)) => break,
                        },
                    }
                }
            }
            Err(_) => {
                // Fall through to backoff; a caller shutdown during backoff still stops us.
            }
        }

        // Reconnect backoff, interruptible by a shutdown command.
        let wait = Duration::from_millis(backoff_ms(attempt));
        attempt = attempt.saturating_add(1);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            cmd = cmd_rx.recv() => {
                if matches!(cmd, Some(Command::Shutdown) | None) {
                    let _ = event_tx.send(RtEvent::Closed);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_ms(0), 250);
        assert_eq!(backoff_ms(1), 500);
        assert_eq!(backoff_ms(3), 2000);
        assert_eq!(backoff_ms(20), 15_000, "capped");
        assert!(backoff_ms(5) <= backoff_ms(6));
    }
}
