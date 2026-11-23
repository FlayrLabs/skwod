//! Realtime hub — one process-wide broadcast bus; each WebSocket task filters by the topics its
//! connection has (successfully) subscribed to. Sized for skwod's target scale (small groups),
//! where a shared bus beats per-topic channel bookkeeping.

use serde_json::{json, Value};
use tokio::sync::broadcast;

/// A published realtime event, fanned out to every connected socket task.
#[derive(Clone, Debug)]
pub struct RtEvent {
    pub topic: String,
    /// Full server→client frame, pre-serialized.
    pub frame: String,
    /// `Some` for the events a device is push-woken for when it has no live socket (a channel
    /// or DM `message`, `sealed` mail, a `ring`). A socket that is handed one of these has to
    /// prove it is still being read (`ws.rs`, "delivery acks"), or the wake is sent anyway.
    pub wake: Option<crate::gateway::Kind>,
    /// Who wrote it, when the event says (a `message`): their own sockets owe no proof.
    pub author: Option<String>,
    /// How many wake-bearing events the hub had published up to and including this one. A
    /// socket that lagged compares it with the last it saw: only if the number moved was
    /// anything dropped that someone could have been woken for (a flood of typing frames
    /// drops nothing of the kind).
    pub wake_no: u64,
    /// The event changes which sessions or installs of the account may act (`device_rekeyed`,
    /// `device_removed`, `sessions_revoked`): each open socket of that account re-checks its
    /// own session before anything else is written to it (`ws.rs`).
    pub security: bool,
    /// Delivered only to a subscriber who may see this channel (`voice_state::may_see`): a
    /// `voice_state` goes on the server's topic, but who is in a private voice channel is not
    /// every member's to know.
    pub gate_channel: Option<String>,
    /// The same count for `ring` events alone: a socket that lagged can tell whether a ring
    /// may be among what it missed.
    pub call_no: u64,
}

/// Which push wake, if any, stands behind a realtime event of this name.
pub fn wake_kind(event: &str) -> Option<crate::gateway::Kind> {
    match event {
        "message" | "sealed" => Some(crate::gateway::Kind::Message),
        "ring" => Some(crate::gateway::Kind::Call),
        _ => None,
    }
}

#[derive(Clone)]
pub struct RealtimeHub {
    tx: broadcast::Sender<RtEvent>,
    /// Wake-bearing events published so far; held across the send so the numbers are in bus order.
    wake_no: std::sync::Arc<std::sync::Mutex<(u64, u64)>>,
}

impl Default for RealtimeHub {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self { tx, wake_no: Default::default() }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RtEvent> {
        self.tx.subscribe()
    }

    /// The wake-bearing event count right now (a new socket starts from here).
    pub fn wake_no(&self) -> u64 {
        self.wake_no.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    /// The `ring` event count right now.
    pub fn call_no(&self) -> u64 {
        self.wake_no.lock().unwrap_or_else(|e| e.into_inner()).1
    }

    /// Publish `payload` as `event` on `topic`. No subscribers is not an error.
    pub fn publish(&self, topic: &str, event: &str, payload: Value) {
        let author = payload.get("author_id").and_then(Value::as_str).map(str::to_string);
        let frame = json!({ "type": "event", "topic": topic, "event": event, "payload": payload }).to_string();
        let wake = wake_kind(event);
        let mut wake_no = self.wake_no.lock().unwrap_or_else(|e| e.into_inner());
        if wake.is_some() {
            wake_no.0 += 1;
        }
        if wake == Some(crate::gateway::Kind::Call) {
            wake_no.1 += 1;
        }
        let security = matches!(event, "device_rekeyed" | "device_removed" | "sessions_revoked" | "account_restored");
        let gate_channel = (event == "voice_state").then(|| payload["channel_id"].as_str().unwrap_or_default().to_string());
        let _ = self.tx.send(RtEvent { topic: topic.to_string(), frame, wake, author, wake_no: wake_no.0, call_no: wake_no.1, security, gate_channel });
    }
}

pub fn channel_topic(channel_id: &str) -> String {
    format!("channel:{channel_id}")
}

pub fn dm_topic(conversation_id: &str) -> String {
    format!("dm:{conversation_id}")
}

pub fn server_topic(server_id: &str) -> String {
    format!("server:{server_id}")
}

pub fn user_topic(user_id: &str) -> String {
    format!("user:{user_id}")
}
