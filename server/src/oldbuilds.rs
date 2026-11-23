//! Telling a build 41/42 app that it has to be updated, in words it can show.
//!
//! Those builds cannot read anything a newer member writes (channel wire v3) and their own
//! messages lack the sealed message id newer members check, so a skwod whose server and friends
//! moved on is silently half-dead for them. They carry no version marker, but one thing only
//! they do: they send a channel message WITHOUT an id of their own. The send is refused with
//! `426`, the device is remembered, and from then on its mailbox poll answers `426` too.
//!
//! What they render (checked against the build 41 and 42 sources): the core maps ANY `426` whose
//! body is `{"error": "<sentence>"}` to `UpdateRequired(<sentence>)`; the app's sync loop
//! (`processControlInbox`, every few seconds — it reads `GET /api/e2ee/sealed/inbox`) shows it
//! as an alert titled "Update required" with the sentence as the message, verbatim. The DM
//! composer shows its own "Update required" line. So the sentence must stand on its own, say
//! where to get the update, and not repeat the title.
//!
//! In memory only: a restart forgets, and the next id-less send remembers again. A device that
//! has been updated (it sends its own id, or names its build) is forgotten at once.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::state::AppState;

/// Shown verbatim under the title "Update required" by builds 41 and 42.
pub const UPDATE_REQUIRED: &str = "This skwod was updated and this version of the app can no longer send or read messages here. Download the latest Skwod from https://skwod.io/download (iPhone: update in TestFlight), then open it again. Nothing is lost.";

/// The request header a build 44+ app names its build in.
pub const BUILD_HEADER: &str = "x-skwod-build";

/// The first build that reads and writes what this server serves.
pub const MIN_BUILD: u32 = 43;

/// Devices (`"<user>:<device>"`) seen behaving like a build ≤ 42.
#[derive(Clone, Default)]
pub struct OldDevices(Arc<Mutex<HashSet<String>>>);

const MAX_REMEMBERED: usize = 10_000;

fn key(user_id: &str, device_id: &str) -> String {
    format!("{user_id}:{device_id}")
}

/// `user`'s device just did what only an old build does.
pub fn seen_old(state: &AppState, user_id: &str, device_id: Option<&str>) {
    let Some(device_id) = device_id else { return };
    let mut set = state.old_devices.0.lock().unwrap_or_else(|e| e.into_inner());
    if set.len() >= MAX_REMEMBERED {
        set.clear();
    }
    set.insert(key(user_id, device_id));
}

/// `user`'s device just did what only a current build does (it was updated).
pub fn seen_current(state: &AppState, user_id: &str, device_id: Option<&str>) {
    if let Some(device_id) = device_id {
        state.old_devices.0.lock().unwrap_or_else(|e| e.into_inner()).remove(&key(user_id, device_id));
    }
}

/// Is this device remembered as an old build? `build` is its `x-skwod-build` header, if it sent
/// one: a build that names itself is judged by the number alone.
pub fn is_old(state: &AppState, user_id: &str, device_id: &str, build: Option<u32>) -> bool {
    match build {
        Some(b) => {
            if b >= MIN_BUILD {
                seen_current(state, user_id, Some(device_id));
            }
            b < MIN_BUILD
        }
        None => state.old_devices.0.lock().unwrap_or_else(|e| e.into_inner()).contains(&key(user_id, device_id)),
    }
}

/// The build a request names, if any.
pub fn build_of(headers: &axum::http::HeaderMap) -> Option<u32> {
    headers.get(BUILD_HEADER)?.to_str().ok()?.trim().parse().ok()
}
