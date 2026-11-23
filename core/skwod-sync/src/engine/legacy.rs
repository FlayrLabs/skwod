//! Reading a protocol-v1 engine snapshot (builds 29–40) so an upgrade can carry over what is still
//! meaningful. This file is **layout only** — field shapes of the old postcard blob. It contains no
//! cryptography, and none of the v1 key material it parses is ever used: v1 sessions cannot be
//! converted to libsignal sessions, so the old identity, prekeys, ratchets and sender keys are
//! wiped as soon as the carry-over has been extracted.
//!
//! What survives the upgrade:
//! - **space keys** (so channel/server names stay readable without waiting for re-provisioning),
//! - **expected provisioners** (which host may hand us a space key for which server),
//! - the set of **users we had a v1 session with**, so each of them gets an explicit
//!   "safety number changed" notice the first time a libsignal session is set up.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::Deserialize;
use zeroize::Zeroize;

#[derive(Deserialize)]
struct KeyPair {
    #[allow(dead_code)]
    public: Vec<u8>,
    secret: Vec<u8>,
}

#[derive(Deserialize)]
struct IdentityKeyPair {
    ik: KeyPair,
    signing: KeyPair,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RatchetState {
    rk: [u8; 32],
    dhs: KeyPair,
    dhr: Option<Vec<u8>>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: BTreeMap<(Vec<u8>, u32), [u8; 32]>,
    ad: Vec<u8>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct InitialMessage {
    ik_public: Vec<u8>,
    ek_public: Vec<u8>,
    kem_ciphertext: Vec<u8>,
    used_opk: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SenderKeyState {
    chain_key: [u8; 32],
    iteration: u32,
    signing: KeyPair,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SenderKeyReceiver {
    chain_key: [u8; 32],
    iteration: u32,
    signing_public: Vec<u8>,
    skipped: BTreeMap<u32, [u8; 32]>,
}

/// The v1 `EngineState`, up to (and excluding) the trailing `group_dist` field that later v1
/// builds appended — postcard ignores trailing bytes, so this one layout reads every v1 blob.
#[derive(Deserialize)]
struct StateV1 {
    identity: IdentityKeyPair,
    spk: KeyPair,
    pq_spk: KeyPair,
    otp_secrets: HashMap<i64, KeyPair>,
    device_id: Option<String>,
    ratchets: HashMap<String, RatchetState>,
    #[allow(dead_code)]
    pending_initial: HashMap<String, (InitialMessage, Option<i64>)>,
    group_send: HashMap<String, SenderKeyState>,
    group_recv: HashMap<String, SenderKeyReceiver>,
    spaces: HashMap<String, [u8; 32]>,
    #[allow(dead_code)]
    initiated: HashSet<String>,
    pinned_ids: HashMap<String, Vec<u8>>,
    expected_provisioner: HashMap<String, String>,
}

impl StateV1 {
    /// Best-effort wipe of the v1 secrets we just deserialized.
    fn wipe(&mut self) {
        for kp in [&mut self.identity.ik, &mut self.identity.signing, &mut self.spk, &mut self.pq_spk] {
            kp.secret.zeroize();
        }
        for kp in self.otp_secrets.values_mut() {
            kp.secret.zeroize();
        }
        for r in self.ratchets.values_mut() {
            r.rk.zeroize();
            r.dhs.secret.zeroize();
            r.cks.zeroize();
            r.ckr.zeroize();
            for k in r.skipped.values_mut() {
                k.zeroize();
            }
        }
        for s in self.group_send.values_mut() {
            s.chain_key.zeroize();
            s.signing.secret.zeroize();
        }
        for s in self.group_recv.values_mut() {
            s.chain_key.zeroize();
        }
    }
}

/// What an upgrade keeps from a v1 snapshot.
pub struct CarryOver {
    pub spaces: HashMap<String, [u8; 32]>,
    pub expected_provisioner: HashMap<String, String>,
    /// User ids we had a v1 session (or pinned identity) with.
    pub peers: BTreeSet<String>,
    /// The v1 device id (already deleted server-side by the v2 migration; informational).
    pub old_device_id: Option<String>,
}

/// Parse a v1 snapshot. `None` if the bytes are not a v1 engine state.
pub fn parse(bytes: &[u8]) -> Option<CarryOver> {
    let mut v1: StateV1 = postcard::from_bytes(bytes).ok()?;
    // Sanity: a real v1 state always has a 32-byte X25519 identity. This keeps arbitrary bytes that
    // happen to decode positionally from being mistaken for one.
    if v1.identity.ik.secret.len() != 32 || v1.identity.ik.public.len() != 32 {
        return None;
    }
    let user_of = |k: &String| k.split(':').next().unwrap_or(k).to_string();
    let mut peers: BTreeSet<String> = v1.ratchets.keys().chain(v1.pinned_ids.keys()).map(user_of).collect();
    // group_recv keys are "<scope>|<user>:<device>".
    peers.extend(v1.group_recv.keys().filter_map(|k| k.rsplit_once('|')).map(|(_, peer)| user_of(&peer.to_string())));
    let out = CarryOver {
        spaces: std::mem::take(&mut v1.spaces),
        expected_provisioner: std::mem::take(&mut v1.expected_provisioner),
        peers,
        old_device_id: v1.device_id.take(),
    };
    v1.wipe();
    Some(out)
}
