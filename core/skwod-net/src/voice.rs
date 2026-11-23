//! LiveKit media over QUIC datagrams.
//!
//! The host's LiveKit advertises exactly one ICE candidate: `127.0.0.1:<udp_port>` (UDP mux). On
//! the host that is LiveKit itself. On a member's device the same loopback address is a small
//! forwarder (this module) that carries each UDP packet to the host as a QUIC datagram on the
//! existing `skwod/1` connection; the host re-emits it to LiveKit from a per-flow loopback socket
//! and sends the answers back the same way. WebRTC never learns it isn't talking to a local SFU,
//! LiveKit never sees a client address, and no media port is exposed to any network.
//!
//! Datagram layout: `flow:u8 | (idx<<4 | count):u8 | [pkt_id:u16 if count>1] | payload`.
//! `flow` distinguishes the member's local UDP sockets (ICE may use several). Packets larger than
//! the QUIC datagram limit (path MTU dependent, ~1.1–1.4 kB) are split into `count` fragments and
//! reassembled; a lost fragment loses the packet, which is exactly UDP semantics.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use iroh::endpoint::Connection;
use tokio::net::UdpSocket;

pub(crate) const MAX_FLOWS: usize = 32;
/// A flow (one local UDP socket of the WebRTC client) unused for this long may be recycled. ICE
/// opens several sockets per call and abandons most; without recycling, a few calls on one
/// connection would exhaust the table and the next call could never connect.
const FLOW_IDLE: std::time::Duration = std::time::Duration::from_secs(20);

/// Media forwarded by the member-side forwarder (local observability only — never sent anywhere).
#[derive(Debug, Default)]
pub struct VoiceStats {
    pub packets_up: std::sync::atomic::AtomicU64,
    pub bytes_up: std::sync::atomic::AtomicU64,
    pub packets_down: std::sync::atomic::AtomicU64,
    pub bytes_down: std::sync::atomic::AtomicU64,
}
const MAX_FRAGMENTS: usize = 15;
const MAX_PARTIAL: usize = 64;
/// Conservative payload budget when the connection can't tell us its datagram limit yet.
const FALLBACK_DATAGRAM: usize = 1100;

/// Split `payload` into datagrams no larger than `max`. `None` if it can't fit in 15 fragments.
pub(crate) fn encode(flow: u8, pkt_id: u16, payload: &[u8], max: usize) -> Option<Vec<Bytes>> {
    if payload.len() + 2 <= max {
        let mut d = Vec::with_capacity(payload.len() + 2);
        d.extend_from_slice(&[flow, 0x01]);
        d.extend_from_slice(payload);
        return Some(vec![d.into()]);
    }
    let chunk = max.checked_sub(4).filter(|c| *c > 0)?;
    let count = payload.len().div_ceil(chunk);
    if count > MAX_FRAGMENTS {
        return None;
    }
    Some(
        payload
            .chunks(chunk)
            .enumerate()
            .map(|(idx, part)| {
                let mut d = Vec::with_capacity(part.len() + 4);
                d.extend_from_slice(&[flow, ((idx as u8) << 4) | count as u8]);
                d.extend_from_slice(&pkt_id.to_be_bytes());
                d.extend_from_slice(part);
                d.into()
            })
            .collect(),
    )
}

#[derive(Default)]
pub(crate) struct Reassembler {
    partial: HashMap<(u8, u16), Vec<Option<Bytes>>>,
    order: VecDeque<(u8, u16)>,
}

impl Reassembler {
    /// Feed one datagram; returns `(flow, packet)` when a whole UDP packet is available.
    pub(crate) fn push(&mut self, d: Bytes) -> Option<(u8, Bytes)> {
        if d.len() < 2 {
            return None;
        }
        let (flow, frag) = (d[0], d[1]);
        let (idx, count) = ((frag >> 4) as usize, (frag & 0x0f) as usize);
        if count == 1 {
            return (idx == 0).then(|| (flow, d.slice(2..)));
        }
        if count == 0 || idx >= count || d.len() < 4 {
            return None;
        }
        let key = (flow, u16::from_be_bytes([d[2], d[3]]));
        if !self.partial.contains_key(&key) {
            if self.order.len() >= MAX_PARTIAL {
                if let Some(old) = self.order.pop_front() {
                    self.partial.remove(&old);
                }
            }
            self.order.push_back(key);
            self.partial.insert(key, vec![None; count]);
        }
        let parts = self.partial.get_mut(&key)?;
        if parts.len() != count {
            return None;
        }
        parts[idx] = Some(d.slice(4..));
        if parts.iter().any(Option::is_none) {
            return None;
        }
        let parts = self.partial.remove(&key)?;
        self.order.retain(|k| *k != key);
        let mut whole = Vec::with_capacity(parts.iter().map(|p| p.as_ref().map_or(0, Bytes::len)).sum());
        for p in parts.into_iter().flatten() {
            whole.extend_from_slice(&p);
        }
        Some((flow, whole.into()))
    }
}

fn send_packet(conn: &Connection, ids: &AtomicU16, flow: u8, payload: &[u8]) {
    let max = conn.max_datagram_size().unwrap_or(FALLBACK_DATAGRAM);
    let id = ids.fetch_add(1, Ordering::Relaxed);
    if let Some(datagrams) = encode(flow, id, payload, max) {
        for d in datagrams {
            // Unreliable by design: a full send buffer drops the oldest datagram (media is real-time).
            let _ = conn.send_datagram(d);
        }
    }
}

struct HostFlow {
    sock: Arc<UdpSocket>,
    last_used: std::time::Instant,
    /// For recycling ONE flow. The task itself is owned by `run_host`'s `JoinSet`.
    reader: tokio::task::AbortHandle,
}

/// Live host-side reader tasks per LiveKit UDP target (observability + tests: proves readers
/// die with their forwarder).
static ACTIVE_READERS: std::sync::Mutex<Option<HashMap<SocketAddr, usize>>> = std::sync::Mutex::new(None);

#[doc(hidden)]
pub fn active_host_readers(livekit_udp: SocketAddr) -> usize {
    ACTIVE_READERS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(|m| m.get(&livekit_udp).copied()).unwrap_or(0)
}

/// Counts a reader task for as long as it exists — decremented on drop, i.e. also when the task
/// is aborted.
struct ReaderGuard(SocketAddr);

impl ReaderGuard {
    fn new(target: SocketAddr) -> Self {
        *ACTIVE_READERS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashMap::new).entry(target).or_insert(0) += 1;
        Self(target)
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        if let Some(n) = ACTIVE_READERS.lock().unwrap_or_else(|e| e.into_inner()).as_mut().and_then(|m| m.get_mut(&self.0)) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Host side: datagrams ⇄ LiveKit's UDP mux port, one loopback socket per member flow.
///
/// Runs until the connection closes — or until this future is DROPPED (voice revocation aborts
/// it). The per-flow reader tasks live in a `JoinSet` owned by this future, so they are aborted
/// with it in every case: nothing keeps forwarding LiveKit media to a member whose grant is gone,
/// and no socket or task outlives the forwarder.
#[allow(clippy::map_entry)] // the insert path awaits (bind/connect); the entry API can't span that
pub(crate) async fn run_host(conn: Connection, livekit_udp: SocketAddr) {
    let ids = Arc::new(AtomicU16::new(0));
    let mut reasm = Reassembler::default();
    let mut flows: HashMap<u8, HostFlow> = HashMap::new();
    let mut readers = tokio::task::JoinSet::new(); // aborts every reader when dropped
    loop {
        let datagram = tokio::select! {
            d = conn.read_datagram() => match d {
                Ok(d) => d,
                Err(_) => break,
            },
            _ = conn.closed() => break,
            // Reap readers that ended on their own so the set doesn't accumulate.
            Some(_) = readers.join_next(), if !readers.is_empty() => continue,
        };
        let Some((flow, packet)) = reasm.push(datagram) else { continue };
        if flow as usize >= MAX_FLOWS {
            continue;
        }
        let now = std::time::Instant::now();
        // A flow id coming back after a long silence is a RECYCLED slot on the member side (a new
        // client socket): give it a fresh local socket so LiveKit sees a new remote address.
        if flows.get(&flow).is_some_and(|f| now.duration_since(f.last_used) >= FLOW_IDLE) {
            if let Some(old) = flows.remove(&flow) {
                old.reader.abort();
            }
        }
        if !flows.contains_key(&flow) {
            let bind: SocketAddr = match livekit_udp {
                SocketAddr::V4(a) if a.ip().is_loopback() => ([127, 0, 0, 1], 0).into(),
                SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
                SocketAddr::V6(_) => ([0u16; 8], 0).into(),
            };
            let Ok(sock) = UdpSocket::bind(bind).await else { continue };
            if sock.connect(livekit_udp).await.is_err() {
                continue;
            }
            let sock = Arc::new(sock);
            let (conn, ids, rx) = (conn.clone(), ids.clone(), sock.clone());
            let reader = readers.spawn(async move {
                let _alive = ReaderGuard::new(livekit_udp);
                let mut buf = vec![0u8; 65536];
                loop {
                    tokio::select! {
                        got = rx.recv(&mut buf) => match got {
                            Ok(n) => send_packet(&conn, &ids, flow, &buf[..n]),
                            Err(_) => break,
                        },
                        _ = conn.closed() => break,
                    }
                }
            });
            flows.insert(flow, HostFlow { sock, last_used: now, reader });
        }
        if let Some(f) = flows.get_mut(&flow) {
            f.last_used = now;
            let _ = f.sock.send(&packet).await;
        }
    }
    readers.shutdown().await;
}

/// Which slot a packet from `from` uses: its existing one, a free one, or — when the table is
/// full — the slot idle the longest, provided it has been idle for at least [`FLOW_IDLE`].
fn assign_flow(slots: &mut Vec<(SocketAddr, std::time::Instant)>, from: SocketAddr, now: std::time::Instant) -> Option<u8> {
    if let Some(i) = slots.iter().position(|(a, _)| *a == from) {
        slots[i].1 = now;
        return Some(i as u8);
    }
    if slots.len() < MAX_FLOWS {
        slots.push((from, now));
        return Some((slots.len() - 1) as u8);
    }
    let (i, (_, last)) = slots.iter().enumerate().min_by_key(|(_, (_, last))| *last)?;
    if now.duration_since(*last) < FLOW_IDLE {
        return None;
    }
    slots[i] = (from, now);
    Some(i as u8)
}

/// Member side: bind the loopback candidate LiveKit advertises and shuttle packets to the host.
/// Returns once the socket is bound; the pump runs until the connection closes or the task is aborted.
pub(crate) async fn start_member(conn: Connection, udp_port: u16, stats: Arc<VoiceStats>) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use std::sync::atomic::Ordering::Relaxed;
    let sock = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], udp_port))).await?;
    Ok(tokio::spawn(async move {
        let ids = AtomicU16::new(0);
        let mut reasm = Reassembler::default();
        let mut slots: Vec<(SocketAddr, std::time::Instant)> = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                got = sock.recv_from(&mut buf) => {
                    let Ok((n, from)) = got else { break };
                    if !is_local_source(&from) {
                        continue;
                    }
                    let Some(flow) = assign_flow(&mut slots, from, std::time::Instant::now()) else { continue };
                    stats.packets_up.fetch_add(1, Relaxed);
                    stats.bytes_up.fetch_add(n as u64, Relaxed);
                    send_packet(&conn, &ids, flow, &buf[..n]);
                }
                datagram = conn.read_datagram() => {
                    let Ok(datagram) = datagram else { break };
                    if let Some((flow, packet)) = reasm.push(datagram) {
                        if let Some((to, _)) = slots.get(flow as usize) {
                            stats.packets_down.fetch_add(1, Relaxed);
                            stats.bytes_down.fetch_add(packet.len() as u64, Relaxed);
                            let _ = sock.send_to(&packet, to).await;
                        }
                    }
                }
            }
        }
    }))
}

/// A socket bound to 127.0.0.1 only ever receives packets that originated on this machine (the
/// kernel drops off-host packets addressed to loopback), but the SOURCE address may be one of the
/// machine's own interface addresses: WebRTC sends from its LAN-bound socket. So any source is
/// accepted here; this hook exists to keep that reasoning in one place.
fn is_local_source(_from: &SocketAddr) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_slots_are_recycled_only_when_idle() {
        let t0 = std::time::Instant::now();
        let addr = |p: u16| SocketAddr::from(([127, 0, 0, 1], p));
        let mut slots = Vec::new();
        for p in 0..MAX_FLOWS as u16 {
            assert_eq!(assign_flow(&mut slots, addr(1000 + p), t0), Some(p as u8));
        }
        assert_eq!(assign_flow(&mut slots, addr(1003), t0), Some(3), "a known source keeps its flow");
        assert_eq!(assign_flow(&mut slots, addr(9999), t0), None, "full of ACTIVE flows: a new source waits");
        // Later, with only flow 5 still in use, a new source takes over the stalest slot.
        let later = t0 + FLOW_IDLE + std::time::Duration::from_secs(1);
        assert_eq!(assign_flow(&mut slots, addr(1005), later), Some(5));
        let got = assign_flow(&mut slots, addr(9999), later).expect("an idle slot is recycled");
        assert_ne!(got, 5, "never the active one");
        assert_eq!(slots.len(), MAX_FLOWS, "the table never grows past its cap");
        assert_eq!(assign_flow(&mut slots, addr(9999), later), Some(got));
    }

    #[test]
    fn small_packets_are_one_datagram() {
        let d = encode(3, 7, b"hello", 1200).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(&d[0][..], b"\x03\x01hello");
        let mut r = Reassembler::default();
        assert_eq!(r.push(d[0].clone()), Some((3, Bytes::from_static(b"hello"))));
    }

    #[test]
    fn large_packets_fragment_and_reassemble_out_of_order() {
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let mut d = encode(1, 42, &payload, 1100).unwrap();
        assert_eq!(d.len(), 3);
        assert!(d.iter().all(|x| x.len() <= 1100));
        d.reverse();
        let mut r = Reassembler::default();
        assert_eq!(r.push(d[0].clone()), None);
        assert_eq!(r.push(d[1].clone()), None);
        let (flow, whole) = r.push(d[2].clone()).unwrap();
        assert_eq!((flow, &whole[..]), (1, &payload[..]));
        assert!(r.partial.is_empty() && r.order.is_empty());
    }

    #[test]
    fn garbage_and_oversize_are_dropped() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(Bytes::from_static(b"\x00")), None);
        assert_eq!(r.push(Bytes::from_static(b"\x00\x00xx")), None, "count 0");
        assert_eq!(r.push(Bytes::from_static(b"\x00\x32\x00\x01x")), None, "idx >= count");
        assert!(encode(0, 0, &vec![0u8; 100_000], 1100).is_none());
        // Incomplete packets are evicted, never accumulate without bound.
        for id in 0..1000u16 {
            let mut d = vec![0u8, 0x02];
            d.extend_from_slice(&id.to_be_bytes());
            d.push(1);
            r.push(d.into());
        }
        assert!(r.partial.len() <= MAX_PARTIAL);
    }
}
