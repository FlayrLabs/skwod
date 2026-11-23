//! Client for the server's loopback admin page (`server/src/admin.rs`).
//!
//! The server writes `<data>/admin.url` (0600): `http://127.0.0.1:<port>/#k=<launch key>` and,
//! on a second line, `pid=<its process id>`. The launch key signs in from this machine only.
//!
//! Two rules keep it safe:
//!
//! - **Nothing is sent to a listener that has not proved itself.** Before every sign-in the
//!   client sends a fresh nonce and checks the answer, `HMAC-SHA256(SHA-256(key), context ‖
//!   nonce)`. A process that took over the port of a dead server cannot compute it, so it never
//!   sees the key. (`server.rs` additionally checks the pid in the file before even connecting.)
//! - **The key never leaves this app.** To open the page in a browser the app asks for a
//!   single-use ticket that lives ten seconds and hands it over inside a private file
//!   (`server.rs`, `write_handoff`) — never on a command line, which any local process can read.
//!
//! Plain `std` HTTP/1.1 on purpose — the only peer is our own child on 127.0.0.1.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

pub const LAUNCH_FILE: &str = "admin.url";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub addr: SocketAddr,
    pub key: String,
    /// The process that wrote the file (absent in a file from an older server: not trusted).
    pub pid: Option<u32>,
}

/// Parse the launch file's contents. Only a loopback address is accepted: this app must never
/// send the key anywhere else, whatever the file says.
pub fn parse_launch(text: &str) -> Option<Launch> {
    let mut lines = text.lines();
    let rest = lines.next()?.trim().strip_prefix("http://")?;
    let pid = lines.find_map(|l| l.trim().strip_prefix("pid=")?.parse::<u32>().ok()).filter(|p| *p > 1);
    let (authority, fragment) = rest.split_once("/#k=")?;
    let addr: SocketAddr = authority.parse().ok()?;
    let key_ok = (16..=128).contains(&fragment.len()) && fragment.bytes().all(|b| b.is_ascii_hexdigit());
    (addr.ip().is_loopback() && key_ok).then(|| Launch { addr, key: fragment.to_string(), pid })
}

pub fn read_launch(data: &Path) -> Option<Launch> {
    parse_launch(&std::fs::read_to_string(data.join(LAUNCH_FILE)).ok()?)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub set_cookie: Option<String>,
    pub body: String,
}

/// Parse one complete HTTP/1.1 response (the request was sent with `Connection: close`).
pub fn parse_response(raw: &[u8]) -> Option<Response> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut set_cookie = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.eq_ignore_ascii_case("set-cookie") {
            set_cookie = value.split(';').next().map(|v| v.trim().to_string());
        } else if name.eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let body = if chunked { dechunk(body)? } else { body.to_string() };
    Some(Response { status, set_cookie, body })
}

fn dechunk(mut rest: &str) -> Option<String> {
    let mut out = String::new();
    loop {
        let (size, after) = rest.split_once("\r\n")?;
        let size = usize::from_str_radix(size.split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        out.push_str(after.get(..size)?);
        rest = after.get(size..)?.strip_prefix("\r\n")?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Stopped,
    Starting,
    Running,
}

pub struct AdminClient {
    launch: Launch,
    cookie: Option<String>,
}

const CHALLENGE_CONTEXT: &[u8] = b"skwod-admin-challenge-v1:";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
}

/// `n` random bytes from the operating system, as hex.
pub fn random_hex(n: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| std::io::Error::other(format!("no randomness: {e}")))?;
    Ok(hex(&buf))
}

/// Is `proof` what the server holding `key` answers to `nonce`? Constant-time.
pub fn proof_is_valid(key: &str, nonce: &str, proof: &str) -> bool {
    use hmac::Mac;
    use sha2::Digest;
    let Some(proof) = unhex(proof) else { return false };
    let Ok(mut mac) = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&sha2::Sha256::digest(key.as_bytes())) else { return false };
    mac.update(CHALLENGE_CONTEXT);
    mac.update(nonce.as_bytes());
    mac.verify_slice(&proof).is_ok()
}

impl AdminClient {
    pub fn new(launch: Launch) -> Self {
        Self { launch, cookie: None }
    }

    pub fn addr(&self) -> SocketAddr {
        self.launch.addr
    }

    fn send(&self, method: &str, path: &str, body: Option<&str>) -> std::io::Result<Response> {
        let mut stream = TcpStream::connect_timeout(&self.launch.addr, TIMEOUT)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nx-skwod-admin: 1\r\n", self.launch.addr);
        if let Some(cookie) = &self.cookie {
            req.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        match body {
            Some(b) => req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{b}", b.len())),
            None if method == "POST" => req.push_str("Content-Length: 0\r\n\r\n"),
            None => req.push_str("\r\n"),
        }
        stream.write_all(req.as_bytes())?;
        let mut raw = Vec::new();
        stream.take(1 << 20).read_to_end(&mut raw)?;
        parse_response(&raw).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "not an HTTP response"))
    }

    /// Make whoever listens on the admin port prove it holds the launch key. Sends a nonce and
    /// nothing else.
    fn prove_server(&self) -> std::io::Result<()> {
        let nonce = random_hex(32)?;
        let res = self.send("POST", "/admin/api/challenge", Some(&serde_json::json!({ "nonce": nonce }).to_string()))?;
        let body: serde_json::Value = serde_json::from_str(&res.body).unwrap_or(serde_json::Value::Null);
        match body["proof"].as_str() {
            Some(proof) if res.status == 200 && proof_is_valid(&self.launch.key, &nonce, proof) => Ok(()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "the program answering on the admin port is not this skwod server")),
        }
    }

    fn login(&mut self) -> std::io::Result<()> {
        self.cookie = None;
        // Before any credential goes out — every time, since the listener behind the port can
        // change between two sign-ins.
        self.prove_server()?;
        let body = serde_json::json!({ "token": self.launch.key }).to_string();
        let res = self.send("POST", "/admin/api/login", Some(&body))?;
        match (res.status, res.set_cookie) {
            (200, Some(cookie)) => {
                self.cookie = Some(cookie);
                Ok(())
            }
            (status, _) => Err(std::io::Error::other(format!("admin sign-in refused ({status})"))),
        }
    }

    /// A signed-in request; signs in (again) when the session is missing or was dropped.
    fn call(&mut self, method: &str, path: &str) -> std::io::Result<Response> {
        if self.cookie.is_none() {
            self.login()?;
        }
        let res = self.send(method, path, None)?;
        if res.status != 401 {
            return Ok(res);
        }
        self.login()?;
        self.send(method, path, None)
    }

    fn json(&mut self, method: &str, path: &str) -> std::io::Result<serde_json::Value> {
        let res = self.call(method, path)?;
        let value: serde_json::Value = serde_json::from_str(&res.body).unwrap_or(serde_json::Value::Null);
        if res.status == 200 {
            return Ok(value);
        }
        let why = value["error"].as_str().map(str::to_string).unwrap_or_else(|| format!("HTTP {}", res.status));
        Err(std::io::Error::other(why))
    }

    pub fn phase(&mut self) -> std::io::Result<Phase> {
        let status = self.json("GET", "/admin/api/status")?;
        Ok(match status["phase"].as_str() {
            Some("running") => Phase::Running,
            Some("starting") => Phase::Starting,
            _ => Phase::Stopped,
        })
    }

    pub fn start(&mut self) -> std::io::Result<()> {
        self.json("POST", "/admin/api/start").map(|_| ())
    }

    pub fn stop(&mut self) -> std::io::Result<()> {
        self.json("POST", "/admin/api/stop").map(|_| ())
    }

    /// Ask the server process to exit cleanly (it closes the p2p endpoint and LiveKit first).
    pub fn quit(&mut self) -> std::io::Result<()> {
        self.json("POST", "/admin/api/quit").map(|_| ())
    }

    /// The URL to hand to a browser: carries a single-use ticket, never the launch key.
    pub fn browser_url(&mut self) -> std::io::Result<String> {
        let ticket = self.json("POST", "/admin/api/ticket")?;
        let ticket = ticket["ticket"].as_str().filter(|t| t.bytes().all(|b| b.is_ascii_hexdigit()) && !t.is_empty());
        let ticket = ticket.ok_or_else(|| std::io::Error::other("no ticket"))?;
        Ok(format!("http://{}/#k={ticket}", self.launch.addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn launch_file_must_be_loopback_with_a_hex_key() {
        let key = "ab".repeat(32);
        let l = parse_launch(&format!("http://127.0.0.1:3477/#k={key}\n")).unwrap();
        assert_eq!((l.addr.port(), l.key.as_str(), l.pid), (3477, key.as_str(), None));
        let l = parse_launch(&format!("http://127.0.0.1:3477/#k={key}\npid=4242\n")).unwrap();
        assert_eq!((l.key.as_str(), l.pid), (key.as_str(), Some(4242)));
        for junk in ["pid=", "pid=abc", "pid=-3", "pid=0", "pid=1"] {
            assert_eq!(parse_launch(&format!("http://127.0.0.1:3477/#k={key}\n{junk}\n")).unwrap().pid, None, "{junk}");
        }
        assert!(parse_launch(&format!("http://[::1]:3477/#k={key}")).is_some());
        for bad in [
            format!("http://192.168.1.9:3477/#k={key}"),
            format!("https://127.0.0.1:3477/#k={key}"),
            format!("http://127.0.0.1:3477/#k={key}&x=1"),
            format!("http://127.0.0.1:3477@evil.example/#k={key}"),
            "http://127.0.0.1:3477/#k=short".to_string(),
            "http://127.0.0.1:3477/".to_string(),
            String::new(),
        ] {
            assert!(parse_launch(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn responses_are_parsed_with_and_without_chunking() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nSet-Cookie: skwod_admin=abc; HttpOnly; Path=/\r\ncontent-length: 11\r\n\r\n{\"ok\":true}").unwrap();
        assert_eq!(r, Response { status: 200, set_cookie: Some("skwod_admin=abc".into()), body: "{\"ok\":true}".into() });
        let r = parse_response(b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap();
        assert_eq!((r.status, r.body.as_str()), (401, "hello world"));
        assert!(parse_response(b"garbage").is_none());
    }

    fn proof_for(key: &str, nonce: &str) -> String {
        use hmac::Mac;
        use sha2::Digest;
        let mut mac = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&sha2::Sha256::digest(key.as_bytes())).unwrap();
        mac.update(CHALLENGE_CONTEXT);
        mac.update(nonce.as_bytes());
        hex(&mac.finalize().into_bytes())
    }

    #[test]
    fn only_the_holder_of_the_key_passes_the_challenge() {
        let nonce = random_hex(32).unwrap();
        assert_eq!(nonce.len(), 64);
        assert_ne!(nonce, random_hex(32).unwrap());
        let proof = proof_for("the-launch-key-0123", &nonce);
        assert!(proof_is_valid("the-launch-key-0123", &nonce, &proof));
        assert!(!proof_is_valid("another-key-0123456", &nonce, &proof));
        assert!(!proof_is_valid("the-launch-key-0123", &random_hex(32).unwrap(), &proof), "an old answer does not fit a new nonce");
        for bad in ["", "zz", &proof[..62], "the-launch-key-0123"] {
            assert!(!proof_is_valid("the-launch-key-0123", &nonce, bad));
        }
    }

    /// Something else on the admin port: it answers every request agreeably and records what it
    /// was sent. It cannot answer the challenge.
    fn squatter() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                log.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_string());
                let body = "{\"ok\":true,\"phase\":\"running\",\"proof\":\"00ff\",\"ticket\":\"abcd\"}";
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nSet-Cookie: skwod_admin=x\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        (addr, seen)
    }

    #[test]
    fn a_port_squatter_never_receives_the_launch_key() {
        let key = "5ec2e7c0ffee5ec2e7c0ffee5ec2e7c0";
        let (addr, seen) = squatter();
        let mut c = AdminClient::new(Launch { addr, key: key.into(), pid: None });
        for result in [c.phase().map(|_| ()), c.start(), c.browser_url().map(|_| ()), c.quit()] {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        }
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 4, "one challenge per attempt, nothing after it");
        for request in seen.iter() {
            assert!(request.starts_with("POST /admin/api/challenge "), "{request}");
            assert!(!request.contains(key) && !request.contains("Cookie:"), "no credential reached the squatter");
        }
    }

    /// A stand-in admin page: one-key login, cookie sessions that can be dropped, tickets.
    fn fake_admin(key: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            let mut session = 0u32;
            let mut running = false;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let line = req.lines().next().unwrap_or_default().to_string();
                log.lock().unwrap().push(line.clone());
                let authed = req.contains(&format!("Cookie: skwod_admin=s{session}\r\n")) && session > 0;
                let has_header = req.contains("x-skwod-admin: 1\r\n");
                let (status, extra, body) = if line.starts_with("POST /admin/api/challenge") {
                    let nonce = req.rsplit_once("{\"nonce\":\"").map(|(_, n)| n.trim_end_matches("\"}").to_string()).unwrap_or_default();
                    ("200 OK", String::new(), format!("{{\"proof\":\"{}\"}}", proof_for(key, &nonce)))
                } else if line.starts_with("POST /admin/api/login") {
                    if has_header && req.ends_with(&format!("{{\"token\":\"{key}\"}}")) {
                        session += 1;
                        ("200 OK", format!("Set-Cookie: skwod_admin=s{session}; HttpOnly\r\n"), "{\"ok\":true}".to_string())
                    } else {
                        ("401 Unauthorized", String::new(), "{\"error\":\"no\"}".to_string())
                    }
                } else if !authed {
                    ("401 Unauthorized", String::new(), "{\"error\":\"sign in\"}".to_string())
                } else if line.starts_with("GET /admin/api/status") {
                    ("200 OK", String::new(), format!("{{\"phase\":\"{}\"}}", if running { "running" } else { "stopped" }))
                } else if line.starts_with("POST /admin/api/start") {
                    running = true;
                    ("200 OK", String::new(), "{\"ok\":true}".to_string())
                } else if line.starts_with("POST /admin/api/stop") {
                    running = false;
                    session += 100; // the server "forgets" the session: the client must sign in again
                    ("200 OK", String::new(), "{\"ok\":true}".to_string())
                } else if line.starts_with("POST /admin/api/ticket") {
                    ("200 OK", String::new(), "{\"ticket\":\"0123abcd\"}".to_string())
                } else {
                    ("500 Internal Server Error", String::new(), "{\"error\":\"boom\"}".to_string())
                };
                let _ = stream.write_all(format!("HTTP/1.1 {status}\r\n{extra}content-length: {}\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        (addr, seen)
    }

    #[test]
    fn signs_in_with_the_launch_key_and_again_when_the_session_is_gone() {
        let key = "feedfacefeedfacefeedface";
        let (addr, seen) = fake_admin(key);
        let mut c = AdminClient::new(Launch { addr, key: key.into(), pid: None });
        assert_eq!(c.phase().unwrap(), Phase::Stopped);
        c.start().unwrap();
        assert_eq!(c.phase().unwrap(), Phase::Running);
        c.stop().unwrap(); // drops our session on the fake
        assert_eq!(c.phase().unwrap(), Phase::Stopped, "re-signed in transparently");
        assert_eq!(c.browser_url().unwrap(), format!("http://{addr}/#k=0123abcd"));
        assert!(!c.browser_url().unwrap().contains(key), "the launch key never goes to a browser");
        let err = c.quit().unwrap_err().to_string();
        assert_eq!(err, "boom", "server errors surface their message");
        let logins = seen.lock().unwrap().iter().filter(|l| l.starts_with("POST /admin/api/login")).count();
        assert_eq!(logins, 2);
        // A wrong key is refused, loudly.
        // A client holding a different key does not get as far as presenting it: the server's
        // proof does not verify against it.
        let before = seen.lock().unwrap().len();
        let mut bad = AdminClient::new(Launch { addr, key: "00000000000000000000".into(), pid: None });
        assert_eq!(bad.phase().unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        let after: Vec<String> = seen.lock().unwrap()[before..].to_vec();
        assert_eq!(after.len(), 1);
        assert!(after[0].starts_with("POST /admin/api/challenge"));
    }
}
