//! The bundled server as a child process: find it, start it, wait until its admin page answers,
//! and take it down cleanly.
//!
//! The server (`skwod run --wait-for-start`) is the long-lived thing; this app is only a remote
//! control for it. If the app dies, the server keeps running and the next launch re-attaches to
//! it through `<data>/admin.url` instead of starting a second one.
//!
//! Re-attaching is where care is needed: the launch file names a port, and a port can be taken
//! over by another local process once its server is gone. So the file is believed only if the
//! pid it names is alive AND runs the bundled `skwod` program (or is the very child this app
//! started), and even then the listener must pass the key challenge (`admin.rs`) before it is
//! sent a credential. Anything less: the file is deleted and a fresh server is started.

use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::admin::{self, AdminClient, Phase};

pub const LOG_FILE: &str = "host.log";
const ADMIN_PORT: u16 = 3477;
const API_PORT: u16 = 38411;
const START_TIMEOUT: Duration = Duration::from_secs(45);
const QUIT_TIMEOUT: Duration = Duration::from_secs(12);

/// Where the server keeps its database and keys: `--data`, else `SKWOD_HOST_DATA`, else the
/// per-user application-data directory.
pub fn data_dir(explicit: Option<PathBuf>) -> Option<PathBuf> {
    let env = |name: &str| std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute());
    if let Some(dir) = explicit.or_else(|| env("SKWOD_HOST_DATA")) {
        return Some(dir);
    }
    if cfg!(windows) {
        return env("LOCALAPPDATA").map(|d| d.join("skwod-host"));
    }
    env("XDG_DATA_HOME").or_else(|| env("HOME").map(|h| h.join(".local").join("share"))).map(|d| d.join("skwod-host"))
}

pub fn prepare_data_dir(data: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(data)?;
    #[cfg(unix)]
    {
        // Keys, the admin launch file and the log live here: this user only.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The `skwod` server binary: `SKWOD_HOST_SERVER_BIN`, else next to this executable (where the
/// packages put it, together with `livekit-server`, which the server finds beside itself).
pub fn server_binary(exe_dir: &Path) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SKWOD_HOST_SERVER_BIN").map(PathBuf::from) {
        return p.is_file().then_some(p);
    }
    let beside = exe_dir.join(if cfg!(windows) { "skwod.exe" } else { "skwod" });
    beside.is_file().then_some(beside)
}

/// `preferred` if nobody listens there, else a port the OS hands out.
fn loopback_port(preferred: u16) -> std::io::Result<u16> {
    if TcpListener::bind((Ipv4Addr::LOCALHOST, preferred)).is_ok() {
        return Ok(preferred);
    }
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port())
}

fn private_log(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// The last lines of the server's log, for "it did not start" messages.
fn log_tail(data: &Path) -> String {
    let text = std::fs::read_to_string(data.join(LOG_FILE)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.contains("admin token")).collect();
    lines[lines.len().saturating_sub(6)..].join("\n")
}

/// The program file process `pid` is running, if that process exists and we may ask.
#[cfg(target_os = "linux")]
pub fn process_executable(pid: u32) -> Option<PathBuf> {
    // A replaced or removed program reads as "<path> (deleted)", which matches nothing — right:
    // that is no longer the program we ship.
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(windows)]
pub fn process_executable(pid: u32) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: the handle is checked before use and closed exactly once; `buf` outlives the call
    // and `len` holds its capacity in characters, as the API requires.
    let ok = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        ok
    };
    (ok != 0).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize])))
}

/// macOS is a development platform for this app only (Mac hosts use the Mac app).
#[cfg(target_os = "macos")]
pub fn process_executable(pid: u32) -> Option<PathBuf> {
    let out = Command::new("/bin/ps").args(["-p", &pid.to_string(), "-o", "comm="]).stdin(Stdio::null()).output().ok()?;
    let path = String::from_utf8(out.stdout).ok()?;
    let path = path.trim();
    (out.status.success() && !path.is_empty()).then(|| PathBuf::from(path))
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub fn process_executable(_pid: u32) -> Option<PathBuf> {
    None // cannot tell: never attach, always start a fresh server
}

/// Is process `pid` alive and running exactly the program at `expected`?
pub fn pid_runs(pid: u32, expected: &Path) -> bool {
    let (Some(actual), Ok(expected)) = (process_executable(pid), std::fs::canonicalize(expected)) else { return false };
    std::fs::canonicalize(&actual).is_ok_and(|actual| actual == expected)
}

pub struct Supervisor {
    data: PathBuf,
    exe_dir: PathBuf,
    child: Option<Child>,
    /// How a pid from the launch file is matched to the bundled server program ([`pid_runs`];
    /// the tests' stand-in server is a script, so they substitute their own).
    pid_check: fn(u32, &Path) -> bool,
}

impl Supervisor {
    pub fn new(data: PathBuf, exe_dir: PathBuf) -> Self {
        Self { data, exe_dir, child: None, pid_check: pid_runs }
    }

    /// A client for the server the launch file describes — only if that file can be believed:
    /// its pid is our own live child, or (no child of ours) a live process running the bundled
    /// server program; and the listener then proves it holds the launch key. `None` otherwise.
    pub fn try_attach(&mut self) -> Option<AdminClient> {
        let launch = admin::read_launch(&self.data)?;
        let pid = launch.pid?;
        let believable = match &mut self.child {
            Some(child) => child.id() == pid && matches!(child.try_wait(), Ok(None)),
            None => server_binary(&self.exe_dir).is_some_and(|bin| (self.pid_check)(pid, &bin)),
        };
        if !believable {
            return None;
        }
        let mut client = AdminClient::new(launch);
        client.phase().ok()?; // challenge first, then sign-in, then the question
        Some(client)
    }

    pub fn data(&self) -> &Path {
        &self.data
    }

    /// Did the server process we started exit?
    pub fn child_exited(&mut self) -> bool {
        match &mut self.child {
            Some(child) => !matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// A client for a server that is up: the one already running on this data directory, or a
    /// freshly started one.
    pub fn ensure(&mut self) -> std::io::Result<AdminClient> {
        if self.child_exited() {
            self.child = None;
        }
        if let Some(client) = self.try_attach() {
            return Ok(client);
        }
        if self.child.is_none() {
            // Whatever the launch file says, it could not be believed: it is stale (or worse).
            // Remove it and start our own server, which writes a new one.
            let _ = std::fs::remove_file(self.data.join(admin::LAUNCH_FILE));
            self.child = Some(self.spawn()?);
        }
        // Ours and alive, but its page does not answer yet: wait for it (never start a second
        // server on the same database).
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if self.child_exited() {
                self.child = None;
                return Err(std::io::Error::other(format!("the skwod server stopped right after starting.\n{}", log_tail(&self.data))));
            }
            if let Some(client) = self.try_attach() {
                return Ok(client);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(format!("the skwod server did not come up.\n{}", log_tail(&self.data))));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn spawn(&self) -> std::io::Result<Child> {
        let bin = server_binary(&self.exe_dir)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("the skwod server program is missing from {}", self.exe_dir.display())))?;
        let log = private_log(&self.data.join(LOG_FILE))?;
        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .arg("--data")
            .arg(&self.data)
            .arg("--listen")
            .arg(format!("127.0.0.1:{}", loopback_port(API_PORT)?))
            .arg("--admin-listen")
            .arg(format!("127.0.0.1:{}", loopback_port(ADMIN_PORT)?))
            // Nobody is served until the host presses Start (the page, or the tray menu); the
            // choice is remembered, so a server that was started comes back after a reboot.
            .arg("--wait-for-start")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console window for the server
        }
        cmd.spawn()
    }

    /// Stop the server process: ask it to quit (it closes the p2p endpoint and LiveKit), wait,
    /// and only then force it.
    pub fn shutdown(&mut self, client: Option<&mut AdminClient>) {
        let asked = client.is_some_and(|c| c.quit().is_ok());
        let deadline = Instant::now() + if asked { QUIT_TIMEOUT } else { Duration::ZERO };
        match &mut self.child {
            Some(child) => {
                while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if matches!(child.try_wait(), Ok(None)) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                self.child = None;
            }
            // Attached to a server an earlier run of this app started: it has no handle here,
            // so wait for its page to go away.
            None => {
                while Instant::now() < deadline && admin::read_launch(&self.data).is_some() {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

/// What the tray and the headless mode drive.
pub struct Controller {
    sup: Supervisor,
    client: Option<AdminClient>,
}

impl Controller {
    pub fn new(sup: Supervisor) -> Self {
        Self { sup, client: None }
    }

    /// For a server that [`Supervisor::try_attach`] already vouched for.
    pub fn attached(sup: Supervisor, client: AdminClient) -> Self {
        Self { sup, client: Some(client) }
    }

    pub fn data(&self) -> &Path {
        self.sup.data()
    }

    /// Make sure the server process is up and we hold a client for it.
    pub fn ensure(&mut self) -> std::io::Result<&mut AdminClient> {
        if self.client.is_none() || self.sup.child_exited() {
            self.client = None;
            self.client = Some(self.sup.ensure()?);
        }
        Ok(self.client.as_mut().expect("just set"))
    }

    /// `None`: the server process is not running.
    pub fn phase(&mut self) -> Option<Phase> {
        if self.sup.child_exited() {
            self.client = None;
        }
        match self.client.as_mut()?.phase() {
            Ok(phase) => Some(phase),
            Err(_) => {
                self.client = None;
                None
            }
        }
    }

    pub fn admin_addr(&self) -> Option<std::net::SocketAddr> {
        self.client.as_ref().map(AdminClient::addr)
    }

    pub fn start(&mut self) -> std::io::Result<()> {
        self.ensure()?.start()
    }

    pub fn stop(&mut self) -> std::io::Result<()> {
        match self.client.as_mut() {
            Some(client) => client.stop(),
            None => Ok(()),
        }
    }

    /// Open the admin page, signed in, in the user's browser.
    ///
    /// The single-use ticket travels inside a private file, not on a command line (any local
    /// process can read another's arguments, and could redeem the ticket first): the browser is
    /// given only the file's path, and the file sends it on to the page. The file is removed a
    /// few seconds later; the ticket is dead by then anyway.
    pub fn open_page(&mut self) -> std::io::Result<()> {
        let url = self.ensure()?.browser_url()?;
        let file = write_handoff(self.sup.data(), &url)?;
        let opened = open_in_browser(&file);
        std::thread::spawn(move || {
            std::thread::sleep(HANDOFF_LIFETIME);
            let _ = std::fs::remove_file(file);
        });
        opened
    }

    pub fn quit(&mut self) {
        self.sup.shutdown(self.client.as_mut());
        self.client = None;
        remove_handoffs(self.sup.data());
    }
}

const HANDOFF_PREFIX: &str = "open-";
const HANDOFF_SUFFIX: &str = ".html";
/// The ticket inside lives ten seconds (`server/src/admin.rs`); the file need not outlive it.
const HANDOFF_LIFETIME: Duration = Duration::from_secs(10);

/// Write the browser hand-off page for `url` (`http://127.0.0.1:<port>/#k=<ticket>`) into the
/// private data directory: a new file with an unguessable name, readable by this user only.
pub fn write_handoff(data: &Path, url: &str) -> std::io::Result<PathBuf> {
    // The URL is embedded in HTML and script: accept exactly the shape we produce.
    let shape_ok = url.strip_prefix("http://").and_then(|r| r.split_once("/#k=")).is_some_and(|(authority, ticket)| {
        authority.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback()) && !ticket.is_empty() && ticket.bytes().all(|b| b.is_ascii_hexdigit())
    });
    if !shape_ok {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unexpected admin page address"));
    }
    let path = data.join(format!("{HANDOFF_PREFIX}{}{HANDOFF_SUFFIX}", admin::random_hex(16)?));
    let page = format!(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<meta name=\"referrer\" content=\"no-referrer\">\n<title>skwod host</title>\n\
         <script>location.replace(\"{url}\");</script>\n<noscript><meta http-equiv=\"refresh\" content=\"0;url={url}\"></noscript>\n\
         <p>Opening your skwod server…</p>\n"
    );
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path)?.write_all(page.as_bytes())?;
    Ok(path)
}

/// Remove hand-off pages left behind (the app was closed before its timer ran).
pub fn remove_handoffs(data: &Path) {
    let Ok(entries) = std::fs::read_dir(data) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(HANDOFF_PREFIX) && name.ends_with(HANDOFF_SUFFIX) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The command that opens a local HTML file in the user's default browser. Only ever given a
/// file path — never a URL carrying a secret, because arguments are visible to other processes.
fn browser_command(file: &Path) -> Command {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(file);
    cmd
}

fn open_in_browser(file: &Path) -> std::io::Result<()> {
    let mut child = browser_command(file).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait(); // reap
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_data_dir_wins_and_a_taken_port_is_avoided() {
        assert_eq!(data_dir(Some(PathBuf::from("/srv/skwod"))), Some(PathBuf::from("/srv/skwod")));
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = taken.local_addr().unwrap().port();
        let other = loopback_port(port).unwrap();
        assert_ne!(other, port);
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, other)).is_ok(), "the port handed out is free");
    }

    /// End to end against a stand-in server program (a shell script that plays `skwod run`:
    /// writes the launch file, answers the admin API, exits on quit).
    #[cfg(unix)]
    #[test]
    fn starts_reattaches_to_and_stops_the_server_process() {
        use std::os::unix::fs::PermissionsExt;
        if Command::new("python3").arg("--version").output().is_err() {
            eprintln!("skipped: python3 not available for the stand-in server");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        prepare_data_dir(&data).unwrap();
        assert_eq!(std::fs::metadata(&data).unwrap().permissions().mode() & 0o777, 0o700);
        let bin = dir.path().join("skwod");
        std::fs::write(&bin, FAKE_SERVER).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        // The stand-in is a script, so its process runs the interpreter, not the file at
        // `<dir>/skwod`: match on "that pid is alive" here. `pid_runs` has its own test.
        let alive: fn(u32, &Path) -> bool = |pid, _| process_executable(pid).is_some();
        let mut ctl = Controller::new(Supervisor::new(data.clone(), dir.path().to_path_buf()));
        assert_eq!(ctl.phase(), None, "nothing runs before ensure()");
        ctl.ensure().unwrap();
        assert_eq!(ctl.phase(), Some(Phase::Stopped));
        ctl.start().unwrap();
        assert_eq!(ctl.phase(), Some(Phase::Running));
        assert_eq!(std::fs::metadata(data.join(LOG_FILE)).unwrap().permissions().mode() & 0o777, 0o600);

        // A second controller on the same data directory attaches instead of starting another.
        let mut sup = Supervisor::new(data.clone(), dir.path().to_path_buf());
        sup.pid_check = alive;
        let mut second = Controller::new(sup);
        second.ensure().unwrap();
        assert_eq!(second.phase(), Some(Phase::Running));
        assert_eq!(second.admin_addr(), ctl.admin_addr());

        ctl.stop().unwrap();
        assert_eq!(ctl.phase(), Some(Phase::Stopped));
        ctl.quit();
        assert!(!data.join(admin::LAUNCH_FILE).exists(), "the server removed its launch file on the way out");
        assert_eq!(second.phase(), None, "the attached controller notices");

        // With no server program next to the app, the error says so.
        let mut none = Controller::new(Supervisor::new(dir.path().join("d2"), dir.path().join("nowhere")));
        prepare_data_dir(none.data()).unwrap();
        assert!(none.ensure().err().unwrap().to_string().contains("missing"));
    }

    #[test]
    fn a_pid_is_matched_to_the_program_it_runs() {
        let me = std::env::current_exe().unwrap();
        assert!(pid_runs(std::process::id(), &me), "this test process runs its own executable");
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("skwod");
        std::fs::write(&other, b"not me").unwrap();
        assert!(!pid_runs(std::process::id(), &other), "alive, but a different program");
        assert!(!pid_runs(std::process::id(), &dir.path().join("missing")));
        // A pid nobody has (far above any real pid range).
        assert!(!pid_runs(0x7fff_fff0, &me));
    }

    /// A listener that answers anything with 200 and records what it was sent.
    fn squatter() -> (std::net::SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                log.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_string());
                let body = "{\"phase\":\"running\",\"proof\":\"00\",\"ok\":true}";
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nSet-Cookie: skwod_admin=x\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        (addr, seen)
    }

    #[test]
    fn a_launch_file_pointing_at_a_squatted_port_is_deleted_not_trusted() {
        let key = "ab".repeat(32);
        let (addr, seen) = squatter();
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        prepare_data_dir(&data).unwrap();
        // The "bundled server program" exists, but nothing alive is running it.
        std::fs::write(dir.path().join(if cfg!(windows) { "skwod.exe" } else { "skwod" }), b"").unwrap();
        let launch = data.join(admin::LAUNCH_FILE);
        let me = std::process::id();

        // 1. No pid in the file (an old or forged file); 2. a pid that is alive but is some
        //    other program (this test process). Neither is even connected to.
        for contents in [format!("http://{addr}/#k={key}\n"), format!("http://{addr}/#k={key}\npid={me}\n")] {
            std::fs::write(&launch, contents).unwrap();
            let mut sup = Supervisor::new(data.clone(), dir.path().to_path_buf());
            assert!(sup.try_attach().is_none());
            assert!(seen.lock().unwrap().is_empty(), "nothing was sent to the squatter");
            // ensure() gives up on the file: deletes it and starts a fresh child (which here is
            // an empty file and cannot run — the point is what happened to the launch file).
            assert!(sup.ensure().is_err());
            assert!(!launch.exists(), "the stale launch file is gone");
            assert!(seen.lock().unwrap().is_empty());
        }

        // 3. Even with a pid check that says yes, the listener must pass the key challenge;
        //    the squatter sees a nonce and nothing else.
        std::fs::write(&launch, format!("http://{addr}/#k={key}\npid={me}\n")).unwrap();
        let mut sup = Supervisor::new(data.clone(), dir.path().to_path_buf());
        sup.pid_check = |_, _| true;
        assert!(sup.try_attach().is_none());
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with("POST /admin/api/challenge "));
        assert!(!seen[0].contains(&key), "the launch key never left");
    }

    #[test]
    fn the_ticket_reaches_the_browser_in_a_private_file_never_in_arguments() {
        let dir = tempfile::tempdir().unwrap();
        let ticket = "c0ffee".repeat(10);
        let url = format!("http://127.0.0.1:3477/#k={ticket}");
        let file = write_handoff(dir.path(), &url).unwrap();
        let other = write_handoff(dir.path(), &url).unwrap();
        assert_ne!(file, other, "a new random name every time");
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("open-") && name.ends_with(".html") && name.len() == "open-.html".len() + 32, "{name}");
        let page = std::fs::read_to_string(&file).unwrap();
        assert!(page.contains(&format!("location.replace(\"{url}\")")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // What the browser launcher is given: the file, and no trace of the ticket.
        let cmd = browser_command(&file);
        let args: Vec<String> = std::iter::once(cmd.get_program()).chain(cmd.get_args()).map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args.last().unwrap(), &file.to_string_lossy());
        assert!(args.iter().all(|a| !a.contains(&ticket) && !a.contains("#k=")), "{args:?}");
        // Only our own URL shape is ever written into a page.
        for bad in ["http://127.0.0.1:3477/#k=\"><script>", "http://evil.example/#k=abcd", "http://192.168.1.2:3477/#k=abcd", "file:///etc/passwd", "http://127.0.0.1:3477/#k="] {
            assert!(write_handoff(dir.path(), bad).is_err(), "{bad}");
        }
        // Leftovers are swept; other files in the data directory are not touched.
        std::fs::write(dir.path().join("skwod.db"), b"x").unwrap();
        std::fs::write(dir.path().join("open-notes.txt"), b"x").unwrap();
        remove_handoffs(dir.path());
        assert!(!file.exists() && !other.exists());
        assert!(dir.path().join("skwod.db").exists() && dir.path().join("open-notes.txt").exists());
    }

    #[cfg(unix)]
    const FAKE_SERVER: &str = r#"#!/usr/bin/env python3
import hashlib, hmac, http.server, json, os, sys
a = sys.argv
data = a[a.index("--data") + 1]
host, port = a[a.index("--admin-listen") + 1].split(":")
assert "--wait-for-start" in a and a[1] == "run"
KEY = "ab" * 32
state = {"phase": "stopped"}
launch = os.path.join(data, "admin.url")
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *x): pass
    def reply(self, code, obj, cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        if cookie: self.send_header("Set-Cookie", cookie)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def authed(self): return self.headers.get("Cookie") == "skwod_admin=sess"
    def do_GET(self):
        if not self.authed(): return self.reply(401, {"error": "sign in"})
        self.reply(200, state)
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n)
        if self.headers.get("x-skwod-admin") is None: return self.reply(403, {"error": "forbidden"})
        if self.path == "/admin/api/challenge":
            nonce = json.loads(body)["nonce"].encode()
            proof = hmac.new(hashlib.sha256(KEY.encode()).digest(), b"skwod-admin-challenge-v1:" + nonce, "sha256").hexdigest()
            return self.reply(200, {"proof": proof})
        if self.path == "/admin/api/login":
            if json.loads(body).get("token") == KEY: return self.reply(200, {"ok": True}, "skwod_admin=sess; HttpOnly")
            return self.reply(401, {"error": "no"})
        if not self.authed(): return self.reply(401, {"error": "sign in"})
        if self.path == "/admin/api/start": state["phase"] = "running"
        elif self.path == "/admin/api/stop": state["phase"] = "stopped"
        elif self.path == "/admin/api/ticket": return self.reply(200, {"ticket": "cd" * 32})
        elif self.path == "/admin/api/quit":
            self.reply(200, {"ok": True})
            os.remove(launch)
            os._exit(0)
        self.reply(200, {"ok": True})
srv = http.server.HTTPServer((host, int(port)), H)
with open(launch, "w") as f: f.write("http://%s:%d/#k=%s\npid=%d\n" % (host, srv.server_address[1], KEY, os.getpid()))
print("[skwod] One-time admin token: AAAAA-BBBBB", flush=True)
srv.serve_forever()
"#;
}
