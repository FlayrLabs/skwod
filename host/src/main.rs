//! skwod host — the tray app for hosting a skwod on a Windows or Linux PC.
//!
//! It runs the bundled `skwod` server (which runs the bundled, pinned `livekit-server` for
//! voice and video), opens the server's admin page in the browser — the page with the big
//! **Start server** button and the invite — and sits in the tray with Start / Stop / Quit and an
//! opt-in "Launch at login". All state lives in the server's data directory; this app holds none.
//!
//! ```text
//! skwod-host [--data DIR] [--background] [--no-tray] [--start]
//!   --data DIR     where the server keeps its database and keys (default: per-user app data)
//!   --background   do not open the admin page at launch (what "Launch at login" uses)
//!   --no-tray      no tray icon: run the server until Ctrl-C (also chosen when there is no display)
//!   --start        press "Start server" for me
//! ```
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod admin;
mod autostart;
mod notes;
mod server;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod tray;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use server::{Controller, Supervisor};

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    data: Option<PathBuf>,
    background: bool,
    no_tray: bool,
    start: bool,
}

const USAGE: &str = "usage: skwod-host [--data DIR] [--background] [--no-tray] [--start]";

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut out = Args::default();
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data" => out.data = Some(PathBuf::from(args.next().ok_or("--data needs a directory")?)),
            "--background" => out.background = true,
            "--no-tray" => out.no_tray = true,
            "--start" => out.start = true,
            "--help" | "-h" => return Err(USAGE.to_string()),
            "--version" | "-V" => return Err(format!("skwod-host {}", env!("CARGO_PKG_VERSION"))),
            other => return Err(format!("unknown option {other}\n{USAGE}")),
        }
    }
    Ok(out)
}

/// A desktop session we can put a tray icon in?
fn has_display() -> bool {
    if cfg!(target_os = "linux") {
        return ["DISPLAY", "WAYLAND_DISPLAY"].iter().any(|v| std::env::var_os(v).is_some_and(|d| !d.is_empty()));
    }
    true
}

fn fail(gui: bool, message: &str) -> ! {
    eprintln!("skwod host: {message}");
    if gui {
        notes::show_dialog("Skwod host", message);
    }
    std::process::exit(1);
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(text) => {
            println!("{text}");
            std::process::exit(if text.starts_with("skwod-host ") || text == USAGE { 0 } else { 2 });
        }
    };
    let gui = !args.no_tray && has_display();
    // GTK must be initialised before any dialog; the tray's event loop does it too, later.
    #[cfg(target_os = "linux")]
    if gui && gtk::init().is_err() {
        fail(false, "could not open the display; run with --no-tray");
    }

    let exe = std::env::current_exe().unwrap_or_else(|e| fail(gui, &format!("cannot find my own program file: {e}")));
    let exe_dir = exe.parent().map(PathBuf::from).unwrap_or_default();
    let data = server::data_dir(args.data.clone()).unwrap_or_else(|| fail(gui, "no home directory to keep the server's data in; pass --data DIR"));
    if let Err(e) = server::prepare_data_dir(&data) {
        fail(gui, &format!("cannot use {}: {e}", data.display()));
    }

    // One instance per data directory. A second launch just brings the page up and leaves.
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(data.join("host.lock"));
    let lock = lock.unwrap_or_else(|e| fail(gui, &format!("cannot use {}: {e}", data.display())));
    if lock.try_lock().is_err() {
        if !args.background {
            // Attaches only to a server that checks out (pid + key challenge); never starts one.
            let mut sup = Supervisor::new(data.clone(), exe_dir);
            if let Some(client) = sup.try_attach() {
                let _ = Controller::attached(sup, client).open_page();
                // Leave the hand-off page in place long enough for the browser to read it; the
                // running instance sweeps leftovers when it quits.
                std::thread::sleep(Duration::from_secs(3));
            }
        }
        println!("skwod host is already running.");
        return;
    }
    server::remove_handoffs(&data);

    let mut ctl = Controller::new(Supervisor::new(data.clone(), exe_dir));
    if let Err(e) = ctl.ensure() {
        fail(gui, &e.to_string());
    }
    if args.start {
        if let Err(e) = ctl.start() {
            fail(gui, &format!("could not start hosting: {e}"));
        }
    }
    let first_run_note = notes::first_run(&data).then_some(notes::FIREWALL_NOTE);
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted = interrupted.clone();
        let _ = ctrlc::set_handler(move || interrupted.store(true, Ordering::SeqCst));
    }
    let ctl = Arc::new(Mutex::new(ctl));

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if gui {
        tray::run(ctl, tray::Options { exe, open_page: !args.background, first_run_note }, interrupted);
    }

    // Headless: the server runs until we are told to stop.
    let _ = (&exe, &lock);
    if let Some(note) = first_run_note {
        println!("{note}\n");
    }
    {
        let guard = ctl.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(addr) = guard.admin_addr() {
            println!("skwod host: the server is up. Admin page: http://{addr}/ (this computer only).");
            println!("skwod host: to sign in there, use the one-time admin token in {}", guard.data().join(server::LOG_FILE).display());
        }
    }
    loop {
        if interrupted.load(Ordering::SeqCst) {
            break;
        }
        if ctl.lock().unwrap_or_else(|e| e.into_inner()).phase().is_none() {
            eprintln!("skwod host: the server stopped.");
            std::process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("skwod host: stopping the server…");
    ctl.lock().unwrap_or_else(|e| e.into_inner()).quit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments() {
        let parse = |a: &[&str]| parse_args(a.iter().map(|s| s.to_string()));
        assert_eq!(parse(&[]).unwrap(), Args::default());
        assert_eq!(
            parse(&["--data", "/srv/x", "--background", "--no-tray", "--start"]).unwrap(),
            Args { data: Some(PathBuf::from("/srv/x")), background: true, no_tray: true, start: true }
        );
        assert!(parse(&["--data"]).is_err());
        assert!(parse(&["--nope"]).unwrap_err().contains("unknown option"));
        assert_eq!(parse(&["--version"]).unwrap_err(), format!("skwod-host {}", env!("CARGO_PKG_VERSION")));
    }
}
