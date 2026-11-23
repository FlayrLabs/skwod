//! skwod self-hostable server (Phase 2, in progress).
//!
//! A single binary that stores only ciphertext, public keys, and routing metadata — never plaintext
//! or private keys (see `docs/SECURITY.md`, ADR-004/005). Default state lives on a `--data` volume
//! (SQLite + encrypted blobs). Subcommands mirror the installer flow (`docs`/installer/README.md):
//! `init` (interactive bootstrap), `run`, `migrate`.
//!
//! This file currently provides the CLI surface, a `/health` endpoint, and data-dir handling. The
//! API, key directory, realtime relay, and blob store land next.

mod admin;
mod admission;
mod api;
mod apns;
mod fcm;
mod auth;
mod blobs;
mod client_key;
mod control;
mod gateway;
mod hostbackup;
mod join;
mod error;
mod init;
mod keydir;
mod limiter;
mod limits;
mod livekit;
mod messages;
mod music;
mod oldbuilds;
mod p2p;
mod pairing;
mod perms;
mod privs;
mod push;
mod retention;
mod rt;
mod safety;
mod state;
mod storage;
mod structure;
mod updates;
mod voice;
mod voice_state;
mod ws;

mod problems;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod p2p_tests;
#[cfg(test)]
mod basics_tests;
#[cfg(test)]
mod accounts_tests;
#[cfg(test)]
mod content_tests;
#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod audit2_tests;
#[cfg(test)]
mod build46_tests;
#[cfg(test)]
mod pairing_tests;
#[cfg(test)]
mod build47_tests;

use clap::{Parser, Subcommand};
use sqlx::any::AnyPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use state::{AppState, Db};
use std::path::{Path, PathBuf};

const DEFAULT_DATA: &str = "./skwod-data";
const DEFAULT_LISTEN: &str = "127.0.0.1:3000";

#[derive(Parser)]
#[command(name = "skwod", about = "Self-hostable, end-to-end-encrypted skwod server", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// One-command setup: check Docker, provision LiveKit, start services, migrate, print URL + join code.
    Init {
        #[arg(long, default_value = DEFAULT_DATA)]
        data: PathBuf,
        #[arg(long)]
        domain: Option<String>,
        /// Skip the voice/video SFU (text-only, Docker-less single-process instance).
        #[arg(long)]
        no_livekit: bool,
        /// Non-interactive: accept defaults and auto-generate secrets.
        #[arg(long)]
        yes: bool,
        /// Use an existing LiveKit API key instead of generating one.
        #[arg(long)]
        livekit_key: Option<String>,
        /// Use an existing LiveKit API secret instead of generating one.
        #[arg(long)]
        livekit_secret: Option<String>,
        /// Use Postgres instead of the default on-volume SQLite.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Run the server against a data volume.
    Run {
        #[arg(long, env = "SKWOD_DATA", default_value = DEFAULT_DATA)]
        data: PathBuf,
        #[arg(long, env = "SKWOD_LISTEN", default_value = DEFAULT_LISTEN)]
        listen: String,
        /// Use Postgres instead of the default on-volume SQLite (e.g. postgres://user:pw@host/db).
        #[arg(long)]
        database_url: Option<String>,
        /// Where the host admin page listens (`ip:port`, or `off`). Loopback by default; a
        /// non-loopback address (containers) is protected by a one-time token printed at start.
        #[arg(long, env = "SKWOD_ADMIN_LISTEN", default_value = admin::DEFAULT_LISTEN)]
        admin_listen: String,
        /// Don't serve anyone until the host presses "Start server" on the admin page (the
        /// choice is remembered). Without this, hosting starts immediately, as it always did.
        #[arg(long, env = "SKWOD_WAIT_FOR_START")]
        wait_for_start: bool,
        /// Read the local-proof secret (one line) from standard input instead of
        /// `SKWOD_LOCAL_PROOF_SECRET`: a supervising app hands it over a pipe only this
        /// process reads, where an environment can be read by other processes of the user.
        #[arg(long)]
        local_proof_stdin: bool,
        #[command(flatten)]
        p2p: P2pArgs,
    },
    /// Exit 0 if the server on this machine answers `/health` (container HEALTHCHECK).
    Healthcheck {
        #[arg(long, env = "SKWOD_LISTEN", default_value = DEFAULT_LISTEN)]
        listen: String,
    },
    /// Give an existing data volume to the user the server runs as (run once, as root, with
    /// only the CHOWN capability). See `privs.rs`.
    FixOwnership {
        #[arg(long, env = "SKWOD_DATA", default_value = DEFAULT_DATA)]
        data: PathBuf,
        /// `uid[:gid]`; default `SKWOD_RUN_AS`, else `PUID`/`PGID`, else 1000:1000.
        #[arg(long)]
        owner: Option<String>,
    },
    /// Write an encrypted backup of this skwod (database, attachments, its address key) to one
    /// file. Safe while the server runs. The passphrase is read from `SKWOD_BACKUP_PASSPHRASE`,
    /// `--passphrase-file`, or asked for.
    Backup {
        #[arg(long, env = "SKWOD_DATA", default_value = DEFAULT_DATA)]
        data: PathBuf,
        /// The backup file to write (outside the data folder).
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Read the host owner's saved login (one line) from standard input, after the
        /// passphrase lines if those are asked for there, instead of `SKWOD_BACKUP_OWNER_LOGIN`.
        #[arg(long)]
        owner_login_stdin: bool,
    },
    /// Restore a backup into a data folder: the same skwod — same address, same invites.
    /// Stop the server first. Nothing is changed unless the whole file checks out.
    Restore {
        /// The backup file to read.
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long, env = "SKWOD_DATA", default_value = DEFAULT_DATA)]
        data: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// The folder already holds a skwod: set it aside (`<data>.replaced-<time>`) and restore.
        #[arg(long)]
        replace: bool,
        /// Only check that the file opens and is whole; restore nothing.
        #[arg(long)]
        verify_only: bool,
        /// Write the host owner's saved login carried by the backup to this file (0600). Used
        /// by the Mac app, which moves it into the keychain and deletes the file.
        #[arg(long)]
        owner_login_out: Option<PathBuf>,
    },
    /// Move this skwod's data folder to a new place (same skwod, not a new one). Stop the
    /// server first.
    MoveData {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
    },
    /// Apply database migrations on the data volume.
    Migrate {
        #[arg(long, default_value = DEFAULT_DATA)]
        data: PathBuf,
        /// Migrate a Postgres database instead of the on-volume SQLite.
        #[arg(long)]
        database_url: Option<String>,
    },
}

/// p2p front door (docs/P2P.md): members reach this instance by its key, no domain / port forward.
#[derive(clap::Args)]
struct P2pArgs {
    /// Don't start the p2p endpoint (classic reverse-proxied https only).
    #[arg(long, env = "SKWOD_NO_P2P")]
    no_p2p: bool,
    /// Allow n0's public relays + DNS as a fallback when the DHT / a direct path isn't enough.
    /// `false` = strictly independent: Mainline DHT + direct connections only.
    #[arg(long, env = "SKWOD_PUBLIC_FALLBACK", default_value_t = true, action = clap::ArgAction::Set)]
    public_fallback: bool,
    /// Fixed UDP port for the p2p endpoint (to forward it by hand). Default: OS-assigned.
    #[arg(long, env = "SKWOD_P2P_PORT")]
    p2p_port: Option<u16>,
    /// Externally reachable `ip:port` to advertise (manual port forward / static address). Repeatable.
    #[arg(long, env = "SKWOD_P2P_EXTERNAL_ADDR", value_delimiter = ',')]
    p2p_external_addr: Vec<std::net::SocketAddr>,
    /// Opt in to announcing this host on the local network (mDNS) so people on the same
    /// Wi-Fi/LAN connect faster. Off by default: only for a network you trust (home), never a
    /// laptop that roams. Also switchable on the admin page.
    #[arg(long, env = "SKWOD_LOCAL_DISCOVERY")]
    local_discovery: bool,
}

/// `SKWOD_X=` (set but empty) means "not set". Compose files and NAS templates pass every
/// variable they know, empty when the user left the field blank; clap would otherwise reject
/// e.g. `SKWOD_NO_P2P=` or `SKWOD_P2P_PORT=` as an invalid value and the server would not start.
pub(crate) fn empty_env_vars(vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>) -> Vec<std::ffi::OsString> {
    vars.filter(|(k, v)| v.is_empty() && k.to_str().is_some_and(|k| k.starts_with("SKWOD_") || matches!(k, "PUID" | "PGID")))
        .map(|(k, _)| k)
        .collect()
}

/// Everything this process creates is for the user it runs as and nobody else (audit M-7).
/// The data directory holds the database — password hashes, the instance signing key, the
/// certificate authority's private key, the LiveKit secret, push credentials, the whole social
/// graph — and used to be created with whatever umask the process inherited: 0644 files in a
/// 0755 directory on a typical Linux host, readable by every local user.
pub(crate) fn private_umask() {
    #[cfg(unix)]
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
}

/// Create the data directory (0700) — and TIGHTEN one that already exists, at every start:
/// the directory itself, `blobs/`, and everything directly inside lose all group and other
/// access. Owner bits are kept as they are (a bundled binary stays executable); symlinks are
/// neither followed nor changed. Files below `blobs/` and the other subdirectories are
/// reached only through a directory that is now 0700.
pub(crate) fn ensure_data_dir(data: &PathBuf) -> std::io::Result<()> {
    std::fs::create_dir_all(data)?;
    std::fs::create_dir_all(data.join("blobs"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let tighten = |path: &Path, dir: bool| -> std::io::Result<()> {
            let meta = std::fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() {
                return Ok(());
            }
            let mode = meta.permissions().mode() & 0o7777;
            let want = if dir { 0o700 } else { mode & 0o700 };
            if mode != want {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(want))?;
            }
            Ok(())
        };
        tighten(data, true)?;
        for entry in std::fs::read_dir(data)? {
            let entry = entry?;
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            // Best-effort per entry: a file the server does not own (a bind-mounted config)
            // must not stop it from starting.
            let _ = tighten(&entry.path(), is_dir);
        }
    }
    Ok(())
}

/// Open the database and apply pending migrations, returning a backend-agnostic `Any` pool.
///
/// Default (no `--database-url`) is SQLite on the data volume — the single-binary self-host path.
/// A `postgres://…` url uses Postgres instead (for operators who want a shared DB). Migrations run
/// on a native typed pool (the sqlx migrator is driver-specific), then the app is served over `Any`.
pub(crate) async fn open_db(data: &Path, database_url: Option<&str>) -> Result<Db, sqlx::Error> {
    sqlx::any::install_default_drivers();
    match database_url {
        Some(url) if url.starts_with("postgres") => {
            let pg = PgPoolOptions::new().max_connections(16).connect(url).await?;
            sqlx::migrate!("./migrations-postgres").run(&pg).await?;
            pg.close().await;
            AnyPoolOptions::new().max_connections(16).connect(url).await
        }
        _ => {
            // SQLite: migrate on a native pool (this writes WAL into the file header), then serve via
            // `Any` with foreign keys re-enabled per connection (SQLite defaults them off).
            let path = data.join("skwod.db");
            let options = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true);
            // An update that changes the schema first keeps a copy of the database as it was
            // (`snapshots/pre-migrate-…`). If that copy cannot be taken the migration does not
            // run: better a server that says why it will not start than one that cannot go back.
            let migrator = sqlx::migrate!("./migrations");
            let latest = migrator.iter().map(|m| m.version).max().unwrap_or_default();
            match hostbackup::copy_before_migrating(data, latest).await {
                Ok(Some(copy)) => tracing::info!(file = %copy.display(), "database copied before migrating"),
                Ok(None) => {}
                Err(e) => return Err(sqlx::Error::Protocol(format!("could not copy the database before updating it ({e}); free some disk space and start again"))),
            }
            let sqlite = SqlitePoolOptions::new().max_connections(1).connect_with(options).await?;
            migrator.run(&sqlite).await?;
            sqlite.close().await;
            // SQLite made the file with the process's default mode: say 0600 outright, for
            // the database and its write-ahead files (audit M-7), whatever the umask was.
            #[cfg(unix)]
            for suffix in ["", "-wal", "-shm"] {
                use std::os::unix::fs::PermissionsExt;
                let file = data.join(format!("skwod.db{suffix}"));
                if file.is_file() {
                    let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
                }
            }
            let url = format!("sqlite://{}", path.display());
            AnyPoolOptions::new()
                .max_connections(8)
                .after_connect(|conn, _meta| {
                    Box::pin(async move {
                        sqlx::query("PRAGMA foreign_keys=ON").execute(conn).await?;
                        Ok(())
                    })
                })
                .connect(&url)
                .await
        }
    }
}

async fn run(data: PathBuf, listen: String, database_url: Option<String>, admin_listen: String, wait_for_start: bool, p2p: P2pArgs) {
    if let Err(e) = privs::probe_writable(&data).and_then(|_| ensure_data_dir(&data)) {
        eprintln!("[skwod] {}", privs::explain_unwritable(&data, &e));
        std::process::exit(78);
    }
    let pool = match open_db(&data, database_url.as_deref()).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("[skwod] {}", problems::database_failure(&data, &e.to_string()));
            std::process::exit(problems::EXIT_DATA);
        }
    };
    // Claim the API port BEFORE anything is started (LiveKit, the p2p endpoint): if another
    // copy of Skwod holds it, say so and leave — do not start half a server first.
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[skwod] {}", problems::bind_failure(&listen, &e));
            std::process::exit(problems::EXIT_PORT);
        }
    };

    let state = AppState::new(pool, data.join("blobs"));
    // A per-file upload limit the owner set from the app replaces SKWOD_MAX_UPLOAD_MB.
    limits::load(&state).await;
    match push::enforce_gateway_policy(&state).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "push registrations naming a gateway this skwod does not use were removed; those devices will register again"),
        Err(_) => tracing::warn!("could not check stored push registrations against the gateway policy"),
    }
    let app = api::router(state.clone());
    let _retention = retention::spawn(state.clone());
    // Who is in which voice room, from LiveKit's room service (`voice_state.rs`).
    let _voice_states = voice_state::spawn(state.clone());
    // A local copy of the database every day, seven kept (SQLite only; `hostbackup.rs`).
    let _snapshots = database_url.as_deref().is_none_or(|u| !u.starts_with("postgres")).then(|| hostbackup::spawn_snapshots(data.clone()));

    let p2p_opts = (!p2p.no_p2p).then_some(p2p::P2pOptions {
        public_fallback: p2p.public_fallback,
        port: p2p.p2p_port,
        external_addrs: p2p.p2p_external_addr,
        local_discovery: p2p.local_discovery,
    });
    let ctl = std::sync::Arc::new(control::HostControl::new(state.clone(), app.clone(), data.clone(), p2p_opts));

    if !wait_for_start || ctl.should_autostart().await {
        match ctl.start().await {
            Ok(fresh_code) => {
                if let Some(code) = &fresh_code {
                    println!("[skwod] fresh instance initialized. The first account to sign up with this code owns it:");
                    println!("Join code: {code}");
                    println!("(stored only as a hash — save it now)");
                }
                if let Some(link) = ctl.invite(fresh_code.as_deref()) {
                    println!("Invite: {link}");
                    // The same invite in the app's own scheme, for tools that read this output
                    // (the Mac host app learns its node id from it) and for pasting into the app.
                    if let Ok(invite) = skwod_net::invite::Invite::parse(&link) {
                        println!("App link: {invite}");
                    }
                }
            }
            Err(e) => {
                eprintln!("[skwod] {e}");
                std::process::exit(1);
            }
        }
    } else {
        state.serving.store(false, std::sync::atomic::Ordering::SeqCst);
        println!("[skwod] Not serving yet: open the admin page and press \"Start server\".");
    }

    let _admin = if admin_listen.eq_ignore_ascii_case("off") {
        None
    } else {
        match admin::serve(ctl.clone(), &admin_listen, &data).await {
            Ok(task) => Some(task),
            Err(e) if wait_for_start => {
                // Without the page nobody could ever press Start.
                eprintln!("[skwod] {e}");
                std::process::exit(1);
            }
            Err(e) => {
                tracing::warn!(error = %e, "admin page unavailable");
                None
            }
        }
    };

    // The p2p endpoint is how friends reach a home-hosted skwod. If it could not start (no
    // network yet at login, a port mapping that was not ready) keep trying for as long as
    // hosting is on, instead of serving nobody until someone restarts the app.
    let _p2p_retry = {
        let ctl = ctl.clone();
        tokio::spawn(async move {
            let mut wait = std::time::Duration::from_secs(5);
            loop {
                tokio::time::sleep(wait).await;
                if ctl.p2p_missing() {
                    wait = if ctl.retry_p2p().await { std::time::Duration::from_secs(5) } else { (wait * 2).min(std::time::Duration::from_secs(60)) };
                } else {
                    wait = std::time::Duration::from_secs(5);
                }
            }
        })
    };
    tracing::info!(%listen, data = %data.display(), "skwod-server listening (ciphertext-only)");
    // ConnectInfo: the socket peer is needed to decide whether X-Forwarded-For may be believed
    // (client_key.rs). It is used for in-memory rate limiting only and never logged.
    let serve = axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>());
    tokio::select! {
        r = serve => r.expect("serve"),
        _ = shutdown_signal() => {}
        _ = ctl.quit.notified() => {}
    }
    // Clean exit (docker stop, the host app's Quit): close the p2p endpoint so members see the
    // host leave instead of timing out, and take LiveKit down with us.
    tracing::info!("shutting down");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(8), ctl.stop(false)).await;
    let _ = std::fs::remove_file(data.join(admin::LAUNCH_FILE));
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `GET /health` on this machine's API port. Plain std: the hardened image has no curl.
fn healthcheck(listen: &str) -> bool {
    use std::io::{Read, Write};
    let Some(port) = listen.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) else { return false };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3)) else { return false };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
    if stream.write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n").is_err() {
        return false;
    }
    let mut body = String::new();
    let _ = stream.read_to_string(&mut body);
    body.starts_with("HTTP/1.0 200") || body.starts_with("HTTP/1.1 200") && body.contains("\"status\":\"ok\"")
}

/// Logging: our own events at INFO; the p2p stack (iroh/QUIC/DHT/port mapping) at ERROR only,
/// because its INFO/DEBUG output includes peer and relay network addresses and this server must
/// not log client IPs. `SKWOD_P2P_DEBUG=1` lifts that for local troubleshooting.
fn init_logging() {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::prelude::*;
    let p2p_level = if std::env::var("SKWOD_P2P_DEBUG").is_ok_and(|v| v == "1") { LevelFilter::DEBUG } else { LevelFilter::ERROR };
    let mut targets = Targets::new().with_default(LevelFilter::INFO);
    for noisy in ["iroh", "iroh_relay", "iroh_dns", "iroh_base", "iroh_mainline_address_lookup", "noq", "noq_proto", "noq_udp", "n0_mainline", "mainline", "portmapper", "netwatch", "hickory_resolver", "hickory_proto", "igd_next"] {
        targets = targets.with_target(noisy, p2p_level);
    }
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_target(false)).with(targets).init();
}

fn main() {
    for name in empty_env_vars(std::env::vars_os()) {
        std::env::remove_var(name);
    }
    private_umask();
    let cli = Cli::parse();
    // Before the runtime exists (no threads yet): the container-entrypoint step — repair the
    // volume's ownership if we were started as root, then stop being root. See `privs.rs`.
    match &cli.command {
        Command::Run { data, .. } => privs::enter(data),
        Command::Healthcheck { listen } => std::process::exit(if healthcheck(listen) { 0 } else { 1 }),
        Command::FixOwnership { data, owner } => std::process::exit(fix_ownership_cmd(data, owner.as_deref())),
        _ => {}
    }
    init_logging();
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime").block_on(dispatch(cli.command));
}

fn fix_ownership_cmd(data: &Path, owner: Option<&str>) -> i32 {
    #[cfg(unix)]
    {
        let explicit = owner.and_then(|o| {
            let (uid, gid) = o.split_once(':').unwrap_or((o, o));
            Some(privs::RunAs { uid: uid.parse().ok()?, gid: gid.parse().ok()? })
        });
        if owner.is_some() && explicit.is_none() {
            eprintln!("[skwod] --owner must be uid[:gid]");
            return 2;
        }
        let to = explicit.or_else(privs::run_as_from_env).unwrap_or(privs::RunAs { uid: 1000, gid: 1000 });
        match privs::fix_ownership(data, to) {
            Ok(f) if f.failed == 0 => {
                println!("[skwod] {}: {} entries given to {}:{}", data.display(), f.changed, to.uid, to.gid);
                0
            }
            Ok(f) => {
                eprintln!("[skwod] {}: {} entries changed, {} could not be (run this as root with the CHOWN capability)", data.display(), f.changed, f.failed);
                1
            }
            Err(e) => {
                eprintln!("[skwod] {}: {e}", data.display());
                1
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (data, owner);
        eprintln!("[skwod] fix-ownership is for Unix containers");
        2
    }
}

/// The backup passphrase: `SKWOD_BACKUP_PASSPHRASE`, else the first line of `file`, else asked
/// for on the terminal (twice when making a backup).
fn backup_passphrase(file: Option<&Path>, confirm: bool) -> String {
    if let Some(p) = std::env::var("SKWOD_BACKUP_PASSPHRASE").ok().filter(|v| !v.is_empty()) {
        return p;
    }
    if let Some(file) = file {
        match std::fs::read_to_string(file) {
            Ok(s) => return s.lines().next().unwrap_or_default().to_string(),
            Err(e) => {
                eprintln!("[skwod] cannot read {}: {e}", file.display());
                std::process::exit(2);
            }
        }
    }
    let ask = |prompt: &str| {
        eprint!("{prompt}");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    let first = ask("Backup passphrase (it will be shown as you type): ");
    if confirm && ask("Again: ") != first {
        eprintln!("[skwod] the two passphrases differ");
        std::process::exit(2);
    }
    first
}

/// One line from standard input, without its line ending (empty at end of input).
fn stdin_line() -> String {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim_end_matches(['\r', '\n']).to_string()
}

fn backup_failed(what: &str, e: &hostbackup::BackupError) -> ! {
    eprintln!("[skwod] {what} failed: {e}");
    std::process::exit(1);
}

async fn dispatch(command: Command) {
    match command {
        Command::Init { data, domain, no_livekit, yes, livekit_key, livekit_secret, database_url } => {
            let opts = init::InitOptions {
                data,
                domain: domain.unwrap_or_else(|| "localhost:3000".to_string()),
                no_livekit,
                yes,
                livekit_key,
                livekit_secret,
                database_url,
            };
            if let Err(e) = init::run_init(opts).await {
                eprintln!("\n[skwod] init failed: {e}");
                std::process::exit(1);
            }
        }
        Command::Run { data, listen, database_url, admin_listen, wait_for_start, local_proof_stdin, p2p } => {
            if local_proof_stdin {
                // Taken before anything listens; an unusable line leaves the route absent (404),
                // which a supervisor reads as "not my server".
                let _ = api::LOCAL_PROOF_SECRET.set(stdin_line());
            }
            run(data, listen, database_url, admin_listen, wait_for_start, p2p).await
        }
        Command::Healthcheck { .. } | Command::FixOwnership { .. } => unreachable!("handled before the runtime starts"),
        Command::Backup { data, out, passphrase_file, owner_login_stdin } => {
            let passphrase = backup_passphrase(passphrase_file.as_deref(), true);
            let owner_login = if owner_login_stdin { Some(stdin_line()).filter(|v| !v.is_empty()) } else { std::env::var("SKWOD_BACKUP_OWNER_LOGIN").ok().filter(|v| !v.is_empty()) };
            match hostbackup::backup(&data, &out, &passphrase, owner_login.as_deref(), skwod_crypto::backup::KdfParams::DEFAULT).await {
                Ok(s) => println!("[skwod] backup written: {} ({} files, {} bytes). Keep the passphrase: without it this file cannot be opened.", out.display(), s.files, s.bytes),
                Err(e) => backup_failed("backup", &e),
            }
        }
        Command::Restore { input, data, passphrase_file, replace, verify_only, owner_login_out } => {
            let passphrase = backup_passphrase(passphrase_file.as_deref(), false);
            if verify_only {
                match hostbackup::verify(&input, &passphrase).await {
                    Ok(s) => println!("[skwod] backup is whole: {} files, {} bytes", s.files, s.bytes),
                    Err(e) => backup_failed("verify", &e),
                }
                return;
            }
            match hostbackup::restore(&input, &data, &passphrase, replace).await {
                Ok(s) => {
                    if let (Some(path), Some(login)) = (owner_login_out, s.owner_login.as_deref()) {
                        if let Err(e) = hostbackup::write_private(&path, login.as_bytes()) {
                            eprintln!("[skwod] restored, but the owner login could not be written to {}: {e}", path.display());
                        }
                    }
                    println!("[skwod] restored {} files into {}. Start the server: it is the same skwod, at the same address.", s.files, data.display());
                    println!("[skwod] everyone is signed out and signs in again; devices upload fresh one-time keys by themselves.");
                    if !s.reverted.is_empty() {
                        println!("[skwod] WARNING — this backup is older than these changes, which it has UNDONE (also saved as {}):", data.join(hostbackup::RESTORE_REPORT).display());
                        for line in &s.reverted {
                            println!("[skwod]   {line}");
                        }
                        println!("[skwod] Remove those devices and members again, and ban again, if that is still what you want.");
                    }
                }
                Err(e) => backup_failed("restore", &e),
            }
        }
        Command::MoveData { from, to } => match hostbackup::move_data(&from, &to).await {
            Ok(()) => println!("[skwod] moved to {}", to.display()),
            Err(e) => backup_failed("move", &e),
        },
        Command::Migrate { data, database_url } => {
            ensure_data_dir(&data).expect("create data dir");
            let _pool = open_db(&data, database_url.as_deref()).await.expect("open database and apply migrations");
            let backend = if database_url.as_deref().is_some_and(|u| u.starts_with("postgres")) { "postgres" } else { "sqlite" };
            println!("[skwod] migrate — {backend} schema up to date (data at {})", data.display());
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn empty_skwod_variables_count_as_unset() {
        let env = [("SKWOD_NO_P2P", ""), ("SKWOD_P2P_PORT", ""), ("SKWOD_PUBLIC_FALLBACK", "false"), ("PUID", ""), ("HOME", ""), ("PATH", "/bin")];
        let empty = empty_env_vars(env.iter().map(|(k, v)| (OsString::from(k), OsString::from(v))));
        assert_eq!(empty, ["SKWOD_NO_P2P", "SKWOD_P2P_PORT", "PUID"].map(OsString::from));
    }

    /// Audit M-7: the data directory and the database are private however they were made.
    #[cfg(unix)]
    #[tokio::test]
    async fn m7_the_data_directory_and_database_are_private_and_tightened_at_every_start() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let chmod = |p: &std::path::Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        // As an older build (or a careless umask) left it: world-readable everything.
        std::fs::create_dir_all(data.join("blobs")).unwrap();
        std::fs::create_dir_all(data.join("snapshots")).unwrap();
        std::fs::write(data.join("config.toml"), "api_secret = \"s\"").unwrap();
        std::fs::write(data.join("livekit-server"), "#!/bin/sh").unwrap();
        for (path, m) in [("", 0o755), ("blobs", 0o777), ("snapshots", 0o755), ("config.toml", 0o644), ("livekit-server", 0o755)] {
            chmod(&data.join(path), m);
        }
        ensure_data_dir(&data).unwrap();
        assert_eq!((mode(&data), mode(&data.join("blobs")), mode(&data.join("snapshots"))), (0o700, 0o700, 0o700));
        assert_eq!(mode(&data.join("config.toml")), 0o600, "the LiveKit secret is not world-readable");
        assert_eq!(mode(&data.join("livekit-server")), 0o700, "owner bits are kept: it still runs");
        // The database is 0600 from the moment it exists (this test runs under the default
        // umask, which would have made it 0644).
        let pool = open_db(&data, None).await.unwrap();
        pool.close().await;
        assert_eq!(mode(&data.join("skwod.db")), 0o600);
        // A fresh directory is created private.
        let fresh = tmp.path().join("fresh");
        ensure_data_dir(&fresh).unwrap();
        assert_eq!((mode(&fresh), mode(&fresh.join("blobs"))), (0o700, 0o700));
    }

    #[test]
    fn run_parses_with_defaults_and_the_new_switches() {
        let Command::Run { admin_listen, wait_for_start, p2p, .. } = Cli::try_parse_from(["skwod", "run"]).unwrap().command else { panic!() };
        assert_eq!((admin_listen.as_str(), wait_for_start, p2p.no_p2p, p2p.local_discovery), ("127.0.0.1:3477", false, false, false));
        let Command::Run { admin_listen, wait_for_start, .. } =
            Cli::try_parse_from(["skwod", "run", "--admin-listen", "0.0.0.0:3477", "--wait-for-start"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((admin_listen.as_str(), wait_for_start), ("0.0.0.0:3477", true));
    }
}
