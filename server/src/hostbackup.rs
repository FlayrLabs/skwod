//! Backing a skwod up, moving it, and putting it back.
//!
//! Everything a skwod IS lives in its data folder: the database (accounts, ciphertext, the
//! instance key), the attachment ciphertext (`blobs/`), and the p2p key whose public half is the
//! skwod's address (`p2p.key`). A backup is that folder — with the database copied CONSISTENTLY
//! (`VACUUM INTO`, which is safe against a live server) — in one file, encrypted under a
//! passphrase: Argon2id stretches the passphrase into a key that wraps a random archive key
//! (`skwod_crypto::backup`, the same construction as the member key backup), and the archive
//! itself is ChaCha20-Poly1305 in 1 MiB chunks with a counter nonce and a final-chunk flag, so
//! a truncated, reordered or altered file fails to restore instead of restoring partly.
//!
//! Restoring on another machine gives the SAME skwod: same node id, same address, same instance
//! key — every invite ever handed out keeps working and members reconnect by themselves.
//!
//! Also here: the daily local snapshot of the database (seven kept) and the copy taken before
//! a migration runs.
//!
//! Not covered: a Postgres database (`--database-url`) — back that up with `pg_dump`.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

use skwod_crypto::aead;
use skwod_crypto::backup::{self as kdf, KdfParams};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::ConnectOptions;

const MAGIC: &[u8; 8] = b"SKWDBK01";
const CHUNK: usize = 1024 * 1024;
const AAD: &[u8] = b"skwod/host-backup/v1";
const DB_FILE: &str = "skwod.db";
/// Where local snapshots live, inside the data folder.
pub const SNAPSHOT_DIR: &str = "snapshots";
/// Daily snapshots kept.
pub const SNAPSHOTS_KEPT: usize = 7;
/// Pre-migration copies kept.
const PRE_MIGRATE_KEPT: usize = 3;
/// The archive entry carrying the host owner's login (what the Mac app keeps in its keychain).
const OWNER_LOGIN_ENTRY: &str = ".owner-login";
/// Largest single archive entry name / owner login accepted on restore.
const MAX_NAME: usize = 4096;
const MAX_OWNER_LOGIN: u64 = 64 * 1024;

/// Never part of a backup: the live database files (a consistent copy goes in instead), this
/// run's process bookkeeping, and the local snapshots themselves.
fn skipped(rel: &Path) -> bool {
    let Some(first) = rel.components().next().and_then(|c| c.as_os_str().to_str()) else { return true };
    matches!(
        first,
        "skwod.db" | "skwod.db-wal" | "skwod.db-shm" | "skwod.db-journal" | ".server.pid" | crate::admin::LAUNCH_FILE | SNAPSHOT_DIR
    ) || first.starts_with(".write-test-")
        || first.starts_with(".restore-")
        || first.starts_with(".backup-")
}

#[derive(Debug)]
pub enum BackupError {
    Io(std::io::Error),
    Db(sqlx::Error),
    /// The passphrase cannot protect a backup (the reason).
    Weak(String),
    /// Wrong passphrase, or not a backup at all.
    Auth,
    /// The file is damaged or incomplete.
    Corrupt,
    /// The request itself was refused (the sentence to show).
    Refused(String),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::Io(e) => write!(f, "{e}"),
            BackupError::Db(e) => write!(f, "database: {e}"),
            BackupError::Weak(why) => write!(f, "that passphrase is too weak to protect a backup: {why}"),
            BackupError::Auth => write!(f, "wrong passphrase, or this is not a Skwod backup"),
            BackupError::Corrupt => write!(f, "this backup file is damaged or incomplete; nothing was restored"),
            BackupError::Refused(why) => write!(f, "{why}"),
        }
    }
}
impl std::error::Error for BackupError {}
impl From<std::io::Error> for BackupError {
    fn from(e: std::io::Error) -> Self {
        BackupError::Io(e)
    }
}
impl From<sqlx::Error> for BackupError {
    fn from(e: sqlx::Error) -> Self {
        BackupError::Db(e)
    }
}

/// What a backup or restore did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub files: u64,
    pub bytes: u64,
    /// The owner login carried by the archive (restore only).
    pub owner_login: Option<String>,
    /// What the restore brought BACK that had been taken away since the backup (restore over
    /// an existing skwod only): one line each, for the host to read and act on.
    pub reverted: Vec<String>,
}

// ---- private files ----
//
// A skwod's files are its secrets (the address key, the instance key inside the database, the
// host's login) and its members' ciphertext. Whatever this module writes is readable by the
// user the server runs as and nobody else: directories 0700, files 0600 — set when the file is
// created, never "tightened afterwards", and set again on anything that already existed.

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// Create ONE new directory, 0700. Fails if anything is already there (never adopts a
/// directory someone else made).
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)?;
    set_mode(path, 0o700) // the umask may only have removed bits; say it outright
}

/// A new scratch directory with an unguessable name inside `parent`, 0700, created atomically.
fn private_scratch(parent: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    let name: [u8; 16] = skwod_crypto::random_bytes();
    let path = parent.join(format!("{prefix}{}", hex::encode(name)));
    create_private_dir(&path)?;
    Ok(path)
}

/// Make sure `dir` exists as a real directory (not a symlink) and is 0700.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => set_mode(dir, 0o700),
        Ok(_) => Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, format!("{} is not a directory", dir.display()))),
        Err(_) => create_private_dir(dir),
    }
}

/// Create a NEW file, 0600. Fails if the path exists — so it never writes through a symlink
/// and never inherits the permissions of a file that was already there.
fn create_private_file(path: &Path) -> std::io::Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    set_mode(path, 0o600)?;
    Ok(file)
}

/// Write `bytes` to `path` as a private file, replacing whatever was there (a symlink is
/// removed, not followed; the old file's permissions do not carry over).
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Make every directory under (and including) `root` 0700 and every file 0600. Symlinks are
/// left alone and never followed.
fn make_private(root: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(root)?;
    if meta.is_dir() {
        set_mode(root, 0o700)?;
        for e in std::fs::read_dir(root)? {
            make_private(&e?.path())?;
        }
    } else if meta.is_file() {
        set_mode(root, 0o600)?;
    }
    Ok(())
}

// ---- consistent database copies ----

async fn sqlite_one(path: &Path, create: bool) -> Result<sqlx::SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new().filename(path).create_if_missing(create).disable_statement_logging();
    SqlitePoolOptions::new().max_connections(1).connect_with(options).await
}

/// Copy the database at `db` to `dest` as one consistent, self-contained file. Safe while a
/// server is using `db`: `VACUUM INTO` reads a single snapshot and never blocks writers for long.
pub async fn copy_database(db: &Path, dest: &Path) -> Result<(), BackupError> {
    let _ = std::fs::remove_file(dest);
    let pool = sqlite_one(db, false).await?;
    // Fold the write-ahead log into the main file first (best-effort: a busy server skips it,
    // and VACUUM INTO reads through the log anyway).
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&pool).await;
    let result = sqlx::query("VACUUM INTO ?").bind(dest.to_string_lossy().to_string()).execute(&pool).await;
    pool.close().await;
    result?;
    // SQLite created the file with the process's default mode.
    set_mode(dest, 0o600)?;
    Ok(())
}

/// Is the SQLite file at `db` whole? (`PRAGMA integrity_check`.)
pub async fn database_ok(db: &Path) -> bool {
    let Ok(pool) = sqlite_one(db, false).await else { return false };
    let verdict: Result<String, _> = sqlx::query_scalar("PRAGMA integrity_check").fetch_one(&pool).await;
    pool.close().await;
    matches!(verdict.as_deref(), Ok("ok"))
}

// ---- the archive ----

/// Chunked AEAD writer (the STREAM construction: counter nonce, last chunk flagged).
struct Sealer<W: Write> {
    out: W,
    key: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

fn nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    n
}

impl<W: Write> Sealer<W> {
    fn flush_chunk(&mut self, last: bool) -> std::io::Result<()> {
        let sealed = aead::seal_with_nonce(&self.key, &nonce(self.counter, last), AAD, &self.buf);
        self.out.write_all(&(sealed.len() as u32).to_be_bytes())?;
        self.out.write_all(&sealed)?;
        self.counter += 1;
        self.buf.clear();
        Ok(())
    }

    fn put(&mut self, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let take = (CHUNK - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buf.len() == CHUNK {
                self.flush_chunk(false)?;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> std::io::Result<W> {
        self.flush_chunk(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// The matching reader. Hands back plaintext only from chunks that authenticated, and reports
/// a clean end only after the chunk flagged as last.
struct Opener<R: Read> {
    input: R,
    key: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl<R: Read> Opener<R> {
    fn fill(&mut self) -> Result<bool, BackupError> {
        if self.done {
            return Ok(false);
        }
        let mut len = [0u8; 4];
        self.input.read_exact(&mut len).map_err(|_| BackupError::Corrupt)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > CHUNK + 16 {
            return Err(BackupError::Corrupt);
        }
        let mut sealed = vec![0u8; len];
        self.input.read_exact(&mut sealed).map_err(|_| BackupError::Corrupt)?;
        // A chunk opens either as "more follow" or as "the last one" — never both.
        let (plain, last) = match aead::open_with_nonce(&self.key, &nonce(self.counter, false), AAD, &sealed) {
            Some(p) => (p, false),
            None => (aead::open_with_nonce(&self.key, &nonce(self.counter, true), AAD, &sealed).ok_or(BackupError::Corrupt)?, true),
        };
        if last {
            // Nothing may follow the final chunk.
            let mut extra = [0u8; 1];
            if self.input.read(&mut extra).map_err(|_| BackupError::Corrupt)? != 0 {
                return Err(BackupError::Corrupt);
            }
            self.done = true;
        }
        self.counter += 1;
        self.buf = plain;
        self.pos = 0;
        Ok(true)
    }

    fn take(&mut self, out: &mut [u8]) -> Result<(), BackupError> {
        let mut filled = 0;
        while filled < out.len() {
            if self.pos == self.buf.len() && !self.fill()? {
                return Err(BackupError::Corrupt);
            }
            let n = (self.buf.len() - self.pos).min(out.len() - filled);
            out[filled..filled + n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            filled += n;
        }
        Ok(())
    }

    /// True once every byte of the archive has been consumed and the final chunk was seen.
    fn at_end(&mut self) -> Result<bool, BackupError> {
        while self.pos == self.buf.len() {
            if !self.fill()? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn files_under(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let rel = path.strip_prefix(root).expect("under root").to_path_buf();
        if skipped(&rel) {
            continue;
        }
        // Symlinks are never followed or stored: a backup holds this folder's own files only.
        let kind = e.file_type()?;
        if kind.is_dir() {
            files_under(root, &path, out)?;
        } else if kind.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}

fn put_entry<W: Write>(sealer: &mut Sealer<W>, name: &str, len: u64, mut body: impl Read) -> std::io::Result<()> {
    sealer.put(&[1])?;
    sealer.put(&(name.len() as u32).to_be_bytes())?;
    sealer.put(name.as_bytes())?;
    sealer.put(&len.to_be_bytes())?;
    let mut left = len;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let want = (buf.len() as u64).min(left) as usize;
        // A file that shrank while being read would desynchronize the archive: fail instead.
        body.read_exact(&mut buf[..want])?;
        sealer.put(&buf[..want])?;
        left -= want as u64;
    }
    Ok(())
}

/// Write an encrypted backup of the skwod in `data` to `out`. `owner_login`, when given, is
/// carried inside the archive (the Mac app's saved host login, so the new Mac can sign in).
/// Works while the server is running; stopping it first only makes the copy smaller in time.
pub async fn backup(data: &Path, out: &Path, passphrase: &str, owner_login: Option<&str>, params: KdfParams) -> Result<Summary, BackupError> {
    kdf::check_passphrase(passphrase).map_err(|e| BackupError::Weak(e.to_string()))?;
    let db = data.join(DB_FILE);
    if !db.is_file() {
        return Err(BackupError::Refused(format!("there is no skwod in {} (no {DB_FILE})", data.display())));
    }
    if out.starts_with(data) {
        return Err(BackupError::Refused("write the backup somewhere outside the skwod's own data folder".into()));
    }
    let staged = data.join(format!(".backup-{}.db", hex::encode(skwod_crypto::random_bytes::<16>())));
    let result = async {
        copy_database(&db, &staged).await?;
        let mut files = Vec::new();
        files_under(data, data, &mut files)?;

        let key: [u8; 32] = skwod_crypto::random_bytes();
        let salt: [u8; 16] = skwod_crypto::random_bytes();
        let wrapped = kdf::wrap_key(&key, passphrase, &salt, params).map_err(|e| BackupError::Weak(e.to_string()))?;
        // The archive is ciphertext, but it is still nobody else's business: 0600, and a
        // leftover (or planted) file at the scratch name is removed, not written through.
        let partial = out.with_extension("partial");
        match std::fs::remove_file(&partial) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut file = BufWriter::new(create_private_file(&partial)?);
        file.write_all(MAGIC)?;
        for v in [params.m_kib, params.t, params.p] {
            file.write_all(&v.to_be_bytes())?;
        }
        file.write_all(&salt)?;
        file.write_all(&(wrapped.len() as u16).to_be_bytes())?;
        file.write_all(&wrapped)?;

        let mut sealer = Sealer { out: file, key, counter: 0, buf: Vec::with_capacity(CHUNK) };
        let mut summary = Summary::default();
        let db_len = std::fs::metadata(&staged)?.len();
        put_entry(&mut sealer, DB_FILE, db_len, File::open(&staged)?)?;
        summary.files += 1;
        summary.bytes += db_len;
        if let Some(login) = owner_login {
            put_entry(&mut sealer, OWNER_LOGIN_ENTRY, login.len() as u64, login.as_bytes())?;
        }
        for rel in files {
            let Some(name) = rel.to_str().map(|s| s.replace('\\', "/")) else { continue };
            let path = data.join(&rel);
            let len = std::fs::metadata(&path)?.len();
            put_entry(&mut sealer, &name, len, File::open(&path)?)?;
            summary.files += 1;
            summary.bytes += len;
        }
        sealer.put(&[0])?;
        let file = sealer.finish()?;
        file.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        std::fs::rename(&partial, out)?;
        set_mode(out, 0o600)?;
        Ok(summary)
    }
    .await;
    let _ = std::fs::remove_file(&staged);
    if result.is_err() {
        let _ = std::fs::remove_file(out.with_extension("partial"));
    }
    result
}

/// A relative path made only of plain names — the only kind a restore will write.
fn safe_relative(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    (!name.is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))).then(|| path.to_path_buf())
}

fn open_archive(file: &Path, passphrase: &str) -> Result<Opener<BufReader<File>>, BackupError> {
    let mut input = BufReader::new(File::open(file)?);
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic).map_err(|_| BackupError::Auth)?;
    if &magic != MAGIC {
        return Err(BackupError::Auth);
    }
    let mut word = [0u8; 4];
    let mut next = |input: &mut BufReader<File>| -> Result<u32, BackupError> {
        input.read_exact(&mut word).map_err(|_| BackupError::Corrupt)?;
        Ok(u32::from_be_bytes(word))
    };
    let params = KdfParams { m_kib: next(&mut input)?, t: next(&mut input)?, p: next(&mut input)? };
    let mut salt = [0u8; 16];
    input.read_exact(&mut salt).map_err(|_| BackupError::Corrupt)?;
    let mut len = [0u8; 2];
    input.read_exact(&mut len).map_err(|_| BackupError::Corrupt)?;
    let mut wrapped = vec![0u8; u16::from_be_bytes(len) as usize];
    input.read_exact(&mut wrapped).map_err(|_| BackupError::Corrupt)?;
    // Parameters come from the file: `unwrap_key` refuses ones outside the accepted range.
    let key = kdf::unwrap_key(&wrapped, passphrase, &salt, params).map_err(|e| match e {
        kdf::BackupError::Auth => BackupError::Auth,
        _ => BackupError::Corrupt,
    })?;
    Ok(Opener { input, key, counter: 0, buf: Vec::new(), pos: 0, done: false })
}

/// What reading an archive writes to disk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unpack {
    /// Every entry (a restore).
    Everything,
    /// The database only (a verify: the rest is authenticated as it streams past and dropped).
    DatabaseOnly,
}

/// Create the directories of `rel`'s parent inside `root`, one level at a time, each 0700 and
/// each a real directory: an existing component that is anything else (a symlink above all)
/// is refused rather than followed.
fn private_parent(root: &Path, rel: &Path) -> Result<(), BackupError> {
    let mut dir = root.to_path_buf();
    let Some(parent) = rel.parent() else { return Ok(()) };
    for part in parent.components() {
        dir.push(part);
        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(BackupError::Corrupt),
            Err(_) => create_private_dir(&dir)?,
        }
    }
    Ok(())
}

/// Read every entry of the archive, writing into `into` — a private directory this process
/// just created — what `mode` says. An entry is a plain file at a plain relative path: the
/// format has no symlinks, hard links or devices, a name with `..`, a root or a drive is
/// refused, a name that appears twice is refused (files are created with `create_new`), and
/// everything is created 0600 / 0700. Any failure leaves the caller to discard `into`.
fn unpack(opener: &mut Opener<BufReader<File>>, into: &Path, mode: Unpack) -> Result<Summary, BackupError> {
    let mut summary = Summary::default();
    loop {
        let mut tag = [0u8; 1];
        opener.take(&mut tag)?;
        match tag[0] {
            0 => break,
            1 => {}
            _ => return Err(BackupError::Corrupt),
        }
        let mut n = [0u8; 4];
        opener.take(&mut n)?;
        let n = u32::from_be_bytes(n) as usize;
        if n > MAX_NAME {
            return Err(BackupError::Corrupt);
        }
        let mut name = vec![0u8; n];
        opener.take(&mut name)?;
        let name = String::from_utf8(name).map_err(|_| BackupError::Corrupt)?;
        let mut len = [0u8; 8];
        opener.take(&mut len)?;
        let mut left = u64::from_be_bytes(len);
        if name == OWNER_LOGIN_ENTRY {
            if left > MAX_OWNER_LOGIN || summary.owner_login.is_some() {
                return Err(BackupError::Corrupt);
            }
            let mut login = vec![0u8; left as usize];
            opener.take(&mut login)?;
            summary.owner_login = Some(String::from_utf8(login).map_err(|_| BackupError::Corrupt)?);
            continue;
        }
        // The archive is authenticated, but a path is still never trusted to stay inside.
        let rel = safe_relative(&name).ok_or(BackupError::Corrupt)?;
        let mut file = if mode == Unpack::Everything || name == DB_FILE {
            private_parent(into, &rel)?;
            // `create_new`: a second entry of the same name, or anything already at the path,
            // fails here instead of being written over or through.
            let file = create_private_file(&into.join(&rel)).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => BackupError::Corrupt,
                _ => BackupError::Io(e),
            })?;
            Some(BufWriter::new(file))
        } else {
            None
        };
        summary.files += 1;
        summary.bytes += left;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let want = (buf.len() as u64).min(left) as usize;
            opener.take(&mut buf[..want])?;
            if let Some(file) = file.as_mut() {
                file.write_all(&buf[..want])?;
            }
            left -= want as u64;
        }
        if let Some(mut file) = file {
            file.flush()?;
        }
    }
    if !opener.at_end()? {
        return Err(BackupError::Corrupt);
    }
    Ok(summary)
}

/// Restore the backup at `file` into `data`. The whole archive is decrypted, authenticated and
/// its database checked in a scratch folder NEXT TO `data` first; only then is it moved into
/// place — so a wrong passphrase or a damaged file changes nothing. `data` must not already
/// hold a skwod unless `replace` is set (the old one is then kept beside it as
/// `<data>.replaced-<time>`, never deleted).
pub async fn restore(file: &Path, data: &Path, passphrase: &str, replace: bool) -> Result<Summary, BackupError> {
    let occupied = data.join(DB_FILE).exists();
    if occupied && !replace {
        return Err(BackupError::Refused(format!(
            "{} already holds a skwod. Choose an empty folder, or pass --replace to set the existing one aside.",
            data.display()
        )));
    }
    let mut opener = open_archive(file, passphrase)?;
    let parent = data.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let stamp = crate::state::now_ms();
    // Unpacked next to its destination (same volume, so the final step is a rename) in a
    // directory nobody else can enter, under a name nobody else can predict.
    let scratch = private_scratch(parent, ".restore-")?;
    let result = async {
        let summary = unpack(&mut opener, &scratch, Unpack::Everything)?;
        if !scratch.join(DB_FILE).is_file() || !database_ok(&scratch.join(DB_FILE)).await {
            return Err(BackupError::Corrupt);
        }
        ensure_private_dir(&scratch.join("blobs"))?;
        // A backup is the skwod as it WAS (audit M-6): see `after_restore`.
        let mut summary = summary;
        summary.reverted = after_restore(&scratch.join(DB_FILE), occupied.then(|| data.join(DB_FILE)).as_deref(), stamp).await?;
        if !summary.reverted.is_empty() {
            write_private(&scratch.join(RESTORE_REPORT), summary.reverted.join("\n").as_bytes())?;
        }
        // SQLite may have left `-wal`/`-shm` beside the database while checking it.
        make_private(&scratch)?;
        if data.exists() {
            let empty = std::fs::read_dir(data)?.next().is_none();
            if empty {
                std::fs::remove_dir(data)?;
            } else {
                let mut aside = data.as_os_str().to_owned();
                aside.push(format!(".replaced-{stamp}"));
                std::fs::rename(data, PathBuf::from(aside))?;
            }
        }
        std::fs::rename(&scratch, data)?;
        Ok(summary)
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&scratch);
    }
    result
}

/// Written into the data folder by a restore that brought security-relevant state back.
pub const RESTORE_REPORT: &str = "restore-report.txt";

/// A backup is the skwod as it was when the backup was taken — including everything that has
/// been REVOKED since (audit M-6). Restoring it used to quietly revert all of that: sessions
/// that had been signed out or revoked worked again, one-time prekeys that had been handed out
/// were handed out a second time, and devices, members and bans went back to their old state
/// without a word to anyone. Now, on the restored database, before it is moved into place:
///
/// - **every session ends** (and every push registration with it). Everyone signs in again;
///   an install then has to prove it is its device's current install (`keydir::bind_session`).
///   A token that was stolen, logged out or revoked before or after the backup opens nothing.
/// - **one-time prekeys are dropped**: some were served after the backup was taken, and a
///   prekey must never be served twice. Devices upload fresh ones when they next connect;
///   until then sessions start from the signed and last-resort keys.
/// - outstanding recovery challenges are dropped, and the restore is recorded
///   (`instance_secrets.restored_at`).
/// - when the restore REPLACES a skwod whose database can still be read, what comes back is
///   listed for the host — devices that had been removed, members that had been removed,
///   bans that are no longer there, accounts that had been deleted, recovery keys that had
///   been retired. It is NOT undone automatically: a restore is also how a host recovers from
///   a mistaken or malicious removal, and only the host knows which this is.
///
/// Returns those lines. A failure to compare is not a failure to restore.
async fn after_restore(restored: &Path, previous: Option<&Path>, now: i64) -> Result<Vec<String>, BackupError> {
    let pool = sqlite_one(restored, false).await?;
    // Tables are named one by one and each statement stands alone: a backup from an older
    // build does not have all of them yet.
    for sql in ["DELETE FROM push_registrations", "DELETE FROM sessions", "DELETE FROM one_time_prekeys", "DELETE FROM backup_auth_nonces"] {
        let _ = sqlx::query(sql).execute(&pool).await;
    }
    let _ = sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('restored_at', ?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value, created_at = excluded.created_at")
        .bind(now.to_string().into_bytes())
        .bind(now)
        .execute(&pool)
        .await;
    let mut reverted = Vec::new();
    if let Some(previous) = previous {
        let attached = sqlx::query("ATTACH DATABASE ? AS live").bind(previous.to_string_lossy().to_string()).execute(&pool).await.is_ok();
        if attached {
            // (what, query listing who) — rows in the backup that the replaced skwod no longer had.
            let checks: [(&str, &str); 5] = [
                (
                    "a device that had been removed is on the account again",
                    "SELECT p.username FROM user_devices d JOIN profiles p ON p.id = d.user_id
                      WHERE EXISTS(SELECT 1 FROM live.users u WHERE u.id = d.user_id)
                        AND NOT EXISTS(SELECT 1 FROM live.user_devices l WHERE l.user_id = d.user_id AND l.device_id = d.device_id)",
                ),
                (
                    "a member who had left or been removed is in a space again",
                    "SELECT p.username FROM server_members m JOIN profiles p ON p.id = m.user_id
                      WHERE EXISTS(SELECT 1 FROM live.servers s WHERE s.id = m.server_id)
                        AND NOT EXISTS(SELECT 1 FROM live.server_members l WHERE l.server_id = m.server_id AND l.user_id = m.user_id)",
                ),
                (
                    "a ban is no longer in force",
                    "SELECT COALESCE((SELECT username FROM profiles WHERE id = b.user_id), b.user_id) FROM live.server_bans b
                      WHERE NOT EXISTS(SELECT 1 FROM server_bans r WHERE r.server_id = b.server_id AND r.user_id = b.user_id)",
                ),
                (
                    "an account that had been deleted exists again",
                    "SELECT p.username FROM profiles p WHERE NOT EXISTS(SELECT 1 FROM live.users u WHERE u.id = p.id)",
                ),
                (
                    "a recovery key that had been retired is in force again",
                    "SELECT p.username FROM backup_keys k JOIN profiles p ON p.id = k.user_id
                      WHERE k.retired_at IS NULL AND EXISTS(SELECT 1 FROM live.backup_keys l WHERE l.id = k.id AND l.retired_at IS NOT NULL)",
                ),
            ];
            for (what, sql) in checks {
                let who: Vec<String> = sqlx::query_scalar(sql).fetch_all(&pool).await.unwrap_or_default();
                for name in who {
                    reverted.push(format!("{name}: {what}"));
                }
            }
            let _ = sqlx::query("DETACH DATABASE live").execute(&pool).await;
        }
    }
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&pool).await;
    pool.close().await;
    Ok(reverted)
}

/// Check a backup without restoring it: the passphrase opens it, every chunk authenticates,
/// and the database inside is whole. The archive is STREAMED: attachments, keys and the owner
/// login are authenticated in memory and never touch the disk; only the database is written —
/// SQLite has to open it to check it — into a private (0700, randomly named, atomically
/// created) directory that is removed before returning.
pub async fn verify(file: &Path, passphrase: &str) -> Result<Summary, BackupError> {
    let mut opener = open_archive(file, passphrase)?;
    let scratch = private_scratch(&std::env::temp_dir(), "skwod-verify-")?;
    let result = async {
        let mut summary = unpack(&mut opener, &scratch, Unpack::DatabaseOnly)?;
        if !scratch.join(DB_FILE).is_file() || !database_ok(&scratch.join(DB_FILE)).await {
            return Err(BackupError::Corrupt);
        }
        // Says that a login is carried, never what it is.
        summary.owner_login = summary.owner_login.map(|_| String::new());
        Ok(summary)
    }
    .await;
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

// ---- moving the data folder ----

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    create_private_dir(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let kind = e.file_type()?;
        let dest = to.join(e.file_name());
        if kind.is_dir() {
            copy_tree(&e.path(), &dest)?;
        } else if kind.is_file() {
            std::io::copy(&mut File::open(e.path())?, &mut create_private_file(&dest)?)?;
        }
    }
    Ok(())
}

/// Move the skwod in `from` to `to` (a folder that holds no skwod yet): the same skwod at a new
/// place, not a new one. The server must be stopped. A rename when both are on one volume;
/// otherwise a consistent copy that is checked before the original is set aside as
/// `<from>.moved-<time>` — the original is never deleted here.
pub async fn move_data(from: &Path, to: &Path) -> Result<(), BackupError> {
    if !from.join(DB_FILE).is_file() {
        return Err(BackupError::Refused(format!("there is no skwod in {}", from.display())));
    }
    if to.join(DB_FILE).exists() {
        return Err(BackupError::Refused(format!("{} already holds a skwod", to.display())));
    }
    if to.starts_with(from) || from.starts_with(to) {
        return Err(BackupError::Refused("the new folder cannot be inside the old one (or the other way round)".into()));
    }
    if to.exists() && std::fs::read_dir(to)?.next().is_some() {
        return Err(BackupError::Refused(format!("{} is not empty", to.display())));
    }
    // Fold the write-ahead log in, so the main file alone is the whole database.
    if let Ok(pool) = sqlite_one(&from.join(DB_FILE), false).await {
        let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&pool).await;
        pool.close().await;
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if to.exists() {
        std::fs::remove_dir(to)?;
    }
    if std::fs::rename(from, to).is_ok() {
        make_private(to)?;
        return Ok(());
    }
    // Another volume: copy, verify, then set the original aside.
    let result = async {
        copy_tree(from, to)?;
        let _ = std::fs::remove_file(to.join(".server.pid"));
        if !database_ok(&to.join(DB_FILE)).await {
            return Err(BackupError::Corrupt);
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = std::fs::remove_dir_all(to);
        return Err(e);
    }
    let mut aside = from.as_os_str().to_owned();
    aside.push(format!(".moved-{}", crate::state::now_ms()));
    std::fs::rename(from, PathBuf::from(aside))?;
    Ok(())
}

// ---- local snapshots ----

/// `YYYY-MM-DD` (UTC) for a unix time in ms.
pub fn day_of(ms: i64) -> String {
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Keep the newest `keep` files in `dir` whose names start with `prefix` (names sort by date).
fn prune(dir: &Path, prefix: &str, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut names: Vec<String> =
        entries.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n.starts_with(prefix) && n.ends_with(".db")).collect();
    names.sort();
    let excess = names.len().saturating_sub(keep);
    for name in names.into_iter().take(excess) {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

/// Take today's snapshot of the database in `data` unless there is one already, then keep the
/// newest [`SNAPSHOTS_KEPT`]. Returns the file written, if any.
pub async fn snapshot_if_due(data: &Path, now_ms: i64) -> Result<Option<PathBuf>, BackupError> {
    let db = data.join(DB_FILE);
    if !db.is_file() {
        return Ok(None);
    }
    let dir = data.join(SNAPSHOT_DIR);
    ensure_private_dir(&dir)?;
    let dest = dir.join(format!("daily-{}.db", day_of(now_ms)));
    if dest.exists() {
        return Ok(None);
    }
    // Written under another name first: a half-written file is never mistaken for a snapshot.
    let partial = dir.join(format!(".daily-{}.partial", std::process::id()));
    copy_database(&db, &partial).await?;
    std::fs::rename(&partial, &dest)?;
    prune(&dir, "daily-", SNAPSHOTS_KEPT);
    Ok(Some(dest))
}

/// The daily snapshot task of a running server (SQLite only).
pub fn spawn_snapshots(data: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match snapshot_if_due(&data, crate::state::now_ms()).await {
                Ok(Some(path)) => tracing::info!(file = %path.display(), "daily snapshot written"),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "daily snapshot failed"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    })
}

/// Called before migrations run on an EXISTING database: when the schema is about to change,
/// keep a copy of the database as it was (`snapshots/pre-migrate-v<from>-<day>.db`). `latest`
/// is the newest migration this binary carries. Returns the copy, if one was taken.
pub async fn copy_before_migrating(data: &Path, latest: i64) -> Result<Option<PathBuf>, BackupError> {
    let db = data.join(DB_FILE);
    if !db.is_file() {
        return Ok(None);
    }
    let pool = sqlite_one(&db, false).await?;
    let applied: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1").fetch_one(&pool).await.unwrap_or(None);
    pool.close().await;
    let Some(applied) = applied else { return Ok(None) };
    if applied >= latest {
        return Ok(None);
    }
    let dir = data.join(SNAPSHOT_DIR);
    ensure_private_dir(&dir)?;
    let dest = dir.join(format!("pre-migrate-v{applied:04}-{}.db", day_of(crate::state::now_ms())));
    copy_database(&db, &dest).await?;
    prune(&dir, "pre-migrate-", PRE_MIGRATE_KEPT);
    Ok(Some(dest))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams::MIN;
    const PASS: &str = "correct horse battery staple";

    /// A data folder with a real (migrated) database holding one account, a blob and a p2p key.
    async fn skwod(dir: &Path, username: &str) {
        crate::ensure_data_dir(&dir.to_path_buf()).unwrap();
        let pool = crate::open_db(dir, None).await.unwrap();
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 1)").bind(format!("test-{username}")).bind(b"x".to_vec()).execute(&pool).await.unwrap();
        pool.close().await;
        std::fs::create_dir_all(dir.join("blobs/ab")).unwrap();
        std::fs::write(dir.join("blobs/ab/blob-1"), vec![7u8; 3 * CHUNK + 17]).unwrap();
        std::fs::write(dir.join(crate::p2p::KEY_FILE), b"the-node-secret-key").unwrap();
        std::fs::write(dir.join(".server.pid"), b"123").unwrap();
    }

    async fn usernames(dir: &Path) -> Vec<String> {
        let pool = sqlite_one(&dir.join(DB_FILE), false).await.unwrap();
        let names: Vec<String> = sqlx::query_scalar("SELECT substr(name, 6) FROM instance_secrets WHERE name LIKE 'test-%' ORDER BY name").fetch_all(&pool).await.unwrap();
        pool.close().await;
        names
    }

    #[tokio::test]
    async fn a_backup_restores_the_same_skwod_into_a_fresh_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, fresh, file) = (tmp.path().join("data"), tmp.path().join("new-mac/data"), tmp.path().join("skwod.backup"));
        skwod(&data, "alice").await;
        // Taken while a "server" holds the database open with unflushed WAL content.
        let live = crate::open_db(&data, None).await.unwrap();
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('test-bob', $1, 1)").bind(b"x".to_vec()).execute(&live).await.unwrap();

        let made = backup(&data, &file, PASS, Some(r#"{"username":"alice","password":"pw"}"#), FAST).await.unwrap();
        assert_eq!(made.files, 3, "database, blob, p2p key — not the pid file");
        let raw = std::fs::read(&file).unwrap();
        assert!(raw.starts_with(MAGIC));
        for secret in [&b"the-node-secret-key"[..], b"alice", b"SQLite format 3"] {
            assert!(!raw.windows(secret.len()).any(|w| w == secret), "the archive is not plaintext");
        }
        assert!(std::fs::read_dir(&data).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with(".backup-")), "no staging file left behind");

        assert_eq!(verify(&file, PASS).await.unwrap().files, 3);
        let restored = restore(&file, &fresh, PASS, false).await.unwrap();
        assert_eq!(restored.owner_login.as_deref(), Some(r#"{"username":"alice","password":"pw"}"#));
        assert_eq!(usernames(&fresh).await, ["alice", "bob"], "including what was only in the write-ahead log");
        assert_eq!(std::fs::read(fresh.join(crate::p2p::KEY_FILE)).unwrap(), b"the-node-secret-key", "same node id, so the same address");
        assert_eq!(std::fs::read(fresh.join("blobs/ab/blob-1")).unwrap(), vec![7u8; 3 * CHUNK + 17]);
        assert!(!fresh.join(".server.pid").exists());
        // The restored folder is a working skwod: the server opens (and migrates) it.
        crate::open_db(&fresh, None).await.unwrap().close().await;
        live.close().await;
    }

    /// Audit M-6: a restore does not quietly bring revoked state back.
    #[tokio::test]
    async fn m6_a_restore_ends_every_session_drops_used_prekeys_and_lists_what_came_back() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, file) = (tmp.path().join("data"), tmp.path().join("skwod.backup"));
        skwod(&data, "alice").await;
        let live = crate::open_db(&data, None).await.unwrap();
        for sql in [
            "INSERT INTO users (id, password_hash, created_at, updated_at) VALUES ('u1', 'x', 1, 1)",
            "INSERT INTO profiles (id, username) VALUES ('u1', 'mallory')",
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_used_at, origin_at) VALUES ('s1', 'u1', X'01', 1, 9999999999999, 1, 1)",
            "INSERT INTO servers (id, owner_id, name_ciphertext, created_at, updated_at) VALUES ('sv', 'u1', X'00', 1, 1)",
            "INSERT INTO server_members (id, server_id, user_id, created_at, updated_at) VALUES ('m1', 'sv', 'u1', 1, 1)",
        ] {
            sqlx::query(sql).execute(&live).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
        }
        crate::tests::seed_device_sqlite(&live, "u1", "stolen-phone").await;
        sqlx::query("INSERT INTO one_time_prekeys (user_id, device_id, kind, key_id, public_key, created_at) VALUES ('u1', 'stolen-phone', 'ec', 1, X'05', 1)").execute(&live).await.unwrap();
        backup(&data, &file, PASS, None, FAST).await.unwrap();
        // After the backup: the phone is removed and the member is kicked and banned.
        for sql in [
            "DELETE FROM user_devices WHERE device_id = 'stolen-phone'",
            "DELETE FROM server_members WHERE id = 'm1'",
            "INSERT INTO server_bans (server_id, user_id, banned_by, created_at) VALUES ('sv', 'u1', 'u1', 2)",
        ] {
            sqlx::query(sql).execute(&live).await.unwrap_or_else(|e| panic!("{sql}: {e}"));
        }
        live.close().await;

        let restored = restore(&file, &data, PASS, true).await.unwrap();
        let said = restored.reverted.join("\n");
        for expected in ["mallory: a device that had been removed", "mallory: a member who had left or been removed", "mallory: a ban is no longer in force"] {
            assert!(said.contains(expected), "{expected:?} missing from:\n{said}");
        }
        assert_eq!(std::fs::read_to_string(data.join(RESTORE_REPORT)).unwrap(), said, "and it is left in the data folder for the host");
        let pool = sqlite_one(&data.join(DB_FILE), false).await.unwrap();
        let count = |table: &'static str| {
            let pool = pool.clone();
            async move { sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {table}")).fetch_one(&pool).await.unwrap() }
        };
        assert_eq!(count("sessions").await, 0, "every session ended: the token from before the backup opens nothing");
        assert_eq!(count("one_time_prekeys").await, 0, "no one-time prekey is served a second time");
        assert_eq!(count("user_devices").await, 1, "nothing is removed automatically: the host decides");
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM instance_secrets WHERE name = 'restored_at'").fetch_one(&pool).await.unwrap(), 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn a_wrong_passphrase_or_a_damaged_file_restores_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, file) = (tmp.path().join("data"), tmp.path().join("skwod.backup"));
        skwod(&data, "alice").await;
        assert!(matches!(backup(&data, &file, "123456", None, FAST).await, Err(BackupError::Weak(_))));
        assert!(matches!(backup(&data, &data.join("inside.backup"), PASS, None, FAST).await, Err(BackupError::Refused(_))));
        backup(&data, &file, PASS, None, FAST).await.unwrap();

        let target = tmp.path().join("target");
        assert!(matches!(restore(&file, &target, "not the right passphrase", false).await, Err(BackupError::Auth)));
        assert!(!target.exists());

        let good = std::fs::read(&file).unwrap();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("truncated", good[..good.len() - CHUNK].to_vec()),
            ("cut at a chunk boundary", good[..good.len() - (good.len() - 100) % (CHUNK + 20)].to_vec()),
            ("one bit flipped", {
                let mut b = good.clone();
                let at = b.len() / 2;
                b[at] ^= 1;
                b
            }),
            ("trailing bytes", [good.clone(), vec![0u8; 5]].concat()),
            ("not a backup", b"hello".to_vec()),
        ];
        for (what, bytes) in cases {
            let bad = tmp.path().join("bad.backup");
            std::fs::write(&bad, bytes).unwrap();
            let r = restore(&bad, &target, PASS, false).await;
            assert!(matches!(r, Err(BackupError::Corrupt | BackupError::Auth)), "{what}: {r:?}");
            assert!(!target.exists(), "{what}: nothing may be left in place");
            assert!(std::fs::read_dir(tmp.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with(".restore-")), "{what}: scratch removed");
        }

        // A folder that already holds a skwod is not overwritten by accident…
        let other = tmp.path().join("other");
        skwod(&other, "carol").await;
        assert!(matches!(restore(&file, &other, PASS, false).await, Err(BackupError::Refused(_))));
        assert_eq!(usernames(&other).await, ["carol"]);
        // …and with --replace the old one is set aside, not deleted.
        restore(&file, &other, PASS, true).await.unwrap();
        assert_eq!(usernames(&other).await, ["alice"]);
        let aside = std::fs::read_dir(tmp.path()).unwrap().flatten().find(|e| e.file_name().to_string_lossy().starts_with("other.replaced-")).expect("old skwod kept");
        assert_eq!(usernames(&aside.path()).await, ["carol"]);
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Every (path, mode) under `root`, symlinks not followed.
    #[cfg(unix)]
    fn modes(root: &Path, out: &mut Vec<(PathBuf, u32, bool)>) {
        let meta = std::fs::symlink_metadata(root).unwrap();
        out.push((root.to_path_buf(), mode(root), meta.is_dir()));
        if meta.is_dir() {
            for e in std::fs::read_dir(root).unwrap() {
                modes(&e.unwrap().path(), out);
            }
        }
    }

    /// Security review, finding 2: nothing a backup, restore or snapshot writes is readable by
    /// another user — not the database, not config files, not attachments, not the archive.
    #[cfg(unix)]
    #[tokio::test]
    async fn everything_written_is_private_whatever_it_was_before() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (data, file) = (tmp.path().join("data"), tmp.path().join("skwod.backup"));
        skwod(&data, "alice").await;
        std::fs::write(data.join("config.toml"), b"domain = \"x\"").unwrap();
        std::fs::write(data.join("livekit.yaml"), b"keys: {a: secret}").unwrap();
        // The original is as loose as an old install could be.
        for p in ["config.toml", "livekit.yaml", "blobs/ab/blob-1", "p2p.key", "skwod.db"] {
            std::fs::set_permissions(data.join(p), std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        std::fs::set_permissions(data.join("blobs"), std::fs::Permissions::from_mode(0o777)).unwrap();

        // A world-readable file already sits where the archive (and its scratch file) will go.
        for p in [file.clone(), file.with_extension("partial")] {
            std::fs::write(&p, b"old").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        backup(&data, &file, PASS, Some("login"), FAST).await.unwrap();
        assert_eq!(mode(&file), 0o600, "the archive itself");

        let fresh = tmp.path().join("fresh");
        restore(&file, &fresh, PASS, false).await.unwrap();
        let mut all = Vec::new();
        modes(&fresh, &mut all);
        assert!(all.len() >= 7, "{all:?}");
        for (path, mode, is_dir) in &all {
            assert_eq!(*mode, if *is_dir { 0o700 } else { 0o600 }, "{}", path.display());
        }

        // Snapshots: the directory and every file in it, also when the directory pre-existed loose.
        std::fs::create_dir_all(data.join(SNAPSHOT_DIR)).unwrap();
        std::fs::set_permissions(data.join(SNAPSHOT_DIR), std::fs::Permissions::from_mode(0o755)).unwrap();
        let snap = snapshot_if_due(&data, 1_763_510_400_000).await.unwrap().unwrap();
        assert_eq!((mode(&data.join(SNAPSHOT_DIR)), mode(&snap)), (0o700, 0o600));

        // The owner-login hand-off file, over a loose file that was already there.
        let login = tmp.path().join("login.json");
        std::fs::write(&login, b"stale").unwrap();
        std::fs::set_permissions(&login, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&login, b"fresh").unwrap();
        assert_eq!((mode(&login), std::fs::read(&login).unwrap()), (0o600, b"fresh".to_vec()));
    }

    /// Security review, finding 1: scratch directories are unpredictable, private and created
    /// atomically; a verify writes nothing but the database; and no write goes through a
    /// symlink or onto an existing path.
    #[cfg(unix)]
    #[tokio::test]
    async fn scratch_space_cannot_be_prepared_by_someone_else() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, file) = (tmp.path().join("data"), tmp.path().join("skwod.backup"));
        skwod(&data, "alice").await;
        backup(&data, &file, PASS, Some("login"), FAST).await.unwrap();

        // Random, 0700, and never an existing directory.
        let a = private_scratch(tmp.path(), "s-").unwrap();
        let b = private_scratch(tmp.path(), "s-").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.file_name().unwrap().len(), 2 + 32, "128 random bits in the name");
        assert_eq!(mode(&a), 0o700);
        assert_eq!(create_private_dir(&a).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists, "an existing directory is never adopted");
        // …nor a symlink standing in for one.
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, tmp.path().join("planted")).unwrap();
        assert!(create_private_dir(&tmp.path().join("planted")).is_err());
        assert!(ensure_private_dir(&tmp.path().join("planted")).is_err());

        // A file is only ever created new: not over a file, not through a symlink.
        std::fs::write(outside.join("victim"), b"untouched").unwrap();
        std::os::unix::fs::symlink(outside.join("victim"), a.join("link")).unwrap();
        assert!(create_private_file(&a.join("link")).is_err());
        std::os::unix::fs::symlink(outside.join("not-yet"), a.join("dangling")).unwrap();
        assert!(create_private_file(&a.join("dangling")).is_err(), "a dangling symlink is not followed into existence");
        assert!(!outside.join("not-yet").exists());
        assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"untouched");
        // `write_private` replaces a planted symlink instead of writing through it.
        write_private(&a.join("link"), b"mine").unwrap();
        assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"untouched");
        assert!(std::fs::symlink_metadata(a.join("link")).unwrap().is_file());

        // Unpacking refuses a symlinked directory inside its target…
        let target = private_scratch(tmp.path(), "t-").unwrap();
        std::os::unix::fs::symlink(&outside, target.join("blobs")).unwrap();
        let r = unpack(&mut open_archive(&file, PASS).unwrap(), &target, Unpack::Everything);
        assert!(matches!(r, Err(BackupError::Corrupt)), "{r:?}");
        assert!(std::fs::read_dir(&outside).unwrap().flatten().all(|e| e.file_name() != "ab"), "nothing was written through the link");
        // …and a file already sitting at an entry's path.
        let target = private_scratch(tmp.path(), "t-").unwrap();
        std::fs::write(target.join(DB_FILE), b"planted").unwrap();
        assert!(matches!(unpack(&mut open_archive(&file, PASS).unwrap(), &target, Unpack::Everything), Err(BackupError::Corrupt)));

        // A verify materialises the database and nothing else.
        let target = private_scratch(tmp.path(), "v-").unwrap();
        let seen = unpack(&mut open_archive(&file, PASS).unwrap(), &target, Unpack::DatabaseOnly).unwrap();
        assert_eq!(seen.files, 3, "every entry was read and authenticated");
        let written: Vec<_> = std::fs::read_dir(&target).unwrap().flatten().map(|e| e.file_name().into_string().unwrap()).collect();
        assert_eq!(written, [DB_FILE]);
        assert_eq!(mode(&target.join(DB_FILE)), 0o600);

        // And the public entry point leaves nothing behind in the temp directory.
        let before: std::collections::BTreeSet<_> = std::fs::read_dir(std::env::temp_dir()).unwrap().flatten().map(|e| e.file_name()).filter(|n| n.to_string_lossy().starts_with("skwod-verify-")).collect();
        let checked = verify(&file, PASS).await.unwrap();
        assert_eq!((checked.files, checked.owner_login.as_deref()), (3, Some("")), "a login is reported as present, never returned");
        let after: std::collections::BTreeSet<_> = std::fs::read_dir(std::env::temp_dir()).unwrap().flatten().map(|e| e.file_name()).filter(|n| n.to_string_lossy().starts_with("skwod-verify-")).collect();
        assert_eq!(before, after);
    }

    /// An archive is authenticated, so a hostile entry needs the passphrase — but a restore
    /// still refuses one: built here with the real key, as an attacker who had it would.
    #[tokio::test]
    async fn hostile_entry_names_and_duplicates_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let build = |entries: &[(&str, &[u8])]| {
            let key: [u8; 32] = skwod_crypto::random_bytes();
            let salt: [u8; 16] = skwod_crypto::random_bytes();
            let wrapped = kdf::wrap_key(&key, PASS, &salt, FAST).unwrap();
            let mut head = MAGIC.to_vec();
            for v in [FAST.m_kib, FAST.t, FAST.p] {
                head.extend(v.to_be_bytes());
            }
            head.extend(salt);
            head.extend((wrapped.len() as u16).to_be_bytes());
            head.extend(&wrapped);
            let mut sealer = Sealer { out: head, key, counter: 0, buf: Vec::new() };
            for (name, body) in entries {
                put_entry(&mut sealer, name, body.len() as u64, *body).unwrap();
            }
            sealer.put(&[0]).unwrap();
            sealer.finish().unwrap()
        };
        type Entries<'a> = Vec<(&'a str, &'a [u8])>;
        let cases: Vec<(&str, Entries)> = vec![
            ("parent traversal", vec![("../escaped", b"x")]),
            ("nested traversal", vec![("blobs/../../escaped", b"x")]),
            ("absolute path", vec![("/tmp/skwod-escaped", b"x")]),
            ("the same name twice", vec![("skwod.db", b"a"), ("skwod.db", b"b")]),
            ("a file where a directory is needed", vec![("blobs", b"x"), ("blobs/ab", b"y")]),
            ("two owner logins", vec![(OWNER_LOGIN_ENTRY, b"a"), (OWNER_LOGIN_ENTRY, b"b")]),
        ];
        for (what, entries) in cases {
            let file = tmp.path().join("hostile.backup");
            std::fs::write(&file, build(&entries)).unwrap();
            let target = tmp.path().join("target");
            let r = restore(&file, &target, PASS, false).await;
            assert!(matches!(r, Err(BackupError::Corrupt)), "{what}: {r:?}");
            assert!(!target.exists(), "{what}");
            assert!(!tmp.path().join("escaped").exists() && !tmp.path().parent().unwrap().join("escaped").exists(), "{what}");
            assert!(matches!(verify(&file, PASS).await, Err(BackupError::Corrupt)), "{what} (verify)");
        }
    }

    #[test]
    fn only_plain_relative_paths_are_ever_written() {
        for bad in ["", "/etc/passwd", "../outside", "blobs/../../outside", "./x"] {
            assert!(safe_relative(bad).is_none(), "{bad}");
        }
        assert_eq!(safe_relative("blobs/ab/blob-1"), Some(PathBuf::from("blobs/ab/blob-1")));
    }

    #[tokio::test]
    async fn moving_the_folder_keeps_the_skwod() {
        let tmp = tempfile::tempdir().unwrap();
        let (from, to) = (tmp.path().join("old/skwod-host-data"), tmp.path().join("new/skwod-host-data"));
        skwod(&from, "alice").await;
        let taken = tmp.path().join("taken");
        skwod(&taken, "carol").await;
        assert!(matches!(move_data(&from, &taken).await, Err(BackupError::Refused(_))), "never onto another skwod");
        assert!(matches!(move_data(&from, &from.join("inside")).await, Err(BackupError::Refused(_))));
        assert!(matches!(move_data(&tmp.path().join("nothing"), &to).await, Err(BackupError::Refused(_))));

        move_data(&from, &to).await.unwrap();
        assert!(!from.join(DB_FILE).exists());
        assert_eq!(usernames(&to).await, ["alice"]);
        assert_eq!(std::fs::read(to.join(crate::p2p::KEY_FILE)).unwrap(), b"the-node-secret-key");
        assert_eq!(std::fs::read(to.join("blobs/ab/blob-1")).unwrap().len(), 3 * CHUNK + 17);
    }

    #[tokio::test]
    async fn one_snapshot_a_day_and_seven_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        skwod(&data, "alice").await;
        const DAY: i64 = 86_400_000;
        let start = 1_763_510_400_000; // 2025-11-19T00:00:00Z
        assert_eq!(day_of(start), "2025-11-19");
        assert_eq!(day_of(0), "1970-01-01");
        assert_eq!(day_of(951_782_400_000), "2000-02-29");

        let first = snapshot_if_due(&data, start).await.unwrap().expect("first snapshot");
        assert_eq!(first.file_name().unwrap(), "daily-2025-11-19.db");
        assert!(database_ok(&first).await);
        assert!(snapshot_if_due(&data, start + DAY - 1).await.unwrap().is_none(), "one per day");
        for d in 1..10 {
            snapshot_if_due(&data, start + d * DAY).await.unwrap().expect("a new day");
        }
        let mut kept: Vec<String> = std::fs::read_dir(data.join(SNAPSHOT_DIR)).unwrap().flatten().map(|e| e.file_name().into_string().unwrap()).collect();
        kept.sort();
        assert_eq!(kept.len(), SNAPSHOTS_KEPT);
        assert_eq!((kept[0].as_str(), kept[6].as_str()), ("daily-2025-11-22.db", "daily-2025-11-28.db"));
        // Snapshots are local history, not part of a backup file.
        let file = tmp.path().join("b.backup");
        assert_eq!(backup(&data, &file, PASS, None, FAST).await.unwrap().files, 3);
    }

    #[tokio::test]
    async fn the_database_is_copied_before_a_migration_changes_it() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        // A brand-new database: nothing to keep.
        crate::ensure_data_dir(&data).unwrap();
        assert!(copy_before_migrating(&data, 12).await.unwrap().is_none());
        skwod(&data, "alice").await;
        let latest: i64 = {
            let pool = sqlite_one(&data.join(DB_FILE), false).await.unwrap();
            let v = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(&pool).await.unwrap();
            pool.close().await;
            v
        };
        assert!(copy_before_migrating(&data, latest).await.unwrap().is_none(), "up to date: no copy");
        // A newer binary arrives carrying one more migration.
        let copy = copy_before_migrating(&data, latest + 1).await.unwrap().expect("copied before migrating");
        assert!(copy.file_name().unwrap().to_string_lossy().starts_with(&format!("pre-migrate-v{latest:04}-")));
        assert_eq!(usernames(copy.parent().unwrap().parent().unwrap()).await, ["alice"]);
        assert!(database_ok(&copy).await);
    }
}
