//! Startup failures in plain sentences.
//!
//! The person reading these pressed "Start server" in a Mac app, or ran one command on a NAS.
//! "bind listen address: Os { code: 48, kind: AddrInUse }" tells them nothing. Each failure is
//! printed as `[skwod] <sentence>` on stderr (the host apps show the last such line) and the
//! process exits with a code a supervisor can act on.

/// Exit codes (sysexits.h where one fits).
pub const EXIT_PORT: i32 = 75; // EX_TEMPFAIL: retrying on another port can work
pub const EXIT_DATA: i32 = 74; // EX_IOERR: the data folder / database / disk

/// Why the API port could not be opened.
pub fn bind_failure(listen: &str, e: &std::io::Error) -> String {
    let port = listen.rsplit(':').next().unwrap_or(listen);
    match e.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "Port {port} on this computer is already in use — usually by another copy of Skwod that is still running. Quit that one (or pick another port) and start again."
        ),
        std::io::ErrorKind::PermissionDenied => {
            format!("This computer does not allow Skwod to open port {port}. Choose a port above 1024, or allow Skwod in your firewall / security settings.")
        }
        std::io::ErrorKind::AddrNotAvailable => format!("The address {listen} does not exist on this computer, so Skwod cannot listen there. Check the listen address."),
        _ => format!("Skwod could not open port {port} on this computer ({e})."),
    }
}

/// Why the database could not be opened or migrated.
pub fn database_failure(data: &std::path::Path, detail: &str) -> String {
    let d = detail.to_ascii_lowercase();
    let folder = data.display();
    if d.contains("database or disk is full") || d.contains("no space left") || d.contains("disk full") {
        format!("This computer is out of disk space, so Skwod cannot open its data in {folder}. Free up some space and start again.")
    } else if d.contains("database is locked") || d.contains("database table is locked") {
        format!("Skwod's data in {folder} is in use by another copy of Skwod. Quit the other copy and start again.")
    } else if d.contains("malformed") || d.contains("not a database") || d.contains("file is encrypted") || d.contains("corrupt") {
        format!("Skwod's data file in {folder} is damaged and cannot be opened. Restore that folder from a backup; if you have none, move it aside to start a new, empty skwod.")
    } else if d.contains("permission denied") || d.contains("readonly") || d.contains("read-only") || d.contains("unable to open database file") {
        format!("Skwod cannot read or write its data in {folder}. Check that the folder exists, that this user owns it, and that the disk is not read-only.")
    } else if d.contains("disk i/o error") || d.contains("input/output error") {
        format!("The disk holding {folder} reported an error while Skwod was opening its data. Check the disk (and its cable, if it is external) and start again.")
    } else if d.contains("migration") || d.contains("was previously applied") {
        format!("Skwod's data in {folder} was written by a NEWER version of Skwod than this one. Update Skwod and start again.")
    } else {
        format!("Skwod could not open its data in {folder} ({detail}).")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn startup_failures_read_as_sentences_not_as_error_kinds() {
        let s = bind_failure("127.0.0.1:4820", &Error::from(ErrorKind::AddrInUse));
        assert!(s.contains("Port 4820") && s.contains("already in use") && !s.contains("AddrInUse") && !s.contains("os error"), "{s}");
        assert!(bind_failure("0.0.0.0:80", &Error::from(ErrorKind::PermissionDenied)).contains("above 1024"));
        assert!(bind_failure("10.9.9.9:4820", &Error::from(ErrorKind::AddrNotAvailable)).contains("does not exist on this computer"));

        let data = std::path::Path::new("/data/skwod");
        for (detail, expect) in [
            ("error returned from database: (code: 13) database or disk is full", "out of disk space"),
            ("No space left on device (os error 28)", "out of disk space"),
            ("error returned from database: (code: 5) database is locked", "another copy of Skwod"),
            ("error returned from database: (code: 11) database disk image is malformed", "damaged"),
            ("error returned from database: (code: 26) file is not a database", "damaged"),
            ("error returned from database: (code: 14) unable to open database file", "cannot read or write"),
            ("error returned from database: (code: 8) attempt to write a readonly database", "cannot read or write"),
            ("error returned from database: (code: 10) disk I/O error", "reported an error"),
            ("migration 12 was previously applied but is missing in the resolved migrations", "NEWER version"),
        ] {
            let s = database_failure(data, detail);
            assert!(s.contains(expect), "{detail:?} → {s}");
            assert!(s.contains("/data/skwod"));
            assert!(s.ends_with('.'));
        }
        // Anything unrecognized still says what it was, in a sentence.
        assert!(database_failure(data, "pool timed out").contains("pool timed out"));
    }
}
