//! Container entrypoint duties, done by the binary itself so the image needs no shell tools:
//! fix the ownership of an existing data volume once, then give up root for good.
//!
//! **Why this exists.** The image runs as uid 1000. A volume created by an older (root) image,
//! or a bind-mount directory Docker created on the host (root:root — the usual case on Unraid
//! and Synology), cannot be opened by uid 1000: the server used to die with "unable to open
//! database file". Two supported ways out:
//!
//! - **Stay non-root** (the image default, `USER 1000`, no capabilities): a one-shot
//!   `skwod fix-ownership` container run as root with only `CAP_CHOWN` repairs the volume
//!   (`deploy/docker-compose.yml` does this automatically);
//! - **Start as root, end as non-root** (single-container platforms — the Unraid template): the
//!   container starts as uid 0 with exactly `CHOWN`, `SETUID`, `SETGID`, and this module chowns
//!   what needs it and then switches to `SKWOD_RUN_AS` *before the runtime starts or any socket
//!   is opened*. After `setuid` the kernel clears every capability; with `no-new-privileges`
//!   nothing can bring them back.
//!
//! **The walk is race-free against whoever controls the volume's contents** (a server
//! compromised on an earlier run is uid 1000 and can rename things under root's feet). It never
//! resolves a path twice: every directory is opened `O_DIRECTORY|O_NOFOLLOW` *relative to its
//! parent's descriptor*, checked with `fstat` on the descriptor that was opened (still a
//! directory, still on the volume's device), and its entries are examined and re-owned with
//! `fstatat`/`fchownat(…, AT_SYMLINK_NOFOLLOW)` relative to that descriptor. Swapping an entry
//! for a symlink in between therefore changes, at worst, the owner of the symlink itself;
//! swapping a directory makes the open fail and the subtree is skipped. Regular files with more
//! than one hard link are skipped too (a link to a file elsewhere on the device must not be
//! handed over). Only entries whose owner is wrong are touched, so every later start is a no-op.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

/// `SKWOD_RUN_AS=uid[:gid]`, else `PUID`/`PGID` (the NAS convention). Root is never a target.
pub fn run_as_from_env() -> Option<RunAs> {
    let parse = |v: String| v.trim().parse::<u32>().ok();
    let from_pair = std::env::var("SKWOD_RUN_AS").ok().and_then(|v| {
        let (uid, gid) = v.split_once(':').unwrap_or((v.as_str(), v.as_str()));
        Some(RunAs { uid: uid.trim().parse().ok()?, gid: gid.trim().parse().ok()? })
    });
    let from_puid = || {
        let uid = std::env::var("PUID").ok().and_then(parse)?;
        Some(RunAs { uid, gid: std::env::var("PGID").ok().and_then(parse).unwrap_or(uid) })
    };
    from_pair.or_else(from_puid).filter(|r| r.uid != 0 && r.gid != 0)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fixed {
    pub changed: u64,
    pub failed: u64,
}

/// Give everything under `data` to `to`. See the module docs for the safety rules.
#[cfg(unix)]
pub fn fix_ownership(data: &Path, to: RunAs) -> std::io::Result<Fixed> {
    use nix::dir::Dir;
    use nix::fcntl::{openat, AtFlags, OFlag};
    use nix::sys::stat::{fstat, fstatat, Mode, SFlag};
    use nix::unistd::{fchown, fchownat, Gid, Uid};
    use std::os::fd::AsRawFd;

    let io = |e: nix::errno::Errno| std::io::Error::from_raw_os_error(e as i32);
    let root = std::fs::canonicalize(data)?;
    // Refuse anything that is obviously not a dedicated data directory.
    if root.components().count() < 2 || ["/etc", "/usr", "/bin", "/sbin", "/var", "/home", "/root", "/lib", "/boot", "/dev", "/proc", "/sys", "/tmp"].iter().any(|p| root == Path::new(p)) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "refusing to change ownership of a system directory"));
    }
    let (uid, gid) = (Uid::from_raw(to.uid), Gid::from_raw(to.gid));
    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let wrong = |st: &nix::sys::stat::FileStat| st.st_uid != to.uid || st.st_gid != to.gid;
    let is_dir = |st: &nix::sys::stat::FileStat| SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFDIR;

    // The volume root: opened once, judged and re-owned through its descriptor.
    let top = Dir::open(&root, dir_flags, Mode::empty()).map_err(io)?;
    let top_stat = fstat(top.as_raw_fd()).map_err(io)?;
    let device = top_stat.st_dev;
    let mut fixed = Fixed::default();
    if wrong(&top_stat) {
        match fchown(top.as_raw_fd(), Some(uid), Some(gid)) {
            Ok(()) => fixed.changed += 1,
            Err(_) => fixed.failed += 1,
        }
    }

    let mut stack = vec![top];
    while let Some(mut dir) = stack.pop() {
        let fd = dir.as_raw_fd();
        let names: Vec<std::ffi::CString> = dir
            .iter()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_owned())
            .filter(|n| !matches!(n.to_bytes(), b"." | b".."))
            .collect();
        for name in names {
            let Ok(st) = fstatat(Some(fd), name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW) else {
                fixed.failed += 1;
                continue;
            };
            if st.st_dev != device {
                continue; // another filesystem mounted inside: not ours
            }
            let kind = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT;
            if kind == SFlag::S_IFREG && st.st_nlink > 1 {
                if wrong(&st) {
                    fixed.failed += 1; // hard-linked: could be someone else's file; leave it
                }
                continue;
            }
            if is_dir(&st) {
                // Open first, then act on what was actually opened.
                let Ok(child) = openat(Some(fd), name.as_c_str(), dir_flags, Mode::empty()).and_then(Dir::from_fd) else {
                    fixed.failed += 1; // replaced by a symlink/file meanwhile, or unreadable
                    continue;
                };
                let Ok(cst) = fstat(child.as_raw_fd()) else {
                    fixed.failed += 1;
                    continue;
                };
                if cst.st_dev != device || !is_dir(&cst) {
                    continue;
                }
                if wrong(&cst) {
                    match fchown(child.as_raw_fd(), Some(uid), Some(gid)) {
                        Ok(()) => fixed.changed += 1,
                        Err(_) => fixed.failed += 1,
                    }
                }
                stack.push(child);
            } else if wrong(&st) {
                // Never follows: if the entry became a symlink since the stat, the symlink
                // itself is what changes owner.
                match fchownat(Some(fd), name.as_c_str(), Some(uid), Some(gid), AtFlags::AT_SYMLINK_NOFOLLOW) {
                    Ok(()) => fixed.changed += 1,
                    Err(_) => fixed.failed += 1,
                }
            }
        }
    }
    Ok(fixed)
}

/// Linux: the capability sets of this process, from `/proc/self/status`
/// (`CapInh`, `CapPrm`, `CapEff`, `CapAmb`). `None` where that cannot be read.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn capability_sets(status: &str) -> Option<[u64; 4]> {
    let get = |key: &str| status.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| u64::from_str_radix(v.trim(), 16).ok());
    Some([get("CapInh:")?, get("CapPrm:")?, get("CapEff:")?, get("CapAmb:")?])
}

/// If this process is root and a target user is configured: repair the volume, then become that
/// user irreversibly. Must run before any thread is spawned. Exits the process if root cannot
/// be dropped — a half-privileged server must never start.
#[cfg(unix)]
pub fn enter(data: &Path) {
    use nix::unistd::{setgid, setuid, Gid, Uid};
    if !Uid::effective().is_root() {
        return;
    }
    let Some(to) = run_as_from_env() else { return }; // plain `sudo skwod run` on a VPS: unchanged
    let _ = std::fs::create_dir_all(data);
    match fix_ownership(data, to) {
        Ok(f) if f.changed > 0 || f.failed > 0 => {
            println!("[skwod] data volume ownership: {} entries given to {}:{}{}", f.changed, to.uid, to.gid, if f.failed > 0 { format!(" ({} could not be changed)", f.failed) } else { String::new() });
        }
        Ok(_) => {}
        Err(e) => eprintln!("[skwod] could not fix data volume ownership: {e}"),
    }
    // Supplementary groups first (root's would otherwise survive the switch). macOS has no
    // usable setgroups and is not a container target.
    #[cfg(not(target_vendor = "apple"))]
    let groups = nix::unistd::setgroups(&[Gid::from_raw(to.gid)]);
    #[cfg(target_vendor = "apple")]
    let groups: nix::Result<()> = Ok(());
    let dropped = groups.and_then(|_| setgid(Gid::from_raw(to.gid))).and_then(|_| setuid(Uid::from_raw(to.uid)));
    if let Err(e) = dropped {
        eprintln!("[skwod] cannot drop root ({e}). Start the container either as a non-root user, or as root WITH the CHOWN, SETUID and SETGID capabilities.");
        std::process::exit(78);
    }
    // Prove it is irreversible before doing anything else.
    if setuid(Uid::from_raw(0)).is_ok() || Uid::effective().is_root() {
        eprintln!("[skwod] root could be regained after dropping it — refusing to start.");
        std::process::exit(78);
    }
    // …and that no capability survived the switch (the kernel clears them on setuid away from
    // 0; this is the check that it did). The server must run with none.
    #[cfg(target_os = "linux")]
    if let Some(sets) = std::fs::read_to_string("/proc/self/status").ok().as_deref().and_then(capability_sets) {
        if sets.iter().any(|s| *s != 0) {
            eprintln!("[skwod] capabilities remain after dropping root ({sets:x?}) — refusing to start.");
            std::process::exit(78);
        }
    }
}

#[cfg(not(unix))]
pub fn enter(_data: &Path) {}

/// Explain an unusable data directory in terms of what to do about it.
pub fn explain_unwritable(data: &Path, err: &dyn std::fmt::Display) -> String {
    #[cfg(unix)]
    let who = format!("uid {}", nix::unistd::Uid::effective());
    #[cfg(not(unix))]
    let who = "this user".to_string();
    format!(
        "cannot use the data directory {}: {err}\n\
         The server runs as {who} and that directory belongs to someone else (typically root, from an older image or a host folder Docker created).\n\
         Fix it once, then start again:\n\
         \x20 docker run --rm --user 0 --cap-drop ALL --cap-add CHOWN -v <your volume or folder>:/data <this image> skwod fix-ownership --data /data\n\
         (deploy/docker-compose.yml and the Unraid template do this for you.)",
        data.display()
    )
}

/// Can we create files in `data`? (Opening the SQLite file fails much less readably.)
pub fn probe_writable(data: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(data)?;
    let probe = data.join(format!(".write-test-{}", std::process::id()));
    std::fs::write(&probe, b"")?;
    std::fs::remove_file(&probe)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// A tree with a file, nested dirs, a symlink to a directory OUTSIDE the volume, a symlink
    /// to a file outside, and a hard link.
    fn tree() -> (tempfile::TempDir, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("deep/deeper")).unwrap();
        std::fs::write(outside.path().join("victim"), b"x").unwrap();
        std::fs::create_dir_all(dir.path().join("blobs/aa")).unwrap();
        std::fs::write(dir.path().join("skwod.db"), b"x").unwrap();
        std::fs::write(dir.path().join("blobs/aa/one"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("victim"), dir.path().join("blobs/link")).unwrap();
        std::fs::hard_link(outside.path().join("victim"), dir.path().join("hard")).unwrap();
        (dir, outside)
    }

    #[test]
    fn already_owned_trees_are_left_alone_and_symlinks_are_not_followed() {
        let (dir, _outside) = tree();
        let me = std::fs::metadata(dir.path()).unwrap();
        let to = RunAs { uid: me.uid(), gid: me.gid() };
        // Everything already belongs to us: a no-op, which is what makes the fix "one-time".
        assert_eq!(fix_ownership(dir.path(), to).unwrap(), Fixed::default());
        // A different owner. We are not root, so every chown attempt fails — which makes the
        // failure count an exact record of what the walk TRIED to re-own:
        //   data dir, skwod.db, blobs, blobs/aa, blobs/aa/one,
        //   the two symlinks THEMSELVES (never their targets), and the skipped hard link.
        // Nothing under `outside` (victim, deep, deep/deeper) is in that count.
        let other = RunAs { uid: me.uid() + 1, gid: me.gid() };
        assert_eq!(fix_ownership(dir.path(), other).unwrap(), Fixed { changed: 0, failed: 8 });
        assert!(fix_ownership(Path::new("/"), to).is_err());
        // (On macOS /etc canonicalizes to /private/etc; the list is for Linux containers.)
        #[cfg(target_os = "linux")]
        assert!(fix_ownership(Path::new("/etc"), to).is_err());
    }

    /// The race the fd-relative walk exists for: a directory that is swapped for a symlink to
    /// somewhere else after it was listed. With path-based code root would descend into (and
    /// re-own) the target; here the `O_NOFOLLOW` open of the swapped entry fails and the
    /// target is never entered. The real thing (as root, in the image) is in docs/SELF-HOSTING.md;
    /// as an ordinary user this asserts the walk's reach via the attempt count.
    #[test]
    fn a_directory_swapped_for_a_symlink_is_not_entered() {
        let (dir, outside) = tree();
        // The state right after the swap: `blobs` is now a symlink to a directory outside.
        std::fs::rename(dir.path().join("blobs"), dir.path().join("blobs.real")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("deep"), dir.path().join("blobs")).unwrap();
        let me = std::fs::metadata(dir.path()).unwrap();
        let other = RunAs { uid: me.uid() + 1, gid: me.gid() };
        // data dir, skwod.db, hard(skipped), escape(link), blobs(link itself),
        // blobs.real, blobs.real/aa, blobs.real/aa/one, blobs.real/link(link) = 9.
        // `outside/deep/deeper` would make it 10+ if the symlink were followed.
        assert_eq!(fix_ownership(dir.path(), other).unwrap(), Fixed { changed: 0, failed: 9 });
        // And nothing outside changed hands.
        assert_eq!(std::fs::metadata(outside.path().join("deep/deeper")).unwrap().uid(), me.uid());
        assert_eq!(std::fs::metadata(outside.path().join("victim")).unwrap().uid(), me.uid());
    }

    #[test]
    fn capability_sets_are_read_from_proc_status() {
        let clean = "Name:\tskwod\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t00000000000000c1\nCapAmb:\t0000000000000000\n";
        assert_eq!(capability_sets(clean), Some([0, 0, 0, 0]), "the bounding set is not a held capability");
        let held = clean.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001");
        assert_eq!(capability_sets(&held), Some([0, 0, 1, 0]));
        assert_eq!(capability_sets("Name: x"), None);
    }

    #[test]
    fn unwritable_data_dir_is_explained() {
        let msg = explain_unwritable(Path::new("/data"), &"Permission denied");
        assert!(msg.contains("fix-ownership") && msg.contains("--cap-add CHOWN"));
    }
}
