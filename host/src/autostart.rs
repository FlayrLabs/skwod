//! Opt-in "launch at login". Off until the user ticks the menu item.
//!
//! - Linux: an XDG autostart entry, `~/.config/autostart/skwod-host.desktop`.
//! - Windows: a value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//!
//! Both start the app with `--background` (tray only, no browser window).

use std::path::Path;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DESKTOP_FILE: &str = "skwod-host.desktop";
#[cfg_attr(not(windows), allow(dead_code))]
const RUN_VALUE: &str = "skwod-host";

/// Quote a path for a desktop entry `Exec=` line (Desktop Entry Specification: the argument is
/// wrapped in double quotes and `"`, `` ` ``, `$`, `\` are backslash-escaped; `%` is doubled).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn desktop_exec_quote(path: &str) -> String {
    let mut out = String::from("\"");
    for c in path.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn desktop_entry(exe: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=skwod host\nComment=Host your skwod server\nExec={} --background\nIcon=skwod-host\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        desktop_exec_quote(&exe.to_string_lossy())
    )
}

#[cfg(target_os = "linux")]
fn autostart_file() -> Option<std::path::PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))?;
    Some(config.join("autostart").join(DESKTOP_FILE))
}

#[cfg(target_os = "linux")]
pub fn is_enabled() -> bool {
    autostart_file().is_some_and(|f| f.is_file())
}

#[cfg(target_os = "linux")]
pub fn set(enabled: bool, exe: &Path) -> std::io::Result<()> {
    let file = autostart_file().ok_or_else(|| std::io::Error::other("no home directory"))?;
    if !enabled {
        return match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&file, desktop_entry(exe))
}

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
pub fn is_enabled() -> bool {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    RegKey::predef(HKEY_CURRENT_USER).open_subkey(RUN_KEY).and_then(|k| k.get_value::<String, _>(RUN_VALUE)).is_ok()
}

#[cfg(windows)]
pub fn set(enabled: bool, exe: &Path) -> std::io::Result<()> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
    if enabled {
        key.set_value(RUN_VALUE, &run_command(exe))
    } else {
        match key.delete_value(RUN_VALUE) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// The `Run` value: the quoted path (Windows paths cannot contain `"`) and the flag.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn run_command(exe: &Path) -> String {
    format!("\"{}\" --background", exe.display())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn is_enabled() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn set(_enabled: bool, _exe: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("launch at login is not supported on this system"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_line_survives_awkward_paths() {
        assert_eq!(desktop_exec_quote("/opt/skwod-host/skwod-host"), "\"/opt/skwod-host/skwod-host\"");
        assert_eq!(desktop_exec_quote("/home/a b/$x/100%/q\"`\\"), "\"/home/a b/\\$x/100%%/q\\\"\\`\\\\\"");
        let entry = desktop_entry(Path::new("/opt/skwod-host/skwod-host"));
        assert!(entry.contains("\nExec=\"/opt/skwod-host/skwod-host\" --background\n"));
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert_eq!(run_command(Path::new(r"C:\Program Files\skwod host\skwod-host.exe")), "\"C:\\Program Files\\skwod host\\skwod-host.exe\" --background");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn toggling_writes_and_removes_the_autostart_entry() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY-free: tests in this module that touch the environment are the only ones doing so.
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        assert!(!is_enabled());
        set(true, Path::new("/opt/skwod-host/skwod-host")).unwrap();
        assert!(is_enabled());
        assert!(std::fs::read_to_string(dir.path().join("autostart/skwod-host.desktop")).unwrap().contains("--background"));
        set(false, Path::new("/x")).unwrap();
        set(false, Path::new("/x")).unwrap();
        assert!(!is_enabled());
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
