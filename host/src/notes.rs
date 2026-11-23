//! The one thing a first-time host should be told before the operating system asks: the
//! firewall question. Shown once (a marker file in the data directory remembers).

use std::path::Path;

const MARKER: &str = "first-run-note-shown";

#[cfg(windows)]
pub const FIREWALL_NOTE: &str = "Welcome to Skwod.\n\nWhen you press \"Start server\", Windows may ask whether \"skwod\" may communicate on your networks. Choose Allow (Private networks is enough): it lets your friends connect straight to this PC.\n\nIf you choose Cancel, skwod still works — connections then go through a relay, which is slower. You can change this later in Windows Security > Firewall & network protection > Allow an app through firewall.\n\nNothing else to set up: no account, no domain, no port forwarding.";

#[cfg(not(windows))]
pub const FIREWALL_NOTE: &str = "Welcome to Skwod.\n\nYour friends connect straight to this computer when they can, and through a relay when they cannot. If this computer runs a firewall (ufw, firewalld), nothing has to be opened for skwod to work; allowing incoming UDP for \"skwod\" only makes direct connections more likely.\n\nNothing else to set up: no account, no domain, no port forwarding.";

/// `true` the first time it is called for this data directory.
pub fn first_run(data: &Path) -> bool {
    let marker = data.join(MARKER);
    if marker.exists() {
        return false;
    }
    std::fs::write(&marker, b"").is_ok()
}

/// A plain native message box. Call from the UI thread.
#[cfg(target_os = "linux")]
pub fn show_dialog(title: &str, text: &str) {
    use gtk::prelude::*;
    let dialog = gtk::MessageDialog::new(None::<&gtk::Window>, gtk::DialogFlags::MODAL, gtk::MessageType::Info, gtk::ButtonsType::Ok, text);
    dialog.set_title(title);
    dialog.run();
    dialog.close();
}

#[cfg(windows)]
pub fn show_dialog(title: &str, text: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (text, title) = (wide(text), wide(title));
    // SAFETY: both pointers are valid, NUL-terminated UTF-16 buffers that outlive the call; a
    // null owner window is allowed.
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONINFORMATION);
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn show_dialog(title: &str, text: &str) {
    println!("{title}\n\n{text}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_note_is_shown_once_per_data_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(super::first_run(dir.path()));
        assert!(!super::first_run(dir.path()));
        assert!(super::FIREWALL_NOTE.contains("relay"));
    }
}
