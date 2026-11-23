//! The tray icon and its menu: Open admin page · Start server · Stop server · Launch at login ·
//! Quit. Every slow action (HTTP to the server, starting it, quitting) runs off the UI thread
//! and reports back through the event loop.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::admin::Phase;
use crate::server::Controller;

const ICON_RGBA: &[u8] = include_bytes!("../assets/icon-32.rgba");

#[derive(Debug)]
enum UserEvent {
    Menu(MenuEvent),
    /// `None`: the server process is not running.
    Phase(Option<Phase>),
    Problem(String),
    Exit,
}

pub struct Options {
    pub exe: PathBuf,
    pub open_page: bool,
    pub first_run_note: Option<&'static str>,
}

struct Items {
    status: MenuItem,
    open: MenuItem,
    start: MenuItem,
    stop: MenuItem,
    autostart: CheckMenuItem,
    quit: MenuItem,
}

fn status_text(phase: Option<Phase>) -> &'static str {
    match phase {
        Some(Phase::Running) => "Skwod server: running",
        Some(Phase::Starting) => "Skwod server: starting…",
        Some(Phase::Stopped) => "Skwod server: stopped",
        None => "Skwod server: not running",
    }
}

/// Run `work` on its own thread with the controller; a failure becomes a `Problem` event.
fn background(ctl: &Arc<Mutex<Controller>>, proxy: &EventLoopProxy<UserEvent>, work: impl FnOnce(&mut Controller) -> std::io::Result<()> + Send + 'static) {
    let (ctl, proxy) = (ctl.clone(), proxy.clone());
    std::thread::spawn(move || {
        let mut guard = ctl.lock().unwrap_or_else(|e| e.into_inner());
        let result = work(&mut guard);
        let phase = guard.phase();
        drop(guard);
        if let Err(e) = result {
            let _ = proxy.send_event(UserEvent::Problem(e.to_string()));
        }
        let _ = proxy.send_event(UserEvent::Phase(phase));
    });
}


pub fn run(ctl: Arc<Mutex<Controller>>, opts: Options, interrupted: Arc<std::sync::atomic::AtomicBool>) -> ! {
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    {
        let proxy = proxy.clone();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::Menu(event));
        }));
    }
    // Keeps the menu in step with the server (which the admin page can also start and stop),
    // and turns Ctrl-C / a session logout into a clean quit.
    {
        let (ctl, proxy) = (ctl.clone(), proxy.clone());
        std::thread::spawn(move || loop {
            if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
                ctl.lock().unwrap_or_else(|e| e.into_inner()).quit();
                let _ = proxy.send_event(UserEvent::Exit);
                return;
            }
            let phase = ctl.lock().unwrap_or_else(|e| e.into_inner()).phase();
            if proxy.send_event(UserEvent::Phase(phase)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_secs(2));
        });
    }

    let mut tray: Option<(TrayIcon, Items)> = None;
    let mut first_run_note = opts.first_run_note;
    let mut quitting = false;
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            // The tray must be created once the loop runs (GTK / the Win32 message pump exist).
            Event::NewEvents(StartCause::Init) => {
                let items = Items {
                    status: MenuItem::new(status_text(None), false, None),
                    open: MenuItem::new("Open admin page", true, None),
                    start: MenuItem::new("Start server", true, None),
                    stop: MenuItem::new("Stop server", false, None),
                    autostart: CheckMenuItem::new("Launch at login", true, crate::autostart::is_enabled(), None),
                    quit: MenuItem::new("Quit Skwod host", true, None),
                };
                let menu = Menu::new();
                let built = menu
                    .append_items(&[
                        &items.status,
                        &PredefinedMenuItem::separator(),
                        &items.open,
                        &items.start,
                        &items.stop,
                        &PredefinedMenuItem::separator(),
                        &items.autostart,
                        &PredefinedMenuItem::separator(),
                        &items.quit,
                    ])
                    .map_err(|e| e.to_string())
                    .and_then(|_| Icon::from_rgba(ICON_RGBA.to_vec(), 32, 32).map_err(|e| e.to_string()))
                    .and_then(|icon| TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip("Skwod host").with_icon(icon).build().map_err(|e| e.to_string()));
                match built {
                    Ok(icon) => tray = Some((icon, items)),
                    // No tray on this desktop (some need an extension): the server and its
                    // page still work, so keep going and say where the page is.
                    Err(e) => eprintln!("skwod host: no tray icon on this desktop ({e}). The admin page still works."),
                }
                if let Some(note) = first_run_note.take() {
                    crate::notes::show_dialog("Skwod host", note);
                }
                if opts.open_page {
                    background(&ctl, &proxy, Controller::open_page);
                }
            }
            Event::UserEvent(UserEvent::Phase(phase)) => {
                if let Some((_, items)) = &tray {
                    items.status.set_text(status_text(phase));
                    items.start.set_enabled(!quitting && !matches!(phase, Some(Phase::Running | Phase::Starting)));
                    items.stop.set_enabled(!quitting && matches!(phase, Some(Phase::Running | Phase::Starting)));
                }
            }
            Event::UserEvent(UserEvent::Problem(text)) => {
                eprintln!("skwod host: {text}");
                if let Some((_, items)) = &tray {
                    let line = text.lines().next().unwrap_or_default();
                    items.status.set_text(format!("Problem: {line}"));
                }
            }
            Event::UserEvent(UserEvent::Menu(event)) => {
                let Some((_, items)) = &tray else { return };
                if quitting {
                    return;
                }
                if event.id == *items.open.id() {
                    background(&ctl, &proxy, Controller::open_page);
                } else if event.id == *items.start.id() {
                    items.start.set_enabled(false);
                    items.status.set_text(status_text(Some(Phase::Starting)));
                    background(&ctl, &proxy, Controller::start);
                } else if event.id == *items.stop.id() {
                    items.stop.set_enabled(false);
                    background(&ctl, &proxy, Controller::stop);
                } else if event.id == *items.autostart.id() {
                    // The click already flipped the check mark; make the system match it.
                    let want = items.autostart.is_checked();
                    if let Err(e) = crate::autostart::set(want, &opts.exe) {
                        items.autostart.set_checked(!want);
                        let _ = proxy.send_event(UserEvent::Problem(format!("could not change launch at login: {e}")));
                    }
                } else if event.id == *items.quit.id() {
                    quitting = true;
                    items.status.set_text("Skwod server: stopping…");
                    for item in [&items.open, &items.start, &items.stop, &items.quit] {
                        item.set_enabled(false);
                    }
                    let (ctl, proxy) = (ctl.clone(), proxy.clone());
                    std::thread::spawn(move || {
                        ctl.lock().unwrap_or_else(|e| e.into_inner()).quit();
                        let _ = proxy.send_event(UserEvent::Exit);
                    });
                }
            }
            Event::UserEvent(UserEvent::Exit) => {
                tray = None; // removes the icon
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    })
}
