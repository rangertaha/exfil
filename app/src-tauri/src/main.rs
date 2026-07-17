//! exfil desktop app.
//!
//! On launch it spawns the `exfil server` HTTP API as a child process and shows
//! a window whose web UI talks to that server. Closing the window does not quit:
//! the window is hidden and the app (and the server) keep running from a system
//! tray icon. "Quit" in the tray menu stops the server and exits.
//!
//! The `exfil` binary is found on `PATH`; override with the `EXFIL_BIN`
//! environment variable. The server binds `127.0.0.1:8080`, which the web UI
//! (see `../ui/app.js`) fetches.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command};
use std::sync::Mutex;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Manager, RunEvent, WindowEvent,
};

/// The spawned `exfil server` child, killed when the app really exits.
struct ServerProcess(Mutex<Option<Child>>);

/// The address the server binds and the web UI connects to.
const SERVER_ADDR: &str = "127.0.0.1:8080";

/// Start `exfil server`. Returns `None` (and logs) if the binary can't be run,
/// so the app still opens — the UI then shows a "disconnected" state.
fn spawn_server() -> Option<Child> {
    let bin = std::env::var("EXFIL_BIN").unwrap_or_else(|_| "exfil".to_string());
    match Command::new(&bin)
        .args(["server", "--addr", SERVER_ADDR])
        .spawn()
    {
        Ok(child) => {
            eprintln!("[app] started '{bin} server --addr {SERVER_ADDR}'");
            Some(child)
        }
        Err(e) => {
            eprintln!(
                "[app] could not start '{bin} server': {e}\n\
                 [app] install exfil (cargo install --path crates/exfil-cli) or set EXFIL_BIN"
            );
            None
        }
    }
}

/// Kill the server child if it's still running.
fn stop_server(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<ServerProcess>() {
        if let Some(mut child) = state.0.lock().unwrap().take() {
            let _ = child.kill();
        }
    }
}

/// Reveal and focus the main window (from the tray).
fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn main() {
    tauri::Builder::default()
        .manage(ServerProcess(Mutex::new(spawn_server())))
        .setup(|app| {
            // Tray icon with an Open/Quit menu, so the app is reachable after
            // its window is closed.
            let open = MenuItem::with_id(app, "open", "Open exfil", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("exfil — server running")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "quit" => {
                        stop_server(app);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // A plain click on the tray icon reopens the window.
                    if matches!(event, TrayIconEvent::Click { .. }) {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it instead of quitting; the server keeps
            // running and the app stays in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the exfil desktop app")
        .run(|app, event| {
            // Make sure the server child dies with the app however it exits.
            if let RunEvent::ExitRequested { .. } = event {
                stop_server(app);
            }
        });
}
