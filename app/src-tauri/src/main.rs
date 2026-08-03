//! exfil desktop app.
//!
//! On launch it starts its own findings API (see [`server`]) on a background
//! thread and shows a window whose web UI fetches it. Closing the window does
//! not quit: the window is hidden and the app keeps running from a system tray
//! icon. "Quit" in the tray menu stops the API and exits.
//!
//! The API runs *in process* — there is no `exfil server` command and no child
//! process. It reads the same findings store the CLI writes: the default store
//! directory, or `EXFIL_STORE` if set. It binds `127.0.0.1:8080`, which the web
//! UI (see `../ui/app.js`) fetches.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod server;

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Manager, RunEvent, WindowEvent,
};

/// Handle on the running API: sending on it asks the server to shut down.
struct ServerHandle(Mutex<Option<tokio::sync::oneshot::Sender<()>>>);

/// The address the API binds and the web UI connects to.
const SERVER_ADDR: &str = "127.0.0.1:8080";

/// The findings store to serve: `EXFIL_STORE` if set, else the same default
/// directory the CLI writes to, so the dashboard shows what `exfil scan` found.
fn store_dir() -> PathBuf {
    match std::env::var_os("EXFIL_STORE") {
        Some(dir) => PathBuf::from(dir),
        None => exfil_config::default_store_dir(),
    }
}

/// Start the findings API on its own runtime thread. Returns the shutdown
/// sender, or `None` (and logs) if the store or listener can't be opened — the
/// app still opens, and the UI then shows a "disconnected" state.
fn start_server() -> Option<tokio::sync::oneshot::Sender<()>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("[app] could not start the async runtime: {e}");
            return None;
        }
    };

    let dir = store_dir();
    // Opening the store and binding both have to happen on the runtime, but the
    // app needs to know whether they succeeded before it decides what to log —
    // so do them synchronously here and only then hand the loop to a thread.
    let started = runtime.block_on(async {
        let store = exfil_engine::setup::open_findings(&dir, None).await?;
        let listener = tokio::net::TcpListener::bind(SERVER_ADDR).await?;
        anyhow::Ok((store, listener))
    });
    let (store, listener) = match started {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[app] could not serve {}: {e:#}", dir.display());
            return None;
        }
    };

    eprintln!("[app] serving findings from {}", dir.display());
    std::thread::spawn(move || {
        runtime.block_on(async move {
            let shutdown = async move {
                let _ = rx.await;
            };
            if let Err(e) = server::serve(listener, store, shutdown).await {
                eprintln!("[app] findings API stopped: {e:#}");
            }
        });
    });
    Some(tx)
}

/// Ask the API to shut down, if it is still running.
fn stop_server(app: &tauri::AppHandle) {
    if let Some(state) = app.try_state::<ServerHandle>() {
        if let Some(tx) = state.0.lock().unwrap().take() {
            let _ = tx.send(());
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
        .manage(ServerHandle(Mutex::new(start_server())))
        .setup(|app| {
            // Tray icon with an Open/Quit menu, so the app is reachable after
            // its window is closed.
            let open = MenuItem::with_id(app, "open", "Open exfil", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("exfil — findings API running")
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
            // Closing the window hides it instead of quitting; the API keeps
            // running and the app stays in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the exfil desktop app")
        .run(|app, event| {
            // Make sure the API stops with the app however it exits.
            if let RunEvent::ExitRequested { .. } = event {
                stop_server(app);
            }
        });
}
