# exfil desktop app

A [Tauri](https://tauri.app) desktop dashboard over the exfil findings graph.
It **serves its own read-only HTTP API in-process** — there is no `exfil
server` command and no child process — and shows a findings dashboard that
fetches it. **Closing the window doesn't quit** — the window hides and the app
keeps running in the system tray with the API alive. Reopen it from the tray
icon; **Quit** in the tray menu stops the API and exits.

```
app/
├── ui/               # web frontend (plain HTML/CSS/JS, no build step)
└── src-tauri/        # Rust shell: serves the API, tray, window lifecycle
    ├── src/server.rs # the in-process HTTP API (/health, /stats, /findings)
    └── src/main.rs   # startup, tray, window lifecycle
```

This is a **standalone Cargo workspace** (note the empty `[workspace]` in
`src-tauri/Cargo.toml`), deliberately excluded from the parent workspace so the
main crates' `cargo build --workspace` and CI never pull in the Tauri toolchain.

## Prerequisites

- Rust, and the [Tauri system dependencies](https://tauri.app/start/prerequisites/)
  for your OS (on Linux: `webkit2gtk-4.1`, `libappindicator`, …).
- The Tauri CLI: `cargo install tauri-cli` (or `cargo binstall tauri-cli`).

No `exfil` binary is needed at runtime — the app links the store crates
directly. You will still want the CLI to *populate* a store to look at.

## Run (development)

From the `app/` directory:

```sh
cargo tauri dev

# …or point it at a specific findings store
EXFIL_STORE=/path/to/.exfil cargo tauri dev
```

The app binds `127.0.0.1:8080` itself; the dashboard polls `/health` until it's
up, then shows `/stats` and `/findings`. The filter box uses the same grammar
as `exfil search` (`severity=critical`, `path=…`, text).

It reads the store the CLI writes: `$EXFIL_STORE` if set, otherwise the default
store directory (the same one `exfil` uses, honouring a `[database]` override
in the config). Populate it first so there's data:

```sh
exfil scan
```

## Build (release)

```sh
cargo tauri build
```

Produces a platform bundle (`.deb`/`.AppImage`, `.dmg`, `.msi`) under
`src-tauri/target/release/bundle/`.

## Notes

- The API binds `127.0.0.1:8080`; the UI fetches that origin. `127.0.0.1` is
  a "potentially trustworthy" origin, so the webview may fetch it over HTTP.
- The API is read-only, so nothing here can modify the store.
- It serves `/health`, `/stats` and `/findings` — exactly what the dashboard
  uses. It is bound to loopback and not intended as a general-purpose API.
