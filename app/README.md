# exfil desktop app

A [Tauri](https://tauri.app) desktop wrapper around **`exfil server`**. On
launch it starts the exfil HTTP API as a child process and shows a findings
dashboard that talks to it. **Closing the window doesn't quit** — the window
hides and the app keeps running in the system tray with the server alive.
Reopen it from the tray icon; **Quit** in the tray menu stops the server and
exits.

```
app/
├── ui/               # web frontend (plain HTML/CSS/JS, no build step)
└── src-tauri/        # Rust shell: spawns the server, tray, window lifecycle
```

This is a **standalone Cargo workspace** (note the empty `[workspace]` in
`src-tauri/Cargo.toml`), deliberately excluded from the parent workspace so the
main crates' `cargo build --workspace` and CI never pull in the Tauri toolchain.

## Prerequisites

- Rust, and the [Tauri system dependencies](https://tauri.app/start/prerequisites/)
  for your OS (on Linux: `webkit2gtk-4.1`, `libappindicator`, …).
- The Tauri CLI: `cargo install tauri-cli` (or `cargo binstall tauri-cli`).
- The `exfil` binary reachable on `PATH`, or point `EXFIL_BIN` at it.

Build the CLI from the repo root first:

```sh
cargo build -p exfil-cli          # produces target/debug/exfil
```

## Run (development)

From the `app/` directory:

```sh
# point the app at the freshly built CLI binary
EXFIL_BIN=../target/debug/exfil cargo tauri dev
```

The app spawns `exfil server --addr 127.0.0.1:8080`; the dashboard polls
`/health` until it's up, then shows `/stats` and `/findings`. The filter box
uses the same grammar as `exfil search` (`severity=critical`, `path=…`, text).

Populate the store first (in the directory the app runs from) so there's data:

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

- The server binds `127.0.0.1:8080`; the UI fetches that origin. `127.0.0.1` is
  a "potentially trustworthy" origin, so the webview may fetch it over HTTP.
- The API is read-only, so nothing here can modify the store.
- To bundle the `exfil` binary with the app instead of relying on `PATH`, wire
  it up as a [Tauri sidecar](https://tauri.app/develop/sidecar/) and spawn it
  via the shell plugin — left out here to keep the scaffold minimal.
