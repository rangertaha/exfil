# Exfil

A plugin-based DevSecOps engine for static analysis.

[![CI](https://github.com/Rangertaha/exfil/actions/workflows/ci.yml/badge.svg)](https://github.com/Rangertaha/exfil/actions/workflows/ci.yml)
[![Docs](https://github.com/Rangertaha/exfil/actions/workflows/docs.yml/badge.svg)](https://rangertaha.github.io/exfil/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

exfil runs static analysis across the whole delivery surface — source code,
infrastructure-as-code, operating systems, and container artifacts — to catch
**privacy leaks**, **OPSEC violations**, **data leaks**, and **vulnerable code**
before they ship. It scans locally, stores findings in an embedded graph
database, and needs no network access to analyze.

📖 **Full documentation: <https://rangertaha.github.io/exfil/>**

## Install

exfil is a single portable binary — pure Rust, building on Linux, macOS, and
Windows.

```sh
# install onto your PATH from a source checkout
cargo install --path crates/exfil-cli

# or just build it
cargo build --release   # binary at target/release/exfil
```

## Quick start

```sh
# scan the current directory (streams matches; progress bar on a terminal)
exfil scan

# query stored findings
exfil search                      # everything
exfil search severity=critical    # by field: rule/cwe/severity/path
exfil search aws                  # free text against rule names

# open the live TUI (mutt-style index + pager)
exfil tui

# look at one record, list rules, clean up
exfil get file:<blake3-hash>
exfil rules
exfil clean
```

Example scan output (severity is color-coded on a terminal):

```text
./.env:1:26 CRIT [aws-access-key-id] export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF
./src/config.toml:1:7 HIGH [password-in-url] db = "postgres://admin:hunter2@db.internal/prod"
scanned 3 files (0 unchanged): 2 new matches, 0 unreadable
```

## Common commands

| Command | What it does |
|---|---|
| `exfil scan [path]` | Scan a directory tree for secrets and security issues |
| `exfil scan-remote [user@]host:/path` | Scan a remote host over SSH/SFTP |
| `exfil search [query]` | Query stored findings (by field or free text) |
| `exfil analyze` | Render a report of the graph (`--format text\|json\|markdown`) |
| `exfil tui` | Open the mutt-style TUI to scan and browse live |
| `exfil pull [ref]` | Download rule/IOC datasets into the catalog |
| `exfil rules` | Show the rules a scan would apply |
| `exfil clean` | Delete the findings store (keeps downloaded datasets) |

The [full command reference](https://rangertaha.github.io/exfil/guide/commands.html)
covers remote, process, network, correlation, and MCP commands. Run
`exfil <command> --help` for a command's own flags.

## Configuration

The first run writes a default TOML config to the user config directory
(e.g. `~/.config/exfil/config.toml`); `exfil config` shows the resolved path
and contents. Each plugin has its own `[plugins.<name>]` table:

```toml
store = ".exfil"

[plugins.regex]
datasets = []            # empty = built-in security ruleset

[plugins.ast]
languages = ["go", "python", "javascript", "rust"]
```

The findings store (default `.exfil/`, override with `--store`) is local to the
scanned project and removed by `exfil clean`; downloaded datasets live in the
config directory and survive cleaning. See the
[Configuration guide](https://rangertaha.github.io/exfil/guide/configuration.html)
for details.

## Documentation

The full docs live at **<https://rangertaha.github.io/exfil/>**:

- [What exfil analyzes](https://rangertaha.github.io/exfil/guide/surfaces.html)
  and the full [feature list](https://rangertaha.github.io/exfil/guide/features.html)
- The [command reference](https://rangertaha.github.io/exfil/guide/commands.html),
  [TUI keys](https://rangertaha.github.io/exfil/guide/tui.html), and
  [configuration](https://rangertaha.github.io/exfil/guide/configuration.html)
- The [architecture guide](https://rangertaha.github.io/exfil/architecture/) — a
  multi-page tour of how exfil is built, written for readers new to Rust

The docs are built with [mdBook](https://rust-lang.github.io/mdBook/) from
[`docs/`](docs/); to preview locally, run `mdbook serve docs`.

## Development

```sh
cargo test --workspace                    # run all tests
cargo fmt --all && cargo clippy --workspace --all-targets  # lint
cargo llvm-cov --workspace                # coverage report
```

The code is deliberately documentation-heavy — each crate's docs include
*Rust notes* explaining the language idioms it uses, aimed at readers new to
Rust.

## License

[MIT](LICENSE)
