# Exfil

***EX**amine **F**iles, **I**nfrastructure & **L**ibraries* — a plugin-based DevSecOps engine for static analysis.

[![CI](https://github.com/Rangertaha/exfil/actions/workflows/ci.yml/badge.svg)](https://github.com/Rangertaha/exfil/actions/workflows/ci.yml)
[![Docs](https://github.com/Rangertaha/exfil/actions/workflows/docs.yml/badge.svg)](https://rangertaha.github.io/exfil/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

exfil is an offline, plugin-based DevSecOps engine that scans your whole
delivery surface for security problems and files every finding into a queryable
graph — so you catch leaked secrets, vulnerable code, and risky configuration
before they ship, with nothing leaving your machine.

```mermaid
flowchart LR
    T["Targets<br/>code · config · deps<br/>hosts · web"] --> S["Scan<br/>walk · parse · render"]
    S --> M["Match<br/>secrets · taint · IOCs<br/>YARA · PII · supply-chain"]
    M --> G[("Findings graph<br/>SurrealDB")]
    G --> R["Report<br/>search · TUI · reports<br/>HTTP · GraphQL · MCP"]
```

**What it scans**

- **Code** — 17 languages via tree-sitter (dangerous calls + taint flow), plus secret/regex rules over any text
- **Infrastructure & config** — Terraform/HCL, Dockerfiles, Kubernetes/YAML
- **Dependencies** — `package.json`, `requirements*.txt`, `Cargo.toml`
- **Archives & container layers** — zip/jar/war/tar/tar.gz/gz, unpacked and scanned in place
- **Hosts** — the local filesystem, remote hosts over SSH, and running processes
- **Web & network** — crawled sites (incl. JavaScript-rendered pages via WebDriver) and TCP service banners

**What it finds** — leaked credentials, code-injection flows, supply-chain
risks (malicious & typosquatted dependencies), malware signatures (YARA ·
ClamAV), IOCs (bad domains/IPs/hashes), and PII. Findings land in an embedded
graph DB (or a remote cluster) you can query, browse in a TUI, or serve over
HTTP/GraphQL.

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

The docs are built with [mdBook](https://rust-lang.github.io/mdBook/) plus
[mdbook-mermaid](https://github.com/badboy/mdbook-mermaid) (for the diagrams),
from [`docs/`](docs/). To preview locally:

```sh
mdbook-mermaid install docs   # vendor the mermaid assets once
mdbook serve docs
```

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
