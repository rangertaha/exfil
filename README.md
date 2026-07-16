# exfill

> **Ex**tra **Fi**le **L**ang **L**ookup — an offline, cross-platform,
> plugin-based filesystem analysis and SAST engine.

[![CI](https://github.com/Rangertaha/exfill/actions/workflows/ci.yml/badge.svg)](https://github.com/Rangertaha/exfill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

exfill walks a directory tree in parallel, scans every file against security
rulesets (leaked credentials, dangerous patterns), and stores the results as a
queryable **graph** — files → findings → rules — in an embedded, pure-Rust
database ([SurrealDB](https://surrealdb.com) on SurrealKV). Everything runs
locally: no network access is needed to analyze, and nothing leaves the
machine.

## Highlights

- **Fast parallel scanning** — gitignore-aware walker fanned out across
  threads; every file is read once, blake3-hashed, and offered to each scanner.
- **Graph storage with provenance** — findings are records linked by real
  graph edges (`finding → in_file → file`, `scan → includes → file`), addressed
  by content hash for dedup, queryable with SurrealQL.
- **Mutt-style TUI** — `exfill tui` is a live workbench: run scans (with a
  progress gauge and findings streaming in), browse the index, open a finding
  in the pager with its file record, `/` to limit, `:` for commands.
- **Plugin architecture** — scanners, dataset sources, and reporters are traits
  behind registries; regex scanning ships today, tree-sitter AST, YARA, and
  taint analysis are planned (see the [roadmap](docs/PLAN.md)).
- **Single portable binary** — pure Rust, builds on Linux, macOS, and Windows.

## Install

```sh
# from a source checkout
cargo install --path crates/exfill-cli

# or just build it
cargo build --release   # binary at target/release/exfill
```

## Quick start

```sh
# scan the current directory (streams matches; progress bar on a terminal)
exfill scan

# query stored findings
exfill search                      # everything
exfill search severity=critical    # by field: rule/cwe/severity/path
exfill search aws                  # free text against rule names

# open the live TUI (mutt-style index + pager)
exfill tui

# look at one record, list rules, clean up
exfill get file:<blake3-hash>
exfill rules
exfill clean
```

Example scan output:

```text
./.env:1:26 [aws-access-key-id] export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF
./src/config.toml:1:7 [password-in-url] db = "postgres://admin:hunter2@db.internal/prod"
scanned 3 files: 2 matches, 0 unreadable
```

## TUI keys

| Key | Action |
|---|---|
| `j`/`k`, arrows | move through the findings index |
| `Enter` | open the finding in the pager (with its file record) |
| `/` | limit (filter) the index, mutt-style |
| `:` | command bar: `scan [path]`, `rules`, `get <id>`, `clean`, `quit` |
| `s` | scan the current directory |
| `r` | reload findings from the store |
| `q` | quit (or leave the pager) |

## Configuration

The first run writes a default TOML config to the user config directory
(e.g. `~/.config/exfill/config.toml`). Each plugin has its own
`[plugins.<name>]` table:

```toml
store = ".exfill"

[plugins.regex]
datasets = []            # empty = built-in security ruleset

[plugins.ast]
languages = ["go", "python", "javascript", "rust"]
```

The findings store (default `.exfill/`, override with `--store`) is local to
the scanned project and removed by `exfill clean`; downloaded datasets live in
the config directory and survive cleaning.

## Workspace layout

| Crate | Purpose |
|---|---|
| `exfill-core` | shared domain types (rules, matches, file metadata) |
| `exfill-config` | TOML config with embedded default |
| `exfill-scan` | `Scanner` trait, registry, regex scanner, builtin ruleset |
| `exfill-store` | embedded SurrealDB graph store (schema, upserts, queries) |
| `exfill-engine` | parallel walk → hash → scan → persist pipeline |
| `exfill-cli` | the `exfill` binary: CLI commands, progress UI, TUI |

The full architecture, data model, and milestone plan live in
[docs/PLAN.md](docs/PLAN.md).

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
