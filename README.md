# Exfil

A plugin-based DevSecOps engine for static analysis.

[![CI](https://github.com/Rangertaha/exfil/actions/workflows/ci.yml/badge.svg)](https://github.com/Rangertaha/exfil/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

exfil is a DevSecOps tool for static analysis across the whole delivery
surface — **application source code**, **infrastructure-as-code**, **operating
systems**, **container artifacts**, and more. It catches problems before they
ship: **privacy leaks**, **OPSEC violations**, **data leaks**, and **vulnerable
code** headed for deployment.

It walks a target in parallel, scans every file against security rulesets
(leaked credentials, dangerous code patterns, insecure configuration,
supply-chain compromise), and stores the results as a queryable **graph** —
files → findings → rules — in an embedded, pure-Rust database
([SurrealDB](https://surrealdb.com) on SurrealKV). Everything runs locally: no
network access is needed to analyze, and nothing leaves the machine — the same
property it helps you enforce on your own code.

## What it analyzes

- **Source code** — 17 languages parsed with tree-sitter (Python, JS/TS, C#,
  Rust, Go, C, C++, Java, Ruby, Dart, Bash, Lua, PowerShell, Swift, Kotlin,
  Groovy including `Jenkinsfile`s) for dangerous calls and taint flow, plus
  regex/secret scanning over any text file.
- **Infrastructure code** — Terraform/HCL, Dockerfiles, Kubernetes/YAML
  manifests, and other config formats scanned for hardcoded secrets and
  insecure directives.
- **Operating systems** — a local filesystem tree, or a remote host over
  SSH/SFTP (`exfil scan-remote user@host:/path`), walked and scanned in place.
- **Container & package artifacts** — zip/jar/war/tar/tar.gz/gz archives (image
  layers and build outputs included) are unpacked into virtual files that flow
  through the same scanners, depth- and size-capped against bombs.
- **Dependencies** — `package.json`, `requirements*.txt`, and `Cargo.toml`
  manifests checked for known-malicious packages, typosquats, and malicious
  install hooks.

## What it prevents

- **Privacy & data leaks** — regex/secret rules catch API keys, tokens,
  passwords-in-URLs, and other credentials before they land in a commit,
  image, or config; IOC/hash feeds flag known-bad content.
- **OPSEC violations** — hardcoded secrets, cleartext dependency sources, and
  insecure infrastructure directives are surfaced where they hide, in code and
  config alike.
- **Vulnerable code shipping to production** — tree-sitter AST analysis and
  taint tracking flag dangerous calls and attacker-controlled data flow, while
  ClamAV/YARA signatures and supply-chain checks catch malicious artifacts and
  dependencies.

## Highlights

- **Fast parallel scanning** — gitignore-aware walker fanned out across
  threads; every file is read once, blake3-hashed, and offered to each scanner.
- **Graph storage with provenance** — findings are records linked by real
  graph edges (`finding → in_file → file`, `scan → includes → file`), addressed
  by content hash for dedup, queryable with SurrealQL.
- **Mutt-style TUI** — `exfil tui` is a live workbench: run scans (with a
  progress gauge and findings streaming in), browse the index, open a finding
  in the pager with its file record, `/` to limit, `:` for commands.
- **Supply-chain compromise detection** — dependency manifests (`package.json`,
  `requirements*.txt`, `Cargo.toml`) are checked for known-malicious packages,
  typosquats (Damerau-Levenshtein against popular package names), malicious
  install hooks, and cleartext dependency sources.
- **Incremental rescans** — a stat fast-path (size + mtime) skips re-reading
  unchanged files; re-scanned files have their findings replaced, never
  duplicated.
- **Archive-aware** — zip/jar/war/tar/tar.gz/gz are unpacked into virtual files
  that flow through the same scanners (depth- and size-capped against bombs),
  each linked to its container in the graph, so a secret inside `dist.zip →
  app/.env` is found exactly as if it sat on disk.
- **Plugin DAG orchestration** — plugins are tasks declaring the artifact kinds
  they consume/produce (`Bytes → Ast → Matches`, `Bytes → Files`); a
  topological scheduler wires them by dependency, so new analyzers slot in
  without touching the engine. Run-level stages sequence fetch → scan → report.
- **Multiple report formats** — `exfil analyze --format text|json|markdown`
  renders the findings graph with severity tallies and a risk score.
- **AST-aware analysis** — Python and JavaScript are parsed with tree-sitter and
  checked for dangerous calls (`eval`, `os.system`, `child_process.exec`,
  `pickle.loads`, …) over the syntax tree, so the same word in a comment or
  string is not a false positive the way a regex would make it.
- **Taint analysis** — tracks untrusted input (`input()`, `request.args`,
  `process.argv`, env) through variable assignments into command/code-injection
  sinks, so `os.system(request.args['cmd'])` is flagged while `os.system('ls')`
  is not — the attacker-controlled flow, not just the dangerous call.
- **Datasets & IOC feeds** — `exfil pull <ref>` downloads rule/IOC datasets
  (builtin, local file, or `https://`) into a catalog; `exfil datasets`
  add/show/rm/list manages them. IOCs ride the same pipeline: content
  indicators are regex rules, file-hash indicators (`sha256:…`) match digests.
- **Malware signatures** — a pure-Rust ClamAV-signature scanner matches files
  against `.hdb`/`.hsb` hash signatures and literal `.ndb` body signatures
  (configured under `[plugins.clamav]`), no libclamav needed.
- **YARA** — pure-Rust `yara-x` matches files against YARA rules configured
  under `[plugins.yara]`, with severity/CWE read from each rule's `meta` block.
- **Remote scanning** — `exfil scan-remote user@host:/path` walks a host over
  SSH/SFTP (pure-Rust russh) and runs every scanner against its files, tagging
  findings with the remote host.
- **Plugin architecture** — scanners, dataset sources, and reporters are traits;
  regex, supply-chain, archive expansion, tree-sitter AST, taint, IOC, and
  ClamAV scanning ship today, YARA is planned (see the [roadmap](docs/PLAN.md)).
- **Single portable binary** — pure Rust, builds on Linux, macOS, and Windows.

## Install

```sh
# from a source checkout
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
(e.g. `~/.config/exfil/config.toml`). Each plugin has its own
`[plugins.<name>]` table:

```toml
store = ".exfil"

[plugins.regex]
datasets = []            # empty = built-in security ruleset

[plugins.ast]
languages = ["go", "python", "javascript", "rust"]
```

The findings store (default `.exfil/`, override with `--store`) is local to
the scanned project and removed by `exfil clean`; downloaded datasets live in
the config directory and survive cleaning.

## Workspace layout

| Crate | Purpose |
|---|---|
| `exfil-core` | shared domain types (rules, datasets, matches, findings, file metadata) — no I/O |
| `exfil-config` | TOML config with embedded default and per-plugin `[plugins.<name>]` tables |
| `exfil-scan` | `Scanner` trait and registry: regex/secret, supply-chain, archive, tree-sitter AST, taint, IOC, ClamAV, YARA |
| `exfil-task` | plugin DAG that turns one file's bytes into findings, AST, and expanded archive entries |
| `exfil-store` | embedded SurrealDB graph store (schema, upserts, queries) |
| `exfil-engine` | parallel walk → hash → scan → persist pipeline |
| `exfil-source` | dataset/IOC sources (`builtin://`, file, `https://`) |
| `exfil-remote` | remote scanning over SSH/SFTP (`RemoteFs` via pure-Rust russh) |
| `exfil-report` | pluggable reporters rendering the findings graph (text/json/markdown) |
| `exfil-view` | pluggable node viewers — the TUI's preview-pane layer |
| `exfil-llm` | finding enrichment: triage notes via the `Enricher` trait (rule-based default) |
| `exfil-script` | user scripting over findings via sandboxed Rhai |
| `exfil-mcp` | Model Context Protocol server exposing the findings graph to AI agents over stdio |
| `exfil-cli` | the `exfil` binary: CLI commands, progress UI, TUI |

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
