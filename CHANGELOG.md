# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cargo workspace with six crates: `exfill-core`, `exfill-config`,
  `exfill-scan`, `exfill-store`, `exfill-engine`, `exfill-cli`.
- Embedded SurrealDB (SurrealKV) graph store: file/finding/rule/scan tables,
  relation edges, content-hash record ids, search/get APIs.
- Parallel, gitignore-aware scan engine: blake3 hashing, binary detection,
  live `ScanEvent` progress streaming, store-directory exclusion.
- Regex scanner with a built-in security ruleset (AWS keys, private keys,
  GitHub/Slack tokens, hard-coded secrets, credentials in URLs).
- Supply-chain scanner over dependency manifests: known-malicious packages,
  typosquat detection, npm install-hook analysis, insecure (http) sources.
- Incremental rescans: stat fast-path skips unchanged files; findings are
  replaced on rescan instead of duplicated.
- Plugin orchestration DAG (`exfill-task`): typed artifacts, `FileTask`
  needs/provides, topologically-sorted `Pipeline` with cycle/missing-producer
  detection. Scanners migrated onto it.
- Archive expansion: `archive-expand` task unpacks zip/jar/war/tar/tar.gz/gz
  into virtual files that flow through the pipeline (depth- and size-capped),
  linked to their container by a `contained_in` graph edge.
- Reporters (`exfill-report`): text, json, and markdown; `exfill analyze
  [query] --format <fmt>` renders the findings graph.
- Run-level orchestration (`exfill-engine::run`): `RunStage` sequence
  fetch → scan → report sharing the graph through `RunCtx`.
- Tree-sitter AST scanning (`exfill-scan::ast`): `AstExtractor` (Bytes→Ast)
  parses Python and JavaScript; `DangerousCallScanner` (Ast→Matches) flags
  dangerous sinks (eval/exec/os.system/subprocess/child_process.exec/
  pickle.loads/yaml.load) from the parse tree, so words in comments and
  strings are not false-positives. ASTs are persisted with a `has_ast` edge.
- Taint analysis (`exfill-scan::taint`): `TaintScanner` (Ast→Matches) tracks
  untrusted input (input/request.*/getenv/os.environ/process.argv/env) through
  variable assignments into command/code-injection sinks, flagging only flows
  that are actually attacker-controlled. The AST is enriched with call and
  assignment facts so taint reuses the extractor's parse.

### Changed

- Folded `exfill update` into `exfill pull`: `pull <ref>` fetches one dataset,
  `pull` (no argument) fetches every configured `[[update]]`.
- CLI commands: `scan`, `search`, `get`, `rules`, `config`, `clean`, `tui`.
- Ratatui progress gauge for `scan` (plain line output when piped).
- Mutt-style `exfill tui`: findings index + pager, `/` limit, `:` commands,
  live scans with streaming results.
- TOML configuration with an embedded default written on first run.
- CI (fmt, clippy, tests on Linux/macOS/Windows) and tag-driven release
  workflow building binaries for all three platforms.
- Dataset sources & catalog (`exfill-source`): builtin/file/http(s) sources;
  `pull`/`sources`/`datasets` (list/add/show/rm); scans apply catalog rules.
- IOC feeds: content indicators as regex rules, file-hash indicators via a
  hash scanner (`sha256:…` rule patterns); an IOC feed is just a dataset.
- ClamAV-style scanning (`exfill-scan::clamav`): pure-Rust matcher for hash
  signatures (.hdb/.hsb) and literal body signatures (.ndb) via Aho–Corasick,
  loaded from `[plugins.clamav]`.
- Remote scanning over SSH/SFTP (`exfill-remote`, pure-Rust russh):
  `exfill scan-remote user@host:/path` walks a host and runs the full
  pipeline on its files (RemoteFs trait + engine::scan_remote).
- YARA scanning (`exfill-scan::yara`): pure-Rust yara-x matcher; rules from
  `[plugins.yara]`, severity/CWE read from each rule's meta block.
- `gc`: prune superseded scans and unreachable file/finding/ast records
  (keeps the latest scan). `graph [query] --format json|dot`: emit the
  finding→file/rule graph. Scan timestamps switched to milliseconds so
  scan ordering is unambiguous.
- Pluggable viewers (`exfill-view`): a Viewer trait + Registry keyed by node
  kind (finding/file/ast/rule + JSON fallback) — the "preview per node type"
  foundation for graph navigation. Wired into the TUI pager.
- Graph navigator in the TUI (M1): Enter opens a two-pane edge-following
  navigator — node view (via pluggable viewers) beside its neighbors — with
  vim motions (j/k, h/l panes, Enter follows an edge), a jumplist (</>) and a
  breadcrumb trail. Backed by Store::neighbors (typed-edge traversal).
- Graph editing in the navigator (M2 CRUD): `c` edits a node field
  (field=value), `d` deletes an edge, `u`/`U` undo/redo. Backed by
  Store::set_field / create_edge / delete_edge with a reversible EditOp
  undo stack.
- Configurable navigator keymap (M4): keys decoupled from actions via a
  Keymap; vim defaults, remappable in `[keymap.nav]` (key = "Action").
