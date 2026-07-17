# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cargo workspace with six crates: `exfil-core`, `exfil-config`,
  `exfil-scan`, `exfil-store`, `exfil-engine`, `exfil-cli`.
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
- Plugin orchestration DAG (`exfil-task`): typed artifacts, `FileTask`
  needs/provides, topologically-sorted `Pipeline` with cycle/missing-producer
  detection. Scanners migrated onto it.
- Archive expansion: `archive-expand` task unpacks zip/jar/war/tar/tar.gz/gz
  into virtual files that flow through the pipeline (depth- and size-capped),
  linked to their container by a `contained_in` graph edge.
- Reporters (`exfil-report`): text, json, and markdown; `exfil analyze
  [query] --format <fmt>` renders the findings graph.
- Run-level orchestration (`exfil-engine::run`): `RunStage` sequence
  fetch → scan → report sharing the graph through `RunCtx`.
- Tree-sitter AST scanning (`exfil-scan::ast`): `AstExtractor` (Bytes→Ast)
  parses Python and JavaScript; `DangerousCallScanner` (Ast→Matches) flags
  dangerous sinks (eval/exec/os.system/subprocess/child_process.exec/
  pickle.loads/yaml.load) from the parse tree, so words in comments and
  strings are not false-positives. ASTs are persisted with a `has_ast` edge.
- Taint analysis (`exfil-scan::taint`): `TaintScanner` (Ast→Matches) tracks
  untrusted input (input/request.*/getenv/os.environ/process.argv/env) through
  variable assignments into command/code-injection sinks, flagging only flows
  that are actually attacker-controlled. The AST is enriched with call and
  assignment facts so taint reuses the extractor's parse.
- CLI/TUI usability: `exfil --help` now carries a worked Examples block and a
  bare `exfil` prints it instead of a usage error; `scan`/`search` print
  next-step hints (TTY-only) and a severity tally.
- Severity is shown in finding lines (`CRIT`/`HIGH`/…) across scan, search,
  and the text report, color-coded on a terminal with `--color
  auto|always|never` and `NO_COLOR` honored.
- `exfil scan --fail-on <severity>` gates CI by exiting non-zero when a
  finding reaches the threshold.
- `exfil completions <shell>` emits bash/zsh/fish/powershell/elvish
  completion scripts.
- `exfil rules [filter]` filters the ruleset by substring and prints a count;
  `clean` now confirms before deleting (with `-y` to skip).
- TUI: findings index color-coded by severity, a `?` help overlay, a titled
  pager, onboarding guidance on an empty index, and `Esc` to clear a limit.
- `exfil server` — a long-lived, read-only HTTP API over the findings graph
  (hand-rolled over `tokio::net`, no web framework): REST routes `/health`,
  `/findings[?q=…]`, `/rules`, `/stats`, plus a GraphQL endpoint at
  `POST /graphql` with a GraphiQL IDE at `GET /graphql`. Binds `127.0.0.1:8080`
  by default; shuts down gracefully on Ctrl-C / SIGTERM.
- Desktop app (`app/`) — a Tauri wrapper that runs `exfil server` and shows a
  findings dashboard; closing the window keeps the app and server alive in the
  system tray. A standalone workspace, excluded from the main build/CI.
- MITRE CWE enrichment: `exfil pull mitre://cwe` downloads the official CWE
  catalog into a local `cwe` table; `exfil enrich` annotates findings with the
  authoritative CWE name; `exfil cwe <id>` looks a weakness up. Offline after
  the pull; reference data, kept out of the detection rules. (CVE/CPE planned.)
- Configurable database engine: the store uses SurrealDB's `engine::any`, so a
  connection endpoint selects embedded (`surrealkv://`/`mem://`) or a remote
  server / cluster (`ws(s)://`, `http(s)://`) with root sign-in.
- WebDriver crawling: `exfil scan-web --driver <url>` renders pages in a
  headless browser (geckodriver/chromedriver) to traverse JavaScript-heavy,
  dynamic sites — content a plain HTTP crawl misses.
- URL feed catalog (`exfil feeds`): manage a catalog of feed URLs and ingest
  them through a fetch → decompress → detect → parse pipeline into rule
  datasets. Formats: native JSON, CSV/TSV (header-mapped regex rules), newline
  IOC lists (domain/IP/sha256), RSS/Atom (IOCs mined from item text), and YARA
  (`.yar` rules compiled into the YARA scanner), over `.gz`/`.zip`/`.tar`/`.tar.gz`.

### Changed

- Folded `exfil update` into `exfil pull`: `pull <ref>` fetches one dataset,
  `pull` (no argument) fetches every configured `[[update]]`.
- CLI commands: `scan`, `search`, `get`, `rules`, `config`, `clean`, `tui`.
- Ratatui progress gauge for `scan` (plain line output when piped).
- Mutt-style `exfil tui`: findings index + pager, `/` limit, `:` commands,
  live scans with streaming results.
- TOML configuration with an embedded default written on first run.
- CI (fmt, clippy, tests on Linux/macOS/Windows) and tag-driven release
  workflow building binaries for all three platforms.
- Dataset sources & catalog (`exfil-source`): builtin/file/http(s) sources;
  `pull`/`sources`/`datasets` (list/add/show/rm); scans apply catalog rules.
- IOC feeds: content indicators as regex rules, file-hash indicators via a
  hash scanner (`sha256:…` rule patterns); an IOC feed is just a dataset.
- ClamAV-style scanning (`exfil-scan::clamav`): pure-Rust matcher for hash
  signatures (.hdb/.hsb) and literal body signatures (.ndb) via Aho–Corasick,
  loaded from `[plugins.clamav]`.
- Remote scanning over SSH/SFTP (`exfil-remote`, pure-Rust russh):
  `exfil scan-remote user@host:/path` walks a host and runs the full
  pipeline on its files (RemoteFs trait + engine::scan_remote).
- YARA scanning (`exfil-scan::yara`): pure-Rust yara-x matcher; rules from
  `[plugins.yara]`, severity/CWE read from each rule's meta block.
- `gc`: prune superseded scans and unreachable file/finding/ast records
  (keeps the latest scan). `graph [query] --format json|dot`: emit the
  finding→file/rule graph. Scan timestamps switched to milliseconds so
  scan ordering is unambiguous.
- Pluggable viewers (`exfil-view`): a Viewer trait + Registry keyed by node
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
- MCP server (`exfil mcp`): a hand-rolled JSON-RPC 2.0 stdio server exposing
  read-only tools (search/graph/neighbors/get/analyze) so AI agents can explore
  the findings graph.
- DAG-CBOR/JSON export (`exfil export`): a portable snapshot of every record
  and edge table (stringified ids), via Store::export_snapshot + ciborium.
- Finding enrichment (`exfil enrich`, `exfil-llm`): an Enricher trait with a
  model-free RuleBasedEnricher writing per-finding `triage` notes; the trait is
  the seam for a future offline Candle model. All CLI commands now implemented.
- Rhai scripting (`exfil-script`, M5): a sandboxed pure-Rust script engine;
  `ScriptEnricher` runs a user `.rhai` script (configured via `[plugins.script]
  enrich`) over each finding to compute a triage note, plugging into the same
  Enricher trait.
- AST/taint language coverage expanded from Python+JavaScript to also cover
  TypeScript, Rust, Go, C, C++, and Java. LangSpec gained configurable call
  fields (Java's method_invocation uses `name`); new cross-language sinks
  (process::Command, exec.Command, popen/exec*, Runtime.exec) and taint sources
  (env::var, os.Getenv/Args, FormValue). C# awaits an ABI-compatible grammar.
- Added a JUnit XML report format (`analyze -f junit`). Each finding becomes a
  failing `<testcase>`, so CI systems that ingest JUnit can gate a build on
  findings; a clean scan is a passing suite. XML metacharacters are escaped.
- Added a multi-page architecture guide under docs/architecture/ (11 pages, ~3k
  lines) with mermaid diagrams for every layer, written to teach Rust: overview
  & file structure, the plugin DAG, a diagram-heavy engine deep-dive, the AST
  scanner, taint analysis, the other scanners, the graph store, CLI/TUI, the
  integrations, and a Rust primer cross-referenced from every page.
- AST language coverage extended to Ruby, Dart, Swift, Kotlin, and Groovy
  (including `Jenkinsfile`s, selected by filename). Ruby and Dart get full
  taint tracking; Swift/Kotlin/Groovy are calls-only. `call_kind` became
  `call_kinds` (a list) so Groovy's two call forms both parse, and a
  positional-callee fallback handles Swift/Kotlin. New sinks: Dart Process.run,
  Kotlin ProcessBuilder, Groovy evaluate. SQL was evaluated and deferred (no
  call-sink model; the sequel grammar fails to parse the T-SQL EXEC sink).
- Added a PII scanner (offline): emails, US SSNs, credit cards (Luhn-validated),
  phone numbers, IBANs (mod-97). Findings mask the matched value so the store
  never holds raw PII.
- Added an indicator extractor (Bytes -> Indicators): emails, domains, IPs,
  URLs, and file hashes are extracted, normalized, deduped, and stored as an
  `indicators` graph node linked to each file (`has_indicators`), viewable in
  the TUI. New ArtifactKind::Indicators is the seam for future DNS/whois/IOC/
  leak checker plugins.
- Added a domain typosquat / brand-impersonation checker, a network-IOC matcher
  (domains/IPs/URLs from feeds), and a log-event scanner (SSH/PAM auth failures,
  privilege use) — the first plugins consuming the Indicators seam plus offline
  log triage.
- Added `exfil processes`: scan the local host's running processes (name, exe
  path, command line) through the full pipeline via a ProcessFs RemoteFs source
  — catches secrets/tokens exposed on command lines, PII, and bad domains/IPs in
  arguments. Linux procfs; other platforms enumerate nothing.
- Added `exfil scan-tcp <host:port…>` (banner grabbing) and `exfil port-scan
  <cidr> --ports <spec>` (IP/CIDR × port sweep with banner scanning and
  service/version fingerprinting), both reusing the pipeline via scan_remote.
  Authorized-testing use; expansion bounded to 65k targets.
- Added `exfil scan-web <url>`: bounded same-origin web crawler (page/depth
  caps) that scans fetched HTML/JS pages through the full pipeline for leaked
  secrets, PII, and bad indicators. robots.txt not yet honored.
- Added `exfil check-dns`: resolves domains observed during scans and flags
  those resolving to reserved/private/loopback addresses (DNS-rebinding /
  internal-exposure signal, CWE-918). Online, opt-in; keeps default scans
  offline. WHOIS registration-age enrichment is a documented follow-on.
- Added a Splunk-CIM-style normalized data model: `exfil normalize` maps every
  finding (from any scanner) onto shared CIM fields (category/action/signature/
  severity/src) stored as `event` graph nodes linked to their finding
  (has_event), enabling cross-source correlation. Events are browsable in the
  TUI and gc-pruned with their findings.
- Added `exfil check-whois`: WHOIS-checks domains observed during scans and
  flags newly-registered ones (a phishing signal) via a port-43 IANA-referral
  lookup, with a dependency-free date parser. Online, opt-in.
