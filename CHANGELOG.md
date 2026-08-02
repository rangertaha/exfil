# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Reports now show **where** the findings are, not just what they are: a
  "findings by directory" breakdown ranking the directories holding the most,
  with each one's share of the total. One directory holding 40% of a scan is a
  different problem from forty holding one each, and the flat finding list
  can't tell you which you have. Appears in `text`, `markdown` (as a table, for
  pasting into a PR) and `json` (as a `hotspots` array); JUnit and SARIF are
  untouched, since those have fixed schemas. Needs no directory records —
  findings already carry a full path, so it is derived at report time.
  Ties break on summed severity then name, so the same findings always render
  the same report; the shared path prefix is stated once in the heading rather
  than repeated on every row; and the whole section is omitted when there is
  only one directory to name.

### Changed

- **Relicensed from MIT to GPL-3.0-or-later.** `LICENSE` carries the full GPLv3
  text; the workspace manifest (inherited by every crate) and the standalone
  desktop app declare `GPL-3.0-or-later`. The Rust dependency tree is
  unaffected — the MIT/Apache-2.0 mix common on crates.io is one-way compatible
  into GPLv3.

### Removed

- `crates/exfil-remote/top-ports.txt`, the port ranking derived from nmap's
  `nmap-services` data. It was retained under MIT with an in-file notice, but
  the Nmap Public Source License is a modified GPLv2 with added restrictions
  and is **not GPL-compatible**, so it could not be carried into a GPLv3 work.
  `--ports common` now reads `netscan::COMMON_PORTS`, written for this project:
  IANA service assignments — facts, not authorship — ordered by our own
  judgement of what a security scan cares about (web and remote access first,
  then file shares, databases, directory/auth, orchestration, industrial
  control, then the long tail). Deliberately *not* a frequency ranking, since
  an observed-frequency ordering is someone's measurement and carries their
  licence with it. 768 unique ports, deduplicated at startup because the
  grouped literal repeats a few for readability; the `top-ports` setting's
  maximum drops 2000 → 750 so it can never advertise more ports than exist.
  exfil now ships no third-party data.

### Fixed

- **New rules were never applied to unchanged files.** The stat fast-path skips
  a file whose size and mtime match the last scan — but that promise only holds
  for the rules that produced the stored findings. `exfil pull` a new dataset,
  rescan, and every unchanged file stayed unexamined by rules that had never
  seen it. Each scan now records a fingerprint of the ruleset it applied
  (`exfil_engine::setup::ruleset_fingerprint`, hashed over built-in plus
  catalog rule names and patterns, order-independent); when the next scan's
  fingerprint differs, the fast-path is bypassed and everything is re-examined
  exactly once, after which it resumes. `Summary::ruleset_changed` reports it,
  and a path model trained under different rules now warns instead of silently
  ranking on stale assumptions.
- A stored path model whose vocabulary outran its emission matrices — a
  truncated write, a hand edit, a version skew — indexed out of bounds and
  panicked the scanner mid-walk. Indices are now clamped to the matrix width
  and an empty vocabulary returns the base rate: a model that cannot be trusted
  degrades to "I know nothing", it does not take the process down.
- `--budget`/`--ranked` were accepted and silently ignored for non-path targets
  (`processes`, `host:port`, URLs), so a request to scan 10% quietly ran a full
  scan. `Target::honors_plan()` now gates it: the CLI warns and the MCP `scan`
  tool appends an explicit note. Being misled about coverage is the exact
  failure this feature exists to prevent.

### Added

- Probability-ranked scanning (`exfil-hmm`, `exfil hmm`, `scan --budget`). A
  hidden Markov model over path components learns which parts of a filesystem
  are worth looking at, so a capped scan spends its budget where findings
  actually are. `exfil hmm train` fits it on the scans already in the store —
  every recorded file is a sample, and whether a finding hangs off it is the
  label, so there is no new scanning and no hand-labelling. `exfil hmm score`
  shows a path's probability with per-component log-odds; `exfil hmm status`
  summarizes the model. The model is stored in the catalog (`hmm_model`), so it
  survives `store clean`. Pure Rust: scaled forward-backward, Baum-Welch and
  Viterbi in ~400 lines with no dependency beyond serde.
  - `scan --budget` caps the work — `30s`/`5m` wall time, `20%` of files,
    `500mb` read, or a bare file count — scanning the most promising files
    first. `--ranked` orders worst-first without stopping early (same results,
    reached sooner). A budgeted scan **states its coverage** and refuses to
    combine with `--fail-on`: a partial scan cannot certify a tree is clean.
    The MCP `scan` tool takes the same `budget`, and its partial results carry
    an explicit "this is not evidence the target is clean" warning.
  - Ranking is lexicographic, not one score: changed files always outrank
    unchanged ones, because only they can produce new findings and the stat
    index knows which they are with certainty. Model value ranks within each
    group, as `P(finding) / cost(bytes)` — a 2 GB image at p=0.9 is worse value
    than five hundred dotfiles at p=0.3.
  - The scoring pass replaces the old `count_files` pre-walk rather than adding
    to it, so ranking costs no extra traversal.
  - Two chains are fitted, one per class, and scored by likelihood ratio.
    Fitting one chain and reading a per-state risk off it does not work:
    Baum-Welch maximises likelihood and the labels take no part in it, so a
    single state that emits `secrets`, `docs` and `vendor` uniformly models the
    corpus perfectly well — after which no read-out can separate those
    families. Making the label pick the chain is what gives training a reason
    to tell them apart. On a 60-file tree a 30% budget found 18 of 20 findings.
- The MCP server now exposes **exfil's whole surface**, not just the findings
  graph: 26 tools covering reads (`search`, `graph`, `neighbors`, `get`,
  `analyze` in any reporter format, `stats`, `export`, `rules`, `cwe`,
  `datasets`, `feeds`, `sources`, `config`, `plugin_settings`), scanning
  (`scan`, taking the same target spec as the CLI), catalog maintenance
  (`pull`, `feed_add`, `feed_rm`, `dataset_rm`, `plugin_set`), post-scan passes
  (`normalize`, `annotate_cwe`, `check_dns`, `check_whois`), and store
  maintenance (`gc`, `clean`). Every advertised description is prefixed with an
  access class — `[read-only]`, `[writes to the local store]`, `[network:
  reaches remote systems]`, `[DESTRUCTIVE: deletes stored data]` — so an agent
  can see a call's consequence before making it. `exfil-mcp` splits into
  `lib.rs` (protocol), `tools.rs` (catalog + dispatch), and `ops.rs`
  (operations); `serve` now takes a `Ctx { store_dir, config }` instead of an
  open `Store`, opening each store per operation so `clean` can delete the
  store directory and a `pull` is visible to the very next `scan`.
- `exfil_engine::setup` and `exfil_remote::target`: store opening, pipeline
  building, and scan-target resolution moved out of the CLI into shared
  library code, so an agent-run scan applies the same ruleset and resolves a
  target spec identically to a shell-run one.
- SQLite database expansion (`SqliteExpander`, `Bytes → Files`): `.db`/
  `.sqlite`/`.sqlite3` files (sniffed by magic header, not just extension)
  have every user table's rows flattened into one virtual file each
  (`app.db!users`, `col=val` per line, NULLs omitted, blobs shown as a byte
  count) so the existing regex/PII/IOC/hash scanners find secrets or PII
  sitting in database content exactly as if it were a plain text file — the
  same `Bytes → Files` seam `ArchiveExpander` uses for zip/tar, row/table/byte
  capped against oversize databases. Opened read-only via a temp file
  (`rusqlite`, bundled SQLite — no system library needed).
- `FileTask`/`Scanner` gained a `binary_safe()` method (default `false`).
  YARA and ClamAV — built to match raw binary signatures — override it to
  `true`; the engine now runs `binary_safe` tasks on binary content (`YARA`
  rules now actually fire on real binaries) via a new
  `Pipeline::run_file_binary_only`, while text-pattern scanners keep skipping
  it as before.

### Fixed

- The engine read every file fully into memory with no size cap, so a single
  large file (a VM image, a database dump, a core file) could exhaust RAM —
  multiplied by the parallel walk, which could have one such allocation per
  thread. Files are now capped at `MAX_SCAN_BYTES` (512 MiB) for *content
  scanning* only: an oversize file is still stat'ed, still hashed (streamed in
  1 MiB chunks, so memory stays bounded), and still recorded, keeping
  filesystem coverage and the stat fast-path intact. `scan_remote` applies the
  same rule, though `RemoteFs` returns a whole `Vec<u8>` with no stat, so there
  it bounds the scanning work rather than the allocation.
- `SqliteExpander` bounded its *output* (rows, tables, bytes) but not its
  input, while opening a database means staging every byte to a temp file
  first — so a multi-gigabyte `.db` was copied to the temp directory in full,
  once per walker thread, before a single row was read. New
  `Limits::max_input_bytes` (2 GiB) rejects it before anything is written.
- A file whose *name* matched a container extension was scanned by nothing at
  all when its content wasn't really that format. The engine decided
  "is this a container?" from `applies(path)`, and expanders match on filename
  alone, so a plain text file named `notes.db` (or `.zip`, `.gz`, …) was
  expanded to nothing and then skipped — its contents never reaching any
  scanner. Container-ness is now decided by content: the name-based branch is
  gone, the expanders declare themselves `binary_safe`, and the binary sniff
  alone routes each file. Real archives and databases still expand (and now
  additionally reach YARA/ClamAV, which they never did before), while a text
  file wearing a container extension is scanned as the text it is. Existing
  `.db`-named non-SQLite files are the most likely to have been silently
  missed, since the new SQLite expander widened `applies` to a very common
  extension.
- `exfil scan --ports <spec>` with no target silently fell through to a plain
  passive scan of the current directory instead of erroring — `ports` now
  `requires` a target at the clap level.
- A plugin setting resolved from `[plugins.<name>]` (or, defensively, a
  catalog override) was used as-is even when it failed the field's own
  schema validation (e.g. `top-ports = 0` or `top-ports = 99999` in config);
  `resolve_plugin_setting` now validates at each layer and falls through
  (with a warning) instead of using an out-of-range value.
- `Config::plugin_field` treated a TOML float the same as an absent field
  (silently falling back to the schema default); it now stringifies floats
  too, so an invalid-for-its-schema value is rejected explicitly instead of
  vanishing as if unconfigured.
- `exfil scan <host/cidr> --ports common` with a resolved `top-ports` of 0
  silently swept zero ports and reported success; `expand_ports` now bails
  instead, consistent with an explicitly empty port spec.
- `plugin_setting` records were keyed by `"{plugin}.{key}"` string
  concatenation, so a plugin/key pair containing a `.` (e.g. plugin `a.b` key
  `c`) could collide with a different pair with the same concatenation
  (plugin `a` key `b.c`); now keyed by a genuine `[plugin, key]` composite
  record id.

### Security

- Upgraded `yara-x` (0.13 → 1.19), which moves its bundled `wasmtime` from
  29.0.1 to 43.0.2 and clears 16 RustSec advisories — including two critical
  (CVSS 9.0) WebAssembly sandbox escapes reachable via YARA rules pulled from
  remote feeds. Bumped `ratatui` (0.29 → 0.30) alongside it (required to resolve
  the shared `unicode-width` pin), which also drops the unsound `lru` 0.12 from
  its dependency path.

### Removed

- Finding enrichment and its two crates. `exfil-llm` (the `Enricher` trait plus
  the model-free `RuleBasedEnricher` that wrote a `triage` note onto each
  finding) and `exfil-script` (the Rhai `ScriptEnricher` for user-written triage
  rules, and the `rhai` dependency) are gone, along with the `[plugins.script]`
  and `[llm]` config blocks and the `llm` field on `Config`. The rule-based
  notes only restated the severity and CWE already on the finding, and the
  offline Candle/GGUF model the trait was a seam for never landed; agent-driven
  triage now goes through the MCP server, which reasons over the graph directly.
  **`exfil enrich` remains**, as the MITRE CWE-name annotation pass it always
  also was — that half never depended on the enricher.
- The `exfil tui` workbench (mutt-style index/pager, the vim-style graph
  navigator, configurable keymaps) has been removed, along with the
  `exfil-view` crate that backed its preview panes. May return in a future
  release.
- SSH/SFTP remote-host scanning (`scan files --remote`, the `russh`/
  `russh-sftp` dependencies) has been removed. Local process scanning, TCP
  banner grabbing, port sweeps, and web crawling are all still available
  under the unified `scan` command (see Changed below) — only logging into a
  remote host over SSH to walk its filesystem is gone. This also obsoletes
  the `russh` RUSTSEC-2025-0090/0091 advisories previously tracked here.

### Changed

- The default config is now a fully-documented reference: every option is shown
  with its default value and commented out (only the shipped `security` dataset
  is active), so exfil runs on built-in defaults and users uncomment only what
  they want to change.

- Grouped the CLI into nested subcommands: the reachability checks live under
  `check` (`check dns`, `check whois`) and store maintenance under `store`
  (`store export`, `store gc`, `store clean`).

- Unified all scan targets onto a single `exfil scan [target]` command
  (previously `scan files`/`tcp`/`port`/`web`/`processes` subcommands): the
  shape of `target` picks the scanner — a local path or nothing (current
  directory), the literal `processes`, comma-separated `host:port` banner
  targets, a host/CIDR swept with `--ports`, or an `http(s)://` URL (`--driver`
  for a WebDriver-rendered crawl). `-a`/`-p` label a scan active (it reached a
  remote system) or passive (local only) in its summary, inferred from the
  target's shape when neither is given.

### Added

- Per-plugin config schemas and overrides: a plugin can publish a typed,
  validated `PluginSchema` (`exfil_config::PluginSchema`/`FieldSchema`) beyond
  its `[plugins.<name>]` config-file table. `exfil plugin config <plugin>`
  interactively walks every setting on a plugin — a select menu for fixed
  choices, a validated text prompt for numbers — pre-filled with each
  setting's current effective value. Overrides are stored in the
  catalog database (a new `plugin_setting` table), so they persist
  independently of the config file and survive `store clean`; a setting
  resolves in order: catalog override → config file → schema default. First
  concrete setting: the `scan` plugin's `top-ports` (1-2000, default 100) —
  how many ports `--ports common` sweeps, taken from a new ranked list of
  common TCP ports by real-world frequency (`crates/exfil-remote/top-ports.txt`,
  derived from nmap's `nmap-services`; note that file carries the Nmap Public
  Source License, not this project's MIT license — see its header).

- SARIF 2.1.0 report format (`analyze -f sarif`): findings become SARIF
  `results` (severity → `error`/`warning`/`note`), the distinct rules that fired
  are emitted once in the tool driver with their CWE as a property/tag, and
  positions become 1-based regions. GitHub code scanning and most SAST
  dashboards ingest it to annotate findings inline on pull requests.

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
  IOC lists (domain/IP/sha256), RSS/Atom (IOCs mined from item text), YARA
  (`.yar` rules compiled into the YARA scanner), gitleaks TOML (`[[rules]]`
  regexes), and the threat-intel formats STIX 2.x, MISP, and OpenIOC (a `.json`
  feed is content-sniffed between native/STIX/MISP; a `.xml` feed between
  OpenIOC and RSS/Atom), over `.gz`/`.zip`/`.tar`/`.tar.gz`.
- TAXII 2.x feeds: a `taxii2+…` feed URL is polled over the TAXII transport (a
  collection's `objects/` endpoint, with `more`/`next` pagination and basic-auth
  from the URL) and its STIX objects normalized into IOC rules.
- Feed ingestion deduplicates rules by `(name, pattern)` (first-seen order), so
  overlapping feeds/pages/archive members no longer inflate the pulled count.
- `exfil feeds show <name>`: print a feed's URL and a breakdown of the rules it
  last pulled by type (domain / ip / url / hash / email / yara / regex).
- `exfil feeds pull` prints a rollup (`pulled N/M feed(s), R rule(s)[, F failed]`)
  when pulling more than one feed, and exits non-zero if any feed failed — so a
  scheduled refresh surfaces a broken feed instead of hiding it in the stream.

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
