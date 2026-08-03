# exfil — Architecture & Build Plan (Rust)

**exfil** (**EX**amine **F**iles, **I**nfrastructure & **L**ibraries) is an offline, cross-platform, plugin-based
filesystem-analysis and SAST engine. It builds a queryable graph of files →
AST → findings → rules with full provenance, backed by an embedded database.
Written in Rust for a single portable binary, fast parallel scanning, and
native multi-language parsing.

This document supersedes the Go prototype and the earlier Go plan.

## Principles

- **Extensible** — sources, scanners, and reporters are traits with registries.
- **Scalable** — parallel, gitignore-aware walking; content-hash dedup;
  incremental rescans; a real query engine instead of hand-rolled indexes.
- **Modular** — a Cargo workspace of small library crates + a thin CLI binary.
- **Offline & private** — no network to analyze; nothing leaves the machine.
- **Cross-platform** — one pure-Rust binary builds and scans on Windows, macOS,
  Linux, and Unix.

## Locked decisions

| Area | Decision |
|---|---|
| Language | **Rust** (workspace of crates + `clap` CLI) |
| Store | **SurrealDB only**, embedded, pure-Rust `SurrealKV` engine (not RocksDB). No IPLD layer. |
| Content addressing | Content hashes (**blake3**) as SurrealDB record IDs → dedup + integrity |
| Graph | SurrealDB records + `RELATE` edges (files/AST/findings/rules/datasets/sources) |
| Scanners | `regex`, **tree-sitter** AST (multi-language), tree-sitter taint, **yara-x** |
| Scan model | Parallel (`rayon` + `ignore` walker); stat fast-path incremental |
| VFS coverage | A record for **every regular file** (metadata + hash, never contents) |
| Provenance | Finding → Rule → Dataset → Source edges |
| Config | **TOML** via `toml`, embedded default (`include_str!`), per-plugin `[plugins.<name>]` tables |
| Platforms | Windows/macOS/Linux/Unix; metadata via `cfg`-gated `MetadataExt` |

## Workspace layout

```
exfil/
  Cargo.toml                 # workspace
  crates/
    exfil-core/     domain types: FileMeta, Symbol, Rule, Dataset, Match, VirtualFile, Severity
    exfil-task/     ✅ plugin DAG: Artifact/ArtifactKind, FileTask, Pipeline (toposort)
    exfil-store/    SurrealDB graph store: schema, upsert, queries, DAG-CBOR export
    exfil-scan/     ✅ Scanner trait + ScanTask: regex, supply-chain, archive-expand, tree-sitter AST, taint, IOC, ClamAV, YARA
    exfil-source/   Source trait + registry: builtin, file, http (reqwest)
    exfil-report/   ✅ Reporter trait: text, json, markdown, junit, sarif + directory hotspots
    exfil-model/    ✅ path model (two-chain HMM) ranking what a scan looks at first
    exfil-config/   ✅ TOML config with embedded default + per-plugin decode
    exfil-mcp/      ✅ MCP server (stdio JSON-RPC, hand-rolled): 30 tools over the whole CLI surface
    exfil-engine/   ✅ orchestration: walk, incremental, expand, commit; run-level stages (fetch→scan→report);
                       setup.rs = shared store opening + pipeline building
    exfil-remote/   ✅ non-local sources (processes/TCP/web) + target.rs = shared scan-target dispatch
  crates/exfil-cli/ (bin "exfil")  ✅ clap commands + progress gauge (the
    mutt-style `exfil tui` workbench was built here too, then later removed)
```

## Plugin orchestration (implemented)

Two levels of dependency-ordered orchestration replace the old fixed
"read then scan" sequence:

- **Per-file DAG** (`exfil-task`) — plugins are `FileTask`s declaring the
  `ArtifactKind` they consume/produce (`Bytes`, `Files`, `Ast`, `Matches`). A
  `Pipeline` topologically sorts them (Kahn's algorithm) and fails fast on
  cycles or missing producers. This is how the archive expander (`Bytes →
  Files`) runs before scanners, and how a future AST scanner (`Bytes → Ast`)
  will slot in ahead of taint (`Ast → Matches`) automatically.
- **Data retrieval / unpack / expand** — the `archive-expand` task turns a
  container's bytes into `VirtualFile`s; the engine re-runs the pipeline over
  them (depth-capped, zip-bomb-bounded) and links each to its container with a
  `contained_in` graph edge, so scanners see files inside zip/jar/tar/gz with
  no changes.
- **Run-level stages** (`exfil-engine::run`) — `RunStage`s sequence a whole
  invocation **fetch → scan → report**, sharing the graph through `RunCtx` and
  communicating *through* it (scan writes findings, report reads them). Fetch
  is a declared stub until sources (M2) land; reporting is live via
  `exfil-report` (`exfil analyze --format text|json|markdown`).

Plugins are `Box<dyn Trait>` registered in registries at startup (compiled-in).

## Crate choices

| Concern | Crate | Notes |
|---|---|---|
| CLI | `clap` (derive) | subcommands, help, completions |
| Store | `surrealdb` (`kv-surrealkv`) | embedded, pure-Rust, graph + query |
| Hashing | `blake3` | content IDs; fast |
| Walk | `ignore`, `rayon` | gitignore-aware, parallel |
| Regex | `regex`, `aho-corasick` | multi-pattern scanning |
| AST | `tree-sitter` + grammars | Go, Python, JS/TS, Rust, C/C++, Java, … |
| YARA | `yara-x` | official Rust YARA engine |
| HTTP | `reqwest` (rustls) | dataset + model downloads, no OpenSSL |
| Progress | `ratatui` | inline scan progress gauge |
| Config | `toml` | pure-Rust, mature, per-plugin tables |
| Serde | `serde`, `serde_json` | reports, MCP |
| Async | `tokio` | SurrealDB + reqwest are async |

**Build note:** tree-sitter grammars are C (compiled via the `cc` crate at
build time); cross-compilation uses `cargo-zigbuild`/`cross`. Everything else is
pure Rust (SurrealKV, yara-x, rustls), so there is no system C/C++
library dependency.

## Graph data model (SurrealDB)

Records (tables) with content-hash IDs where dedup matters, connected by graph
edges. The graph is naturally queryable and traversable — no hand-built index.

**Tables**
- `file` (id = `blake3(content)`) — `{ path, abs, host, mode, uid, gid, user, group, size, mtime, hash }` (metadata only).
- `ast` — `{ lang, symbols: [{kind,name,line}] }`.
- `source` — `{ name, scheme, ref }`.
- `dataset` — `{ name }`.
- `rule` (id = hash of definition) — `{ name, pattern, description, severity, cwe, cve }`.
- `finding` — `{ line, col, snippet, severity, cwe, cve }`.
- `scan` — `{ root, host, started_at, files, matches, counts }` (the run/root).

**Edges (`RELATE`)**
- `file ->has_ast-> ast`
- `finding ->in_file-> file`, `finding ->at_ast-> ast`, `finding ->flagged_by-> rule`
- `rule ->from_dataset-> dataset ->from_source-> source`
- `scan ->includes-> file`

**Example queries** replace the hand-rolled Go logic:
- search: `SELECT * FROM finding WHERE cwe = 'CWE-78'`
- graph: `SELECT ->flagged_by->rule->from_dataset->dataset FROM finding`
- analyze: `SELECT severity, count() FROM finding GROUP BY severity`

**Stores / locations**
- Findings DB: local, at `--store` (default `.exfil/`), removed by `exfil store clean`.
- Datasets + rules DB: user config dir (`~/.config/exfil/…`), survives `clean`.
  (Two SurrealDB namespaces/databases, or two embedded instances.)

## Scan pipeline

1. **Walk** with the `ignore` crate (respects `.gitignore`, skips the store);
   feed entries to a `rayon` pool.
2. **Incremental**: compare `(path, size, mtime)` to the last scan's record;
   unchanged → reuse the existing `file`/`ast`/`finding` records, skip reading.
3. **Read once**: stream the file through one pass that computes the blake3 hash
   and feeds the applicable scanners (AST/taint get the buffered source; regex
   streams).
4. **Upsert** `file`, `ast`, and `finding` records + edges (dedup by content id).
5. **Stream** matches to stdout as found.
6. **Commit**: write the `scan` record, mark it current, persist the manifest.

## Cross-platform metadata

One `fn platform_meta(&Metadata) -> PlatformMeta`, `cfg`-gated:
- `cfg(unix)` — `std::os::unix::fs::MetadataExt`: uid/gid (→ user/group), inode, ctime, mode.
- `cfg(windows)` — `std::os::windows::fs::MetadataExt`: attributes/times; best-effort owner SID → account.
- fallback — portable `Metadata`: mode/size/mtime.

Portable core (path, host, mode, size, mtime, blake3) everywhere; platform
fields fill in where available. ACL/xattr and security labels are a follow-up.

## Offline embedded LLM (removed)

An `Enricher` seam with a rule-based triage-note implementation shipped in an
`exfil-llm` crate, alongside a Rhai (`exfil-script`) enricher for user-written
triage rules, with a Candle/GGUF model as the intended future implementation.
Both crates have since been **removed**: the rule-based notes restated what the
finding's severity and CWE already said, and the model never landed. `exfil
enrich` remains as the MITRE CWE-name annotation pass, which was always
independent of the enricher.

Agent-driven triage now happens through the
[MCP server](./architecture/integrations.md) instead — an agent reads the graph
and reasons about it directly, rather than exfil pre-writing a note into every
record.

## Plugin traits

```rust
trait Source   { fn name(&self)->&str; fn handles(&self,scheme:&str)->bool;
                 async fn fetch(&self, r:&str) -> Result<Dataset>; }
trait Scanner  { fn name(&self)->&str; fn applies(&self,p:&Path,m:&Metadata)->bool;
                 fn scan(&self, p:&Path, content:&[u8]) -> Result<Vec<Match>>; }
trait Reporter { fn name(&self)->&str; fn report(&self, w:&mut dyn Write, a:&Analysis)->Result<()>; }

// opt-in capabilities:
trait Updater { async fn update(&self) -> Result<()>; }         // refresh datasets
```

The engine reads each file once and passes `content` to scanners.

## Commands

```
exfil sources | pull | update | datasets | rules
exfil scan [path]        # parallel, incremental, streaming
exfil search [query]     # SurrealQL under the hood (rule/lang/cwe/severity)
exfil graph  [query]     # findings graph (dot/json) via traversal
exfil analyze [query]    # whole-graph report (text/json/markdown/junit/sarif)
exfil enrich             # annotate findings with MITRE CWE names
exfil config | clean | gc | mcp | get <id>
```

`pull` downloads dataset refs into the catalog with concurrent progress bars.

## Config (TOML, embedded default)

Per-plugin config is a `[plugins.<name>]` table; each plugin decodes its own
table into its own struct (the "custom fields per plugin").

```toml
store = ".exfil"

[plugins.regex]
datasets = ["security", "gitleaks"]

[plugins.ast]
languages = ["go", "python", "javascript"]

[plugins.yara]
rules = ["datasets/example.yar"]

[[update]]
name = "security"
ref = "builtin://security"

[Offline embedded LLM (removed)](#offline-embedded-llm-removed).
- **M4 Ops** — `gc`, DAG-CBOR `export`, MCP server, docs, CI cross-builds.

## Risks & tradeoffs

- **Rewrite cost** — the ~2.5k-line Go prototype is discarded; Rust iteration is
  slower. Mitigated by reusing its proven data model and rule sets.
- **tree-sitter C grammars** — build needs a C compiler (`cc`); cross-compiles
  via `zigbuild`. The only non-pure-Rust piece; well-trodden.
- **No IPLD** — SurrealDB is the sole store; content-hash record IDs give dedup
  and integrity. Merkle-DAG portability is out of scope (revisit only if a
  content-addressed export is ever needed).
- **Store size on huge trees** — a record per file; incremental + `gc` bound it.


## Graph-vim workbench (removed)

A layered "neovim for graph traversal/editing" over the findings graph was
built out (pluggable viewers in `exfil-view`, a two-pane edge-following
navigator, field/edge CRUD with undo/redo, and remappable vim keymaps) and
shipped as the `exfil tui` command. It has since been
removed (along with the `exfil-view` crate); it may return in a future
release.

## Backlog (user-requested)

**Done:** dataset sources + catalog + pull/CRUD, IOC feeds (hash + content), ClamAV-style signatures, plugin orchestration. (SSH remote-host scanning was also built here but has since been removed.)


- **ClamAV malware scanning** — a `clamav` scanner plugin: match files against
  ClamAV signature databases (CVD/CLD; the `clamav-rs` bindings need libclamav,
  so a pure-Rust signature-subset matcher may fit the single-binary goal
  better). Findings land in the graph like any other scanner's.
- **IOC feeds** — download indicator-of-compromise datasets (hashes, IPs,
  domains, filenames; e.g. STIX/TAXII or MISP exports) via the source/dataset
  pipeline, then scan for them: file-hash IOCs check the already-computed
  blake3/sha256, content IOCs become regex/aho-corasick rules.
- **Dataset management (CRUD)** — create, update, list, and view datasets per
  plugin: `exfil datasets` grows `add/edit/show/rm`, backed by the catalog
  store, so users can maintain their own rule/IOC collections.
- **Supply-chain detection, dataset-driven** — v1 ships (offline heuristics in
  `exfil-scan::supply`: known-malware list, typosquats, install hooks,
  insecure sources); next step is feeding it OSV/malicious-package datasets via
  `update` for version-aware compromise detection (e.g. `ua-parser-js`-style
  hijacks).
- **Plugin orchestration** — evaluate a pipeline/DAG model where plugins
  declare inputs/outputs (bytes, AST, graph records) and the engine schedules
  them in dependency order; see discussion in session notes.

## Resolved

- Storage: **SurrealDB only** (SurrealKV engine), content-hash IDs. No IPLD.
- Config: **TOML** (`toml` crate).
- Go prototype: **removed**.
