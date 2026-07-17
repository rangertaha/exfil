# exfil — Architecture & Build Plan (Rust)

**exfil** (Extra File Lang Lookup) is an offline, cross-platform, plugin-based
filesystem-analysis and SAST engine. It builds a queryable graph of files →
AST → findings → rules with full provenance, backed by an embedded database,
and can optionally enrich results with an embedded offline LLM. Written in
Rust for a single portable binary, fast parallel scanning, native multi-language
parsing, and a native embeddable LLM runtime.

This document supersedes the Go prototype and the earlier Go plan.

## Principles

- **Extensible** — sources, scanners, and reporters are traits with registries.
- **Scalable** — parallel, gitignore-aware walking; content-hash dedup;
  incremental rescans; a real query engine instead of hand-rolled indexes.
- **Modular** — a Cargo workspace of small library crates + a thin CLI binary.
- **Offline & private** — no network to analyze; embedded LLM runtime; nothing
  leaves the machine.
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
| LLM | Embedded **Candle** runtime (pure-Rust, CPU); GGUF weights downloaded by `exfil update` into config |
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
    exfil-report/   ✅ Reporter trait: text, json, markdown
    exfil-llm/      ✅ Enricher trait + rule-based triage (Candle model = future impl); `enrich`
    exfil-config/   ✅ TOML config with embedded default + per-plugin decode
    exfil-mcp/      ✅ MCP server (stdio JSON-RPC, hand-rolled): search/graph/neighbors/get/analyze
    exfil-engine/   ✅ orchestration: walk, incremental, expand, commit; run-level stages (fetch→scan→report)
  crates/exfil-cli/ (bin "exfil")  ✅ clap commands + progress + mutt-style TUI
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
| Progress/TUI | `ratatui` (+`crossterm`) | inline scan gauge; mutt-style `exfil tui` |
| Config | `toml` | pure-Rust, mature, per-plugin tables |
| LLM | `candle-core`, `candle-transformers`, `tokenizers` | pure-Rust GGUF inference (CPU) |
| Serde | `serde`, `serde_json` | reports, MCP |
| Async | `tokio` | SurrealDB + reqwest are async |

**Build note:** tree-sitter grammars are C (compiled via the `cc` crate at
build time); cross-compilation uses `cargo-zigbuild`/`cross`. Everything else is
pure Rust (SurrealKV, Candle-CPU, yara-x, rustls), so there is no system C/C++
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
- Findings DB: local, at `--store` (default `.exfil/`), removed by `exfil clean`.
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

## Offline embedded LLM

- **Engine in the binary** — `candle` runs quantized GGUF models in pure Rust on
  CPU, cross-platform, no CGo. Compiled in behind an `Llm` trait
  (`available()`, `extract(text, schema)`, `enrich(finding)`); every call is a
  **no-op when disabled or the model is absent**.
- **Weights are a data file** — the GGUF is downloaded by `exfil update` into
  the LLM plugin's config dir (`~/.config/exfil/plugins/llm/`), like a dataset:
  fetched once, offline thereafter, preserved across `clean`. Precedence:
  downloaded model → optional tiny `include_bytes!` default → disabled.
- **Uses** — (1) extract structure from unstructured text (logs/docs/config
  prose) into finding/entity records; (2) triage/enrich findings. Runs as a
  separate **`exfil enrich`** pass over the stored graph so scans stay fast.

## Plugin traits

```rust
trait Source   { fn name(&self)->&str; fn handles(&self,scheme:&str)->bool;
                 async fn fetch(&self, r:&str) -> Result<Dataset>; }
trait Scanner  { fn name(&self)->&str; fn applies(&self,p:&Path,m:&Metadata)->bool;
                 fn scan(&self, p:&Path, content:&[u8]) -> Result<Vec<Match>>; }
trait Reporter { fn name(&self)->&str; fn report(&self, w:&mut dyn Write, a:&Analysis)->Result<()>; }

// opt-in capabilities:
trait Updater { async fn update(&self) -> Result<()>; }         // refresh datasets/model
trait UsesLlm { fn set_llm(&mut self, llm: Arc<dyn Llm>); }     // receive the model
```

The engine reads each file once and passes `content` to scanners.

## Commands

```
exfil sources | pull | update | datasets | rules
exfil scan [path]        # parallel, incremental, streaming
exfil search [query]     # SurrealQL under the hood (rule/lang/cwe/severity)
exfil graph  [query]     # findings graph (dot/json) via traversal
exfil analyze [query]    # whole-graph report (text/json/markdown)
exfil enrich             # offline LLM pass (structure extraction + triage)
exfil config | clean | gc | mcp | get <id>
exfil tui                # mutt-style live workbench (scan/browse/query)
```

`update` downloads dataset refs *and* the LLM GGUF into their plugin config dirs
with concurrent progress bars.

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

[llm]
enabled = true
tasks = ["extract", "triage"]

[[update]]
name = "security"
ref = "builtin://security"

[[update]]
name = "llm-model"
ref = "https://…/model.gguf"
```

## Milestones

- **M0 Scaffold** ✅ — Cargo workspace, `clap` skeleton, SurrealKV store
  open/close, TOML config + embedded default, cross-platform metadata.
- **M1 Graph + scan** — mostly done: schema + edges (✅ `exfil-store`), regex
  scanner + builtin ruleset (✅ `exfil-scan`), parallel walk → hash → scan →
  upsert engine with live `ScanEvent` streaming (✅ `exfil-engine`),
  `scan`/`search`/`get`/`rules` wired with a ratatui progress gauge (✅), and
  a mutt-style `exfil tui` workbench (✅ index/pager, `/` limit, `:` commands,
  live scans). Still to do: incremental rescan (stat fast-path; today a rescan
  re-reads and re-creates findings — dedup/replace prior scan's findings),
  tree-sitter AST scanner + `has_ast` edges, `flagged_by`/rule provenance
  edges (needs stored rules, ties into M2 datasets).
- **M2 SAST breadth** — taint (tree-sitter), yara-x, sources (builtin/file/http),
  `pull`/`update` with progress; provenance edges; `graph`/`analyze` + reports.
- **M3 LLM** — Candle engine, model download, `enrich` (structure + triage).
- **M4 Ops** — `gc`, DAG-CBOR `export`, MCP server, docs, CI cross-builds.

## Risks & tradeoffs

- **Rewrite cost** — the ~2.5k-line Go prototype is discarded; Rust iteration is
  slower. Mitigated by reusing its proven data model and rule sets.
- **tree-sitter C grammars** — build needs a C compiler (`cc`); cross-compiles
  via `zigbuild`. The only non-pure-Rust piece; well-trodden.
- **LLM quality/size** — Candle CPU inference suits small models; fine for
  extraction/triage, not deep reasoning. Weights download keeps the binary lean.
- **No IPLD** — SurrealDB is the sole store; content-hash record IDs give dedup
  and integrity. Merkle-DAG portability is out of scope (revisit only if a
  content-addressed export is ever needed).
- **Store size on huge trees** — a record per file; incremental + `gc` bound it.


## Graph-vim workbench (in progress)

A layered "neovim for graph traversal/editing" over the findings graph:
- ✅ M3 pluggable viewers (`exfil-view`): preview-per-node-kind registry.
- ✅ M1 navigation core: two-pane edge-following navigator (Store::neighbors),
  jumplist (</>), breadcrumbs, node view via viewers.
- ✅ M2 CRUD: field edit (`c`), edge delete (`d`), undo/redo (`u`/`U`) via
  reversible EditOps (Store::set_field/create_edge/delete_edge).
- ✅ M4 keymaps: vim defaults, remappable via `[keymap.nav]` in config.
- ✅ M5 scripting: Rhai script enricher (`exfil-script`, `[plugins.script] enrich`).

## Backlog (user-requested)

**Done:** dataset sources + catalog + pull/CRUD, IOC feeds (hash + content), ClamAV-style signatures, SSH remote scanning, plugin orchestration.


- **ClamAV malware scanning** — a `clamav` scanner plugin: match files against
  ClamAV signature databases (CVD/CLD; the `clamav-rs` bindings need libclamav,
  so a pure-Rust signature-subset matcher may fit the single-binary goal
  better). Findings land in the graph like any other scanner's.
- **IOC feeds** — download indicator-of-compromise datasets (hashes, IPs,
  domains, filenames; e.g. STIX/TAXII or MISP exports) via the source/dataset
  pipeline, then scan for them: file-hash IOCs check the already-computed
  blake3/sha256, content IOCs become regex/aho-corasick rules.
- **Dataset management (CRUD)** — create, update, list, and view datasets per
  plugin: `exfil datasets` grows `add/edit/show/rm` (and TUI views), backed by
  the catalog store, so users can maintain their own rule/IOC collections.
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
