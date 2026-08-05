# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `exfil plugin list|get|set|remove`, so plugin settings are reachable without a
  prompt. `plugin config` was the only way in and is interactive, which put
  every setting out of reach of a CI job, a Dockerfile or a script.
  - `get` names the *source* of each value — `[override]`, `[config]` or
    `[default]`. A setting can come from three places, and being shown only the
    number leaves you guessing which one you are looking at and which file to
    edit to change it.
  - `set` validates against the field's own schema before storing. An override
    that fails validation is ignored at read time, which looks exactly like the
    setting having no effect.
  - `remove` drops an override and says what the value falls back to, so
    "removed" is not mistaken for "unset". With no key it clears the plugin.
  - `Store::remove_plugin_setting` backs it; there was previously no way to
    take an override back off once stored.

- An end-to-end test suite (`crates/exfil-cli/tests/e2e.rs`) driving the real
  binary through whole journeys rather than one command at a time, because the
  interesting failures live *between* commands. Seven of them: a named run
  addressed by every read path (and a name that matches nothing resolving to
  nothing rather than everything); a no-op rescan taking the stat fast-path and
  adding no findings; all six report formats rendering the same scan, checked
  for being the format they claim; train → `model list`/`get` → a budgeted scan
  stating its coverage and refusing to also certify the tree; the MCP surface
  agreeing with the CLI about the store it just wrote; piped output keeping
  whole `path:line:col` prefixes; and a store nested inside its own scan target
  not being ingested back into itself. Builds its own tree in a temp directory,
  so it needs no `e2e/generate.py` run first and no fixture edit can silently
  change what is asserted.

- **`exfil train --model <kind>` and `exfil scan --model <name>`** — the path
  model is now a choice rather than a fixed algorithm. `path-hmm` (the default)
  is the sequence model; `dir-prior` is the parent-directory frequency prior
  that `model eval` has always measured against, promoted from benchmark
  fixture to something you can actually scan with. When `eval` reports the
  baseline ties — which it does on simple corpora — that verdict is now
  actionable.
  - `--model` means "which kind to fit" on `train` and "which stored model to
    use" on `scan`, because a model that does not exist yet can only be named
    by kind and one that does can only be named by name.
  - `dir-prior` is **calibrated by construction**: a smoothed frequency already
    is a probability, so `--budget 90c` works with it on corpora far too small
    to fit a Platt map for the HMM.
  - Stored models carry a `kind` tag, and the tag is the same string the scorer
    reports as its name, so what a model calls itself and what it is stored as
    cannot drift. Models written before the tag existed still load — decoding
    falls back to reading an untagged document as a `path-hmm`, declaratively,
    via a `#[serde(untagged)]` shim — so no migration step and no re-training.
    The fallback lives in `exfil-model` rather than in each front end, and
    describes the *format* without depending on an encoding of it.
  - `model get` and the MCP `model_status` report per kind rather than
    flattening both into one shape with fields left blank.
  - Naming a model that is not stored is now an **error**. Falling back to walk
    order would answer a question nobody asked: the caller named a ranking, and
    a typo would otherwise produce a differently-shaped scan under a summary
    that reads the same.

- `exfil report -f pdf` — a paginated PDF: summary, per-severity tally,
  directory hotspots, then the findings worst-first, colour-coded by severity.
  For handing a scan's result to someone who will read it rather than parse it.
  - Set in base-14 **Helvetica**, which every PDF reader must provide, so no
    font is embedded: a 60-finding, two-page report is ~13 KB, and no font file
    has to be found at build time.
  - Finding lines reuse `exfil_report::fit`, the same elision the terminal uses,
    at the width a page holds — one layout decision serving two media.
  - Characters outside Latin-1 are dropped rather than mangled. The base-14
    fonts are single-byte encoded, and in a report a wrong glyph is worse than
    a missing one.
  - `printpdf` is pulled in with `--no-default-features`; its defaults carry
    image codecs, an HTML renderer and hyphenation that a text report has no
    use for.

- `exfil report [-o FILE]` — the same rendering `analyze` prints, aimed at a
  file you keep or send. With no `--out` it writes to stdout, so it is a
  superset of `analyze`; `analyze` stays because it is the one you type
  constantly and `report -f text -o -` is a worse way to ask for it.
  - The format is validated **before** the file is opened. `File::create`
    truncates, so checking afterwards would leave an empty file behind on a
    typo — and would destroy a good report from a previous run.
  - A report written to a file is never fitted to a window. Fitting is for
    terminals; a saved report is a document, and truncating its paths would
    corrupt the artifact that was asked for.

- `run_list`, `run_get` and `run_remove` MCP tools. Cutting `exfil run` from
  the CLI rested on every departed command still existing as an MCP tool; for
  `run` that was not yet true, which left named runs creatable and filterable
  but enumerable from nowhere — and `Store::list_runs`/`get_run`/`remove_run`
  reachable only from their own tests.

- **`exfil datasets update [target]`** — re-fetch the datasets a config already
  names. With no target it runs every `[[update]]` entry; with one it runs that
  entry, or, when no entry matches, fetches the target as a source reference
  (`builtin://…`, a path, an `https://` URL, or `mitre://cwe` for the MITRE CWE
  catalog that `exfil cwe` reads).
  - Resolving a target against the configured names *first* is what lets one
    argument carry either a name or a URL. The alternative — a `--name` flag
    beside a positional reference — makes the caller declare which kind of
    thing they are holding when the command can just look.
  - A configured entry is stored under **its** name, so `[[update]] name` finally
    decides what a dataset is called instead of being decorative while the
    source's own name won. `datasets add` already worked this way.
  - One failed fetch is reported and the remaining entries still run. A feed
    being down should cost you that dataset, not the whole update, so the
    command exits zero with the failures on stderr.

- **Named scan runs.** `exfil scan --name nightly` labels a run, and
  `exfil analyze -n nightly` and `exfil search run=nightly` ask for one run's
  findings. A run given no name is
  still recorded under one generated from its start time
  (`2026-08-03T14-22-05`), so every run stays addressable — a name you did not
  choose beats no handle at all.
  - `run=` is not a column. Findings hang off file *content*, which outlives
    any single run, so "findings from run X" is a join across
    `finding->in_file->file` and `scan->includes->file`. The store resolves it,
    so no caller has to know the graph shape.
  - `--name` is sugar for the `run=` filter rather than a second code path, so
    there is one query grammar; combining it with a query is rejected out loud
    instead of silently dropping one.
  - The MCP `scan` tool takes the same `name`, so an agent can scan and then
    ask for exactly what that scan found.

- The path model's tokenizer now treats `!` as a path separator, so a file
  expanded from a container contributes the container as its own observation
  (`archive.zip`, `inner`, `<ext:py>`) rather than one opaque token. "This came
  out of an archive" is real signal, and it stops an extensionless entry at a
  container root producing a junk `<ext:zip!readme>` vocabulary entry.
- ISO 9660 disc-image expansion (`IsoExpander`, `Bytes → Files`): `.iso`/`.img`
  images are expanded into the files they contain (`appliance.iso!etc/shadow`),
  so a secret on installer media, an appliance image or a forensic capture is
  found by the ordinary scanners — the same seam `ArchiveExpander` uses for
  zip/tar. Reads the **Joliet** tree in preference to the primary one: plain
  ISO 9660 folds names to uppercase 8.3, which turns `package.json` into
  `PACKAGE.JSO` and hides it from the supply-chain scanner, so this is a
  correctness matter rather than cosmetics. The reader is written here rather
  than pulled in — the available crates are C bindings (against the pure-Rust
  rule) or carry licences needing reconciliation with GPL-3.0. Sniffed by magic
  rather than trusted by extension, every offset bounds-checked, recursion
  depth- and cycle-capped, output bounded by `Limits`. Validated against images
  produced by `genisoimage`, not only against a hand-built fixture.
- `--budget 90c` — a **confidence** stop condition. Every other budget caps
  cost; this one caps uncertainty: scan in ranked order until the files examined
  account for 90% of the total *expected* findings. It is the only budget that
  adapts to the tree — risk concentrated in a handful of files stops almost
  immediately, risk spread thin keeps going — because no fixed percentage can
  do that without assuming a shape in advance. On a sample tree it settled at
  24% of the files and recovered 39 of 40 findings. It only means anything with
  a calibrated model, since it sums probabilities, which is why it arrives now
  rather than alongside `--budget`.
- **Calibrated probabilities.** The raw likelihood ratio between the two chains
  is enormously confident — on a separable corpus scores piled up at exactly
  1.0 and 0.0, which ranks fine but is not a probability anyone should act on.
  The log-odds now pass through a Platt scaling fitted on **out-of-fold**
  predictions: calibrating on the paths the chains were fitted on would be
  circular, so a throwaway model is fitted on part of the corpus and scored on
  the rest. `secrets/x.env` went from a flat `1.0000` to `0.9000`.
  - Calibration cannot change the ranking — a logistic with a positive slope is
    monotonic — and `fit_platt` refuses a non-positive slope rather than invert
    it. A test asserts the calibrated and raw orderings are identical.
  - With too little data to hold anything out, the map stays at the identity and
    `hmm status` reports `uncalibrated` instead of pretending.
  - Quality is measured, not asserted: `hmm eval` now reports a **Brier score**
    and **expected calibration error**, and says outright when the values should
    be read as a ranking rather than as probabilities.
- `exfil hmm eval` (and the MCP `hmm_eval` tool): measure whether the path model
  actually helps, before trusting a budgeted scan. Fits on part of the stored
  scans and reports how much of the findings a budgeted scan recovers on the
  held-out rest, at 5/10/20/30/50/75% budgets, against **two** references — a
  plain parent-directory frequency prior, and blind selection. It prints a
  verdict rather than leaving you to infer one.
  - Out of sample, split by a deterministic hash of the path: scoring the paths
    a model was fitted on measures memorisation, and an RNG split would let a
    lucky draw pass for an improvement.
  - The directory prior is the reference that matters. On a corpus where the
    directory name alone explains the label — `secrets/` always has findings,
    `docs/` never does — it **ties the HMM exactly**, and `eval` says so. The
    sequence model only earns its complexity where context disambiguates
    (`/srv/deploy/config` vs `/var/cache/config`, same name, opposite labels).
    Tests pin both outcomes.
- The path model reaches AI agents: `hmm_train`, `hmm_score` and `hmm_status`
  join the MCP surface (30 tools with `hmm_eval`), so an agent can fit the model on a store,
  ask what a path scores and why, and be told when the model is stale relative
  to the ruleset now in force. `exfil hmm` was previously CLI-only, which
  contradicted the server's claim to expose everything the CLI does.
- Architecture guide chapter 9, [Ranked scanning](docs/src/architecture/ranking.md):
  why a sequence model rather than a frequency table, why two chains rather than
  one (and the wrong first attempt that proved it), the scaling and determinism
  the maths needs, budgets and expected-value ordering, the two-phase walk, the
  three rules that stop a partial scan reading as a clean one, and the ruleset
  fingerprint. Ranked scanning is also documented in the command guide, the
  feature list, and the README.


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

- **The crawl's bounds moved off `scan` and onto the plugin that owns them.**
  `--max-pages` and `--max-depth` only ever applied to an `http(s)://` target,
  so as flags they cluttered every scan that could not use them — part of why
  `scan --help` was the longest in the tool. They are now settings on a new
  `web` plugin schema, reachable with `exfil plugin get web` and
  `exfil plugin set web max-pages 200`, resolved through the same
  override → config → default chain as every other setting.

  `--driver` stays a flag for now: a WebDriver endpoint is a property of the
  machine you run on rather than a preference, and `FieldKind` has no free-text
  variant to hold a URL.

- **`--active` is a permission, not a label.** It used to tag the summary line,
  and the *actual* decision to reach the network was inferred from the target's
  shape — a colon in the string was enough, so `exfil scan example.com:22` read
  like a typo for a path and behaved like a port scan. Targets that leave this
  machine (`host:port` banners, a host/CIDR sweep, an `http(s)://` crawl) are
  now **refused** without `-a`, before any connection is attempted.
  `--passive` becomes the opposite assertion — it fails if the target is not
  local — so a CI job can guarantee a scan stays on the machine instead of
  assuming it. `-p` is no longer bound to `--passive`, freeing it for
  `--plugin`.

- **`analyze` is now a summary, not a second `report`.** It was byte-identical
  to `report` — same query, same `-f`, every flag — so two commands existed
  where one had no capability the other lacked. `analyze` now prints only the
  shape of a scan (counts, per-severity tally, directory hotspots) and drops
  `--format`; the finding list is what `search` and `report` are for. Each
  command has a job the other does not: a glance between scans, and an artifact
  you keep. Both render through one `write_summary`, so they cannot disagree
  about the same scan — an e2e test asserts their counts match.

- **One vocabulary across the nouns.** `datasets` becomes `dataset` (you act on
  one at a time; `list` is the plural), and its verbs become `list`/`get`/
  `add`/`remove`/`update` — `show` and `rm` are gone. `model` already used
  `list`/`get`/`remove`, so knowing one noun now teaches you the others instead
  of teaching you nothing.

- **`search -n` is `search -l/--limit`.** `-n` meant "how many" on `search` and
  "which one" on `scan`, `analyze` and `report`, so `exfil search -n 5` and
  `exfil analyze -n nightly` did unrelated things with the same letter. `-n` now
  means *name* everywhere.

- **`exfil-model` is a set of parts rather than one algorithm.** It was the only
  crate in the workspace shipping a fixed implementation where the other six
  ship a trait — `Scanner`, `FileTask`, `Reporter`, `Source`, `RunStage`,
  `RemoteFs` — and it now ships one too.
  - **`PathScorer`** is the seam: `name`, `score`, `base_rate`, and two questions
    a caller must be able to ask before acting on an answer — `has_calibration`
    (may this be read as a probability, or only as a rank?) and `explain` (what
    drove it?). `ScanPlan.model` holds `Box<dyn PathScorer>`, so the engine is
    no longer welded to the HMM.
  - **`DirPrior` is a real scorer, not a benchmark fixture.** It was a private
    struct inside the evaluation harness — a working path scorer that could only
    ever be the *rival* in a comparison, never a model you could scan with.
    That mattered because on some corpora it **ties** the HMM, and "then use the
    thirty-line one" was a conclusion the architecture could not express. It is
    public, tested on its own, and implements the trait.
  - The harness now ranks `&dyn PathScorer` instead of closing over two concrete
    types, so comparing a third scorer is passing it in rather than editing
    `evaluate`.
  - The crate splits along the lines it already had: `tokens` (what the model
    observes), `hmm` (a scaled Markov chain that knows nothing about paths),
    `calibrate` (ratio → probability), `model` (the classifier), `scorer`,
    `dir_prior`, `eval`. Every item moved verbatim; `lib.rs` is now a facade, so
    `exfil_model::PathModel` and friends still resolve. `hmm` in particular is a
    general Baum-Welch/forward-backward/Viterbi implementation that was sitting
    inside a file about filesystems.

- **`exfil train` is a top-level command**, no longer `exfil model train`.
  Exactly two commands in this tool do work and write a result — `scan`
  produces findings, `train` produces a model — and everything else reads one
  back. Burying training a level down hid that pairing. `model` is left holding
  only the verbs that read: `model list`, `model get <name>` (was
  `model status`), `model score`, `model eval` and `model remove <name>`, with
  a bare `exfil model` listing. Over MCP the same reshaping lands as `train`,
  `model_get`, `model_list` and `model_remove`.

- CI is one job instead of two. `cargo test` already builds every target it
  runs, so the separate `cargo build --workspace` step only compiled the
  workspace a second time; formatting and clippy are platform-independent and
  now run once on Linux rather than being a job of their own. The dead `master`
  branch trigger is gone (the default branch is `main`). The release workflow's
  packaging step moved its per-OS `if` into the matrix as a `package` command,
  so the step body is one line.

- Terminal output fits an 80-column window. Help text wraps (clap's `wrap_help`
  with `max_term_width = 80`) instead of printing single 387-column lines, and
  finding lines are laid out to the window by a new `exfil_report::fit`: the
  location is elided from the left so the file name, `line:col`, severity and
  rule survive, and the snippet from the right. The hotspot table sizes its
  name column and bar from the same width, and its `under <root>` header is
  elided rather than running to 131 columns.

  **Piped output is untouched** — fitting applies only when stdout is a
  terminal, so `path:line:col` prefixes stay whole for editors, `grep` and
  scripts, and the JSON/JUnit/SARIF reporters are never shortened. `markdown`
  is likewise left at full width: it is a document to paste into a PR, not
  something read in a terminal. The layout lives in `exfil-report` because the
  live scan feed and the text report both need it and must not drift; that also
  retired the near-duplicate `truncate_left` the hotspot table carried.

- `exfil hmm` is now **`exfil model`**, and the `exfil-hmm` crate is
  `exfil-model`. The command names what it is — the path model that ranks a
  scan — rather than the algorithm behind it, which is an implementation
  detail the model is free to change. The `Hmm` type is `PathModel`, the MCP
  tools are `model_train`/`model_score`/`model_eval`/`model_status`, and the
  catalog table `hmm_model` is `path_model`. **A model trained before this
  change is not found under the new table name; re-run `exfil model train`.**

- Dropped the `is-root` dependency for `rustix` (already in the tree, safe,
  maintained). `is-root`'s entire unix implementation was one call into
  `users`, an unmaintained crate carrying three RUSTSEC advisories
  (RUSTSEC-2025-0040 root appended to group listings, RUSTSEC-2023-0059
  unaligned read, RUSTSEC-2023-0040 unmaintained). Both crates are now absent
  from the lockfile: the advisory count drops from 3 vulnerabilities and 6
  warnings to 2 and 5, with everything remaining transitive through `yara-x`
  and `surrealdb`. On Windows, where there is no uid and the token API would
  need `unsafe` (which this workspace denies), elevation is now decided by
  probing whether the system data directory is writable — which is the question
  that actually matters, rather than the one that approximates it.

- **Relicensed from MIT to GPL-3.0-or-later.** `LICENSE` carries the full GPLv3
  text; the workspace manifest (inherited by every crate) and the standalone
  desktop app declare `GPL-3.0-or-later`. The Rust dependency tree is
  unaffected — the MIT/Apache-2.0 mix common on crates.io is one-way compatible
  into GPLv3.


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

### Removed

- `Store::create_edge`, `Store::delete_edge` (and their shared `edit_edge`
  body) and `Store::cwe_count`. Public API with no caller anywhere in the
  workspace or the desktop app — their only references were their own tests, so
  they read as supported surface that nothing actually depended on. The same
  shape as the `list_runs` gap fixed one commit earlier, and the reason to look
  for the rest. `EDGE_TABLES` stays: the snapshot export and `neighbors` use it.
  `cwe_catalog()` remains the way to count CWE entries.

- **Eight CLI commands: `pull`, `feeds`, `rules`, `run`, `check`, `normalize`,
  `graph` and `enrich`** — twenty-two top-level commands down to fourteen. Every
  one of them survives as an MCP tool (`pull`, `feeds`, `rules`, `normalize`,
  `enrich`, `graph`, `check_dns`, `check_whois`), so nothing was deleted from
  the engine and no subsystem became unreachable; what went is a second way to
  ask, from a shell, for things an agent asks for over `exfil mcp`.
  - `exfil datasets add <name> <reference>` is now the only CLI route into the
    catalog. It takes the same references `pull` did — `builtin://…`, a path, an
    `https://` URL — and stores the result under a name you choose.
  - Named runs can still be created and filtered on (`scan --name`,
    `analyze -n`, `search run=`), but no longer enumerated.
  - The post-scan hint, the empty-`datasets` message and the `cwe` not-found
    message no longer point at commands that are gone.

- `exfil server` and the HTTP/GraphQL API behind it (`crates/exfil-cli/src/
  server.rs`, `graphql.rs`, and the direct `async-graphql` dependency — the
  crate is still built, as `surrealdb-core` depends on it). A long-lived
  network listener is a standing attack surface and a second, drifting way to
  ask the same questions the CLI and MCP already answer; the CLI's tokio
  features narrow back to the workspace default with it. The desktop app was
  the only consumer, so it now **serves its own API in-process**
  (`app/src-tauri/src/server.rs`) on the same `127.0.0.1:8080` — same
  `/health`, `/stats` and `/findings` routes and the same JSON, but with no
  child process to spawn or supervise, no `exfil` binary needed on `PATH` (and
  so no `EXFIL_BIN`), and nothing listening unless the app is open. It resolves
  its store through `exfil_engine::setup::open_findings`, the same path the CLI
  takes, so both honour a `[database]` override identically; `EXFIL_STORE`
  points it at a specific store. GraphQL is not reproduced — the dashboard
  never used it.

- `exfil server` and the HTTP/GraphQL API behind it (`crates/exfil-cli/src/
  server.rs`, `graphql.rs`, and the `async-graphql` dependency). A long-lived
  network listener is a standing attack surface and a second, drifting way to
  ask the same questions the CLI and MCP already answer; the CLI's tokio
  features narrow back to the workspace default with it. The desktop app was
  the only consumer, so it now **serves its own API in-process**
  (`app/src-tauri/src/server.rs`) on the same `127.0.0.1:8080` — same
  `/health`, `/stats` and `/findings` routes and the same JSON, but with no
  child process to spawn or supervise, no `exfil` binary needed on `PATH` (and
  so no `EXFIL_BIN`), and nothing listening unless the app is open. It resolves
  its store through `exfil_engine::setup::open_findings`, the same path the CLI
  takes, so both honour a `[database]` override identically; `EXFIL_STORE`
  points it at a specific store. GraphQL is not reproduced — the dashboard
  never used it.

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

### Fixed

- `search run = nightly` (with spaces) returned nothing. The `run=` branch
  emits two SQL statements and the index of the row-bearing one was re-derived
  afterwards by a *different* test than the one that chose the branch —
  `starts_with("run=")` against `key.trim() == "run"`. They agreed on `run=x`
  and disagreed on `run = x`, which took the graph join and then read the `LET`
  slot. A filter is now parsed once into SQL + binding + result slot, so there
  is no second derivation to fall out of step.
- `findings_with_ids` claimed to reuse the search filter's grammar but
  re-implemented a stricter one: it omitted `run` and split on `=` without
  trimming, so `rule = aws-key` was an error there and a match in `search`.
  Both go through the one parser now.
- A free-text search was not trimmed while every `key=value` branch was, so
  `exfil search "aws-key "` — a trailing space from a shell completion — found
  nothing while `rule=aws-key ` found everything.
- JUnit reports emitted C0 control characters verbatim. They are illegal in XML
  1.0 at *any* escaping, so a snippet from an ANSI-coloured log produced a
  document every parser rejects, from a command that exited 0 — the CI ingest
  failed rather than the build gate.
- Markdown reports escaped only the snippet's pipes. A `|` in a path (legal on
  Linux) added a column and shifted every cell after it; a backtick in a
  snippet closed the code span early. Every cell is escaped now.
- The PDF reporter dropped the `…` that marks an elision, so a truncated path
  rendered as a complete-looking one pointing nowhere, and PII `•` masks
  vanished. Unrepresentable characters are transliterated rather than deleted.
- `fit::fitted_line` could return a line wider than the width it was given when
  the width left no room for the location.

- Piping any command into `head`, `less` or `grep -m` panicked. Rust ignores
  `SIGPIPE`, so `exfil search | head -5` kept writing past the fifth line until
  the closed pipe surfaced as an I/O error, which `println!` turned into a
  backtrace on the user's terminal. A panic hook now recognises that one panic
  and exits 0 — a closed reader ends a pipeline rather than failing it. Every
  other panic keeps its message and backtrace. Done with a hook rather than by
  restoring the default `SIGPIPE` handler, which would need `unsafe`, and this
  workspace denies it.

- The MCP `plugin_set` tool stored overrides without validating them. An
  override that fails its field's schema is ignored when the setting is read,
  so an agent got a success reply for a change that never took effect. It now
  validates against the same schemas the CLI does — which it could not before,
  because the plugin registry lived in the CLI binary where the server could
  not see it. `PLUGIN_SCHEMAS` and `find_plugin_field` moved to `exfil-remote`,
  beside the plugins that publish them.
- Added the matching `plugin_remove` MCP tool. `plugin_set` had no inverse, so
  an agent could store an override and never take it back off.

- `--fail-on` no longer gates a scan on findings from a tree it did not look
  at. One store can hold several roots, so scanning `./b` could fail a build on
  a critical that only exists under `./a`. The gate is now scoped to the tree
  being scanned. It still checks *stored* state rather than only what this run
  re-read — an incremental scan re-reads just the changed files, and a critical
  in a file that did not change is still a critical.
- A tripped `--fail-on` gate exits **2**, not 1. Both meant the same thing
  before, so CI could not tell "findings exceeded your threshold" from "exfil
  broke" and could not treat them differently. Errors still exit 1.

- **A `90c` budget no longer runs silently against an uncalibrated model.** The
  `c` budget is the one that reads a path score as a *probability* — it stops
  once the scanned files account for a share of the expected findings, which
  means summing them — but a model trained on a corpus too small to hold out a
  calibration set keeps the identity map, and its raw likelihood ratios pile up
  at 0 and 1. The sum was then not an expectation and the scan stopped nowhere
  in particular, while the coverage line reported the resulting file count with
  the same confidence as any other run. `scan` now says so before starting.
  It stays quiet for `%`/time/size budgets, which cap cost and never read the
  score as a probability, and for `--ranked`, which only orders.
  - The stale-ruleset and no-calibration checks are separate `if`s rather than
    match arms, because a model can be both and hearing only the first would
    leave the more consequential problem unsaid.
  - `PathModel::has_calibration()` is what `scan` asks. It reports whether a map
    was *fitted*, which is a different question from `eval::Report::is_calibrated`
    — whether the probabilities hold up against held-out outcomes. A model can
    have a calibration and still be a bad one; a model without one is certainly
    not producing probabilities.

- `fit_calibration` took the full-data model and discarded it (`let _ = full;`),
  under a comment promising a check that the map "must not flip the ranking".
  The invariant is real, but it is enforced in `fit_platt` — which refuses a
  slope ≤ 0 — and pinned by `eval::tests::calibration_preserves_the_ranking`.
  The parameter is gone and the reasoning now sits at the graft, where a reader
  asking "is it safe to put this map on those chains?" will actually look.

- Documentation drift, swept mechanically rather than by eye: 14 `file.rs:NNN`
  citations pointed at lines that no longer held the symbol they named, and
  `cli.md`'s whole handler table had gone stale again after the `hmm` commands
  landed. Every citation is now checked against the symbol's real definition.
  Also corrected: `build_pipeline` was cited in `main.rs` when it lives in
  `engine/setup.rs`; two pages still described scanning "a remote host over
  SSH", removed several commits ago; the crate count said 13 (it is 12); and
  the layer table still listed `exfil-llm`/`exfil-script`. `exfil-hmm` joins the
  layer diagram and the `hmm` commands join the CLI table.
- **A ranked scan could rank differently depending on how the root was typed.**
  The path model is trained on the store's canonical `abs` paths, but the walk
  scored whatever the user passed — so `exfil scan ./tree` fed the model a
  different token sequence than `exfil scan /abs/path/tree` for the very same
  file, and a budget then cut somewhere else. The walk now canonicalises once
  and uses that for both the stat lookup and the model, which also removes a
  duplicated `canonicalize` call per candidate.
- **A manifest at the root of any archive or disc image was silently skipped.**
  Expanded files carry a path like `archive.zip!package.json`, where `!` — not
  `/` — separates the container from the entry, so `Path::file_name` returned
  the whole string and a scanner gating on `name == "package.json"` never
  matched. The identical file one directory deeper (`archive.zip!x/package.json`)
  was found, which is what made it easy to miss. New `exfil_core::leaf_name`
  treats `!` as a separator alongside `/` and `\\`; the supply-chain, AST, log
  and gzip paths all route through it. Pre-existing, and it affected every
  container type.
- Removed two dead public items left behind by the two-chain rewrite:
  `Chain::posteriors` (the state posteriors the abandoned single-chain read-out
  needed; the classifier scores by likelihood ratio and never computes γ) and
  `Ctx::new` (a convenience constructor with no callers).

- `exfil hmm train` rejected a corpus where no file carried a finding, but
  accepted one where *every* file did — equally unlearnable, since the negative
  chain is then fitted on nothing and every path scores identically. Both
  degenerate cases are now reported, in the CLI and over MCP.


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
