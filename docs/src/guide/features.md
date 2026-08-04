# Features

- **Fast parallel scanning** — gitignore-aware walker fanned out across
  threads; every file is read once, blake3-hashed, and offered to each scanner.
- **Graph storage with provenance** — findings are records linked by real
  graph edges (`finding → in_file → file`, `scan → includes → file`), addressed
  by content hash for dedup, queryable with SurrealQL.
- **Supply-chain compromise detection** — dependency manifests (`package.json`,
  `requirements*.txt`, `Cargo.toml`) are checked for known-malicious packages,
  typosquats (Damerau-Levenshtein against popular package names), malicious
  install hooks, and cleartext dependency sources.
- **Probability-ranked scanning** — a hidden Markov model over path components,
  trained on the scans already in your store (every recorded file is a sample;
  whether it carried a finding is the label), estimates where findings are
  likely. `exfil scan --ranked` scans worst-first; `--budget 20%` / `30s` /
  `500mb` caps the work and spends it where it counts. A budgeted scan states
  its coverage and refuses to combine with `--fail-on`, because a clean result
  from a partial scan is not evidence a tree is clean. Changed files always
  outrank unchanged ones — only they can produce new findings.

- **Findings by directory** — every report names the directories holding the
  most findings, with each one's share, so you know where to start rather than
  only what is wrong.

- **Incremental rescans, honestly** — a stat fast-path (size + mtime) skips re-reading
  unchanged files; re-scanned files have their findings replaced, never
  duplicated.
- **Archive-aware** — zip/jar/war/tar/tar.gz/gz are unpacked into virtual files
  that flow through the same scanners (depth- and size-capped against bombs),
  each linked to its container in the graph, so a secret inside `dist.zip →
  app/.env` is found exactly as if it sat on disk.
- **Disc-image aware** — `.iso`/`.img` disc images are expanded into the files
  they contain (`appliance.iso!etc/shadow`), so a secret on installer media or
  an appliance image is found by the ordinary scanners. Reads the **Joliet**
  tree when present, which preserves real filenames — plain ISO 9660 folds them
  to uppercase 8.3, turning `package.json` into `PACKAGE.JSO` and hiding it from
  the supply-chain scanner. Pure-Rust reader, bounds-checked, depth- and
  cycle-capped.

- **SQLite-aware** — `.db`/`.sqlite`/`.sqlite3` files (sniffed by magic header)
  have every table's rows flattened into a virtual file, row/table-count
  capped, so the same scanners catch a secret or PII value sitting in a
  database column exactly as if it were a plain text file.
- **Binary-signature scanning** — YARA and ClamAV still match raw binary
  content directly; text-oriented scanners (regex, PII, IOC) skip binary
  files, since matching noise as text would only produce garbage findings.
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
- **Datasets & IOC feeds** — `exfil dataset add <name> <ref>` pulls a rule/IOC
  dataset (builtin, local file, or `https://`) into the catalog,
  `exfil dataset update` re-fetches everything configured under `[[update]]`,
  and `exfil dataset` list/get/remove manages what is there. IOCs ride the same pipeline: content
  indicators are regex rules, file-hash indicators (`sha256:…`) match digests.
- **Malware signatures** — a pure-Rust ClamAV-signature scanner matches files
  against `.hdb`/`.hsb` hash signatures and literal `.ndb` body signatures
  (configured under `[plugins.clamav]`), no libclamav needed.
- **YARA** — pure-Rust `yara-x` matches files against YARA rules configured
  under `[plugins.yara]`, with severity/CWE read from each rule's `meta` block.
- **Unified scan target** — one `exfil scan [target]` command dispatches on the
  shape of `target`: a local path or nothing scans the directory tree,
  `processes` scans running processes, one or more `host:port` grabs TCP
  banners, a host/CIDR with `--ports` sweeps and grabs banners, and an
  `http(s)://` URL crawls the site (`--driver` for JS-rendered pages). `-a`/`-p`
  label the summary active/passive; it's otherwise inferred from the target.
- **Plugin architecture** — scanners, dataset sources, and reporters are traits;
  regex, supply-chain, archive/SQLite expansion, tree-sitter AST, taint, IOC,
  ClamAV, and YARA scanning all ship today (see the [roadmap](../PLAN.md) for
  what's next).
- **Single portable binary** — pure Rust, builds on Linux, macOS, and Windows.
