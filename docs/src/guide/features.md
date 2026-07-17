# Features

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
  ClamAV scanning ship today, YARA is planned (see the
  [roadmap](../PLAN.md)).
- **Single portable binary** — pure Rust, builds on Linux, macOS, and Windows.
