# End-to-end fixtures

A scan-target tree that exercises the engine's edge cases in one pass, plus the
YARA ruleset that goes with it.

```sh
python3 e2e/generate.py                 # build e2e/files/
cargo run --bin exfil -- scan e2e/files --store e2e/store
```

Regenerating is idempotent — the tree is removed and rebuilt. Nothing here is
committed: see [Why it is generated](#why-it-is-generated).

## Shape

The tree is a single chain **20 folders deep**. Each level nests inside the one
above it and owns one family of edge cases:

```
e2e/files/01-secrets/02-pii/03-binary/…/19-mixed/20-leaf/
```

So a scan of `e2e/files` covers deep recursion and every family at once, and a
scan of any intermediate level covers the remainder. Level 20 nests ten more
directories below itself, so the deepest fixture sits 30 directories down.

## Levels

| Level | Covers |
|---|---|
| `01-secrets` | One file per built-in rule (AWS, GitHub, Slack, PEM, generic key, password-in-URL); multiple hits per file and per line; a dotfile; near-miss negatives |
| `02-pii` | Email, SSN, credit card (Luhn-valid *and* invalid), phone, IBAN; a bulk CSV for per-line attribution |
| `03-binary` | The `binary_safe` gate; NUL at byte 8191 vs. 8192 (the `BINARY_SNIFF_LEN` boundary); UTF-16; invalid UTF-8; empty and all-NUL files |
| `04-archives` | zip/tar/tar.gz/tgz/gz/jar/war; empty, duplicate-entry, traversal, absolute-path, unicode-entry, and corrupt archives |
| `05-sqlite` | `.db`/`.sqlite`/`.sqlite3`; all column types; blobs and NULLs; a `"`-containing table name; views and indexes; the row cap; a corrupt database |
| `06-false-extensions` | Text named `.db`/`.zip`/`.gz`, and real containers named `.txt`; case-insensitive extensions; double extensions |
| `07-manifests` | `package.json`, `Cargo.toml`, `requirements*.txt`, including malformed ones |
| `08-source` | Python/JS/Rust with dangerous calls, for the AST and taint scanners; syntactically broken and empty sources |
| `09-names` | Spaces, quotes, shell metacharacters, unicode, emoji, a newline in a filename, a non-UTF-8 filename, very long names |
| `10-ignores` | `.gitignore` rules (including negation); the unconditionally skipped `.git/` and `.exfil/` |
| `11-symlinks` | File, directory, dangling, absolute, self-loop, and two-link-cycle symlinks |
| `12-permissions` | chmod-000 file and directory, write-only file, a FIFO, an executable |
| `13-duplicates` | Identical content at several paths, a hard link, and one-byte-apart near-duplicates |
| `14-encodings` | UTF-8/UTF-16 BOMs, CRLF/CR/mixed line endings, latin-1, bidi and zero-width characters, no trailing newline |
| `15-nested-containers` | Nesting on both sides of `MAX_EXPAND_DEPTH`; mixed flavors; a database inside an archive and vice versa |
| `16-limits` | A multi-megabyte file with the secret at the very end, a 2 MiB single line, 300 small files, a high-ratio zip, a sparse file |
| `17-network` | IPv4/IPv6/private addresses, domains, URLs, punycode, a hosts file, and near-miss negatives |
| `18-logs` | syslog, JSON lines, Apache access, audit; a 100 KB log line; empty and whitespace-only logs |
| `19-mixed` | A realistic small project interleaving several families |
| `20-leaf` | Proves the walk reached 20 levels, plus ten more directories below |

## Fixtures that straddle a limit

The ones worth knowing about, because "no finding" is the *correct* result on
one side of each:

| Fixture | Inside the limit | Past it |
|---|---|---|
| `03-binary/nul-at-{8191,8192}.bin` | `8192` reads as text → regex runs | `8191` reads as binary → regex held back |
| `05-sqlite/many-rows.db` | marker at row 5 → found | marker at row 10 040 → cut by the 10 000-row cap |
| `15-nested-containers/nested-{6,12}.zip` | 6 wraps → payload found | 12 wraps → stopped by `MAX_EXPAND_DEPTH` (8) |
| `16-limits/over-scan-cap.bin` | `large.txt` (5 MiB) → scanned | 512 MiB + 1 → recorded and hashed, content unscanned (`MAX_SCAN_BYTES`) |

## Expected results

A clean run over the default tree:

```
scanned 1020 files (0 unchanged): 674 new matches, 3 unreadable
```

The three unreadable entries are the chmod-000 file, the write-only file, and
the file inside the chmod-000 directory — they must be *counted*, never fatal.
**Running as root changes this**: root can read all three, so the count drops to
zero and the match total rises.

Notable expectations, all of which a passing run satisfies:

- Every `06-false-extensions` file produces a finding. Expanders match on
  filename alone, so a text file named `notes.db` expands to nothing and must
  then be scanned as the text it is.
- `03-binary/blob.bin` produces a YARA hit (with `--yara`) but **no** regex hit,
  even though an AWS key sits in its bytes.
- Nothing under `10-ignores/.git/`, `.exfil/`, or the ignored paths appears.
- Nothing under `01-secrets/negative/` appears.

## YARA

`generate.py` also writes `e2e/rules/e2e.yar`, matching the `EVILMARKER` string
carried by the binary fixtures:

```sh
cargo run --bin exfil -- scan e2e/files --store e2e/store --yara e2e/rules/e2e.yar
```

## Why it is generated

The tree is built by a script rather than committed because several fixtures
are hostile to git: a nested `.git/`, chmod-000 entries, a FIFO, symlink loops,
a non-UTF-8 filename, and multi-megabyte blobs. `e2e/.gitignore` keeps
`files/` and `store/` out of the repository.

Pass `--large-mb N` to change the size of the large fixture (default 5), or
`--out DIR` to build somewhere else.

## Safety

Every "secret" is inert: syntactically valid but non-existent keys, RFC 5737 /
3849 documentation IP ranges, RFC 2606 example domains, and the standard
`4111…` test card number. Nothing here is a real credential, and nothing
resolves to a real host.
