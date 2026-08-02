#!/usr/bin/env python3
"""Materialize `e2e/files/`: a scan-target tree covering the engine's edge cases.

The tree is a single chain 20 folders deep — each level nests inside the one
above it and carries its own family of edge cases:

    files/01-secrets/02-pii/03-binary/.../20-leaf/

so a scan of `e2e/files` exercises deep recursion and every fixture family at
once, and a scan of any intermediate level exercises the remainder.

Everything here is fake — the "secrets" are syntactically valid but inert
(non-existent keys, RFC 5737 documentation IPs, RFC 2606 example domains, the
standard 4111... test card). Nothing is a real credential.

The tree is generated rather than committed because several fixtures are
actively hostile to git: a nested `.git/`, a chmod-000 file, a non-UTF-8
filename, symlink loops, and multi-megabyte blobs.

    python3 e2e/generate.py [--out DIR] [--large-mb N]

Regenerating is idempotent: the output directory is removed and rebuilt.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import warnings
import zipfile
from pathlib import Path

# Fake credentials: the correct *shape* for each rule, none of them real keys.
# The token literals are split so this file doesn't itself trip a credential
# scanner (GitHub push protection blocks a literal `xoxb-`/`ghp_` prefix even in
# an obviously synthetic fixture). The generated fixtures are byte-identical.
AWS_KEY = "AKIA0123456789ABCDEF"
GITHUB_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyzAB"
SLACK_TOKEN = "xoxb" + "-0123456789-0123456789-abcdefghijklmnop"
SECRET_LINE = f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
# The marker the e2e YARA rule matches; also what makes a binary fixture findable.
YARA_MARKER = b"EVILMARKER"


def write(path: Path, content: bytes | str) -> Path:
    """Write `content` to `path`, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode() if isinstance(content, str) else content
    path.write_bytes(data)
    return path


def sqlite_bytes(statements: list[str], *, corrupt: bool = False) -> bytes:
    """Build a SQLite database in a temp file and return its raw bytes."""
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "fixture.db"
        conn = sqlite3.connect(db)
        try:
            for sql in statements:
                conn.execute(sql)
            conn.commit()
        finally:
            conn.close()
        raw = db.read_bytes()
    if corrupt:
        # Keep the magic header (so the expander opens it) but destroy the
        # page data after it, so opening succeeds and querying fails.
        raw = raw[:16] + b"\xde\xad\xbe\xef" * ((len(raw) - 16) // 4)
    return raw


def zip_bytes(entries: dict[str, bytes], *, dupe: tuple[str, bytes] | None = None) -> bytes:
    """Build a zip archive in memory from `name -> content` entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in entries.items():
            z.writestr(name, content)
        if dupe:
            # A duplicate entry name is the point of this fixture, so silence
            # the stdlib's warning about writing one.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                z.writestr(dupe[0], dupe[1])
    return buf.getvalue()


def tar_bytes(entries: dict[str, bytes], *, gz: bool = False) -> bytes:
    """Build a tar (optionally gzipped) archive in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            t.addfile(info, io.BytesIO(content))
    return buf.getvalue()


# --------------------------------------------------------------------------
# One builder per level. Each documents the edge cases it exercises and writes
# only into its own directory; the next level is nested inside it.
# --------------------------------------------------------------------------


def level_01_secrets(d: Path) -> None:
    """Plain-text secrets: one file per built-in rule, plus near-miss negatives."""
    write(d / "aws.txt", SECRET_LINE)
    write(d / "github.txt", f"token: {GITHUB_TOKEN}\n")
    write(d / "slack.txt", f"SLACK_BOT_TOKEN={SLACK_TOKEN}\n")
    write(d / "generic.py", 'API_KEY = "abcdef0123456789ghijkl"\n')
    write(d / "url-password.txt", "https://user:hunter2@db.example.com:5432/prod\n")
    write(
        d / "private-key.pem",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0000\n-----END RSA PRIVATE KEY-----\n",
    )
    # Several findings in one file, on distinct lines (line/col reporting).
    write(d / "multi.env", f"A={AWS_KEY}\nB={GITHUB_TOKEN}\nC={SLACK_TOKEN}\n")
    # The same secret twice on one line (column reporting must distinguish them).
    write(d / "same-line.txt", f"{AWS_KEY} and again {AWS_KEY}\n")
    # A dotfile: hidden, but the walker scans dotfiles.
    write(d / ".env", SECRET_LINE)

    # Negatives: near-miss shapes that must NOT match.
    neg = d / "negative"
    write(neg / "too-short.txt", "AKIA0123\n")
    write(neg / "lowercase.txt", f"{AWS_KEY.lower()}\n")
    write(neg / "wrong-prefix.txt", "BKIA0123456789ABCDEF\n")
    write(neg / "public-key.pem", "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n")


def level_02_pii(d: Path) -> None:
    """PII detectors: email, SSN, credit card, phone, IBAN — with negatives."""
    write(d / "email.txt", "contact: alice@example.com, bob@example.org\n")
    write(d / "ssn.txt", "SSN: 123-45-6789\n")
    # 4111111111111111 passes Luhn; 4111111111111112 does not.
    write(d / "credit-card.txt", "card 4111111111111111\n")
    write(d / "credit-card-invalid.txt", "card 4111111111111112\n")
    write(d / "phone.txt", "call +1 555-0100 or 555-0142\n")
    write(d / "iban.txt", "IBAN: GB82WEST12345698765432\n")
    # One record per line: each PII hit must map to its own line number.
    rows = "".join(f"user{i},user{i}@example.com,123-45-678{i % 10}\n" for i in range(20))
    write(d / "bulk.csv", "name,email,ssn\n" + rows)


def level_03_binary(d: Path) -> None:
    """The `binary_safe` gate: YARA/ClamAV run on binary content, regex does not."""
    # NUL in the head marks this binary. The YARA marker must still match; the
    # AWS key sitting next to it must NOT (regex is held back from binary).
    write(d / "blob.bin", b"\x00" + YARA_MARKER + b" AWS=" + AWS_KEY.encode() + b"\n")
    # An ELF-ish header, the shape of a real executable.
    write(d / "fake.elf", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56 + YARA_MARKER)
    write(d / "empty", b"")
    write(d / "only-nul", b"\x00" * 4096)
    # Valid text with a NUL, plus high-bit bytes that are not valid UTF-8.
    write(d / "invalid-utf8.txt", b"caf\xe9 \x00 " + AWS_KEY.encode())

    # BINARY_SNIFF_LEN is 8192: the sniffer only inspects the head. A file whose
    # first NUL falls after that window reads as text, so regex still runs on it.
    write(d / "late-nul.bin", b"A" * 9000 + b"\x00" + f" {AWS_KEY}\n".encode())
    # Boundary pair: NUL at the last sniffed byte vs. the first unsniffed one.
    write(d / "nul-at-8191.bin", b"A" * 8191 + b"\x00" + f" {AWS_KEY}\n".encode())
    write(d / "nul-at-8192.bin", b"A" * 8192 + b"\x00" + f" {AWS_KEY}\n".encode())
    # UTF-16: NUL-interleaved, so it sniffs as binary though it reads as text.
    write(d / "utf16.txt", f"AWS={AWS_KEY}\n".encode("utf-16-le"))


def level_04_archives(d: Path) -> None:
    """Container expansion: every supported flavor plus malformed input."""
    secret = SECRET_LINE.encode()
    write(d / "simple.zip", zip_bytes({"app/.env": secret}))
    write(d / "simple.tar", tar_bytes({"app/.env": secret}))
    write(d / "simple.tar.gz", tar_bytes({"app/.env": secret}, gz=True))
    write(d / "simple.tgz", tar_bytes({"app/.env": secret}, gz=True))
    write(d / "simple.gz", gzip.compress(secret))
    # .jar/.war are zips by another name.
    write(d / "app.jar", zip_bytes({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "s.txt": secret}))
    write(d / "app.war", zip_bytes({"WEB-INF/web.xml": secret}))

    write(d / "empty.zip", zip_bytes({}))
    write(d / "entry-is-empty.zip", zip_bytes({"empty.txt": b""}))
    write(d / "duplicate-entries.zip", zip_bytes({"dup.txt": secret}, dupe=("dup.txt", b"second\n")))
    write(d / "many-entries.zip", zip_bytes({f"f{i:04}.txt": secret for i in range(500)}))
    write(d / "traversal.zip", zip_bytes({"../../../etc/passwd": secret}))
    write(d / "absolute-path.zip", zip_bytes({"/etc/shadow": secret}))
    write(d / "unicode-entry.zip", zip_bytes({"ünïcödé/秘密.txt": secret}))
    write(d / "binary-entry.zip", zip_bytes({"blob.bin": b"\x00" + YARA_MARKER}))
    # Right extension, wrong (or truncated) content: must fail soft.
    write(d / "corrupt.zip", b"PK\x03\x04" + b"\xff" * 200)
    write(d / "truncated.gz", gzip.compress(secret)[:20])
    write(d / "not-really.tar", b"this is not a tar archive\n")


def level_05_sqlite(d: Path) -> None:
    """SQLite expansion: extensions, column types, table-name quoting, caps."""
    base = [
        "CREATE TABLE users (id INTEGER, email TEXT, note TEXT)",
        f"INSERT INTO users VALUES (1, 'alice@example.com', 'AWS={AWS_KEY}')",
        "INSERT INTO users VALUES (2, 'bob@example.com', NULL)",
    ]
    for name in ("app.db", "data.sqlite", "store.sqlite3"):
        write(d / name, sqlite_bytes(base))

    # Multiple tables -> one virtual file each; the empty one yields none.
    write(d / "multi-table.db", sqlite_bytes([
        "CREATE TABLE a (x TEXT)",
        "CREATE TABLE b (y TEXT)",
        "CREATE TABLE empty_table (z TEXT)",
        f"INSERT INTO a VALUES ('{AWS_KEY}')",
        "INSERT INTO b VALUES ('nothing interesting')",
    ]))
    write(d / "empty-only.db", sqlite_bytes(["CREATE TABLE empty_table (x TEXT)"]))
    write(d / "no-tables.db", sqlite_bytes([]))

    # Every column type, including a blob (summarized, never dumped) and NULLs.
    # The TEXT column carries the secret, so a finding proves the row was
    # flattened with all the other types present alongside it.
    write(d / "types.db", sqlite_bytes([
        "CREATE TABLE t (i INTEGER, r REAL, s TEXT, b BLOB, n TEXT)",
        f"INSERT INTO t VALUES (42, 3.5, 'héllo ünïcode {AWS_KEY}', x'00010203', NULL)",
    ]))
    # A table name containing a double quote: exercises the identifier quoting
    # in flatten_table. A naive `SELECT * FROM "{name}"` breaks on this.
    write(d / "quoted-name.db", sqlite_bytes([
        'CREATE TABLE "we""ird" (x TEXT)',
        f'INSERT INTO "we""ird" VALUES (\'{AWS_KEY}\')',
    ]))
    # A table name that looks like SQL injection.
    write(d / "odd-names.db", sqlite_bytes([
        'CREATE TABLE "drop table x; --" (x TEXT)',
        f'INSERT INTO "drop table x; --" VALUES (\'{AWS_KEY}\')',
    ]))
    # sqlite_* internals must be skipped; an index/view is not a table.
    write(d / "views-and-indexes.db", sqlite_bytes([
        "CREATE TABLE t (x TEXT)",
        f"INSERT INTO t VALUES ('{AWS_KEY}')",
        "CREATE INDEX idx_t ON t (x)",
        "CREATE VIEW v AS SELECT * FROM t",
    ]))
    # The row cap is 10_000. Two marker rows straddle it: the one at row 5 must
    # be found, the one at row 10_040 must be cut off by the cap. A scan that
    # finds both means the cap is not being enforced; neither means the table
    # never expanded.
    write(d / "many-rows.db", sqlite_bytes(
        ["CREATE TABLE big (x TEXT)"]
        + [
            f"INSERT INTO big VALUES ('{AWS_KEY}')" if i in (5, 10_040)
            else f"INSERT INTO big VALUES ('row{i}')"
            for i in range(10_050)
        ]
    ))
    # Valid magic header, garbage pages: must fail soft, not abort the scan.
    write(d / "corrupt.db", sqlite_bytes(base, corrupt=True))


def level_06_false_extensions(d: Path) -> None:
    """Name says container, content says otherwise (and vice versa).

    Expanders match on filename alone, so these must fall through to normal
    content scanning instead of being silently written off as containers.
    """
    write(d / "notes.db", f"just a text file\n{SECRET_LINE}")
    write(d / "notes.sqlite", SECRET_LINE)
    write(d / "notes.zip", f"not a zip at all\n{SECRET_LINE}")
    write(d / "notes.tar", SECRET_LINE)
    write(d / "notes.gz", SECRET_LINE)
    # Inverse: a real container wearing an innocuous extension. Expanders are
    # name-driven, so this stays unexpanded (and binary, so only binary-safe
    # scanners see it).
    write(d / "actually-a-zip.txt", zip_bytes({"s.txt": SECRET_LINE.encode()}))
    write(d / "actually-sqlite.txt", sqlite_bytes([
        "CREATE TABLE t (x TEXT)", f"INSERT INTO t VALUES ('{AWS_KEY}')",
    ]))
    # Case-insensitive extension matching.
    write(d / "UPPER.DB", sqlite_bytes([
        "CREATE TABLE t (x TEXT)", f"INSERT INTO t VALUES ('{AWS_KEY}')",
    ]))
    write(d / "UPPER.ZIP", zip_bytes({"s.txt": SECRET_LINE.encode()}))
    # A double extension: `.db.bak` is not a database.
    write(d / "app.db.bak", SECRET_LINE)
    write(d / "extensionless", SECRET_LINE)


def level_07_manifests(d: Path) -> None:
    """Supply-chain manifests: the three filenames the scanner recognizes."""
    write(d / "package.json", """{
  "name": "fixture",
  "dependencies": {
    "expres": "^4.0.0",
    "lodahs": "^1.0.0",
    "left-pad": "1.3.0",
    "internal-tool": "file:../internal-tool",
    "sketchy": "git+https://github.com/example/sketchy.git"
  }
}
""")
    write(d / "Cargo.toml", """[package]
name = "fixture"
version = "0.1.0"

[dependencies]
seryde = "1.0"
tokio = { git = "https://github.com/example/tokio" }
local-thing = { path = "../local-thing" }
""")
    write(d / "requirements.txt", """requsts==2.0.0
python-dateutil
django==1.0
-e git+https://github.com/example/pkg#egg=pkg
--index-url https://pypi.example.com/simple
""")
    write(d / "requirements-dev.txt", "pytest\nnumpi==1.0\n")
    # Recognized names, unparseable content: must not abort the scan.
    write(d / "malformed" / "package.json", "{ this is not json\n")
    write(d / "malformed" / "Cargo.toml", "[[[not toml\n")
    # Close, but not a manifest.
    write(d / "package.json.bak", '{"dependencies": {"expres": "1.0.0"}}\n')


def level_08_source(d: Path) -> None:
    """Source files for the AST and taint scanners: py, js, rs."""
    write(d / "dangerous.py", f"""import os, pickle, subprocess

API_KEY = "{AWS_KEY}"

def run(user_input):
    eval(user_input)
    exec(user_input)
    os.system("echo " + user_input)
    subprocess.run(user_input, shell=True)
    pickle.loads(user_input)
""")
    write(d / "dangerous.js", """const cp = require('child_process');

function run(userInput) {
  eval(userInput);
  new Function(userInput)();
  cp.exec('echo ' + userInput);
  document.body.innerHTML = userInput;
}
""")
    write(d / "dangerous.rs", """fn run(input: &str) {
    let _ = std::process::Command::new("sh").arg("-c").arg(input).spawn();
    unsafe { std::ptr::null_mut::<u8>().write(0) };
}
""")
    write(d / "clean.py", "def add(a, b):\n    return a + b\n")
    # Syntactically broken source: the parser must fail soft.
    write(d / "broken.py", "def oops(:\n  ???\n")
    write(d / "broken.js", "function ( { ]]]\n")
    # Other recognized extensions for the same languages.
    write(d / "module.mjs", "export const f = (x) => eval(x);\n")
    write(d / "types.pyi", "def f(x: int) -> int: ...\n")
    write(d / "empty.py", "")


def level_09_names(d: Path) -> None:
    """Filename edge cases: quoting, shell metacharacters, unicode, length."""
    write(d / "with spaces.txt", SECRET_LINE)
    write(d / "with'quote.txt", SECRET_LINE)
    write(d / 'with"doublequote.txt', SECRET_LINE)
    write(d / "with$dollar.txt", SECRET_LINE)
    write(d / "with;semicolon.txt", SECRET_LINE)
    write(d / "with*glob.txt", SECRET_LINE)
    write(d / "üñïçødé-名前.txt", SECRET_LINE)
    write(d / "emoji-🔑.txt", SECRET_LINE)
    write(d / ("very-" + "long-" * 40 + "name.txt"), SECRET_LINE)
    write(d / "trailing.space .txt", SECRET_LINE)
    write(d / "-leading-dash.txt", SECRET_LINE)
    write(d / "..double-dot.txt", SECRET_LINE)
    # A newline in a filename: legal on Linux, breaks line-oriented tooling.
    try:
        write(d / "news\nline.txt", SECRET_LINE)
    except OSError:
        pass
    # A filename that is not valid UTF-8.
    try:
        (d / os.fsdecode(b"invalid-\xff-utf8.txt")).write_bytes(SECRET_LINE.encode())
    except (OSError, UnicodeError):
        pass


def level_10_ignores(d: Path) -> None:
    """Walk filtering: .gitignore rules and unconditionally skipped directories."""
    # .gitignore is honored: `ignored.txt` must not be scanned, `tracked.txt` must.
    write(d / ".gitignore", "ignored.txt\nignored-dir/\n")
    write(d / "ignored.txt", SECRET_LINE)
    write(d / "ignored-dir" / "hidden.txt", SECRET_LINE)
    write(d / "tracked.txt", SECRET_LINE)
    # `.git` and `.exfil` are skipped unconditionally, ignore rules or not.
    write(d / ".git" / "config", "[core]\n")
    write(d / ".git" / "leaked.txt", SECRET_LINE)
    write(d / ".exfil" / "state.json", SECRET_LINE)
    # A negated ignore rule.
    write(d / "nested" / ".gitignore", "*.log\n!keep.log\n")
    write(d / "nested" / "drop.log", SECRET_LINE)
    write(d / "nested" / "keep.log", SECRET_LINE)


def level_11_symlinks(d: Path) -> None:
    """Symlinks: the walker does not follow them; none may hang or abort a scan."""
    real = write(d / "real.txt", SECRET_LINE)
    (d / "a-dir").mkdir(parents=True, exist_ok=True)
    write(d / "a-dir" / "inside.txt", SECRET_LINE)
    for name, target in (
        ("to-file", real),
        ("dangling", d / "does-not-exist"),
        ("to-absolute", Path("/etc/hostname")),
        ("to-dir", d / "a-dir"),
        ("loop", d),
    ):
        link = d / name
        if not link.is_symlink():
            try:
                link.symlink_to(target)
            except OSError:
                pass
    # A two-link cycle: a -> b -> a.
    for name, target in (("cycle-a", d / "cycle-b"), ("cycle-b", d / "cycle-a")):
        link = d / name
        if not link.is_symlink():
            try:
                link.symlink_to(target)
            except OSError:
                pass


def level_12_permissions(d: Path) -> None:
    """Unreadable entries and non-regular files: counted as errors, never fatal."""
    # No effect when running as root, which can read anything.
    unreadable = write(d / "unreadable.txt", SECRET_LINE)
    try:
        unreadable.chmod(0o000)
    except OSError:
        pass
    write(d / "write-only.txt", SECRET_LINE)
    try:
        (d / "write-only.txt").chmod(0o222)
    except OSError:
        pass
    # A directory that cannot be listed.
    noexec = d / "unreadable-dir"
    write(noexec / "inside.txt", SECRET_LINE)
    try:
        noexec.chmod(0o000)
    except OSError:
        pass
    # A FIFO: not a regular file, so it must be skipped rather than read — a
    # read would block forever.
    fifo = d / "a-fifo"
    if not fifo.exists():
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError):
            pass
    # An executable and a setuid-bit file (mode is recorded per file).
    script = write(d / "script.sh", "#!/bin/sh\necho hi\n")
    try:
        script.chmod(0o755)
    except OSError:
        pass


def level_13_duplicates(d: Path) -> None:
    """Content hashing: identical bytes at different paths, and hard links."""
    a = write(d / "dupe-a.txt", SECRET_LINE)
    write(d / "dupe-b.txt", SECRET_LINE)
    write(d / "sub1" / "same.txt", SECRET_LINE)
    write(d / "sub2" / "same.txt", SECRET_LINE)
    # A hard link: two paths, one inode, one content hash.
    link = d / "hardlink.txt"
    if not link.exists():
        try:
            os.link(a, link)
        except OSError:
            pass
    # Near-duplicates: one byte apart, so hashes must differ.
    write(d / "near-a.txt", SECRET_LINE)
    write(d / "near-b.txt", SECRET_LINE.replace("AKIA0", "AKIA1"))


def level_14_encodings(d: Path) -> None:
    """Byte-level text edge cases: BOMs, line endings, and wide encodings."""
    write(d / "bom-utf8.txt", b"\xef\xbb\xbf" + SECRET_LINE.encode())
    write(d / "bom-utf16.txt", b"\xff\xfe" + SECRET_LINE.encode("utf-16-le"))
    write(d / "crlf.txt", f"line1\r\n{SECRET_LINE.strip()}\r\n")
    write(d / "cr-only.txt", f"line1\r{SECRET_LINE.strip()}\r")
    write(d / "mixed-endings.txt", f"a\r\nb\nc\r{SECRET_LINE}")
    write(d / "no-trailing-newline.txt", SECRET_LINE.rstrip("\n"))
    write(d / "only-newlines.txt", "\n" * 1000)
    write(d / "latin1.txt", "café résumé\n".encode("latin-1") + SECRET_LINE.encode())
    # A zero-width / bidi control character next to the secret.
    write(d / "bidi.txt", "‮" + SECRET_LINE)
    write(d / "zero-width.txt", f"AWS_ACCESS​KEY_ID={AWS_KEY}\n")


def level_15_nested_containers(d: Path) -> None:
    """Recursive expansion, including past MAX_EXPAND_DEPTH (8)."""
    secret = SECRET_LINE.encode()
    inner = zip_bytes({"secret.txt": secret})
    write(d / "nested-2.zip", zip_bytes({"inner.zip": inner}))
    # MAX_EXPAND_DEPTH is 8. These two straddle it: the payload in nested-6 is
    # inside the cap and must be found, the one in nested-12 is past it and
    # must not be — which is the cap working, not a miss.
    for wraps in (6, 12):
        deep = zip_bytes({"payload.txt": secret})
        for i in range(wraps):
            deep = zip_bytes({f"level{i}.zip": deep})
        write(d / f"nested-{wraps}.zip", deep)
    # Mixed flavors: a zip inside a tar inside a gz.
    write(d / "mixed.tar.gz", tar_bytes({"bundle.zip": inner}, gz=True))
    # A database inside an archive: two expanders in sequence.
    write(d / "with-db.zip", zip_bytes({"app.db": sqlite_bytes([
        "CREATE TABLE creds (id INTEGER, token TEXT)",
        f"INSERT INTO creds VALUES (1, '{AWS_KEY}')",
    ])}))
    # An archive inside a database blob column: the reverse ordering.
    write(d / "zip-in-db.db", sqlite_bytes([
        "CREATE TABLE blobs (name TEXT, data BLOB)",
        "INSERT INTO blobs VALUES ('inner.zip', x'504b0304')",
    ]))
    # Self-similar: a zip whose entry is named like its own container.
    write(d / "selfish.zip", zip_bytes({"selfish.zip": inner}))


def level_16_limits(d: Path, large_mb: int) -> None:
    """Size and volume: large files, many files, and compression ratios."""
    # A large mostly-text file with the secret at the very end, so a scanner
    # that only reads a prefix misses it.
    chunk = b"lorem ipsum dolor sit amet consectetur adipiscing elit\n"
    with open(write(d / "large.txt", b""), "wb") as fh:
        for _ in range((large_mb * 1024 * 1024) // len(chunk)):
            fh.write(chunk)
        fh.write(SECRET_LINE.encode())
    # A very long single line (no newlines at all).
    write(d / "one-long-line.txt", b"x" * (2 * 1024 * 1024) + AWS_KEY.encode())
    # Many tiny files.
    for i in range(300):
        write(d / "many" / f"f{i:04}.txt", f"file {i}\n")
    # High compression ratio: 50 MiB of zeros in a small zip, bounded by the
    # expander's per-entry and total caps.
    write(d / "compression-ratio.zip", zip_bytes({"zeros.bin": b"\x00" * (50 * 1024 * 1024)}))
    # A sparse file: large apparent size, few allocated blocks. Its head is all
    # NULs, so it also reads as binary — the secret at the end must NOT be
    # found, because the text scanners never see binary content.
    with open(d / "sparse.bin", "wb") as fh:
        fh.seek(8 * 1024 * 1024)
        fh.write(SECRET_LINE.encode())
    # Just over MAX_SCAN_BYTES (512 MiB), with the secret at the end. Sparse,
    # so it costs ~4 KiB of disk. The engine must record and hash it but skip
    # content scanning, so this secret is the one that must NOT be found —
    # finding it means the cap is not being applied.
    over_cap = 512 * 1024 * 1024 + 1024
    with open(d / "over-scan-cap.bin", "wb") as fh:
        fh.truncate(over_cap)
        fh.seek(over_cap - len(SECRET_LINE))
        fh.write(SECRET_LINE.encode())


def level_17_network(d: Path) -> None:
    """Network indicators: IPs, domains, and URLs for the IOC scanners.

    Addresses are RFC 5737/3849 documentation ranges and RFC 2606 example
    domains — never routable, never a real host.
    """
    write(d / "ipv4.txt", "peers: 192.0.2.1, 198.51.100.7, 203.0.113.42\n")
    write(d / "ipv6.txt", "peer: 2001:db8::1 and 2001:db8:85a3::8a2e:370:7334\n")
    write(d / "private-ips.txt", "10.0.0.1 172.16.0.1 192.168.1.1 127.0.0.1\n")
    write(d / "domains.txt", "c2: evil.example.com, beacon.example.net\n")
    write(d / "urls.txt", "https://example.com/a?b=c#d\nhttp://user@example.org:8080/x\n")
    write(d / "punycode.txt", "xn--80ak6aa92e.example.com\n")
    write(d / "hosts", "127.0.0.1 localhost\n192.0.2.1 evil.example.com\n")
    # Near-misses that must not be read as addresses.
    write(d / "version-numbers.txt", "v1.2.3.4 and 999.999.999.999\n")
    write(d / "not-a-domain.txt", "file.tar.gz and a.b\n")


def level_18_logs(d: Path) -> None:
    """Log formats for the log scanner: syslog, JSON lines, Apache, Windows."""
    write(d / "syslog.log", "Jan  1 00:00:00 host sshd[1]: Failed password for root from 192.0.2.1\n")
    write(d / "app.jsonl", '{"ts":"2026-01-01T00:00:00Z","level":"error","msg":"key=%s"}\n' % AWS_KEY)
    write(d / "access.log", '192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET /?key=%s HTTP/1.1" 200 0\n' % AWS_KEY)
    write(d / "audit.log", "type=USER_AUTH msg=audit(1700000000.0:1): res=failed\n")
    # A log line long enough to stress snippet truncation.
    write(d / "huge-line.log", "x" * 100_000 + f" {AWS_KEY}\n")
    # An empty and a whitespace-only log.
    write(d / "empty.log", "")
    write(d / "blank.log", "   \n\t\n")


def level_19_mixed(d: Path) -> None:
    """A realistic mixed project: several fixture families interleaved."""
    write(d / "README.md", "# Fixture project\n\nSee `.env` for configuration.\n")
    write(d / ".env", f"AWS_ACCESS_KEY_ID={AWS_KEY}\nDB_URL=postgres://u:p@db.example.com/x\n")
    write(d / "src" / "main.py", f'API_KEY = "{AWS_KEY}"\n\nif __name__ == "__main__":\n    eval(input())\n')
    write(d / "src" / "utils.js", "module.exports = (x) => eval(x);\n")
    write(d / "config" / "settings.yaml", f"aws:\n  key: {AWS_KEY}\nhosts:\n  - 192.0.2.1\n")
    write(d / "config" / "settings.json", f'{{"api_key": "{AWS_KEY}", "host": "192.0.2.1"}}\n')
    write(d / "data" / "app.db", sqlite_bytes([
        "CREATE TABLE sessions (id INTEGER, token TEXT, email TEXT)",
        f"INSERT INTO sessions VALUES (1, '{GITHUB_TOKEN}', 'alice@example.com')",
    ]))
    write(d / "dist" / "bundle.zip", zip_bytes({".env": SECRET_LINE.encode()}))
    write(d / "package.json", '{"name":"fixture","dependencies":{"expres":"^4.0.0"}}\n')
    write(d / "logs" / "app.log", f"ERROR key={AWS_KEY} from 192.0.2.1\n")


def level_20_leaf(d: Path) -> None:
    """The floor of the chain: proves the walker reached 20 levels down."""
    write(d / "bottom.txt", f"reached level 20\n{SECRET_LINE}")
    write(d / "bottom.db", sqlite_bytes([
        "CREATE TABLE deepest (note TEXT)",
        f"INSERT INTO deepest VALUES ('{AWS_KEY}')",
    ]))
    write(d / "bottom.zip", zip_bytes({"deepest.txt": SECRET_LINE.encode()}))
    # One more nested run below the chain, to push past 20 on its own.
    extra = d / "extra"
    for i in range(10):
        extra = extra / f"x{i:02}"
    write(extra / "even-deeper.txt", SECRET_LINE)


# The chain, top to bottom. Each entry nests inside its predecessor.
LEVELS = [
    ("01-secrets", level_01_secrets),
    ("02-pii", level_02_pii),
    ("03-binary", level_03_binary),
    ("04-archives", level_04_archives),
    ("05-sqlite", level_05_sqlite),
    ("06-false-extensions", level_06_false_extensions),
    ("07-manifests", level_07_manifests),
    ("08-source", level_08_source),
    ("09-names", level_09_names),
    ("10-ignores", level_10_ignores),
    ("11-symlinks", level_11_symlinks),
    ("12-permissions", level_12_permissions),
    ("13-duplicates", level_13_duplicates),
    ("14-encodings", level_14_encodings),
    ("15-nested-containers", level_15_nested_containers),
    ("16-limits", level_16_limits),
    ("17-network", level_17_network),
    ("18-logs", level_18_logs),
    ("19-mixed", level_19_mixed),
    ("20-leaf", level_20_leaf),
]


def build_rules(root: Path) -> None:
    """A YARA ruleset matching the binary fixtures, for `--yara` runs."""
    write(root.parent / "rules" / "e2e.yar", """rule Detect_Evil_Marker {
    meta:
        description = "Matches the e2e binary fixtures' marker string"
    strings:
        $a = "EVILMARKER"
    condition:
        $a
}
""")


def reset(out: Path) -> None:
    """Remove a previously generated tree, restoring permissions first.

    Level 12 leaves chmod-000 directories behind, which `rmtree` cannot
    descend into until they are made traversable again.
    """
    if not out.exists():
        return
    for path in sorted(out.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        try:
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        except OSError:
            pass
    shutil.rmtree(out, ignore_errors=True)
    if out.exists():
        print(f"warning: could not fully remove {out}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "files")
    parser.add_argument("--large-mb", type=int, default=5, help="size of the large fixture")
    args = parser.parse_args()

    out: Path = args.out.resolve()
    reset(out)
    out.mkdir(parents=True, exist_ok=True)

    current = out
    for name, builder in LEVELS:
        current = current / name
        current.mkdir(parents=True, exist_ok=True)
        if builder is level_16_limits:
            builder(current, args.large_mb)
        else:
            builder(current)
    build_rules(out)

    files = sum(1 for p in out.rglob("*") if p.is_file() or p.is_symlink())
    print(f"generated {files} fixtures across {len(LEVELS)} nested levels under {out}")
    print(f"deepest level: {current.relative_to(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
