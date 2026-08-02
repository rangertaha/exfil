//! SQLite database expansion: a [`FileTask`] that turns a `.db`/`.sqlite`
//! file's tables into [`VirtualFile`]s of flattened row text, so every other
//! scanner (secrets, PII, IOC, hash) sees database contents without knowing
//! anything about SQLite — the same `Bytes → Files` seam
//! [`ArchiveExpander`](crate::ArchiveExpander) uses for zip/tar.
//!
//! One virtual file per table (path `container!table`), one line per row
//! (`col1=val1 col2=val2 …`, NULLs omitted, blobs shown as a byte count
//! rather than dumped) — line-oriented enough that scanners which iterate
//! `text.lines()` (like the PII scanner) map each row to its own finding
//! line.
//!
//! # Safety
//!
//! An arbitrary `.db`-named file is untrusted input: it might not actually be
//! a SQLite database (sniffed by magic header before opening), might be
//! corrupt, or might be enormous. Opened read-only, with [`Limits`] bounding
//! the work at both ends — `max_input_bytes` before the database is staged to
//! a temp file, and row/table/byte caps on the flattened output — mirroring
//! the archive expander's `Limits`. Anything over an output limit is
//! truncated, not failed; an oversize, unreadable, or non-SQLite file yields
//! no files rather than failing the scan.

use std::path::Path;

use anyhow::Result;
use exfil_core::VirtualFile;
use exfil_task::{Artifact, ArtifactKind, FileTask};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

/// The first 16 bytes of every SQLite database file.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// Caps that bound the work a database can cause.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest database this task will open at all. Reading a database means
    /// staging its bytes in a temp file (SQLite cannot open a memory buffer),
    /// so unlike the other caps — which bound *output* — this one has to bound
    /// the *input*, before any bytes are written. Without it a multi-gigabyte
    /// `.db` would be copied to the temp directory in full, once per walker
    /// thread, before a single row was read.
    pub max_input_bytes: usize,
    /// Largest number of rows to read from a single table.
    pub max_rows_per_table: usize,
    /// Largest flattened text a single table can contribute (bytes).
    pub per_table: usize,
    /// Largest total flattened text across all tables (bytes).
    pub total: usize,
    /// Maximum number of tables to expand.
    pub max_tables: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_rows_per_table: 10_000,
            per_table: 8 * 1024 * 1024, // 8 MiB
            total: 64 * 1024 * 1024,    // 64 MiB
            max_tables: 500,
        }
    }
}

/// Expands SQLite database files into one virtual text file per table.
#[derive(Debug, Default)]
pub struct SqliteExpander {
    limits: Limits,
}

impl SqliteExpander {
    /// An expander with custom limits.
    pub fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }

    /// Whether `path`'s extension names a SQLite database.
    fn has_sqlite_extension(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "db" | "sqlite" | "sqlite3"))
    }
}

impl FileTask for SqliteExpander {
    fn name(&self) -> &str {
        "sqlite-expand"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Bytes
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Files
    }

    fn applies(&self, path: &Path) -> bool {
        Self::has_sqlite_extension(path)
    }

    /// A database file is binary by nature — reading its tables is exactly
    /// this task's job, so it must not be held back from binary content.
    fn binary_safe(&self) -> bool {
        true
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Bytes(bytes) = input else {
            anyhow::bail!("sqlite-expand: expected Bytes input");
        };
        // A `.db`-named file need not actually be a SQLite database (many
        // apps use that extension for their own formats); sniff the magic
        // header before ever opening it, so a false-extension-match yields
        // no files rather than a confusing open error.
        if !bytes.starts_with(SQLITE_MAGIC) {
            return Ok(Artifact::Files(Vec::new()));
        }
        // Refuse an oversize database before staging it to disk, not after.
        if bytes.len() > self.limits.max_input_bytes {
            return Ok(Artifact::Files(Vec::new()));
        }
        let container = path.to_string_lossy();
        Ok(Artifact::Files(expand_sqlite(
            &container,
            bytes,
            &self.limits,
        )))
    }
}

/// Build the `container!table` display path used for expanded tables.
fn vpath(container: &str, table: &str) -> String {
    format!("{container}!{table}")
}

/// Load `bytes` as a SQLite database (via a temp file — SQLite has no stable
/// "open from an in-memory buffer" API) and flatten every user table's rows
/// into one virtual file each, bounded by `limits`.
fn expand_sqlite(container: &str, bytes: &[u8], limits: &Limits) -> Vec<VirtualFile> {
    let Ok(tmp) = tempfile::NamedTempFile::new() else {
        return Vec::new();
    };
    if std::fs::write(tmp.path(), bytes).is_err() {
        return Vec::new();
    }
    let Ok(conn) = Connection::open_with_flags(tmp.path(), OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return Vec::new();
    };

    let Ok(tables) = list_tables(&conn) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut total = 0usize;
    for table in tables.iter().take(limits.max_tables) {
        if total >= limits.total {
            break;
        }
        let Ok(text) = flatten_table(&conn, table, limits) else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        total += text.len();
        out.push(VirtualFile {
            path: vpath(container, table),
            content: text.into_bytes(),
        });
    }
    out
}

/// List user-created table names (skipping SQLite's own `sqlite_*` bookkeeping
/// tables), in a stable order.
fn list_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
}

/// Flatten one table's rows into `col1=val1 col2=val2 …` lines, one row per
/// line, NULLs omitted and blobs shown as a byte count rather than dumped.
/// Bounded by `limits.max_rows_per_table` and `limits.per_table`.
fn flatten_table(conn: &Connection, table: &str, limits: &Limits) -> rusqlite::Result<String> {
    // `table` came from sqlite_master, not user input, but it's still quoted
    // (doubling any embedded quote) since a table name can contain arbitrary
    // characters, including `"`.
    let quoted = table.replace('"', "\"\"");
    let mut stmt = conn.prepare(&format!("SELECT * FROM \"{quoted}\""))?;
    let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();

    let mut out = String::new();
    let mut rows = stmt.query([])?;
    let mut row_count = 0usize;
    while let Some(row) = rows.next()? {
        if row_count >= limits.max_rows_per_table || out.len() >= limits.per_table {
            break;
        }
        let mut line = String::new();
        for (i, col) in columns.iter().enumerate() {
            let value = match row.get_ref(i)? {
                ValueRef::Null => continue,
                ValueRef::Integer(n) => n.to_string(),
                ValueRef::Real(f) => f.to_string(),
                ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                ValueRef::Blob(b) => format!("<blob {} bytes>", b.len()),
            };
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(col);
            line.push('=');
            line.push_str(&value);
        }
        line.push('\n');
        out.push_str(&line);
        row_count += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_of(setup: &[&str]) -> Vec<u8> {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        for stmt in setup {
            conn.execute(stmt, []).unwrap();
        }
        drop(conn);
        std::fs::read(tmp.path()).unwrap()
    }

    fn run(path: &str, bytes: Vec<u8>) -> Vec<VirtualFile> {
        let exp = SqliteExpander::default();
        assert!(exp.applies(Path::new(path)), "should apply to {path}");
        let Artifact::Files(files) = exp.run(Path::new(path), &Artifact::Bytes(bytes)).unwrap()
        else {
            panic!("expander must produce Files");
        };
        files
    }

    #[test]
    fn applies_to_recognized_extensions_only() {
        let exp = SqliteExpander::default();
        for name in ["app.db", "app.sqlite", "app.sqlite3", "APP.DB"] {
            assert!(exp.applies(Path::new(name)), "{name}");
        }
        for name in ["app.txt", "app", "app.db.bak"] {
            assert!(!exp.applies(Path::new(name)), "{name}");
        }
    }

    #[test]
    fn expands_a_table_into_key_value_lines() {
        let bytes = sqlite_of(&[
            "CREATE TABLE users (id INTEGER, email TEXT, note TEXT)",
            "INSERT INTO users VALUES (1, 'a@example.com', 'AWS=AKIA0123456789ABCDEF')",
            "INSERT INTO users VALUES (2, 'b@example.com', NULL)",
        ]);
        let files = run("app.db", bytes);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "app.db!users");
        let text = String::from_utf8(files[0].content.clone()).unwrap();
        assert!(text.contains("email=a@example.com"), "{text}");
        assert!(text.contains("note=AWS=AKIA0123456789ABCDEF"), "{text}");
        // NULL is omitted, not printed as a literal "note=" or "NULL".
        let second_row = text.lines().nth(1).unwrap();
        assert!(!second_row.contains("note="), "{second_row}");
    }

    #[test]
    fn multiple_tables_become_multiple_virtual_files() {
        let bytes = sqlite_of(&[
            "CREATE TABLE a (x TEXT)",
            "CREATE TABLE b (y TEXT)",
            "INSERT INTO a VALUES ('one')",
            "INSERT INTO b VALUES ('two')",
        ]);
        let files = run("data.sqlite", bytes);
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"data.sqlite!a"));
        assert!(paths.contains(&"data.sqlite!b"));
    }

    #[test]
    fn empty_table_produces_no_virtual_file() {
        let bytes = sqlite_of(&["CREATE TABLE empty (x TEXT)"]);
        assert!(run("app.db", bytes).is_empty());
    }

    #[test]
    fn blob_is_shown_as_a_byte_count_not_dumped() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        conn.execute("CREATE TABLE t (data BLOB)", []).unwrap();
        conn.execute("INSERT INTO t VALUES (?1)", [vec![0u8, 1, 2, 3]])
            .unwrap();
        drop(conn);
        let bytes = std::fs::read(tmp.path()).unwrap();
        let files = run("app.db", bytes);
        let text = String::from_utf8(files[0].content.clone()).unwrap();
        assert!(text.contains("data=<blob 4 bytes>"), "{text}");
    }

    #[test]
    fn non_sqlite_file_with_db_extension_yields_no_files() {
        // A ".db" file that isn't actually SQLite (wrong magic header) must
        // not be opened at all — sniffed and skipped.
        let files = run("app.db", b"not a real sqlite database".to_vec());
        assert!(files.is_empty());
    }

    #[test]
    fn sqlite_internal_tables_are_not_expanded() {
        // sqlite_master itself and friends are excluded from expansion.
        let bytes = sqlite_of(&["CREATE TABLE t (x TEXT)", "INSERT INTO t VALUES ('v')"]);
        let files = run("app.db", bytes);
        assert!(files.iter().all(|f| !f.path.contains("sqlite_")));
    }

    #[test]
    fn row_and_table_caps_bound_the_output() {
        let mut setup = vec!["CREATE TABLE t (x TEXT)".to_string()];
        for i in 0..10 {
            setup.push(format!("INSERT INTO t VALUES ('row{i}')"));
        }
        let setup_refs: Vec<&str> = setup.iter().map(|s| s.as_str()).collect();
        let bytes = sqlite_of(&setup_refs);

        let exp = SqliteExpander::with_limits(Limits {
            max_rows_per_table: 3,
            ..Limits::default()
        });
        let Artifact::Files(files) = exp
            .run(Path::new("app.db"), &Artifact::Bytes(bytes))
            .unwrap()
        else {
            unreachable!()
        };
        let text = String::from_utf8(files[0].content.clone()).unwrap();
        assert_eq!(text.lines().count(), 3, "row cap must bound the output");
    }

    #[test]
    fn oversize_database_is_refused_before_being_staged_to_disk() {
        // A real database, rejected purely on size: the cap has to bite before
        // the bytes are copied to a temp file, since that copy is the cost
        // being bounded.
        let bytes = sqlite_of(&[
            "CREATE TABLE t (x TEXT)",
            "INSERT INTO t VALUES ('AWS=AKIA0123456789ABCDEF')",
        ]);
        let exp = SqliteExpander::with_limits(Limits {
            max_input_bytes: 8, // smaller than the 16-byte magic header
            ..Limits::default()
        });
        let Artifact::Files(files) = exp
            .run(Path::new("app.db"), &Artifact::Bytes(bytes.clone()))
            .unwrap()
        else {
            unreachable!()
        };
        assert!(files.is_empty(), "oversize database must yield no files");

        // The same database expands normally once the cap allows it.
        let exp = SqliteExpander::with_limits(Limits {
            max_input_bytes: bytes.len(),
            ..Limits::default()
        });
        let Artifact::Files(files) = exp
            .run(Path::new("app.db"), &Artifact::Bytes(bytes))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            files.len(),
            1,
            "at exactly the cap the database still opens"
        );
    }

    #[test]
    fn wrong_artifact_input_errors() {
        let exp = SqliteExpander::default();
        let err = exp
            .run(Path::new("app.db"), &Artifact::Matches(vec![]))
            .unwrap_err();
        assert!(err.to_string().contains("expected Bytes"), "{err}");
    }
}
