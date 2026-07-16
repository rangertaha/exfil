//! The exfill graph store: an embedded, pure-Rust SurrealDB (SurrealKV engine).
//!
//! Two logical stores share this code, differing only in location and database
//! name: the *findings* store (local, under `--store`, wiped by `clean`) and the
//! *catalog* store (datasets + rules, in the user config dir, preserved across
//! `clean`). Both open with [`Store::open`]; the schema is idempotent.
//!
//! # Rust notes
//!
//! - Methods here are `async fn`: they don't block a thread while the database
//!   works; instead they return a *future* that a runtime (tokio) drives.
//!   Calling one does nothing until you `.await` it. Async spreads virally:
//!   anything that awaits must itself be `async`.
//! - SurrealDB's API is generic over the return type: `let x: Option<FileMeta> =
//!   db.upsert(...)`. You tell it what shape you expect with a type annotation,
//!   and serde does the conversion — mismatches are runtime errors, so the
//!   annotated type must match what was stored.
//! - Queries use `$name` placeholders with `.bind()` rather than string
//!   interpolation — same reason as SQL prepared statements: user-supplied
//!   values can never change the query's structure (injection safety).

use std::path::Path;

use anyhow::{bail, Context, Result};
use exfill_core::{FileMeta, Match};
use serde::{Deserialize, Serialize};
use surrealdb::engine::local::{Db, SurrealKv};
use surrealdb::{RecordId, Surreal};

/// The single SurrealDB namespace all exfill data lives under.
pub const NAMESPACE: &str = "exfill";
/// Database name for the local findings store.
pub const DB_FINDINGS: &str = "findings";
/// Database name for the datasets/rules catalog.
pub const DB_CATALOG: &str = "catalog";

/// Idempotent schema: record tables, edge (relation) tables, and lookup
/// indexes. Applied on every open so an older store is migrated forward.
const SCHEMA: &str = r#"
-- record tables (content-hash ids where dedup matters)
DEFINE TABLE IF NOT EXISTS file SCHEMALESS;
DEFINE TABLE IF NOT EXISTS ast SCHEMALESS;
DEFINE TABLE IF NOT EXISTS source SCHEMALESS;
DEFINE TABLE IF NOT EXISTS dataset SCHEMALESS;
DEFINE TABLE IF NOT EXISTS rule SCHEMALESS;
DEFINE TABLE IF NOT EXISTS finding SCHEMALESS;
DEFINE TABLE IF NOT EXISTS scan SCHEMALESS;

-- graph edges connecting the records
DEFINE TABLE IF NOT EXISTS has_ast TYPE RELATION FROM file TO ast;
DEFINE TABLE IF NOT EXISTS in_file TYPE RELATION FROM finding TO file;
DEFINE TABLE IF NOT EXISTS at_ast TYPE RELATION FROM finding TO ast;
DEFINE TABLE IF NOT EXISTS flagged_by TYPE RELATION FROM finding TO rule;
DEFINE TABLE IF NOT EXISTS from_dataset TYPE RELATION FROM rule TO dataset;
DEFINE TABLE IF NOT EXISTS from_source TYPE RELATION FROM dataset TO source;
DEFINE TABLE IF NOT EXISTS includes TYPE RELATION FROM scan TO file;

-- lookup indexes for the common queries (search by cwe/severity, path)
DEFINE INDEX IF NOT EXISTS finding_cwe ON finding FIELDS cwe;
DEFINE INDEX IF NOT EXISTS finding_severity ON finding FIELDS severity;
DEFINE INDEX IF NOT EXISTS file_path ON file FIELDS path;
"#;

/// A handle to one opened exfill database.
///
/// Cloning is cheap: the inner SurrealDB handle is reference-counted, so
/// clones share one connection (useful for handing a copy to a background
/// scan task).
#[derive(Clone)]
pub struct Store {
    db: Surreal<Db>,
}

impl Store {
    /// Open (creating if needed) the SurrealKV store rooted at `path` and select
    /// `database` within the exfill namespace, applying the schema.
    pub async fn open(path: &Path, database: &str) -> Result<Self> {
        let db = Surreal::new::<SurrealKv>(path)
            .await
            .with_context(|| format!("open SurrealKV store at {}", path.display()))?;
        db.use_ns(NAMESPACE)
            .use_db(database)
            .await
            .context("select namespace/database")?;
        let store = Self { db };
        store.apply_schema().await?;
        Ok(store)
    }

    /// Open the local findings database under a store directory.
    pub async fn open_findings(store_dir: &Path) -> Result<Self> {
        Self::open(store_dir, DB_FINDINGS).await
    }

    /// Open the datasets/rules catalog database under a directory.
    pub async fn open_catalog(catalog_dir: &Path) -> Result<Self> {
        Self::open(catalog_dir, DB_CATALOG).await
    }

    /// Apply the idempotent schema. Called by [`Store::open`]; safe to re-run.
    pub async fn apply_schema(&self) -> Result<()> {
        self.db
            .query(SCHEMA)
            .await
            .context("apply schema")?
            .check()
            .context("schema statement failed")?;
        Ok(())
    }

    /// Borrow the underlying SurrealDB handle for queries.
    pub fn db(&self) -> &Surreal<Db> {
        &self.db
    }

    /// Upsert one file's metadata, keyed by its content hash (dedup: the same
    /// content seen at two paths keeps one record, last path wins).
    pub async fn upsert_file(&self, meta: &FileMeta) -> Result<()> {
        let _: Option<FileMeta> = self
            .db
            .upsert(("file", meta.hash.as_str()))
            .content(meta.clone())
            .await
            .with_context(|| format!("upsert file {}", meta.path))?;
        Ok(())
    }

    /// Create a finding record and relate it to the file it was found in.
    pub async fn add_finding(&self, m: &Match, file_hash: &str) -> Result<()> {
        self.db
            .query("LET $f = (CREATE finding CONTENT $data)[0].id; RELATE $f->in_file->$file;")
            .bind(("data", m.clone()))
            .bind(("file", RecordId::from(("file", file_hash))))
            .await
            .context("create finding")?
            .check()
            .context("finding statement failed")?;
        Ok(())
    }

    /// Write the scan record and its `includes` edges to every scanned file.
    pub async fn commit_scan(&self, scan: &ScanRecord, file_hashes: &[String]) -> Result<()> {
        self.db
            .query(
                "LET $s = (CREATE scan CONTENT $data)[0].id; \
                 FOR $h IN $hashes { RELATE $s->includes->(type::thing('file', $h)); };",
            )
            .bind(("data", scan.clone()))
            .bind(("hashes", file_hashes.to_vec()))
            .await
            .context("create scan record")?
            .check()
            .context("scan statement failed")?;
        Ok(())
    }

    /// Query stored findings. `filter` is either empty (all), `key=value` for
    /// an allowed field (`rule`, `cwe`, `severity`, `path`), or free text
    /// matched against the rule name.
    ///
    /// The field name is checked against a whitelist because identifiers can't
    /// be bound as `$params` — only the *value* side is user-controlled text.
    pub async fn search_findings(&self, filter: &str) -> Result<Vec<Match>> {
        // `match` can destructure: `split_once('=')` yields Some((key, value))
        // when a '=' exists, and the arms bind those pieces directly.
        let (sql, bind): (String, Option<(String, String)>) = match filter.split_once('=') {
            Some((k, v)) => {
                let k = k.trim();
                if !["rule", "cwe", "severity", "path"].contains(&k) {
                    bail!("unknown search field {k:?} (use rule/cwe/severity/path)");
                }
                (
                    format!("SELECT * OMIT id FROM finding WHERE {k} = $v"),
                    Some(("v".into(), v.trim().to_string())),
                )
            }
            None if filter.is_empty() => ("SELECT * OMIT id FROM finding".into(), None),
            None => (
                "SELECT * OMIT id FROM finding WHERE rule CONTAINS $v".into(),
                Some(("v".into(), filter.to_string())),
            ),
        };
        let mut q = self.db.query(sql);
        if let Some((k, v)) = bind {
            q = q.bind((k, v));
        }
        let rows: Vec<Match> = q.await.context("search findings")?.take(0)?;
        Ok(rows)
    }

    /// Fetch one record by full id (`table:key`) as JSON.
    pub async fn get_record(&self, id: &str) -> Result<Option<serde_json::Value>> {
        let Some((table, key)) = id.split_once(':') else {
            bail!("record id must look like table:key, got {id:?}");
        };
        let mut res = self
            .db
            .query("SELECT * OMIT id FROM type::thing($tb, $key)")
            .bind(("tb", table.to_string()))
            .bind(("key", key.to_string()))
            .await
            .with_context(|| format!("get {id}"))?;
        let rows: Vec<serde_json::Value> = res.take(0)?;
        Ok(rows.into_iter().next())
    }
}

/// One scan run: the root, host, and result counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    /// The directory tree that was scanned.
    pub root: String,
    /// Hostname the scan ran on.
    pub host: String,
    /// Seconds since the Unix epoch when the scan started.
    pub started_at: u64,
    /// Regular files recorded.
    pub files: u64,
    /// Total matches found.
    pub matches: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct FileRow {
        path: String,
    }

    #[tokio::test]
    async fn opens_and_roundtrips_a_record() {
        let dir = std::env::temp_dir().join(format!("exfill-store-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir, DB_FINDINGS).await.expect("open store");
        // Re-applying the schema must not error (idempotent).
        store.apply_schema().await.expect("reapply schema");

        // A schema-defined table must accept a create and return it on select.
        let created: Option<FileRow> = store
            .db()
            .create(("file", "abc123"))
            .content(FileRow {
                path: "src/main.rs".into(),
            })
            .await
            .expect("create file record");
        assert_eq!(created.expect("created row").path, "src/main.rs");

        let fetched: Option<FileRow> = store
            .db()
            .select(("file", "abc123"))
            .await
            .expect("select back");
        assert_eq!(fetched.expect("fetched row").path, "src/main.rs");

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn sample_meta(hash: &str, path: &str) -> FileMeta {
        FileMeta {
            path: path.into(),
            abs: format!("/abs/{path}"),
            host: "testhost".into(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            user: String::new(),
            group: String::new(),
            size: 42,
            mtime: "1700000000".into(),
            hash: hash.into(),
        }
    }

    fn sample_match(rule: &str, path: &str) -> Match {
        Match {
            rule: rule.into(),
            path: path.into(),
            line: 3,
            col: 7,
            snippet: "secret = ...".into(),
            severity: Some(exfill_core::Severity::High),
            cwe: Some("CWE-798".into()),
            cve: None,
        }
    }

    #[tokio::test]
    async fn findings_scan_search_and_get() {
        let dir =
            std::env::temp_dir().join(format!("exfill-store-test-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir, DB_FINDINGS).await.unwrap();

        // Two files, two findings, one scan.
        store
            .upsert_file(&sample_meta("aaa", "a.env"))
            .await
            .unwrap();
        store
            .upsert_file(&sample_meta("bbb", "b.py"))
            .await
            .unwrap();
        // Re-upserting the same hash must not error (dedup path).
        store
            .upsert_file(&sample_meta("aaa", "a-copy.env"))
            .await
            .unwrap();

        store
            .add_finding(&sample_match("aws-key", "a.env"), "aaa")
            .await
            .unwrap();
        store
            .add_finding(&sample_match("password-in-url", "b.py"), "bbb")
            .await
            .unwrap();
        store
            .commit_scan(
                &ScanRecord {
                    root: "/tree".into(),
                    host: "testhost".into(),
                    started_at: 1700000000,
                    files: 2,
                    matches: 2,
                },
                &["aaa".to_string(), "bbb".to_string()],
            )
            .await
            .unwrap();

        // Every search branch.
        assert_eq!(store.search_findings("").await.unwrap().len(), 2);
        assert_eq!(
            store.search_findings("rule=aws-key").await.unwrap().len(),
            1
        );
        assert_eq!(store.search_findings("cwe=CWE-798").await.unwrap().len(), 2);
        assert_eq!(
            store.search_findings("severity=high").await.unwrap().len(),
            2
        );
        assert_eq!(store.search_findings("path=b.py").await.unwrap().len(), 1);
        assert_eq!(store.search_findings("password").await.unwrap().len(), 1);
        assert_eq!(
            store.search_findings("no-such-rule").await.unwrap().len(),
            0
        );
        let err = store.search_findings("bogus=1").await.unwrap_err();
        assert!(err.to_string().contains("unknown search field"), "{err}");

        // get_record: hit, miss, malformed.
        let rec = store
            .get_record("file:aaa")
            .await
            .unwrap()
            .expect("file:aaa exists");
        assert_eq!(rec["host"], "testhost");
        assert!(store.get_record("file:zzz").await.unwrap().is_none());
        let err = store.get_record("no-colon").await.unwrap_err();
        assert!(err.to_string().contains("table:key"), "{err}");

        // The finding is connected to its file (edge traversal works).
        let mut res = store
            .db()
            .query("SELECT count() AS n FROM finding WHERE ->in_file->file CONTAINS file:aaa GROUP ALL")
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = res.take(0).unwrap();
        assert_eq!(rows[0]["n"], 1, "one finding relates to file:aaa");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
