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

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use exfill_core::{Dataset, FileMeta, Match, Rule};
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
DEFINE TABLE IF NOT EXISTS indicators SCHEMALESS;
DEFINE TABLE IF NOT EXISTS source SCHEMALESS;
DEFINE TABLE IF NOT EXISTS dataset SCHEMALESS;
DEFINE TABLE IF NOT EXISTS rule SCHEMALESS;
DEFINE TABLE IF NOT EXISTS finding SCHEMALESS;
DEFINE TABLE IF NOT EXISTS event SCHEMALESS;
DEFINE TABLE IF NOT EXISTS scan SCHEMALESS;

-- graph edges connecting the records
DEFINE TABLE IF NOT EXISTS has_ast TYPE RELATION FROM file TO ast;
DEFINE TABLE IF NOT EXISTS has_indicators TYPE RELATION FROM file TO indicators;
DEFINE TABLE IF NOT EXISTS has_event TYPE RELATION FROM finding TO event;
DEFINE TABLE IF NOT EXISTS in_file TYPE RELATION FROM finding TO file;
DEFINE TABLE IF NOT EXISTS at_ast TYPE RELATION FROM finding TO ast;
DEFINE TABLE IF NOT EXISTS flagged_by TYPE RELATION FROM finding TO rule;
DEFINE TABLE IF NOT EXISTS from_dataset TYPE RELATION FROM rule TO dataset;
DEFINE TABLE IF NOT EXISTS from_source TYPE RELATION FROM dataset TO source;
DEFINE TABLE IF NOT EXISTS includes TYPE RELATION FROM scan TO file;
DEFINE TABLE IF NOT EXISTS contained_in TYPE RELATION FROM file TO file;

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

    /// A stat-cache index of every stored file: absolute path → (size, mtime,
    /// content hash). The engine uses it to skip re-reading files whose size
    /// and mtime are unchanged since the last scan.
    pub async fn file_index(&self) -> Result<HashMap<String, FileStat>> {
        let mut res = self
            .db
            .query("SELECT abs, size, mtime, hash FROM file")
            .await
            .context("load file index")?;
        let rows: Vec<FileStat> = res.take(0)?;
        Ok(rows.into_iter().map(|f| (f.abs.clone(), f)).collect())
    }

    /// Delete all findings attached to a file (and their edges), so a rescan
    /// replaces them instead of piling up duplicates.
    pub async fn clear_findings(&self, file_hash: &str) -> Result<()> {
        self.db
            .query(
                "DELETE finding WHERE ->in_file->file CONTAINS $file; \
                 DELETE in_file WHERE out = $file;",
            )
            .bind(("file", RecordId::from(("file", file_hash))))
            .await
            .context("clear findings")?
            .check()
            .context("clear findings statement failed")?;
        Ok(())
    }

    /// Relate an expanded file to the container (archive) it came from, so the
    /// graph records that `inner` lives inside `container`. Idempotent.
    pub async fn relate_contained_in(&self, inner_hash: &str, container_hash: &str) -> Result<()> {
        self.db
            .query(
                "DELETE contained_in WHERE in = $inner AND out = $container; \
                 RELATE $inner->contained_in->$container;",
            )
            .bind(("inner", RecordId::from(("file", inner_hash))))
            .bind(("container", RecordId::from(("file", container_hash))))
            .await
            .context("relate contained_in")?
            .check()
            .context("contained_in statement failed")?;
        Ok(())
    }

    /// Store a file's AST (keyed by the file's content hash, so it dedups with
    /// the file) and relate the file to it with `has_ast`. Idempotent.
    pub async fn upsert_ast(
        &self,
        file_hash: &str,
        lang: &str,
        symbols: &serde_json::Value,
    ) -> Result<()> {
        self.db
            .query(
                "UPSERT type::thing('ast', $h) CONTENT { lang: $lang, symbols: $symbols }; \
                 DELETE has_ast WHERE in = $file; \
                 RELATE $file->has_ast->(type::thing('ast', $h));",
            )
            .bind(("h", file_hash.to_string()))
            .bind(("lang", lang.to_string()))
            .bind(("symbols", symbols.clone()))
            .bind(("file", RecordId::from(("file", file_hash))))
            .await
            .context("upsert ast")?
            .check()
            .context("ast statement failed")?;
        Ok(())
    }

    /// Store a file's extracted indicators (keyed by content hash) and relate
    /// the file to them with `has_indicators`. Idempotent.
    pub async fn upsert_indicators(
        &self,
        file_hash: &str,
        indicators: &serde_json::Value,
    ) -> Result<()> {
        self.db
            .query(
                "UPSERT type::thing('indicators', $h) CONTENT $ind; \
                 DELETE has_indicators WHERE in = $file; \
                 RELATE $file->has_indicators->(type::thing('indicators', $h));",
            )
            .bind(("h", file_hash.to_string()))
            .bind(("ind", indicators.clone()))
            .bind(("file", RecordId::from(("file", file_hash))))
            .await
            .context("upsert indicators")?
            .check()
            .context("indicators statement failed")?;
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

    /// Export the whole graph as a portable snapshot: every record table and
    /// every edge table, keyed by name. Content-addressed record ids make the
    /// result stable and deduplicated — suitable for CBOR (or JSON) export and
    /// diffing between hosts.
    pub async fn export_snapshot(&self) -> Result<serde_json::Value> {
        let mut tables = serde_json::Map::new();
        // Record tables: keep every field, but stringify the RecordId id (which
        // JSON can't represent as-is) so the snapshot is plain JSON/CBOR.
        const RECORD_TABLES: &[&str] = &[
            "file",
            "ast",
            "indicators",
            "source",
            "dataset",
            "rule",
            "finding",
            "event",
            "scan",
        ];
        for table in RECORD_TABLES {
            let mut res = self
                .db
                .query(format!(
                    "SELECT type::string(id) AS rid, * OMIT id FROM {table}"
                ))
                .await
                .with_context(|| format!("export {table}"))?;
            let rows: Vec<serde_json::Value> = res.take(0)?;
            tables.insert((*table).to_string(), serde_json::Value::Array(rows));
        }
        // Edge tables: just the endpoints, stringified, keyed `from`/`to`.
        for table in EDGE_TABLES {
            let mut res = self
                .db
                .query(format!(
                    "SELECT type::string(id) AS rid, type::string(`in`) AS `from`, \
                     type::string(`out`) AS `to` FROM {table}"
                ))
                .await
                .with_context(|| format!("export edge {table}"))?;
            let rows: Vec<serde_json::Value> = res.take(0)?;
            tables.insert((*table).to_string(), serde_json::Value::Array(rows));
        }
        Ok(serde_json::json!({
            "version": 1,
            "namespace": NAMESPACE,
            "tables": tables,
        }))
    }

    /// Garbage-collect the findings store: keep only the most recent scan and
    /// delete everything not reachable from it — older scan records, file
    /// records they alone referenced (e.g. superseded content versions), and
    /// the findings, ASTs, and edges hanging off those files. Returns what was
    /// removed. A store with zero or one scan is left untouched.
    pub async fn gc(&self) -> Result<GcStats> {
        // The latest scan (by start time). Nothing to prune without one.
        #[derive(Deserialize)]
        struct ScanId {
            id: RecordId,
        }
        let mut res = self
            .db
            .query("SELECT id, started_at FROM scan ORDER BY started_at DESC LIMIT 1")
            .await
            .context("find latest scan")?;
        let latest: Vec<ScanId> = res.take(0)?;
        let Some(latest) = latest.into_iter().next().map(|s| s.id) else {
            return Ok(GcStats::default());
        };

        let before = self.gc_counts().await?;

        // Drop older scans and their includes edges, then anything no longer
        // referenced by a surviving includes edge.
        self.db
            .query(
                "DELETE includes WHERE in != $latest; \
                 DELETE scan WHERE id != $latest; \
                 LET $live = (SELECT VALUE out FROM includes); \
                 DELETE in_file WHERE out NOT IN $live; \
                 DELETE has_ast WHERE in NOT IN $live; \
                 DELETE has_indicators WHERE in NOT IN $live; \
                 DELETE contained_in WHERE in NOT IN $live OR out NOT IN $live; \
                 DELETE finding WHERE count(->in_file) = 0; \
                 DELETE has_event WHERE in NOT IN (SELECT VALUE id FROM finding); \
                 DELETE event WHERE count(<-has_event) = 0; \
                 DELETE ast WHERE count(<-has_ast) = 0; \
                 DELETE indicators WHERE count(<-has_indicators) = 0; \
                 DELETE file WHERE id NOT IN $live;",
            )
            .bind(("latest", latest))
            .await
            .context("gc sweep")?
            .check()
            .context("gc statement failed")?;

        let after = self.gc_counts().await?;
        Ok(GcStats {
            scans: before.0 - after.0,
            files: before.1 - after.1,
            findings: before.2 - after.2,
        })
    }

    /// `(scans, files, findings)` counts, for gc deltas.
    async fn gc_counts(&self) -> Result<(u64, u64, u64)> {
        let mut res = self
            .db
            .query("SELECT count() AS n FROM scan GROUP ALL")
            .query("SELECT count() AS n FROM file GROUP ALL")
            .query("SELECT count() AS n FROM finding GROUP ALL")
            .await
            .context("gc counts")?;
        let n =
            |rows: Vec<serde_json::Value>| rows.first().and_then(|r| r["n"].as_u64()).unwrap_or(0);
        Ok((n(res.take(0)?), n(res.take(1)?), n(res.take(2)?)))
    }

    /// Whole-store counts for reports: `(files, scans)`.
    pub async fn counts(&self) -> Result<(u64, u64)> {
        let mut res = self
            .db
            .query("SELECT count() AS n FROM file GROUP ALL")
            .query("SELECT count() AS n FROM scan GROUP ALL")
            .await
            .context("count store")?;
        let files: Vec<serde_json::Value> = res.take(0)?;
        let scans: Vec<serde_json::Value> = res.take(1)?;
        let n =
            |rows: Vec<serde_json::Value>| rows.first().and_then(|r| r["n"].as_u64()).unwrap_or(0);
        Ok((n(files), n(scans)))
    }

    /// Store a dataset and its rules in the catalog: upsert the dataset record
    /// (with a denormalized rule count), content-address each rule (so the same
    /// rule shared by two datasets dedups), and relate rules to the dataset with
    /// `from_dataset`. Replaces the dataset's previous rule set. Returns the
    /// number of rules stored.
    pub async fn upsert_dataset(&self, dataset: &Dataset) -> Result<usize> {
        let name = dataset.name.as_str();
        let count = dataset.rules.len();
        // Dataset record + clear its old rule edges (rules may have changed).
        self.db
            .query(
                "UPSERT type::thing('dataset', $name) CONTENT { name: $name, rules: $count }; \
                 DELETE from_dataset WHERE out = type::thing('dataset', $name);",
            )
            .bind(("name", name.to_string()))
            .bind(("count", count))
            .await
            .with_context(|| format!("upsert dataset {name}"))?
            .check()
            .context("dataset statement failed")?;

        for rule in &dataset.rules {
            let id = rule_id(rule);
            self.db
                .query(
                    "UPSERT type::thing('rule', $id) CONTENT $rule; \
                     RELATE (type::thing('rule', $id))->from_dataset->(type::thing('dataset', $name));",
                )
                .bind(("id", id))
                .bind(("rule", rule.clone()))
                .bind(("name", name.to_string()))
                .await
                .with_context(|| format!("store rule {}", rule.name))?
                .check()
                .context("rule statement failed")?;
        }
        Ok(count)
    }

    /// Findings with their record ids, for normalization/enrichment passes.
    /// Returns `(finding_id, Match)` pairs matching the (optional) `filter`.
    pub async fn findings_with_ids(&self, filter: &str) -> Result<Vec<(String, Match)>> {
        #[derive(Deserialize)]
        struct Row {
            fid: String,
            #[serde(flatten)]
            m: Match,
        }
        // Reuse search_findings' filter contract, but keep the id.
        let base = "SELECT type::string(id) AS fid, * OMIT id FROM finding";
        let mut res = if let Some((k, v)) = filter.split_once('=') {
            const FIELDS: &[&str] = &["rule", "cwe", "severity", "path"];
            if !FIELDS.contains(&k) {
                bail!("unknown search field {k:?}");
            }
            self.db
                .query(format!("{base} WHERE {k} = $v"))
                .bind(("v", v.to_string()))
                .await?
        } else if filter.is_empty() {
            self.db.query(base).await?
        } else {
            self.db
                .query(format!("{base} WHERE rule CONTAINS $v"))
                .bind(("v", filter.to_string()))
                .await?
        };
        let rows: Vec<Row> = res.take(0)?;
        Ok(rows.into_iter().map(|r| (r.fid, r.m)).collect())
    }

    /// Store a normalized CIM event and relate the finding to it with
    /// `has_event`. Idempotent per finding (replaces any prior event).
    pub async fn upsert_event(&self, finding_id: &str, event: &serde_json::Value) -> Result<()> {
        let fid = record_id(finding_id)?;
        self.db
            .query(
                "DELETE event WHERE id IN (SELECT VALUE out FROM has_event WHERE in = $f); \
                 DELETE has_event WHERE in = $f; \
                 LET $e = (CREATE event CONTENT $data)[0].id; \
                 RELATE $f->has_event->$e;",
            )
            .bind(("f", fid))
            .bind(("data", event.clone()))
            .await
            .context("upsert event")?
            .check()
            .context("event statement failed")?;
        Ok(())
    }

    /// Count normalized events per CIM category, most-frequent first.
    pub async fn event_summary(&self) -> Result<Vec<(String, u64)>> {
        #[derive(Deserialize)]
        struct Row {
            category: String,
            n: u64,
        }
        let mut res = self
            .db
            .query("SELECT category, count() AS n FROM event GROUP BY category")
            .await
            .context("event summary")?;
        let mut rows: Vec<Row> = res.take(0)?;
        rows.sort_by(|a, b| b.n.cmp(&a.n).then(a.category.cmp(&b.category)));
        Ok(rows.into_iter().map(|r| (r.category, r.n)).collect())
    }

    /// Every stored indicators node as `(file_hash, domains)`. Used by the DNS
    /// checker to resolve domains observed during a scan. The `indicators`
    /// record id is the file's content hash (keyed alongside the file).
    pub async fn indicator_domains(&self) -> Result<Vec<(String, Vec<String>)>> {
        #[derive(Deserialize)]
        struct Row {
            iid: String,
            #[serde(default)]
            domains: Vec<String>,
        }
        let mut res = self
            .db
            .query("SELECT type::string(id) AS iid, domains FROM indicators")
            .await
            .context("list indicator domains")?;
        let rows: Vec<Row> = res.take(0)?;
        Ok(rows
            .into_iter()
            .filter(|r| !r.domains.is_empty())
            .map(|r| {
                // `iid` is `indicators:<hash>`; the file hash is the key part.
                let hash = r.iid.split_once(':').map(|(_, k)| k).unwrap_or(&r.iid);
                (hash.to_string(), r.domains)
            })
            .collect())
    }

    /// List records of a table as `(record_id, label)` for browsing, capped at
    /// `limit`. `kind` must be a known record table (whitelisted, since it is
    /// interpolated into the query — table names can't be bound as `$params`).
    pub async fn list_records(&self, kind: &str, limit: usize) -> Result<Vec<(String, String)>> {
        const TABLES: &[&str] = &[
            "file",
            "ast",
            "indicators",
            "source",
            "dataset",
            "rule",
            "finding",
            "event",
            "scan",
        ];
        if !TABLES.contains(&kind) {
            bail!("unknown record table {kind:?}");
        }
        let mut res = self
            .db
            .query(format!(
                "SELECT type::string(id) AS rid, * OMIT id FROM {kind} LIMIT {limit}"
            ))
            .await
            .with_context(|| format!("list {kind}"))?;
        let rows: Vec<serde_json::Value> = res.take(0)?;
        Ok(rows
            .into_iter()
            .map(|v| {
                let id = v
                    .get("rid")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                let label = node_label(kind, &v).unwrap_or_else(|| id.clone());
                (id, label)
            })
            .collect())
    }

    /// List stored datasets as `(name, rule_count)`, alphabetical.
    pub async fn list_datasets(&self) -> Result<Vec<(String, u64)>> {
        #[derive(Deserialize)]
        struct Row {
            name: String,
            #[serde(default)]
            rules: u64,
        }
        let mut res = self
            .db
            .query("SELECT name, rules FROM dataset ORDER BY name")
            .await
            .context("list datasets")?;
        let rows: Vec<Row> = res.take(0)?;
        Ok(rows.into_iter().map(|r| (r.name, r.rules)).collect())
    }

    /// Fetch one dataset with its rules, or `None` if absent.
    pub async fn get_dataset(&self, name: &str) -> Result<Option<Dataset>> {
        // Confirm the dataset exists.
        let mut d = self
            .db
            .query("SELECT name FROM type::thing('dataset', $name)")
            .bind(("name", name.to_string()))
            .await
            .context("get dataset")?;
        let names: Vec<serde_json::Value> = d.take(0)?;
        if names.is_empty() {
            return Ok(None);
        }
        let rules = self.rules_of(name).await?;
        Ok(Some(Dataset {
            name: name.to_string(),
            rules,
        }))
    }

    /// The rules related to one dataset.
    async fn rules_of(&self, name: &str) -> Result<Vec<Rule>> {
        let mut res = self
            .db
            .query(
                "SELECT * OMIT id FROM rule \
                 WHERE ->from_dataset->dataset CONTAINS type::thing('dataset', $name)",
            )
            .bind(("name", name.to_string()))
            .await
            .context("rules of dataset")?;
        Ok(res.take(0)?)
    }

    /// Every rule reachable from a dataset (what a scan applies). Deduplicated
    /// by content-addressed id at the storage layer.
    pub async fn all_rules(&self) -> Result<Vec<Rule>> {
        let mut res = self
            .db
            .query("SELECT * OMIT id FROM rule WHERE count(->from_dataset) > 0")
            .await
            .context("all rules")?;
        Ok(res.take(0)?)
    }

    /// Remove a dataset and its rule edges. Orphaned rule records are left for
    /// `gc`. Returns whether the dataset existed.
    pub async fn remove_dataset(&self, name: &str) -> Result<bool> {
        let existed = self.get_dataset(name).await?.is_some();
        self.db
            .query(
                "DELETE from_dataset WHERE out = type::thing('dataset', $name); \
                 DELETE type::thing('dataset', $name);",
            )
            .bind(("name", name.to_string()))
            .await
            .with_context(|| format!("remove dataset {name}"))?
            .check()
            .context("remove dataset statement failed")?;
        Ok(existed)
    }

    /// Build the findings graph: for each finding (optionally filtered like
    /// [`search_findings`]), a finding node plus its file, and edges
    /// `finding -in_file-> file`. Findings also link to their rule by name.
    pub async fn graph(&self, filter: &str) -> Result<Graph> {
        let findings = self.search_findings(filter).await?;
        let mut graph = Graph::default();
        let mut seen_files = std::collections::HashSet::new();

        for (i, m) in findings.iter().enumerate() {
            let fid = format!("finding:{i}");
            graph.nodes.push(GraphNode {
                id: fid.clone(),
                kind: "finding".into(),
                label: format!("{} @ {}:{}", m.rule, m.path, m.line),
            });
            // File node (deduped by path).
            let file_id = format!("file:{}", m.path);
            if seen_files.insert(m.path.clone()) {
                graph.nodes.push(GraphNode {
                    id: file_id.clone(),
                    kind: "file".into(),
                    label: m.path.clone(),
                });
            }
            graph.edges.push(GraphEdge {
                from: fid.clone(),
                to: file_id,
                rel: "in_file".into(),
            });
            // Rule node (deduped by name).
            let rule_id = format!("rule:{}", m.rule);
            if seen_files.insert(rule_id.clone()) {
                graph.nodes.push(GraphNode {
                    id: rule_id.clone(),
                    kind: "rule".into(),
                    label: m.rule.clone(),
                });
            }
            graph.edges.push(GraphEdge {
                from: fid,
                to: rule_id,
                rel: "flagged_by".into(),
            });
        }
        Ok(graph)
    }

    /// Set a field on a node, returning its previous value (for undo). The
    /// field name is validated (identifier characters only) since it can't be
    /// bound as a `$param` — the value side is bound safely.
    pub async fn set_field(
        &self,
        node_id: &str,
        field: &str,
        value: serde_json::Value,
    ) -> Result<serde_json::Value> {
        if field.is_empty()
            || !field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            bail!("invalid field name {field:?}");
        }
        let (table, key) = node_id
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("node id must be table:key"))?;
        let rid = RecordId::from((table, key));
        let old = self
            .get_record(node_id)
            .await?
            .and_then(|v| v.get(field).cloned())
            .unwrap_or(serde_json::Value::Null);
        self.db
            .query(format!("UPDATE $id SET {field} = $v"))
            .bind(("id", rid))
            .bind(("v", value))
            .await
            .with_context(|| format!("set {field} on {node_id}"))?
            .check()
            .context("set_field statement failed")?;
        Ok(old)
    }

    /// Create a graph edge `from -rel-> to`. `rel` must be a known edge table.
    pub async fn create_edge(&self, rel: &str, from_id: &str, to_id: &str) -> Result<()> {
        self.edit_edge(rel, from_id, to_id, true).await
    }

    /// Delete the graph edge `from -rel-> to`.
    pub async fn delete_edge(&self, rel: &str, from_id: &str, to_id: &str) -> Result<()> {
        self.edit_edge(rel, from_id, to_id, false).await
    }

    /// Shared body of [`create_edge`]/[`delete_edge`].
    async fn edit_edge(&self, rel: &str, from_id: &str, to_id: &str, create: bool) -> Result<()> {
        if !EDGE_TABLES.contains(&rel) {
            bail!("unknown edge relation {rel:?}");
        }
        let rid = |id: &str| -> Result<RecordId> {
            let (t, k) = id
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("id must be table:key"))?;
            Ok(RecordId::from((t, k)))
        };
        let from = rid(from_id)?;
        let to = rid(to_id)?;
        let q = if create {
            format!("RELATE $from->{rel}->$to")
        } else {
            format!("DELETE {rel} WHERE in = $from AND out = $to")
        };
        self.db
            .query(q)
            .bind(("from", from))
            .bind(("to", to))
            .await
            .with_context(|| format!("edit edge {rel}"))?
            .check()
            .context("edge statement failed")?;
        Ok(())
    }

    /// The nodes directly connected to `node_id` (`table:key`) by any graph
    /// edge, each tagged with the relation and direction. This is the motion
    /// primitive for graph navigation — "go to a neighbor by following an edge".
    pub async fn neighbors(&self, node_id: &str) -> Result<Vec<Neighbor>> {
        let Some((table, key)) = node_id.split_once(':') else {
            bail!("node id must look like table:key, got {node_id:?}");
        };
        let node = RecordId::from((table, key));
        let mut out = Vec::new();
        // (edge table, the field holding the *other* endpoint, the field to
        // filter on, and whether that direction is outgoing from `node`).
        for edge in EDGE_TABLES {
            for (other, filter, outgoing) in [("out", "in", true), ("in", "out", false)] {
                let q = format!("SELECT VALUE {other} FROM {edge} WHERE {filter} = $n");
                let mut res = self
                    .db
                    .query(q)
                    .bind(("n", node.clone()))
                    .await
                    .with_context(|| format!("neighbors via {edge}"))?;
                let ids: Vec<RecordId> = res.take(0)?;
                for nid in ids {
                    let id_str = nid.to_string();
                    let kind = id_str.split(':').next().unwrap_or("").to_string();
                    let data = self
                        .get_record(&id_str)
                        .await?
                        .unwrap_or(serde_json::Value::Null);
                    let label = node_label(&kind, &data).unwrap_or_else(|| id_str.clone());
                    out.push(Neighbor {
                        rel: (*edge).to_string(),
                        outgoing,
                        id: id_str,
                        kind,
                        label,
                        data,
                    });
                }
            }
        }
        Ok(out)
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

/// The graph edge tables traversed by [`Store::neighbors`].
const EDGE_TABLES: &[&str] = &[
    "has_ast",
    "has_indicators",
    "has_event",
    "in_file",
    "at_ast",
    "flagged_by",
    "from_dataset",
    "from_source",
    "includes",
    "contained_in",
];

/// A node reachable from another by one edge: the relation, its direction, and
/// the neighbor's id/kind/label/data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Neighbor {
    /// The edge relation (`in_file`, `flagged_by`, …).
    pub rel: String,
    /// True if the edge points *from* the queried node *to* this neighbor.
    pub outgoing: bool,
    /// Neighbor record id (`table:key`).
    pub id: String,
    /// Neighbor kind (the record table).
    pub kind: String,
    /// Short display label for the neighbor.
    pub label: String,
    /// The neighbor record's fields.
    pub data: serde_json::Value,
}

/// A short human label for a node of `kind` from its `data`, if derivable.
/// Used for breadcrumbs and neighbor lists in the graph navigator.
pub fn node_label(kind: &str, data: &serde_json::Value) -> Option<String> {
    let s = |k: &str| data.get(k).and_then(|v| v.as_str());
    let n = |k: &str| data.get(k).and_then(|v| v.as_u64());
    match kind {
        "finding" => Some(format!(
            "{} @ {}:{}",
            s("rule").unwrap_or("?"),
            s("path").unwrap_or("?"),
            n("line").unwrap_or(0)
        )),
        "file" => s("path").map(String::from),
        "rule" => s("name").map(String::from),
        "ast" => Some(format!("{} ast", s("lang").unwrap_or("?"))),
        "indicators" => {
            let count = |k: &str| {
                data.get(k)
                    .and_then(|v| v.as_array())
                    .map_or(0, |a| a.len())
            };
            Some(format!(
                "indicators ({}e {}d {}ip {}url {}h)",
                count("emails"),
                count("domains"),
                count("ips"),
                count("urls"),
                count("hashes"),
            ))
        }
        "event" => Some(format!(
            "{}/{} {}",
            s("category").unwrap_or("?"),
            s("action").unwrap_or("?"),
            s("signature").unwrap_or("")
        )),
        "dataset" | "source" => s("name").map(String::from),
        "scan" => s("root").map(String::from),
        _ => None,
    }
}

/// Parse a `table:key` string into a [`RecordId`].
fn record_id(id: &str) -> Result<RecordId> {
    let (table, key) = id
        .split_once(':')
        .with_context(|| format!("record id {id:?} is not table:key"))?;
    Ok(RecordId::from((table, key)))
}

/// Content-addressed id for a rule (blake3 of name+pattern), so the same rule
/// shared by two datasets stores once with two `from_dataset` edges.
fn rule_id(rule: &Rule) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(rule.name.as_bytes());
    hasher.update(b"\0");
    hasher.update(rule.pattern.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// The stat-cache row for one stored file, keyed by absolute path.
///
/// Size + mtime is the classic freshness heuristic (same one `make` and
/// `rsync` use): if both are unchanged the content is assumed unchanged and
/// the stored hash is reused without reading the file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStat {
    /// Absolute, canonicalized path.
    pub abs: String,
    /// File size in bytes at last scan.
    pub size: u64,
    /// Modification time (seconds since epoch, stringly) at last scan.
    pub mtime: String,
    /// blake3 content hash recorded at last scan.
    pub hash: String,
}

/// What a [`Store::gc`] pass removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GcStats {
    /// Older scan records deleted.
    pub scans: u64,
    /// Stale file records deleted.
    pub files: u64,
    /// Findings deleted along with their files.
    pub findings: u64,
}

/// One node in the exported findings graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// Node id (`finding:…`, `file:…`, `rule:…`).
    pub id: String,
    /// Node kind (`finding`, `file`, `rule`).
    pub kind: String,
    /// Display label.
    pub label: String,
}

/// One directed edge in the exported findings graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Source node id.
    pub from: String,
    /// Target node id.
    pub to: String,
    /// Edge relation (`in_file`, `flagged_by`).
    pub rel: String,
}

/// The findings graph: nodes (findings, files, rules) and edges between them.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Graph {
    /// Graph nodes.
    pub nodes: Vec<GraphNode>,
    /// Graph edges.
    pub edges: Vec<GraphEdge>,
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

        // The findings graph has finding, file, and rule nodes with edges.
        let graph = store.graph("").await.unwrap();
        assert_eq!(
            graph.nodes.iter().filter(|n| n.kind == "finding").count(),
            2
        );
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.kind == "file" && n.label == "a.env"));
        assert!(graph
            .nodes
            .iter()
            .any(|n| n.kind == "rule" && n.label == "aws-key"));
        assert!(graph.edges.iter().any(|e| e.rel == "in_file"));
        assert!(graph.edges.iter().any(|e| e.rel == "flagged_by"));
        // Filtered graph narrows to one finding.
        let one = store.graph("rule=aws-key").await.unwrap();
        assert_eq!(one.nodes.iter().filter(|n| n.kind == "finding").count(), 1);

        // Snapshot export includes the record and edge tables.
        let snap = store.export_snapshot().await.unwrap();
        assert_eq!(snap["version"], 1);
        assert_eq!(snap["tables"]["file"].as_array().unwrap().len(), 2);
        assert_eq!(snap["tables"]["finding"].as_array().unwrap().len(), 2);
        assert!(snap["tables"].get("in_file").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn rule(name: &str, pattern: &str) -> Rule {
        Rule {
            name: name.into(),
            pattern: pattern.into(),
            description: String::new(),
            severity: Some(exfill_core::Severity::High),
            cwe: Some("CWE-798".into()),
            cve: None,
        }
    }

    #[tokio::test]
    async fn catalog_dataset_crud() {
        let dir = std::env::temp_dir().join(format!("exfill-catalog-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir, DB_CATALOG).await.unwrap();

        // Upsert two datasets, one sharing a rule with the other.
        let shared = rule("aws-key", r"AKIA[0-9A-Z]{16}");
        let n = store
            .upsert_dataset(&Dataset {
                name: "security".into(),
                rules: vec![shared.clone(), rule("gh", r"ghp_\w+")],
            })
            .await
            .unwrap();
        assert_eq!(n, 2);
        store
            .upsert_dataset(&Dataset {
                name: "extra".into(),
                rules: vec![shared.clone(), rule("slack", r"xox[bp]-\w+")],
            })
            .await
            .unwrap();

        // list: two datasets with their counts.
        let list = store.list_datasets().await.unwrap();
        assert_eq!(list, vec![("extra".into(), 2), ("security".into(), 2)]);

        // all_rules dedups the shared rule: 3 distinct (aws-key, gh, slack).
        let all = store.all_rules().await.unwrap();
        assert_eq!(
            all.len(),
            3,
            "{:?}",
            all.iter().map(|r| &r.name).collect::<Vec<_>>()
        );

        // get: the security dataset has its two rules.
        let ds = store.get_dataset("security").await.unwrap().unwrap();
        assert_eq!(ds.rules.len(), 2);
        assert!(store.get_dataset("nope").await.unwrap().is_none());

        // Re-upsert with fewer rules replaces the set.
        store
            .upsert_dataset(&Dataset {
                name: "security".into(),
                rules: vec![rule("only", r"X")],
            })
            .await
            .unwrap();
        assert_eq!(
            store
                .get_dataset("security")
                .await
                .unwrap()
                .unwrap()
                .rules
                .len(),
            1
        );

        // remove: gone from the list; second remove reports false.
        assert!(store.remove_dataset("extra").await.unwrap());
        assert!(!store.remove_dataset("extra").await.unwrap());
        let names: Vec<String> = store
            .list_datasets()
            .await
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["security".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn node_and_edge_crud_roundtrip() {
        let dir = std::env::temp_dir().join(format!("exfill-crud-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir, DB_FINDINGS).await.unwrap();

        // Two file nodes.
        store
            .upsert_file(&sample_meta("aaa", "a.txt"))
            .await
            .unwrap();
        store
            .upsert_file(&sample_meta("bbb", "b.txt"))
            .await
            .unwrap();

        // set_field returns the old value and applies the new one.
        let old = store
            .set_field("file:aaa", "path", serde_json::json!("renamed.txt"))
            .await
            .unwrap();
        assert_eq!(old, serde_json::json!("a.txt"));
        let rec = store.get_record("file:aaa").await.unwrap().unwrap();
        assert_eq!(rec["path"], "renamed.txt");

        // Invalid field names are rejected (no injection surface).
        assert!(store
            .set_field("file:aaa", "a; DROP", serde_json::json!(1))
            .await
            .is_err());

        // create_edge then it shows up as a neighbor; delete_edge removes it.
        store
            .create_edge("contained_in", "file:aaa", "file:bbb")
            .await
            .unwrap();
        let neigh = store.neighbors("file:aaa").await.unwrap();
        assert!(neigh
            .iter()
            .any(|n| n.id == "file:bbb" && n.rel == "contained_in"));
        store
            .delete_edge("contained_in", "file:aaa", "file:bbb")
            .await
            .unwrap();
        let neigh = store.neighbors("file:aaa").await.unwrap();
        assert!(!neigh.iter().any(|n| n.rel == "contained_in"), "{neigh:?}");

        // Unknown relations are rejected.
        assert!(store
            .create_edge("bogus", "file:aaa", "file:bbb")
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
