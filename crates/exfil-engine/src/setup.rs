//! Shared run setup: opening the two stores and building the scan pipeline
//! from config plus catalog contents.
//!
//! Both front ends need this — the CLI for its commands, the MCP server for the
//! tools it exposes to agents — and they must agree, or an agent-run scan would
//! apply a different ruleset than the same scan from a shell. Keeping it here
//! (rather than in either front end) is what makes that agreement structural.
//!
//! # Rust notes
//!
//! These functions take `Option<&Path>` for the config: `None` means "the
//! default user config", not "no config". That mirrors the CLI's `--config`
//! flag, which is itself optional.

use std::path::Path;

use anyhow::Result;
use exfil_store::Store;
use exfil_task::Pipeline;

/// The `[database]` override from config, or `None` for the embedded default.
/// An empty (or absent) endpoint keeps the built-in per-path embedded stores.
pub fn database_override(config: Option<&Path>) -> Option<exfil_store::DbConfig> {
    let db = exfil_config::load(config).ok()?.database?;
    if db.endpoint.trim().is_empty() {
        return None;
    }
    Some(exfil_store::DbConfig {
        endpoint: db.endpoint,
        username: db.username,
        password: db.password,
    })
}

/// Open the findings database: the configured `[database]` endpoint, or the
/// embedded on-disk store at `store_dir`.
pub async fn open_findings(store_dir: &Path, config: Option<&Path>) -> Result<Store> {
    match database_override(config) {
        Some(db) => Store::connect(&db, exfil_store::DB_FINDINGS).await,
        None => Store::open_findings(store_dir).await,
    }
}

/// Open the catalog database (datasets, rules, CWE): the configured
/// `[database]` endpoint, or the embedded catalog in the user data directory.
pub async fn open_catalog(config: Option<&Path>) -> Result<Store> {
    if let Some(db) = database_override(config) {
        return Store::connect(&db, exfil_store::DB_CATALOG).await;
    }
    let dir = exfil_config::catalog_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    Store::open_catalog(&dir).await
}

/// A built pipeline plus what had to be dropped to build it: the names of rules
/// whose patterns the regex engine could not compile. Callers surface that
/// however suits them (a stderr note, an MCP tool result); the scan itself runs
/// with everything that did compile.
pub struct BuiltPipeline {
    /// The dependency-ordered task pipeline.
    pub pipeline: Pipeline,
    /// Names of rules skipped because their pattern would not compile.
    pub skipped: Vec<String>,
}

/// Build the scan pipeline: built-in rules plus any catalog datasets, plus
/// YARA rules and ClamAV signatures from the files listed under
/// `[plugins.yara]` / `[plugins.clamav]` in config. Non-compiling external
/// regex patterns are reported in [`BuiltPipeline::skipped`] and skipped.
pub async fn build_pipeline(config: Option<&Path>) -> Result<BuiltPipeline> {
    let mut rules = exfil_scan::builtin_rules();
    // YARA rules from feeds are stored as `yara:<source>` in the catalog;
    // split them out and compile them into the YARA scanner.
    let mut yara_from_feeds = String::new();
    if let Ok(catalog) = open_catalog(config).await {
        for rule in catalog.all_rules().await.unwrap_or_default() {
            if let Some(src) = exfil_scan::yara::is_yara_source(&rule.pattern) {
                yara_from_feeds.push_str(src);
                yara_from_feeds.push('\n');
            } else {
                rules.push(rule);
            }
        }
    }
    let clamav_signatures = load_plugin_files(config, "clamav", "signatures");
    let yara_rules = format!(
        "{}\n{yara_from_feeds}",
        load_plugin_files(config, "yara", "rules")
    );
    let (pipeline, skipped) =
        exfil_scan::pipeline_with_rules(rules, &clamav_signatures, &yara_rules)?;
    Ok(BuiltPipeline { pipeline, skipped })
}

/// A stable fingerprint of the ruleset a scan would apply: the built-in rules
/// plus everything in the catalog, hashed by name and pattern.
///
/// Findings are whatever the active rules happened to fire on. That makes the
/// fingerprint the thing that decides whether "unchanged since last scan" is
/// still a safe reason to skip a file — pull a new dataset and it isn't, because
/// those rules have never seen that file. Order-independent, so merely
/// reordering a dataset doesn't force a full rescan.
pub async fn ruleset_fingerprint(config: Option<&Path>) -> String {
    let mut entries: Vec<String> = exfil_scan::builtin_rules()
        .iter()
        .map(|r| format!("{}={}", r.name, r.pattern))
        .collect();
    if let Ok(catalog) = open_catalog(config).await {
        for rule in catalog.all_rules().await.unwrap_or_default() {
            entries.push(format!("{}={}", rule.name, rule.pattern));
        }
    }
    entries.sort();
    entries.dedup();
    blake3::hash(entries.join("\n").as_bytes()).to_hex()[..16].to_string()
}

/// Read and concatenate the files listed in a plugin's string-array field
/// (e.g. `[plugins.clamav] signatures = [...]`). Missing files are skipped
/// silently; a missing/unreadable config or absent field yields an empty
/// string.
pub fn load_plugin_files(config: Option<&Path>, plugin: &str, field: &str) -> String {
    let Ok(cfg) = exfil_config::load(config) else {
        return String::new();
    };
    let mut text = String::new();
    for path in cfg.plugin_strings(plugin, field) {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            text.push_str(&contents);
            text.push('\n');
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with no `[database]` block keeps the embedded stores.
    #[test]
    fn absent_and_empty_endpoints_keep_embedded_stores() {
        let dir = std::env::temp_dir().join(format!("exfil-setup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let none = dir.join("none.toml");
        std::fs::write(&none, "store = \".exfil\"\n").unwrap();
        assert!(database_override(Some(&none)).is_none());

        let empty = dir.join("empty.toml");
        std::fs::write(&empty, "[database]\nendpoint = \"\"\n").unwrap();
        assert!(database_override(Some(&empty)).is_none());

        let set = dir.join("set.toml");
        std::fs::write(&set, "[database]\nendpoint = \"mem://\"\n").unwrap();
        assert_eq!(database_override(Some(&set)).unwrap().endpoint, "mem://");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Listed signature files are concatenated; missing ones are skipped.
    #[test]
    fn load_plugin_files_concatenates_and_skips_missing() {
        let dir = std::env::temp_dir().join(format!("exfil-setup-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sig = dir.join("a.ndb");
        std::fs::write(&sig, "one").unwrap();
        let cfg = dir.join("config.toml");
        std::fs::write(
            &cfg,
            format!(
                "[plugins.clamav]\nsignatures = [{:?}, {:?}]\n",
                sig.display().to_string(),
                dir.join("missing.ndb").display().to_string()
            ),
        )
        .unwrap();

        let text = load_plugin_files(Some(&cfg), "clamav", "signatures");
        assert_eq!(text, "one\n");
        // An absent plugin block is simply empty.
        assert!(load_plugin_files(Some(&cfg), "yara", "rules").is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_pipeline_includes_builtin_rules() {
        let dir = std::env::temp_dir().join(format!("exfil-setup-pipe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, "store = \".exfil\"\n").unwrap();

        let built = build_pipeline(Some(&cfg)).await.unwrap();
        let names: Vec<&str> = built.pipeline.tasks().iter().map(|t| t.name()).collect();
        assert!(names.contains(&"regex"), "{names:?}");
        // The AST extractor must precede its taint consumer.
        let ast = names.iter().position(|n| *n == "ast").unwrap();
        let taint = names.iter().position(|n| *n == "taint").unwrap();
        assert!(ast < taint, "{names:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
