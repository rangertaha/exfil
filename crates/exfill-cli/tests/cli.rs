//! End-to-end tests driving the real `exfill` binary through every wired
//! command: scan a seeded tree, query it back, fetch records, and clean up.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SECRET_LINE: &str = "export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF\n";

fn exfill(store: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exfill"))
        .arg("--store")
        .arg(store)
        .args(args)
        .output()
        .expect("run exfill")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A per-test sandbox: a tree with one secret and one clean file, plus a
/// store directory beside it.
struct Sandbox {
    base: PathBuf,
    tree: PathBuf,
    store: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("exfill-cli-{}-{name}", std::process::id()));
        let tree = base.join("tree");
        let store = base.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("leak.env"), SECRET_LINE).unwrap();
        std::fs::write(tree.join("clean.rs"), "fn main() {}\n").unwrap();
        Self { base, tree, store }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[test]
fn scan_search_get_clean_roundtrip() {
    let sb = Sandbox::new("roundtrip");

    // scan: finds the secret, streams it, and prints a summary.
    let out = exfill(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "scan failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("aws-access-key-id"), "{text}");
    assert!(
        text.contains("scanned 2 files (0 unchanged): 1 new matches"),
        "{text}"
    );

    // Rescan: unchanged files take the stat fast-path, findings don't duplicate.
    let out = exfill(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "rescan failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("scanned 2 files (2 unchanged): 0 new matches"),
        "{text}"
    );

    // search with no query lists the finding.
    let out = exfill(&sb.store, &["search"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("1 finding(s)"), "{}", stdout(&out));

    // field filter narrows; a non-matching filter returns zero.
    let out = exfill(&sb.store, &["search", "severity=critical"]);
    assert!(stdout(&out).contains("1 finding(s)"));
    let out = exfill(&sb.store, &["search", "severity=low"]);
    assert!(stdout(&out).contains("0 finding(s)"));

    // an unknown field is a hard error.
    let out = exfill(&sb.store, &["search", "bogus=1"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unknown search field"),
        "{}",
        stderr(&out)
    );

    // analyze: renders a report over the graph in each format.
    let out = exfill(&sb.store, &["analyze"]);
    assert!(out.status.success(), "analyze failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("1 finding(s) across"),
        "{}",
        stdout(&out)
    );
    let out = exfill(&sb.store, &["analyze", "--format", "json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid json report");
    assert_eq!(v["summary"]["findings"], 1);
    let out = exfill(&sb.store, &["analyze", "-f", "xml"]);
    assert!(!out.status.success(), "unknown format must error");

    // get: the file record is addressable by its content hash.
    let hash = blake3::hash(SECRET_LINE.as_bytes()).to_hex().to_string();
    let out = exfill(&sb.store, &["get", &format!("file:{hash}")]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("leak.env"), "{}", stdout(&out));

    // get: missing record and malformed id.
    let out = exfill(&sb.store, &["get", "file:doesnotexist"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no record"));
    let out = exfill(&sb.store, &["get", "garbage"]);
    assert!(!out.status.success());

    // clean removes the store; a second clean is a no-op.
    let out = exfill(&sb.store, &["clean"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("removed store"));
    assert!(!sb.store.exists());
    let out = exfill(&sb.store, &["clean"]);
    assert!(stdout(&out).contains("no store"));
}

#[test]
fn rules_lists_builtin_ruleset() {
    let sb = Sandbox::new("rules");
    let out = exfill(&sb.store, &["rules"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for rule in ["aws-access-key-id", "private-key-block", "password-in-url"] {
        assert!(text.contains(rule), "missing {rule} in:\n{text}");
    }
}

#[test]
fn config_shows_explicit_file_and_errors_when_missing() {
    let sb = Sandbox::new("config");
    let cfg = sb.base.join("exfill.toml");
    std::fs::write(
        &cfg,
        "store = \".exfill\"\n[plugins.regex]\ndatasets = []\n\n[[update]]\nname = \"security\"\nref = \"builtin://security\"\n",
    )
    .unwrap();

    let out = exfill(&sb.store, &["--config", cfg.to_str().unwrap(), "config"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("plugin \"regex\""), "{text}");
    assert!(text.contains("update \"security\""), "{text}");

    let out = exfill(
        &sb.store,
        &["--config", "/nonexistent/exfill.toml", "config"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("read config"), "{}", stderr(&out));
}

#[test]
fn unimplemented_commands_say_so() {
    let sb = Sandbox::new("stub");
    for cmd in ["enrich", "gc", "mcp"] {
        let out = exfill(&sb.store, &[cmd]);
        assert!(out.status.success(), "{cmd}");
        assert!(stdout(&out).contains("not yet implemented"), "{cmd}");
    }
}

/// Run exfill with an isolated catalog dir (so tests never touch the real one).
fn exfill_catalog(store: &Path, catalog: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exfill"))
        .arg("--store")
        .arg(store)
        .args(args)
        .env("EXFILL_CATALOG_DIR", catalog)
        .output()
        .expect("run exfill")
}

#[test]
fn sources_pull_datasets_flow() {
    let sb = Sandbox::new("catalog");
    let catalog = sb.base.join("catalog");

    // sources lists the plugins.
    let out = exfill_catalog(&sb.store, &catalog, &["sources"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("builtin") && text.contains("file") && text.contains("http"));

    // datasets is empty before any pull.
    let out = exfill_catalog(&sb.store, &catalog, &["datasets"]);
    assert!(stdout(&out).contains("no datasets"), "{}", stdout(&out));

    // pull the built-in security dataset into the catalog.
    let out = exfill_catalog(&sb.store, &catalog, &["pull", "builtin://security"]);
    assert!(out.status.success(), "pull failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("pulled \"security\""),
        "{}",
        stdout(&out)
    );

    // pull a custom dataset from a JSON file.
    let ds = sb.base.join("custom.json");
    std::fs::write(
        &ds,
        r#"{"name":"custom","rules":[{"name":"acme-token","pattern":"ACME-[0-9]{6}","severity":"high"}]}"#,
    )
    .unwrap();
    let out = exfill_catalog(&sb.store, &catalog, &["pull", ds.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    // datasets now lists both.
    let out = exfill_catalog(&sb.store, &catalog, &["datasets"]);
    let text = stdout(&out);
    assert!(
        text.contains("security") && text.contains("custom"),
        "{text}"
    );
    assert!(text.contains("2 dataset(s)"), "{text}");

    // A scan now applies the custom rule from the catalog.
    std::fs::write(sb.tree.join("token.txt"), "key = ACME-123456\n").unwrap();
    let out = exfill_catalog(&sb.store, &catalog, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("acme-token"), "{}", stdout(&out));
}

#[test]
fn dataset_crud_subcommands() {
    let sb = Sandbox::new("dscrud");
    let catalog = sb.base.join("catalog");

    // add a named dataset from a builtin reference.
    let out = exfill_catalog(
        &sb.store,
        &catalog,
        &["datasets", "add", "sec", "builtin://security"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("added dataset \"sec\""),
        "{}",
        stdout(&out)
    );

    // show lists its rules.
    let out = exfill_catalog(&sb.store, &catalog, &["datasets", "show", "sec"]);
    let text = stdout(&out);
    assert!(text.contains("aws-access-key-id"), "{text}");

    // show of a missing dataset is graceful.
    let out = exfill_catalog(&sb.store, &catalog, &["datasets", "show", "nope"]);
    assert!(stdout(&out).contains("no dataset"), "{}", stdout(&out));

    // rm removes it; a second rm reports absence.
    let out = exfill_catalog(&sb.store, &catalog, &["datasets", "rm", "sec"]);
    assert!(stdout(&out).contains("removed dataset"), "{}", stdout(&out));
    let out = exfill_catalog(&sb.store, &catalog, &["datasets", "rm", "sec"]);
    assert!(stdout(&out).contains("no dataset"), "{}", stdout(&out));
}
