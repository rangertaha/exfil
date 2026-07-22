//! End-to-end tests driving the real `exfil` binary through every wired
//! command: scan a seeded tree, query it back, fetch records, and clean up.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SECRET_LINE: &str = "export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF\n";

fn exfil(store: &Path, args: &[&str]) -> Output {
    // Point the catalog at a non-existent dir so scans use only the built-in
    // rules — never the developer's real ~/.config/exfil/catalog.
    let no_catalog = store.parent().unwrap_or(store).join("no-catalog");
    Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(store)
        .args(args)
        .env("EXFIL_CATALOG_DIR", no_catalog)
        .output()
        .expect("run exfil")
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
        let base = std::env::temp_dir().join(format!("exfil-cli-{}-{name}", std::process::id()));
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
    let out = exfil(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "scan failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("aws-access-key-id"), "{text}");
    assert!(
        text.contains("scanned 2 files (0 unchanged): 1 new matches"),
        "{text}"
    );

    // Rescan: unchanged files take the stat fast-path, findings don't duplicate.
    let out = exfil(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "rescan failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("scanned 2 files (2 unchanged): 0 new matches"),
        "{text}"
    );

    // search with no query lists the finding.
    let out = exfil(&sb.store, &["search"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("1 finding(s)"), "{}", stdout(&out));

    // field filter narrows; a non-matching filter returns zero.
    let out = exfil(&sb.store, &["search", "severity=critical"]);
    assert!(stdout(&out).contains("1 finding(s)"));
    let out = exfil(&sb.store, &["search", "severity=low"]);
    assert!(stdout(&out).contains("0 finding(s)"));

    // an unknown field is a hard error.
    let out = exfil(&sb.store, &["search", "bogus=1"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unknown search field"),
        "{}",
        stderr(&out)
    );

    // analyze: renders a report over the graph in each format.
    let out = exfil(&sb.store, &["analyze"]);
    assert!(out.status.success(), "analyze failed: {}", stderr(&out));
    assert!(
        stdout(&out).contains("1 finding(s) across"),
        "{}",
        stdout(&out)
    );
    let out = exfil(&sb.store, &["analyze", "--format", "json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid json report");
    assert_eq!(v["summary"]["findings"], 1);
    let out = exfil(&sb.store, &["analyze", "-f", "xml"]);
    assert!(!out.status.success(), "unknown format must error");

    // get: the file record is addressable by its content hash.
    let hash = blake3::hash(SECRET_LINE.as_bytes()).to_hex().to_string();
    let out = exfil(&sb.store, &["get", &format!("file:{hash}")]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("leak.env"), "{}", stdout(&out));

    // get: missing record and malformed id.
    let out = exfil(&sb.store, &["get", "file:doesnotexist"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no record"));
    let out = exfil(&sb.store, &["get", "garbage"]);
    assert!(!out.status.success());

    // graph emits nodes/edges as JSON; gc runs and reports.
    let out = exfil(&sb.store, &["graph"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let g: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid graph json");
    assert!(g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["kind"] == "finding"));
    let out = exfil(&sb.store, &["graph", "--format", "dot"]);
    assert!(stdout(&out).contains("digraph exfil"));
    let out = exfil(&sb.store, &["store", "gc"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("gc: removed"), "{}", stdout(&out));

    // clean removes the store; a second clean is a no-op.
    let out = exfil(&sb.store, &["store", "clean"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("removed store"));
    assert!(!sb.store.exists());
    let out = exfil(&sb.store, &["store", "clean"]);
    assert!(stdout(&out).contains("no store"));
}

#[test]
fn scan_ports_without_a_target_is_rejected() {
    // `--ports` only makes sense sweeping a host/CIDR target; without one it
    // must error, not silently fall through to a plain local directory scan.
    let sb = Sandbox::new("ports-no-target");
    let out = exfil(&sb.store, &["scan", "--ports", "22,80"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("TARGET"),
        "expected a missing-target error, got:\n{}",
        stderr(&out)
    );
}

#[test]
fn rules_lists_builtin_ruleset() {
    let sb = Sandbox::new("rules");
    let out = exfil(&sb.store, &["rules"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for rule in ["aws-access-key-id", "private-key-block", "password-in-url"] {
        assert!(text.contains(rule), "missing {rule} in:\n{text}");
    }
}

#[test]
fn config_shows_explicit_file_and_errors_when_missing() {
    let sb = Sandbox::new("config");
    let cfg = sb.base.join("exfil.toml");
    std::fs::write(
        &cfg,
        "store = \".exfil\"\n[plugins.regex]\ndatasets = []\n\n[[update]]\nname = \"security\"\nref = \"builtin://security\"\n",
    )
    .unwrap();

    let out = exfil(&sb.store, &["--config", cfg.to_str().unwrap(), "config"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    // `config` prints the resolved path then the file's actual contents.
    assert!(text.contains("# config:"), "{text}");
    assert!(text.contains("[plugins.regex]"), "{text}");
    assert!(text.contains("ref = \"builtin://security\""), "{text}");

    let out = exfil(
        &sb.store,
        &["--config", "/nonexistent/exfil.toml", "config"],
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("read config"), "{}", stderr(&out));
}

#[test]
fn enrich_and_export_commands() {
    let sb = Sandbox::new("enrich");
    let out = exfil(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    // enrich writes a triage note to the finding.
    let out = exfil(&sb.store, &["enrich"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("enriched 1 finding(s)"),
        "{}",
        stdout(&out)
    );

    // export --format json includes the enriched triage field.
    let out = exfil(&sb.store, &["store", "export", "--format", "json"]);
    assert!(out.status.success());
    let snap: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("json snapshot");
    let triage = snap["tables"]["finding"][0]["triage"]
        .as_str()
        .unwrap_or("");
    assert!(triage.contains("credential"), "{triage}");
}

#[test]
fn mcp_server_answers_over_stdio() {
    use std::io::Write;
    use std::process::Stdio;

    let sb = Sandbox::new("mcp");
    let out = exfil(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    let mut child = Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(&sb.store)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"query":""}}}"#,
        "\n",
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let init: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "exfil");
    let call: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert!(call["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("aws-access-key-id"));
}

/// Run exfil with an isolated catalog dir (so tests never touch the real one).
fn exfil_catalog(store: &Path, catalog: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(store)
        .args(args)
        .env("EXFIL_CATALOG_DIR", catalog)
        .output()
        .expect("run exfil")
}

#[test]
fn sources_pull_datasets_flow() {
    let sb = Sandbox::new("catalog");
    let catalog = sb.base.join("catalog");

    // sources lists the plugins.
    let out = exfil_catalog(&sb.store, &catalog, &["sources"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("builtin") && text.contains("file") && text.contains("http"));

    // datasets is empty before any pull.
    let out = exfil_catalog(&sb.store, &catalog, &["datasets"]);
    assert!(stdout(&out).contains("no datasets"), "{}", stdout(&out));

    // pull the built-in security dataset into the catalog.
    let out = exfil_catalog(&sb.store, &catalog, &["pull", "builtin://security"]);
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
    let out = exfil_catalog(&sb.store, &catalog, &["pull", ds.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    // datasets now lists both.
    let out = exfil_catalog(&sb.store, &catalog, &["datasets"]);
    let text = stdout(&out);
    assert!(
        text.contains("security") && text.contains("custom"),
        "{text}"
    );
    assert!(text.contains("2 dataset(s)"), "{text}");

    // A scan now applies the custom rule from the catalog.
    std::fs::write(sb.tree.join("token.txt"), "key = ACME-123456\n").unwrap();
    let out = exfil_catalog(
        &sb.store,
        &catalog,
        &["scan", sb.tree.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("acme-token"), "{}", stdout(&out));
}

#[test]
fn ioc_hash_and_content_scanning() {
    let sb = Sandbox::new("ioc");
    let catalog = sb.base.join("catalog");

    // A "malware" file (match by hash) and a config referencing a bad domain.
    let payload = b"malicious payload\n";
    std::fs::write(sb.tree.join("mal.bin"), payload).unwrap();
    std::fs::write(sb.tree.join("cfg.txt"), "c2 = evil-c2.example\n").unwrap();

    // IOC dataset: one sha256 hash IOC + one content (domain) IOC.
    use sha2::{Digest, Sha256};
    let sha = hex_encode(&Sha256::digest(payload));
    let ds = sb.base.join("iocs.json");
    std::fs::write(
        &ds,
        format!(
            r#"{{"name":"iocs","rules":[
                {{"name":"bad-file","pattern":"sha256:{sha}","severity":"critical"}},
                {{"name":"bad-domain","pattern":"evil-c2\\.example","severity":"high"}}
            ]}}"#
        ),
    )
    .unwrap();

    let out = exfil_catalog(&sb.store, &catalog, &["pull", ds.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    let out = exfil_catalog(
        &sb.store,
        &catalog,
        &["scan", sb.tree.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("bad-file"), "hash IOC missing:\n{text}");
    assert!(text.contains("bad-domain"), "content IOC missing:\n{text}");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn clamav_signatures_from_config() {
    let sb = Sandbox::new("clam");

    // A file whose sha256 we'll list as a hash signature, and a file with a
    // literal body signature ("MALSTRING" = 4d414c535452494e47).
    let payload = b"clamav sample payload\n";
    std::fs::write(sb.tree.join("mal.bin"), payload).unwrap();
    std::fs::write(sb.tree.join("body.txt"), "junk MALSTRING junk\n").unwrap();

    use sha2::{Digest, Sha256};
    let sha = hex_encode(&Sha256::digest(payload));
    let sigs = sb.base.join("sigs.hdb");
    std::fs::write(
        &sigs,
        format!(
            "{sha}:{}:Test.Sample.Hash\nTest.Body.Sig:0:*:4d414c535452494e47\n",
            payload.len()
        ),
    )
    .unwrap();
    let cfg = sb.base.join("exfil.toml");
    std::fs::write(
        &cfg,
        format!(
            "store = \".exfil\"\n[plugins.clamav]\nsignatures = [{:?}]\n",
            sigs.to_str().unwrap()
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(&sb.store)
        .arg("--config")
        .arg(&cfg)
        .args(["scan", sb.tree.to_str().unwrap()])
        .output()
        .expect("run exfil");
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("clamav:Test.Sample.Hash"),
        "hash sig:\n{text}"
    );
    assert!(text.contains("clamav:Test.Body.Sig"), "body sig:\n{text}");
}

#[test]
fn script_enricher_from_config() {
    let sb = Sandbox::new("script");
    let out = exfil(&sb.store, &["scan", sb.tree.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));

    let script = sb.base.join("enrich.rhai");
    std::fs::write(
        &script,
        r#"if finding.severity == "critical" { "SCRIPTED: " + finding.rule } else { () }"#,
    )
    .unwrap();
    let cfg = sb.base.join("exfil.toml");
    std::fs::write(
        &cfg,
        format!(
            "store = \".exfil\"\n[plugins.script]\nenrich = {:?}\n",
            script.to_str().unwrap()
        ),
    )
    .unwrap();

    // enrich runs the user script.
    let out = exfil_cfg(&sb.store, &cfg, &["enrich"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("enrich.rhai"), "{}", stdout(&out));

    // The scripted triage note landed on the finding.
    let out = exfil(&sb.store, &["store", "export", "--format", "json"]);
    let snap: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let triage = snap["tables"]["finding"][0]["triage"]
        .as_str()
        .unwrap_or("");
    assert!(triage.contains("SCRIPTED: aws-access-key-id"), "{triage}");
}

/// Run exfil with an explicit config file (and an isolated catalog).
fn exfil_cfg(store: &Path, cfg: &Path, args: &[&str]) -> Output {
    let no_catalog = store.parent().unwrap_or(store).join("no-catalog");
    Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(store)
        .arg("--config")
        .arg(cfg)
        .args(args)
        .env("EXFIL_CATALOG_DIR", no_catalog)
        .output()
        .expect("run exfil")
}

#[test]
fn yara_rules_from_config() {
    let sb = Sandbox::new("yara");
    std::fs::write(sb.tree.join("suspect.bin"), "has EVILMARKER in it\n").unwrap();

    let rules = sb.base.join("rules.yar");
    std::fs::write(
        &rules,
        "rule Detect_Evil {\n  meta:\n    severity = \"critical\"\n  strings:\n    $a = \"EVILMARKER\"\n  condition:\n    $a\n}\n",
    )
    .unwrap();
    let cfg = sb.base.join("exfil.toml");
    std::fs::write(
        &cfg,
        format!(
            "store = \".exfil\"\n[plugins.yara]\nrules = [{:?}]\n",
            rules.to_str().unwrap()
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(&sb.store)
        .arg("--config")
        .arg(&cfg)
        .args(["scan", sb.tree.to_str().unwrap()])
        .output()
        .expect("run exfil");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("yara:Detect_Evil"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn dataset_crud_subcommands() {
    let sb = Sandbox::new("dscrud");
    let catalog = sb.base.join("catalog");

    // add a named dataset from a builtin reference.
    let out = exfil_catalog(
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
    let out = exfil_catalog(&sb.store, &catalog, &["datasets", "show", "sec"]);
    let text = stdout(&out);
    assert!(text.contains("aws-access-key-id"), "{text}");

    // show of a missing dataset is graceful.
    let out = exfil_catalog(&sb.store, &catalog, &["datasets", "show", "nope"]);
    assert!(stdout(&out).contains("no dataset"), "{}", stdout(&out));

    // rm removes it; a second rm reports absence.
    let out = exfil_catalog(&sb.store, &catalog, &["datasets", "rm", "sec"]);
    assert!(stdout(&out).contains("removed dataset"), "{}", stdout(&out));
    let out = exfil_catalog(&sb.store, &catalog, &["datasets", "rm", "sec"]);
    assert!(stdout(&out).contains("no dataset"), "{}", stdout(&out));
}
