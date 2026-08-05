//! End-to-end journeys through the real `exfil` binary.
//!
//! `cli.rs` covers commands one at a time. This file covers the paths a person
//! actually walks — scan, then ask what was found, then act on it — where the
//! interesting failures live *between* commands: a run named by one command and
//! addressed by the next, a model trained from stored scans and used to rank
//! the following one, a gate that reads what earlier scans wrote.
//!
//! Everything is built in a temp directory rather than read from `e2e/files`,
//! so the suite runs anywhere without `python3 e2e/generate.py` having been run
//! first, and a fixture edit can never silently change what is asserted here.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Run `exfil` against an isolated store *and* an isolated catalog, so a
/// developer's real `~/.local/share/exfil` is never read or written.
fn exfil(sb: &Journey, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(&sb.store)
        .args(args)
        .env("EXFIL_CATALOG_DIR", &sb.catalog)
        .output()
        .expect("run exfil")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A scan target with enough variety that ranking and reporting have something
/// to say: secrets in some places, clean files in others, several directories.
struct Journey {
    base: PathBuf,
    tree: PathBuf,
    store: PathBuf,
    catalog: PathBuf,
}

impl Journey {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("exfil-e2e-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tree = base.join("tree");

        // Risky material, concentrated in one directory.
        let secrets = tree.join("deploy/secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(
            secrets.join("aws.env"),
            "export AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF\n",
        )
        .unwrap();
        std::fs::write(
            secrets.join("id_rsa"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        // Source with a dangerous call, caught from the parse tree.
        let src = tree.join("src/handlers");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("run.py"),
            "def handle(req):\n    return os.system(req)\n",
        )
        .unwrap();

        // Bulk that should stay quiet, so "found nothing here" is meaningful.
        let docs = tree.join("docs/guide");
        std::fs::create_dir_all(&docs).unwrap();
        for i in 0..12 {
            std::fs::write(
                docs.join(format!("page{i}.md")),
                "# Docs\n\nNothing here.\n",
            )
            .unwrap();
        }

        Self {
            store: base.join("store"),
            catalog: base.join("catalog"),
            tree,
            base,
        }
    }
}

impl Drop for Journey {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// scan → the run is addressable → every read path agrees on what it found.
#[test]
fn a_named_scan_is_addressable_by_every_read_path() {
    let j = Journey::new("named");

    let o = exfil(&j, &["scan", "-n", "nightly", j.tree.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("aws-access-key-id"), "{}", out(&o));

    // The run's own findings, reached three different ways, must agree.
    let by_filter = exfil(&j, &["search", "run=nightly"]);
    assert!(by_filter.status.success(), "{}", err(&by_filter));
    assert!(
        out(&by_filter).contains("finding(s)"),
        "{}",
        out(&by_filter)
    );

    let reported = exfil(&j, &["report", "-n", "nightly", "-f", "json"]);
    let a: serde_json::Value = serde_json::from_str(&out(&reported)).expect("json report");

    // `analyze` is the glance over the same run: no finding list, but its
    // counts must match the document's or the two are lying to each other.
    let glance = exfil(&j, &["analyze", "-n", "nightly"]);
    assert!(glance.status.success(), "{}", err(&glance));
    let n = a["summary"]["findings"].as_u64().unwrap();
    assert!(
        out(&glance).contains(&format!("{n} finding(s)")),
        "analyze and report disagree about the same run:\n{}",
        out(&glance)
    );
    assert!(
        !out(&glance).contains("aws-access-key-id"),
        "analyze should summarize, not list findings:\n{}",
        out(&glance)
    );
    assert!(
        a["summary"]["findings"].as_u64().unwrap() >= 3,
        "expected the seeded secrets and the os.system call: {a}"
    );

    // A run that was never created resolves to nothing rather than everything —
    // the failure mode that would make a filter silently useless.
    let empty = exfil(&j, &["report", "-n", "no-such-run", "-f", "json"]);
    let e: serde_json::Value = serde_json::from_str(&out(&empty)).expect("json report");
    assert_eq!(e["summary"]["findings"], 0, "{e}");
}

/// A second scan of an unchanged tree must not duplicate findings, and must
/// take the stat fast-path — the guarantee incremental scanning rests on.
#[test]
fn rescanning_an_unchanged_tree_adds_nothing() {
    let j = Journey::new("rescan");

    let first = exfil(&j, &["scan", j.tree.to_str().unwrap()]);
    assert!(first.status.success(), "{}", err(&first));
    let count = |o: &Output| -> u64 {
        let v: serde_json::Value = serde_json::from_str(&out(o)).unwrap();
        v["summary"]["findings"].as_u64().unwrap()
    };
    let before = count(&exfil(&j, &["report", "-f", "json"]));

    let second = exfil(&j, &["scan", j.tree.to_str().unwrap()]);
    assert!(second.status.success(), "{}", err(&second));
    assert!(
        out(&second).contains("unchanged"),
        "expected the stat fast-path:\n{}",
        out(&second)
    );
    assert_eq!(
        before,
        count(&exfil(&j, &["report", "-f", "json"])),
        "a no-op rescan changed the finding count"
    );
}

/// Every report format renders the same scan without erroring, and the file
/// formats produce something recognisable as that format.
#[test]
fn every_report_format_renders_the_same_scan() {
    let j = Journey::new("formats");
    let o = exfil(&j, &["scan", j.tree.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));

    for format in ["text", "json", "markdown", "junit", "sarif", "pdf"] {
        let path = j.base.join(format!("report.{format}"));
        let o = exfil(&j, &["report", "-f", format, "-o", path.to_str().unwrap()]);
        assert!(o.status.success(), "{format}: {}", err(&o));
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.is_empty(), "{format} produced an empty file");

        match format {
            "json" => {
                serde_json::from_slice::<serde_json::Value>(&bytes).expect("valid json");
            }
            "junit" | "sarif" => {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    text.contains("testsuite") || text.contains("\"runs\""),
                    "{format} does not look like {format}"
                );
            }
            "pdf" => {
                assert!(bytes.starts_with(b"%PDF-"), "pdf lacks its header");
                assert!(
                    bytes.windows(5).any(|w| w == b"%%EOF"),
                    "pdf lacks its EOF marker"
                );
            }
            _ => {}
        }
    }
}

/// train → the model is stored, describable, and usable to rank the next scan.
#[test]
fn a_trained_model_ranks_the_next_scan() {
    let j = Journey::new("model");
    let o = exfil(&j, &["scan", j.tree.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));

    let trained = exfil(&j, &["train"]);
    assert!(trained.status.success(), "{}", err(&trained));

    // The tree has both labels (secrets and quiet docs), so training must
    // actually produce a model rather than refusing for want of examples.
    let listed = exfil(&j, &["model", "list"]);
    assert!(
        out(&listed).contains("default"),
        "no model was stored:\n{}\n{}",
        out(&trained),
        out(&listed)
    );
    assert!(out(&exfil(&j, &["model", "get"])).contains("states"));

    // A budgeted scan reports its coverage — the rule that stops a partial
    // scan from reading like a clean bill of health.
    let budgeted = exfil(&j, &["scan", "--budget", "30%", j.tree.to_str().unwrap()]);
    assert!(budgeted.status.success(), "{}", err(&budgeted));
    assert!(
        out(&budgeted).contains("coverage"),
        "a budgeted scan must state its coverage:\n{}",
        out(&budgeted)
    );

    // …and must refuse to also certify the tree via `--fail-on`.
    let both = exfil(
        &j,
        &[
            "scan",
            "--budget",
            "30%",
            "--fail-on",
            "high",
            j.tree.to_str().unwrap(),
        ],
    );
    assert!(!both.status.success(), "a partial scan certified a tree");
}

/// The MCP surface answers for the same store the CLI just wrote, so an agent
/// and a shell never disagree about what was found.
#[test]
fn mcp_sees_what_the_cli_just_scanned() {
    use std::io::Write;
    use std::process::Stdio;

    let j = Journey::new("mcp");
    let o = exfil(&j, &["scan", "-n", "shared", j.tree.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));

    let mut child = Command::new(env!("CARGO_BIN_EXE_exfil"))
        .arg("--store")
        .arg(&j.store)
        .arg("mcp")
        .env("EXFIL_CATALOG_DIR", &j.catalog)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_list","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"query":"run=shared"}}}"#,
        "\n",
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    let mcp = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&mcp.stdout);
    let mut lines = text.lines();

    let runs: serde_json::Value = serde_json::from_str(lines.next().expect("run_list")).unwrap();
    let listed = runs["result"]["content"][0]["text"].as_str().unwrap();
    assert!(listed.contains("shared"), "{listed}");

    let found: serde_json::Value = serde_json::from_str(lines.next().expect("search")).unwrap();
    let hits = found["result"]["content"][0]["text"].as_str().unwrap();
    assert!(hits.contains("aws-access-key-id"), "{hits}");
}

/// Piped output is a machine interface: it is never fitted to a window, so a
/// `path:line:col` prefix stays whole for editors, `grep` and scripts.
#[test]
fn piped_output_is_never_truncated() {
    let j = Journey::new("pipe");
    let o = exfil(&j, &["scan", j.tree.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));

    // stdout here is a pipe, so full absolute paths must survive intact.
    let listed = out(&exfil(&j, &["search", ""]));
    let root = j.tree.canonicalize().unwrap_or_else(|_| j.tree.clone());
    let root = root.display().to_string();
    assert!(
        listed.lines().any(|l| l.contains(&root)),
        "an absolute path was truncated in piped output:\n{listed}"
    );
    assert!(
        !listed.contains('…'),
        "piped output contains an elision marker:\n{listed}"
    );
}

/// The store directory is never scanned into itself — the recursion that would
/// make every scan grow without bound.
#[test]
fn a_scan_does_not_ingest_its_own_store() {
    let j = Journey::new("selfscan");
    // Put the store *inside* the tree, the arrangement that makes this bite.
    let store = j.tree.join(".exfil");
    let run = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_exfil"))
            .arg("--store")
            .arg(&store)
            .args(args)
            .env("EXFIL_CATALOG_DIR", &j.catalog)
            .output()
            .expect("run exfil")
    };
    assert!(run(&["scan", j.tree.to_str().unwrap()]).status.success());
    let first: serde_json::Value =
        serde_json::from_str(&out(&run(&["report", "-f", "json"]))).unwrap();
    assert!(run(&["scan", j.tree.to_str().unwrap()]).status.success());
    let second: serde_json::Value =
        serde_json::from_str(&out(&run(&["report", "-f", "json"]))).unwrap();

    assert_eq!(
        first["summary"]["files"], second["summary"]["files"],
        "the store's own files were scanned back into it"
    );
}

/// Reaching a remote system is a permission, not something a target string can
/// grant itself. Nothing here opens a socket: the refusal happens before any
/// connection is attempted, which is the whole point.
#[test]
fn network_targets_are_refused_without_active() {
    let j = Journey::new("permission");

    for target in ["example.invalid:22", "https://example.invalid/"] {
        let o = exfil(&j, &["scan", target]);
        assert!(!o.status.success(), "{target} was scanned without --active");
        assert!(err(&o).contains("--active"), "{target}: {}", err(&o));
    }

    // `--passive` asks a different question and gets a different answer.
    let o = exfil(&j, &["scan", "--passive", "example.invalid:22"]);
    assert!(!o.status.success());
    assert!(err(&o).contains("not local"), "{}", err(&o));

    // A local tree is unaffected, and `--passive` on one is simply true.
    let o = exfil(&j, &["scan", "--passive", j.tree.to_str().unwrap()]);
    assert!(o.status.success(), "{}", err(&o));
}
