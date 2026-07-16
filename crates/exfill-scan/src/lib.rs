//! Scanners: pluggable analyzers that turn file content into [`Match`]es.
//!
//! A [`Scanner`] decides which files it [`applies`](Scanner::applies) to and
//! produces matches for the ones it handles. Scanners are registered in a
//! [`Registry`]; the engine reads each file once and offers its bytes to every
//! applicable scanner. This crate ships the [`RegexScanner`]; AST, taint, and
//! YARA scanners join the registry as later milestones land.
//!
//! # Rust notes
//!
//! This crate is exfill's *plugin system*, built from two Rust features:
//!
//! - A **trait** (`Scanner`) is an interface: any type that implements its
//!   three methods can act as a scanner. Traits are how Rust does
//!   polymorphism — there is no inheritance.
//! - A **trait object** (`Box<dyn Scanner>`) is a value of *some* type
//!   implementing `Scanner`, decided at runtime. `dyn` means calls are
//!   dispatched through a vtable (like a virtual method); `Box` puts the
//!   value on the heap because different scanners have different sizes.
//!   The registry stores a `Vec<Box<dyn Scanner>>` — a list of mixed scanner
//!   types behind one interface.
//! - `Send + Sync` on the trait declares that scanners may be shared across
//!   threads — required because the engine scans files in parallel. The
//!   compiler *proves* this; a scanner holding non-thread-safe state simply
//!   won't compile into the registry.

pub mod builtin;
pub mod supply;
pub use builtin::builtin_rules;
pub use supply::SupplyChainScanner;

use std::fs::Metadata;
use std::path::Path;

use anyhow::{Context, Result};
use exfill_core::{Match, Rule};
use regex::Regex;

/// A pluggable analyzer over a single file's bytes.
pub trait Scanner: Send + Sync {
    /// Stable identifier used in config and reports.
    fn name(&self) -> &str;

    /// Whether this scanner wants to look at `path`. The engine still only reads
    /// each file once; this just gates which scanners receive the bytes.
    fn applies(&self, path: &Path, meta: &Metadata) -> bool;

    /// Analyze `content` (the bytes of `path`) and return any matches.
    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>>;
}

/// An ordered collection of scanners the engine drives per file.
///
/// `#[derive(Default)]` generates `Registry::default()` returning an empty
/// registry (an empty `Vec`), which `new()` simply delegates to.
#[derive(Default)]
pub struct Registry {
    scanners: Vec<Box<dyn Scanner>>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a scanner, returning `self` for chaining.
    ///
    /// Taking `mut self` (by value, not by reference) *consumes* the registry
    /// and hands back the modified one — the builder pattern:
    /// `Registry::new().with(a).with(b)`.
    pub fn with(mut self, scanner: Box<dyn Scanner>) -> Self {
        self.scanners.push(scanner);
        self
    }

    /// Register a scanner in place.
    pub fn register(&mut self, scanner: Box<dyn Scanner>) {
        self.scanners.push(scanner);
    }

    /// The registered scanners.
    pub fn scanners(&self) -> &[Box<dyn Scanner>] {
        &self.scanners
    }

    /// Run every applicable scanner over one file's bytes, concatenating their
    /// matches. A single scanner erroring aborts the file.
    pub fn scan_file(&self, path: &Path, meta: &Metadata, content: &[u8]) -> Result<Vec<Match>> {
        let mut out = Vec::new();
        for s in &self.scanners {
            if s.applies(path, meta) {
                out.extend(
                    s.scan(path, content)
                        .with_context(|| format!("scanner {:?} on {}", s.name(), path.display()))?,
                );
            }
        }
        Ok(out)
    }
}

/// The standard scanner lineup: regex over the built-in security ruleset plus
/// supply-chain manifest checks. The CLI and TUI both scan with this.
pub fn default_registry() -> Result<Registry> {
    Ok(Registry::new()
        .with(Box::new(RegexScanner::new(builtin_rules())?))
        .with(Box::new(SupplyChainScanner)))
}

/// A compiled rule: its pattern plus the metadata carried onto every match.
struct Compiled {
    rule: Rule,
    re: Regex,
}

/// Scans text files by matching a set of regex [`Rule`]s line by line.
pub struct RegexScanner {
    rules: Vec<Compiled>,
}

impl RegexScanner {
    /// Compile the given rules. Invalid patterns fail fast with the rule name.
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let re = Regex::new(&rule.pattern)
                .with_context(|| format!("compile rule {:?} pattern", rule.name))?;
            compiled.push(Compiled { rule, re });
        }
        Ok(Self { rules: compiled })
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Scanner for RegexScanner {
    fn name(&self) -> &str {
        "regex"
    }

    fn applies(&self, _path: &Path, meta: &Metadata) -> bool {
        // Regex scanning targets regular files; content-type filtering (skip
        // binaries) is applied by the engine before handing over bytes.
        meta.is_file()
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        // Non-UTF-8 bytes are matched lossily; binary files are expected to be
        // filtered out upstream, so this stays cheap for the common case.
        // (`from_utf8_lossy` returns a Cow — "clone on write" — which borrows
        // the input when it's already valid UTF-8 and only allocates a fixed-up
        // copy when it isn't.)
        let text = String::from_utf8_lossy(content);
        let path_str = path.to_string_lossy().into_owned();
        let mut matches = Vec::new();

        for (idx, line) in text.lines().enumerate() {
            for c in &self.rules {
                if let Some(m) = c.re.find(line) {
                    // Column is a 1-based char offset into the line.
                    let col = line[..m.start()].chars().count() as u32 + 1;
                    matches.push(Match {
                        rule: c.rule.name.clone(),
                        path: path_str.clone(),
                        line: idx as u32 + 1,
                        col,
                        snippet: line.trim().to_string(),
                        severity: c.rule.severity,
                        cwe: c.rule.cwe.clone(),
                        cve: c.rule.cve.clone(),
                    });
                }
            }
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfill_core::Severity;

    fn rule(name: &str, pattern: &str) -> Rule {
        Rule {
            name: name.into(),
            pattern: pattern.into(),
            description: String::new(),
            severity: Some(Severity::High),
            cwe: Some("CWE-798".into()),
            cve: None,
        }
    }

    #[test]
    fn matches_report_line_col_and_metadata() {
        let scanner = RegexScanner::new(vec![rule("aws-key", r"AKIA[0-9A-Z]{16}")]).unwrap();
        let content = b"first line\nkey = AKIA0123456789ABCDEF\nlast";
        let matches = scanner.scan(Path::new("secrets.txt"), content).unwrap();

        assert_eq!(matches.len(), 1);
        let m = &matches[0];
        assert_eq!(m.rule, "aws-key");
        assert_eq!(m.line, 2);
        assert_eq!(m.col, 7); // "key = " is 6 chars, match starts at col 7
        assert_eq!(m.snippet, "key = AKIA0123456789ABCDEF");
        assert_eq!(m.severity, Some(Severity::High));
        assert_eq!(m.cwe.as_deref(), Some("CWE-798"));
    }

    #[test]
    fn invalid_pattern_fails_fast() {
        let err = match RegexScanner::new(vec![rule("bad", r"(unclosed")]) {
            Ok(_) => panic!("expected compile error"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("bad"),
            "error names the rule: {err}"
        );
    }

    #[test]
    fn no_rules_no_matches() {
        let scanner = RegexScanner::new(vec![]).unwrap();
        let matches = scanner.scan(Path::new("f"), b"anything at all").unwrap();
        assert!(matches.is_empty());
    }

    /// A scanner that always errors, for exercising registry error handling.
    struct FailingScanner;

    impl Scanner for FailingScanner {
        fn name(&self) -> &str {
            "failing"
        }
        fn applies(&self, _p: &Path, _m: &Metadata) -> bool {
            true
        }
        fn scan(&self, _p: &Path, _c: &[u8]) -> Result<Vec<Match>> {
            anyhow::bail!("boom")
        }
    }

    /// A scanner that never applies; its scan must never run.
    struct NeverApplies;

    impl Scanner for NeverApplies {
        fn name(&self) -> &str {
            "never"
        }
        fn applies(&self, _p: &Path, _m: &Metadata) -> bool {
            false
        }
        fn scan(&self, _p: &Path, _c: &[u8]) -> Result<Vec<Match>> {
            panic!("scan called on a scanner that does not apply")
        }
    }

    fn file_fixture(name: &str) -> (std::path::PathBuf, Metadata) {
        let path =
            std::env::temp_dir().join(format!("exfill-scan-fixture-{}-{name}", std::process::id()));
        std::fs::write(&path, "key = AKIA0123456789ABCDEF\n").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        (path, meta)
    }

    #[test]
    fn registry_runs_applicable_scanners_and_skips_others() {
        let (path, meta) = file_fixture("applies");
        let mut registry = Registry::new().with(Box::new(
            RegexScanner::new(vec![rule("aws-key", r"AKIA[0-9A-Z]{16}")]).unwrap(),
        ));
        registry.register(Box::new(NeverApplies));
        assert_eq!(registry.scanners().len(), 2);
        assert_eq!(registry.scanners()[0].name(), "regex");

        let matches = registry
            .scan_file(&path, &meta, &std::fs::read(&path).unwrap())
            .unwrap();
        assert_eq!(matches.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn registry_error_names_the_scanner_and_file() {
        let (path, meta) = file_fixture("error");
        let registry = Registry::new().with(Box::new(FailingScanner));
        let err = registry.scan_file(&path, &meta, b"x").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("failing") && msg.contains("boom"), "{msg}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn regex_scanner_skips_non_files() {
        let scanner = RegexScanner::new(vec![]).unwrap();
        let dir_meta = std::fs::metadata(std::env::temp_dir()).unwrap();
        assert!(!scanner.applies(Path::new("/tmp"), &dir_meta));
        assert_eq!(scanner.name(), "regex");
        assert_eq!(scanner.rule_count(), 0);
    }
}
