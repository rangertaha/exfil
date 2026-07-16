//! Scanners: pluggable analyzers that turn file content into [`Match`]es.
//!
//! A [`Scanner`] decides which files it [`applies`](Scanner::applies) to and
//! produces matches for the ones it handles. Each scanner is wrapped in a
//! [`ScanTask`] (its `Bytes → Matches` edge) and placed in the task
//! [`Pipeline`](exfill_task::Pipeline), which the engine drives per file. This
//! crate ships the [`RegexScanner`], the [`SupplyChainScanner`], and the
//! archive [`ArchiveExpander`]; AST, taint, and YARA scanners join later.
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
//! - `Send + Sync` on the trait declares that scanners may be shared across
//!   threads — required because the engine scans files in parallel. The
//!   compiler *proves* this; a scanner holding non-thread-safe state simply
//!   won't compile into the pipeline.

pub mod ast;
pub mod builtin;
pub mod expand;
pub mod supply;
pub use ast::{AstExtractor, DangerousCallScanner};
pub use builtin::builtin_rules;
pub use expand::ArchiveExpander;
pub use supply::SupplyChainScanner;

use std::path::Path;

use anyhow::{Context, Result};
use exfill_core::{Match, Rule};
use exfill_task::{Artifact, ArtifactKind, FileTask, Pipeline};
use regex::Regex;

/// A pluggable analyzer over a single file's bytes.
pub trait Scanner: Send + Sync {
    /// Stable identifier used in config and reports.
    fn name(&self) -> &str;

    /// Whether this scanner wants to look at `path`, by name/extension. The
    /// engine only offers actual files (real or expanded from an archive), so
    /// this is purely content-type gating, not a file-vs-directory check.
    fn applies(&self, path: &Path) -> bool;

    /// Analyze `content` (the bytes of `path`) and return any matches.
    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>>;
}

/// Adapts a [`Scanner`] (bytes → matches) into a [`FileTask`] in the pipeline
/// DAG. Scanners keep their simple trait; this is the `Bytes → Matches` edge.
pub struct ScanTask<S: Scanner>(pub S);

impl<S: Scanner> FileTask for ScanTask<S> {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Bytes
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Matches
    }

    fn applies(&self, path: &Path) -> bool {
        self.0.applies(path)
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Bytes(bytes) = input else {
            anyhow::bail!("{}: expected Bytes input", self.0.name());
        };
        Ok(Artifact::Matches(self.0.scan(path, bytes)?))
    }
}

/// The standard plugin lineup as a pipeline: an archive expander (so scanners
/// see files inside archives), regex over the built-in security ruleset, and
/// supply-chain manifest checks. The CLI and TUI both scan with this.
/// Additional tasks (AST, taint) register here and the scheduler orders them by
/// their declared dependencies.
pub fn default_pipeline() -> Result<Pipeline> {
    Pipeline::new(vec![
        Box::new(ArchiveExpander::default()),
        Box::new(ScanTask(RegexScanner::new(builtin_rules())?)),
        Box::new(ScanTask(SupplyChainScanner)),
        // AST chain: the scheduler places the extractor (Bytes→Ast) before the
        // dangerous-call scanner (Ast→Matches) automatically.
        Box::new(AstExtractor),
        Box::new(DangerousCallScanner),
    ])
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

    fn applies(&self, _path: &Path) -> bool {
        // Regex scanning targets any text file; binary content is filtered out
        // by the engine before bytes are handed over.
        true
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

    /// A scanner that always errors, for exercising pipeline error handling.
    struct FailingScanner;

    impl Scanner for FailingScanner {
        fn name(&self) -> &str {
            "failing"
        }
        fn applies(&self, _p: &Path) -> bool {
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
        fn applies(&self, _p: &Path) -> bool {
            false
        }
        fn scan(&self, _p: &Path, _c: &[u8]) -> Result<Vec<Match>> {
            panic!("scan called on a scanner that does not apply")
        }
    }

    #[test]
    fn pipeline_runs_applicable_scanners_and_skips_others() {
        let pipeline = Pipeline::new(vec![
            Box::new(ScanTask(
                RegexScanner::new(vec![rule("aws-key", r"AKIA[0-9A-Z]{16}")]).unwrap(),
            )),
            Box::new(ScanTask(NeverApplies)),
        ])
        .unwrap();
        let out = pipeline
            .run_file(Path::new("f"), b"key = AKIA0123456789ABCDEF\n".to_vec())
            .unwrap();
        assert_eq!(out.matches.len(), 1);
        assert_eq!(out.matches[0].rule, "aws-key");
    }

    #[test]
    fn pipeline_error_names_the_scanner_and_file() {
        let pipeline = Pipeline::new(vec![Box::new(ScanTask(FailingScanner))]).unwrap();
        let err = pipeline
            .run_file(Path::new("victim.txt"), b"x".to_vec())
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("failing") && msg.contains("boom"), "{msg}");
        assert!(msg.contains("victim.txt"), "{msg}");
    }

    #[test]
    fn default_pipeline_builds_and_names_are_stable() {
        let pipeline = default_pipeline().unwrap();
        let names: Vec<&str> = pipeline.tasks().iter().map(|t| t.name()).collect();
        // Expander must precede the scanners so archive contents get scanned.
        assert_eq!(names.first(), Some(&"archive-expand"));
        assert!(names.contains(&"regex") && names.contains(&"supply-chain"));
    }
}
