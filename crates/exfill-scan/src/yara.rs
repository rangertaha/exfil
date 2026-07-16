//! YARA rule matching via the pure-Rust [`yara-x`](https://docs.rs/yara-x)
//! engine — no libyara, no C.
//!
//! [`YaraScanner`] compiles YARA rules (from files listed under
//! `[plugins.yara]` in config) and matches each file's bytes against them,
//! emitting one finding per matching rule. Severity and CWE are read from the
//! rule's `meta` block (`severity = "high"`, `cwe = "CWE-506"`) when present.
//!
//! The compiled rule set is `Send + Sync`, but a scan needs a short-lived
//! `yara_x::Scanner`; one is created per file so the type stays thread-safe
//! across the parallel walk.

use std::path::Path;

use anyhow::{Context, Result};
use exfill_core::{Match, Severity};

use crate::Scanner;

/// Matches file contents against a compiled set of YARA rules.
pub struct YaraScanner {
    rules: Option<yara_x::Rules>,
}

impl YaraScanner {
    /// Compile YARA rules from concatenated source. Invalid rule text fails
    /// with the compiler's diagnostics. An empty source yields an inert
    /// scanner (matches nothing, doesn't apply).
    pub fn from_sources(source: &str) -> Result<Self> {
        if source.trim().is_empty() {
            return Ok(Self { rules: None });
        }
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).context("compile YARA rules")?;
        Ok(Self {
            rules: Some(compiler.build()),
        })
    }

    /// Whether any rules are loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_none()
    }

    /// Parse a `severity = "..."` meta value into a [`Severity`].
    fn severity_of(value: &str) -> Option<Severity> {
        match value.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl Scanner for YaraScanner {
    fn name(&self) -> &str {
        "yara"
    }

    fn applies(&self, _path: &Path) -> bool {
        self.rules.is_some()
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        let Some(rules) = &self.rules else {
            return Ok(Vec::new());
        };
        let mut scanner = yara_x::Scanner::new(rules);
        let results = scanner.scan(content).context("YARA scan")?;

        let path_str = path.to_string_lossy().into_owned();
        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            // Pull severity/cwe from the rule's meta block when present.
            let mut severity = Some(Severity::High);
            let mut cwe = None;
            for (key, value) in rule.metadata() {
                if let yara_x::MetaValue::String(s) = value {
                    match key {
                        "severity" => severity = Self::severity_of(s).or(severity),
                        "cwe" => cwe = Some(s.to_string()),
                        _ => {}
                    }
                }
            }
            matches.push(Match {
                rule: format!("yara:{}", rule.identifier()),
                path: path_str.clone(),
                line: 1,
                col: 1,
                snippet: format!("YARA rule {:?} matched", rule.identifier()),
                severity,
                cwe,
                cve: None,
            });
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule Detect_Evil {
    meta:
        severity = "critical"
        cwe = "CWE-506"
    strings:
        $a = "EVILMARKER"
    condition:
        $a
}

rule Detect_Two_Strings {
    strings:
        $x = "foo"
        $y = "bar"
    condition:
        $x and $y
}
"#;

    fn scan(source: &str, path: &str, content: &[u8]) -> Vec<Match> {
        let scanner = YaraScanner::from_sources(source).unwrap();
        scanner.scan(Path::new(path), content).unwrap()
    }

    #[test]
    fn matches_rule_and_reads_meta() {
        let m = scan(RULES, "f.bin", b"junk EVILMARKER junk");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "yara:Detect_Evil");
        assert_eq!(m[0].severity, Some(Severity::Critical));
        assert_eq!(m[0].cwe.as_deref(), Some("CWE-506"));
    }

    #[test]
    fn condition_with_multiple_strings() {
        assert!(scan(RULES, "f", b"has foo only").is_empty());
        let m = scan(RULES, "f", b"has foo and bar");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "yara:Detect_Two_Strings");
        // No meta → default High severity, no CWE.
        assert_eq!(m[0].severity, Some(Severity::High));
        assert!(m[0].cwe.is_none());
    }

    #[test]
    fn clean_content_produces_nothing() {
        assert!(scan(RULES, "f", b"perfectly benign content").is_empty());
    }

    #[test]
    fn empty_source_is_inert() {
        let scanner = YaraScanner::from_sources("   \n").unwrap();
        assert!(scanner.is_empty());
        assert!(!scanner.applies(Path::new("x")));
        assert!(scanner
            .scan(Path::new("x"), b"EVILMARKER")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn invalid_rules_error() {
        let err = match YaraScanner::from_sources("rule broken { condition }") {
            Ok(_) => panic!("expected a compile error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("compile YARA rules"), "{err}");
    }

    #[test]
    fn severity_parsing() {
        assert_eq!(
            YaraScanner::severity_of("critical"),
            Some(Severity::Critical)
        );
        assert_eq!(YaraScanner::severity_of("LOW"), Some(Severity::Low));
        assert_eq!(YaraScanner::severity_of("bogus"), None);
    }
}
