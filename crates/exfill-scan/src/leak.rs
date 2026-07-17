//! Breach / leak checking: flag emails that appear in a breach corpus.
//!
//! An `Indicators → Matches` checker that reuses the emails the
//! [`IndicatorExtractor`](crate::indicator) already pulled from a file and looks
//! each one up in a locally-loaded breach list — so it stays **offline** (no
//! HaveIBeenPwned API call). A breach feed supplies entries as [`Rule`]s whose
//! pattern is `breach-email:<value>`, where `<value>` is either the lowercased
//! address or its SHA-1 hex (privacy-preserving corpora ship hashes). For each
//! observed email the checker tests both the plaintext and `sha1(email)`, so a
//! hashed feed matches a plaintext observation and vice versa.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use exfill_core::{Match, Rule, Severity};
use exfill_task::{Artifact, ArtifactKind, FileTask, Indicators};
use sha1::{Digest, Sha1};

/// Parse a rule pattern as a breach entry: `breach-email:<email|sha1>`. Shared
/// with the regex scanner, which skips these. The value is lowercased.
pub fn is_breach_ioc(pattern: &str) -> Option<String> {
    let (scheme, value) = pattern.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("breach-email") {
        return None;
    }
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

/// SHA-1 hex of a value (how hashed breach corpora key their entries).
fn sha1_hex(value: &str) -> String {
    let mut h = Sha1::new();
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

/// Flags emails present in a loaded breach corpus.
pub struct LeakScanner {
    /// Plaintext emails and/or SHA-1 hex digests of breached addresses.
    entries: HashSet<String>,
}

impl LeakScanner {
    /// Build from a rule set, keeping only `breach-email:` entries.
    pub fn new(rules: &[Rule]) -> Self {
        let entries = rules
            .iter()
            .filter_map(|r| is_breach_ioc(&r.pattern))
            .collect();
        Self { entries }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn analyze(&self, ind: &Indicators, path: &str) -> Vec<Match> {
        let mut matches = Vec::new();
        for email in &ind.emails {
            let lower = email.to_ascii_lowercase();
            // Match a plaintext feed or a hashed feed with one lookup each.
            if self.entries.contains(&lower) || self.entries.contains(&sha1_hex(&lower)) {
                matches.push(Match {
                    rule: "breach-email".into(),
                    path: path.to_string(),
                    line: 0,
                    col: 1,
                    snippet: format!("email in breach corpus: {email}"),
                    severity: Some(Severity::High),
                    cwe: Some("CWE-359".into()),
                    cve: None,
                });
            }
        }
        matches
    }
}

impl FileTask for LeakScanner {
    fn name(&self) -> &str {
        "leak"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Indicators
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Matches
    }

    fn applies(&self, _path: &Path) -> bool {
        !self.is_empty()
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Indicators(ind) = input else {
            anyhow::bail!("leak: expected Indicators input");
        };
        Ok(Artifact::Matches(
            self.analyze(ind, &path.to_string_lossy()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str) -> Rule {
        Rule {
            name: "breach".into(),
            pattern: pattern.into(),
            description: String::new(),
            severity: None,
            cwe: None,
            cve: None,
        }
    }

    fn ind(emails: &[&str]) -> Indicators {
        Indicators {
            emails: emails.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn parses_and_rejects_patterns() {
        assert_eq!(
            is_breach_ioc("breach-email:Bob@X.com"),
            Some("bob@x.com".into())
        );
        assert!(is_breach_ioc("domain:evil.com").is_none());
        assert!(is_breach_ioc("AKIA[0-9]+").is_none());
    }

    #[test]
    fn matches_plaintext_feed() {
        let s = LeakScanner::new(&[rule("breach-email:alice@corp.com")]);
        let m = s.analyze(&ind(&["Alice@Corp.com"]), "f");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "breach-email");
        assert!(m[0].snippet.contains("Alice@Corp.com"));
    }

    #[test]
    fn matches_hashed_feed() {
        // A privacy-preserving feed ships sha1(email); a plaintext observation
        // still matches.
        let hash = sha1_hex("victim@example.org");
        let s = LeakScanner::new(&[rule(&format!("breach-email:{hash}"))]);
        let m = s.analyze(&ind(&["victim@example.org"]), "f");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn clean_email_no_match() {
        let s = LeakScanner::new(&[rule("breach-email:alice@corp.com")]);
        assert!(s.analyze(&ind(&["safe@corp.com"]), "f").is_empty());
    }

    #[test]
    fn inert_without_feed() {
        let s = LeakScanner::new(&[rule("AKIA[0-9]+")]);
        assert!(s.is_empty());
        assert!(!s.applies(Path::new("f")));
    }

    #[test]
    fn wrong_input_errors() {
        let s = LeakScanner::new(&[rule("breach-email:a@b.co")]);
        let err = s.run(Path::new("f"), &Artifact::Bytes(vec![])).unwrap_err();
        assert!(err.to_string().contains("expected Indicators"), "{err}");
    }
}
