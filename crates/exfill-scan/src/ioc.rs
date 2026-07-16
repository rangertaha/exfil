//! Indicator-of-compromise (IOC) matching.
//!
//! IOC feeds come in two shapes, and exfill handles both through the ordinary
//! rule/dataset/catalog pipeline — no bespoke storage:
//!
//! - **Content indicators** (domains, IPs, URLs, filenames, strings) are just
//!   regex [`Rule`](exfill_core::Rule)s whose pattern matches the indicator, so
//!   the [`RegexScanner`](crate::RegexScanner) already finds them.
//! - **File-hash indicators** (md5/sha1/sha256 of known-bad files) are rules
//!   whose pattern is `"<algo>:<hex>"`, matched by the [`HashIocScanner`] here
//!   against each file's computed digest rather than its content.
//!
//! Because both are `Rule`s, an IOC feed is just a dataset: `exfill pull` /
//! `datasets add` load it, and scans apply it. The regex scanner skips the
//! `algo:hash` rules (via [`is_hash_ioc`]) so they aren't misread as content
//! patterns, and this scanner claims them.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use exfill_core::{Match, Rule, Severity};

use crate::Scanner;

/// A file-hash algorithm used by IOC feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algo {
    /// MD5 (32 hex chars).
    Md5,
    /// SHA-1 (40 hex chars).
    Sha1,
    /// SHA-256 (64 hex chars).
    Sha256,
}

/// Parse a hash-IOC rule pattern `"<algo>:<hex>"` into its parts. Returns
/// `None` for anything else (e.g. a normal content regex), so the regex scanner
/// can skip exactly the hash IOCs this scanner consumes.
pub fn is_hash_ioc(pattern: &str) -> Option<(Algo, String)> {
    let (algo, hash) = pattern.split_once(':')?;
    let algo = match algo.to_ascii_lowercase().as_str() {
        "md5" => Algo::Md5,
        "sha1" => Algo::Sha1,
        "sha256" => Algo::Sha256,
        _ => return None,
    };
    let hash = hash.trim().to_ascii_lowercase();
    let expected = match algo {
        Algo::Md5 => 32,
        Algo::Sha1 => 40,
        Algo::Sha256 => 64,
    };
    if hash.len() == expected && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some((algo, hash))
    } else {
        None
    }
}

/// Classification carried onto a hash-IOC match.
struct IocMeta {
    name: String,
    severity: Option<Severity>,
    cwe: Option<String>,
}

/// Matches file digests against a set of known-bad hashes from IOC feeds.
pub struct HashIocScanner {
    /// Which digests any loaded IOC uses (so we compute only what's needed).
    algos: HashSet<Algo>,
    /// (algo, lowercase hex) → the IOC's metadata.
    sigs: HashMap<(Algo, String), IocMeta>,
}

impl HashIocScanner {
    /// Build from a rule set, keeping only the `algo:hash` (hash-IOC) rules.
    pub fn new(rules: &[Rule]) -> Self {
        let mut algos = HashSet::new();
        let mut sigs = HashMap::new();
        for rule in rules {
            if let Some((algo, hash)) = is_hash_ioc(&rule.pattern) {
                algos.insert(algo);
                sigs.insert(
                    (algo, hash),
                    IocMeta {
                        name: rule.name.clone(),
                        severity: rule.severity,
                        cwe: rule.cwe.clone(),
                    },
                );
            }
        }
        Self { algos, sigs }
    }

    /// Number of hash IOCs loaded.
    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    /// Whether any hash IOCs are loaded.
    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    /// Hex digest of `content` under `algo`.
    fn digest(algo: Algo, content: &[u8]) -> String {
        use md5::Md5;
        use sha1::Sha1;
        use sha2::{Digest, Sha256};
        match algo {
            Algo::Md5 => hex::encode(Md5::digest(content)),
            Algo::Sha1 => hex::encode(Sha1::digest(content)),
            Algo::Sha256 => hex::encode(Sha256::digest(content)),
        }
    }
}

impl Scanner for HashIocScanner {
    fn name(&self) -> &str {
        "ioc-hash"
    }

    fn applies(&self, _path: &Path) -> bool {
        // Skip hashing entirely when no hash IOCs are loaded.
        !self.algos.is_empty()
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        let mut matches = Vec::new();
        for &algo in &self.algos {
            let digest = Self::digest(algo, content);
            if let Some(meta) = self.sigs.get(&(algo, digest.clone())) {
                matches.push(Match {
                    rule: meta.name.clone(),
                    path: path.to_string_lossy().into_owned(),
                    line: 1,
                    col: 1,
                    snippet: format!("file {algo:?} digest matches IOC {:?}", meta.name),
                    severity: meta.severity.or(Some(Severity::Critical)),
                    cwe: meta.cwe.clone().or_else(|| Some("CWE-506".into())),
                    cve: None,
                });
            }
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_rule(name: &str, algo_hash: &str) -> Rule {
        Rule {
            name: name.into(),
            pattern: algo_hash.into(),
            description: String::new(),
            severity: Some(Severity::Critical),
            cwe: Some("CWE-506".into()),
            cve: None,
        }
    }

    #[test]
    fn is_hash_ioc_recognizes_algos_and_rejects_others() {
        assert_eq!(
            is_hash_ioc("md5:d41d8cd98f00b204e9800998ecf8427e"),
            Some((Algo::Md5, "d41d8cd98f00b204e9800998ecf8427e".into()))
        );
        assert!(is_hash_ioc("sha256:abc").is_none(), "wrong length");
        assert!(is_hash_ioc("evil\\.com").is_none(), "content regex");
        assert!(is_hash_ioc("sha999:deadbeef").is_none(), "unknown algo");
        // uppercase hex normalizes to lower.
        assert_eq!(
            is_hash_ioc("SHA1:DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
                .unwrap()
                .1,
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn matches_known_bad_sha256() {
        let content = b"malware payload";
        let sha = super::HashIocScanner::digest(Algo::Sha256, content);
        let scanner = HashIocScanner::new(&[hash_rule("evil-bin", &format!("sha256:{sha}"))]);
        assert_eq!(scanner.len(), 1);
        assert!(scanner.applies(Path::new("x")));

        let m = scanner.scan(Path::new("mal.bin"), content).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "evil-bin");
        assert_eq!(m[0].severity, Some(Severity::Critical));

        // A different file does not match.
        assert!(scanner.scan(Path::new("ok"), b"benign").unwrap().is_empty());
    }

    #[test]
    fn empty_scanner_does_not_apply() {
        let scanner = HashIocScanner::new(&[Rule {
            name: "content".into(),
            pattern: "evil".into(), // not a hash IOC
            description: String::new(),
            severity: None,
            cwe: None,
            cve: None,
        }]);
        assert!(scanner.is_empty());
        assert!(!scanner.applies(Path::new("x")));
        assert!(scanner.scan(Path::new("x"), b"evil").unwrap().is_empty());
    }

    #[test]
    fn multiple_algos_are_each_checked() {
        let content = b"bad";
        let md5 = super::HashIocScanner::digest(Algo::Md5, content);
        let sha256 = super::HashIocScanner::digest(Algo::Sha256, content);
        let scanner = HashIocScanner::new(&[
            hash_rule("by-md5", &format!("md5:{md5}")),
            hash_rule("by-sha256", &format!("sha256:{sha256}")),
        ]);
        let m = scanner.scan(Path::new("f"), content).unwrap();
        // Both algorithms match the same file → two findings.
        assert_eq!(m.len(), 2);
    }
}
