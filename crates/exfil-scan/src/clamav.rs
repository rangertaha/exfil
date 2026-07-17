//! ClamAV-style malware signature matching, pure Rust.
//!
//! Parses a practical subset of ClamAV's signature formats and matches files
//! against them — no libclamav, no C, so the single-binary story holds:
//!
//! - **Hash signatures** (`.hdb` MD5, `.hsb` SHA) — one per line as
//!   `hash:size:name`. A file matches when its digest equals `hash` and its
//!   size equals `size` (or `size` is `*`).
//! - **Body signatures** (`.ndb`) — `name:target:offset:hexsig`. Only literal
//!   hex signatures are supported; ones using ClamAV wildcards (`*`, `?`,
//!   `{n}`, `(a|b)`) are skipped and counted, because faithfully evaluating the
//!   ClamAV pattern language is out of scope. Literal signatures are matched as
//!   raw bytes with Aho–Corasick (so they work on binary files, unlike a text
//!   regex).
//!
//! Signatures are loaded from files listed under `[plugins.clamav]` in config.

use std::collections::HashMap;
use std::path::Path;

use aho_corasick::AhoCorasick;
use anyhow::Result;
use exfil_core::{Match, Severity};

/// A parsed hash signature: expected size (None = any) and malware name.
struct HashSig {
    size: Option<u64>,
    name: String,
}

/// Which digest a hash signature uses, inferred from its hex length.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum HashKind {
    Md5,
    Sha256,
}

/// Matches files against ClamAV hash and literal-body signatures.
pub struct ClamavScanner {
    /// (kind, lowercase hex) → signature.
    hashes: HashMap<(HashKind, String), HashSig>,
    /// Which hash kinds are present (compute only those digests).
    kinds: Vec<HashKind>,
    /// Aho–Corasick automaton over literal body signatures, if any.
    body: Option<AhoCorasick>,
    /// Malware names parallel to the body automaton's patterns.
    body_names: Vec<String>,
}

impl ClamavScanner {
    /// Parse ClamAV-format signature text (hash and `.ndb` lines mixed).
    /// Returns the scanner and the number of signatures skipped (wildcarded
    /// body sigs or malformed lines).
    pub fn from_signatures(text: &str) -> (Self, usize) {
        let mut hashes = HashMap::new();
        let mut body_patterns: Vec<Vec<u8>> = Vec::new();
        let mut body_names = Vec::new();
        let mut skipped = 0;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            match parse_line(&fields) {
                Some(Parsed::Hash { kind, hex, sig }) => {
                    hashes.insert((kind, hex), sig);
                }
                Some(Parsed::Body { name, bytes }) => {
                    body_patterns.push(bytes);
                    body_names.push(name);
                }
                None => skipped += 1,
            }
        }

        let mut kinds = Vec::new();
        if hashes.keys().any(|(k, _)| *k == HashKind::Md5) {
            kinds.push(HashKind::Md5);
        }
        if hashes.keys().any(|(k, _)| *k == HashKind::Sha256) {
            kinds.push(HashKind::Sha256);
        }
        let body = if body_patterns.is_empty() {
            None
        } else {
            AhoCorasick::new(&body_patterns).ok()
        };

        (
            Self {
                hashes,
                kinds,
                body,
                body_names,
            },
            skipped,
        )
    }

    /// Total signatures loaded (hash + body).
    pub fn len(&self) -> usize {
        self.hashes.len() + self.body_names.len()
    }

    /// Whether no signatures are loaded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn digest(kind: HashKind, content: &[u8]) -> String {
        use md5::Md5;
        use sha2::{Digest, Sha256};
        match kind {
            HashKind::Md5 => hex::encode(Md5::digest(content)),
            HashKind::Sha256 => hex::encode(Sha256::digest(content)),
        }
    }
}

impl crate::Scanner for ClamavScanner {
    fn name(&self) -> &str {
        "clamav"
    }

    fn applies(&self, _path: &Path) -> bool {
        !self.is_empty()
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        let path_str = path.to_string_lossy();
        let mut matches = Vec::new();
        let finding = |name: &str, what: &str| Match {
            rule: format!("clamav:{name}"),
            path: path_str.to_string(),
            line: 1,
            col: 1,
            snippet: format!("ClamAV signature {name:?} matched ({what})"),
            severity: Some(Severity::Critical),
            cwe: Some("CWE-506".into()),
            cve: None,
        };

        // Hash signatures (size-gated).
        for &kind in &self.kinds {
            let digest = Self::digest(kind, content);
            if let Some(sig) = self.hashes.get(&(kind, digest)) {
                if sig.size.is_none_or(|s| s == content.len() as u64) {
                    matches.push(finding(&sig.name, "hash"));
                }
            }
        }

        // Literal body signatures.
        if let Some(ac) = &self.body {
            let mut seen = std::collections::HashSet::new();
            for m in ac.find_iter(content) {
                if seen.insert(m.pattern().as_usize()) {
                    matches.push(finding(&self.body_names[m.pattern()], "body"));
                }
            }
        }
        Ok(matches)
    }
}

/// A recognized signature line.
enum Parsed {
    Hash {
        kind: HashKind,
        hex: String,
        sig: HashSig,
    },
    Body {
        name: String,
        bytes: Vec<u8>,
    },
}

/// Parse one signature line's colon-split fields.
fn parse_line(fields: &[&str]) -> Option<Parsed> {
    // Hash: `hash:size:name` (exactly 3 fields, field0 is md5/sha256 hex).
    if fields.len() == 3 {
        let hex = fields[0].to_ascii_lowercase();
        let kind = match hex.len() {
            32 if is_hex(&hex) => HashKind::Md5,
            64 if is_hex(&hex) => HashKind::Sha256,
            _ => return parse_body(fields),
        };
        let size = match fields[1] {
            "*" => None,
            n => Some(n.parse().ok()?),
        };
        return Some(Parsed::Hash {
            kind,
            hex,
            sig: HashSig {
                size,
                name: fields[2].to_string(),
            },
        });
    }
    parse_body(fields)
}

/// Parse an `.ndb` body signature `name:target:offset:hexsig[:min:max]`.
fn parse_body(fields: &[&str]) -> Option<Parsed> {
    if fields.len() < 4 {
        return None;
    }
    let name = fields[0].to_string();
    let hexsig = fields[3];
    // Wildcarded signatures use ClamAV's pattern language — skip them.
    if hexsig.contains(['*', '?', '{', '}', '(', ')', '[', ']', '!']) {
        return None;
    }
    let bytes = decode_hex(hexsig)?;
    if bytes.is_empty() {
        return None;
    }
    Some(Parsed::Body { name, bytes })
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode an even-length hex string to bytes, or `None` if malformed.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !is_hex(s) {
        return None;
    }
    hex::decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scanner;

    #[test]
    fn parses_and_matches_hash_signature() {
        let content = b"totally malicious";
        let md5 = ClamavScanner::digest(HashKind::Md5, content);
        let sigs = format!("{md5}:{}:Win.Test.Malware", content.len());
        let (scanner, skipped) = ClamavScanner::from_signatures(&sigs);
        assert_eq!(skipped, 0);
        assert_eq!(scanner.len(), 1);

        let m = scanner.scan(Path::new("mal.exe"), content).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "clamav:Win.Test.Malware");
        assert_eq!(m[0].severity, Some(Severity::Critical));
    }

    #[test]
    fn hash_signature_respects_size_gate() {
        let content = b"payload";
        let md5 = ClamavScanner::digest(HashKind::Md5, content);
        // Wrong size → no match even though the hash matches.
        let (scanner, _) = ClamavScanner::from_signatures(&format!("{md5}:999:Bad"));
        assert!(scanner.scan(Path::new("f"), content).unwrap().is_empty());
        // Size `*` matches any size.
        let (any, _) = ClamavScanner::from_signatures(&format!("{md5}:*:Bad"));
        assert_eq!(any.scan(Path::new("f"), content).unwrap().len(), 1);
    }

    #[test]
    fn matches_literal_body_signature_in_binary() {
        // Body sig for the bytes "EVIL" (45 56 49 4c) anywhere in the file.
        let (scanner, skipped) = ClamavScanner::from_signatures("Test.Body:0:*:4556494c");
        assert_eq!(skipped, 0);
        let content = b"\x00\x01 here is EVIL inside \xff";
        let m = scanner.scan(Path::new("blob.bin"), content).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "clamav:Test.Body");
        // A clean file does not match.
        assert!(scanner.scan(Path::new("ok"), b"nice").unwrap().is_empty());
    }

    #[test]
    fn wildcarded_body_signatures_are_skipped() {
        let (scanner, skipped) =
            ClamavScanner::from_signatures("Test.Wild:0:*:4556{4}494c\nBad.Line:only-two:fields");
        assert!(scanner.is_empty());
        assert_eq!(skipped, 2);
        assert!(!scanner.applies(Path::new("x")));
    }

    #[test]
    fn comments_and_blanks_are_ignored() {
        let (scanner, skipped) = ClamavScanner::from_signatures("# a comment\n\n   \n");
        assert!(scanner.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn sha256_hash_signature() {
        let content = b"sha sample";
        let sha = ClamavScanner::digest(HashKind::Sha256, content);
        let (scanner, _) = ClamavScanner::from_signatures(&format!("{sha}:*:Sha.Malware"));
        let m = scanner.scan(Path::new("f"), content).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "clamav:Sha.Malware");
    }
}
