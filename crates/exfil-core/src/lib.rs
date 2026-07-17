//! Core domain types shared across exfil crates: the vocabulary of rules,
//! datasets, matches, findings, and file metadata. No I/O, no plugins — just
//! the data model the rest of the workspace agrees on.
//!
//! # Rust notes (for readers new to the language)
//!
//! - `#[derive(...)]` above a struct/enum asks the compiler to *generate* an
//!   implementation of a trait for you. `Debug` gives `{:?}` printing, `Clone`
//!   gives `.clone()`, and `Serialize`/`Deserialize` (from the serde crate)
//!   generate JSON/TOML conversion code at compile time — no reflection.
//! - `#[serde(...)]` attributes tweak that generated code, e.g. renaming
//!   fields or skipping empty ones in output.
//! - `Option<T>` is Rust's "nullable": a value is either `Some(t)` or `None`.
//!   There is no null — the type system forces you to handle absence.
//! - `pub` marks items visible outside this crate; everything else is private.

use serde::{Deserialize, Serialize};

pub mod platform;

/// Severity of a rule or finding.
///
/// `Copy` (alongside `Clone`) means values of this enum are so small they are
/// duplicated implicitly instead of *moved* — you can pass a `Severity` around
/// without ownership bookkeeping. `rename_all = "lowercase"` makes it appear
/// as `"high"` (not `"High"`) in JSON and TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; not a problem by itself.
    Info,
    /// Worth knowing about, unlikely to be exploitable.
    Low,
    /// Should be reviewed.
    Medium,
    /// Likely a real problem.
    High,
    /// Confirmed dangerous pattern (e.g. leaked live credentials).
    Critical,
}

impl Severity {
    /// Weight used when computing an aggregate risk score.
    ///
    /// A `match` on an enum must cover every variant — if a new severity is
    /// ever added, this function stops compiling until it's handled. That
    /// exhaustiveness check is one of Rust's main safety levers.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 5,
            Severity::Critical => 10,
        }
    }
}

/// A single named pattern. Security rules also carry a classification.
///
/// The serde attributes here shape the wire format: `#[serde(default)]` lets
/// a field be omitted in input (it gets its type's default, e.g. `""`), and
/// `skip_serializing_if = "Option::is_none"` drops `None` fields from output
/// instead of writing `"cwe": null`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier, e.g. `aws-access-key-id`.
    pub name: String,
    /// The regex (or scanner-specific pattern) to match.
    pub pattern: String,
    /// Human-readable summary of what the rule detects.
    #[serde(default)]
    pub description: String,
    /// How serious a match is, when the rule has an opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Common Weakness Enumeration id, e.g. `CWE-798`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// Specific vulnerability id, e.g. `CVE-2024-12345`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
}

/// A named collection of rules — the unit a source fetches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Dataset identifier, e.g. `security` or `gitleaks`.
    pub name: String,
    /// The rules the dataset provides.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// One hit: a rule matching at a location in a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// Name of the [`Rule`] that matched.
    pub rule: String,
    /// Path of the file the match was found in.
    #[serde(default)]
    pub path: String,
    /// 1-based line number of the match.
    pub line: u32,
    /// 1-based column (character offset) within the line.
    pub col: u32,
    /// The matching line, trimmed, for display.
    pub snippet: String,
    /// Severity inherited from the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// CWE inherited from the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// CVE inherited from the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
}

/// A file produced by an expander task rather than read from disk — e.g. an
/// entry unpacked from an archive. It carries its own bytes and a display path
/// (typically `archive.zip!inner/file.txt`) so downstream tasks treat it like
/// any other file.
#[derive(Debug, Clone)]
pub struct VirtualFile {
    /// Display path, usually `<container>!<inner path>`.
    pub path: String,
    /// The entry's decompressed content.
    pub content: Vec<u8>,
}

/// One element of a file's AST: a declaration, import, or call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Kind of symbol: `function`, `import`, `call`, ….
    pub kind: String,
    /// The symbol's name as written in source.
    pub name: String,
    /// 1-based line where the symbol appears.
    pub line: u32,
}

/// Virtual-filesystem metadata for a file: OS-level details and a content
/// hash, never the contents themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// Path as encountered during the walk (may be relative).
    pub path: String,
    /// Absolute, canonicalized path.
    pub abs: String,
    /// Hostname of the machine the file was scanned on.
    pub host: String,
    /// Unix permission/mode bits (0 where the platform has none).
    pub mode: u32,
    /// Owning user id (0 where the platform has none).
    pub uid: u32,
    /// Owning group id (0 where the platform has none).
    pub gid: u32,
    /// Resolved user name, when available.
    #[serde(default)]
    pub user: String,
    /// Resolved group name, when available.
    #[serde(default)]
    pub group: String,
    /// File size in bytes.
    pub size: u64,
    /// Modification time as seconds since the Unix epoch (stringly, for
    /// portability across stores).
    pub mtime: String,
    /// blake3 of the contents (hex); used as the file's content-addressed id.
    pub hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_weights_are_ordered() {
        let ordered = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let weights: Vec<u32> = ordered.iter().map(|s| s.weight()).collect();
        assert_eq!(weights, [0, 1, 2, 5, 10]);
        assert!(weights.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn severity_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
        let s: Severity = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(s, Severity::Critical);
    }

    #[test]
    fn rule_optional_fields_roundtrip() {
        let r: Rule = serde_json::from_str(r#"{"name":"n","pattern":"p"}"#).unwrap();
        assert_eq!(r.description, "");
        assert!(r.severity.is_none() && r.cwe.is_none() && r.cve.is_none());
        // None fields are omitted on the way back out.
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("cwe") && !json.contains("severity"));
    }
}
