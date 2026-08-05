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

    /// Short uppercase tag for compact displays (finding lines, tallies):
    /// `CRIT`/`HIGH`/`MED`/`LOW`/`INFO`.
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
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

/// One MITRE CWE weakness, used to enrich findings that carry a `cwe`.
///
/// This is *reference* data (a taxonomy), not a detection rule: it never enters
/// the scan pipeline. A downloaded copy lets exfil annotate a finding's bare
/// `CWE-798` with the authoritative weakness name and description, offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweEntry {
    /// Full identifier, e.g. `CWE-798`.
    pub id: String,
    /// Weakness name, e.g. `Use of Hard-coded Credentials`.
    pub name: String,
    /// Abstraction level: `Pillar`/`Class`/`Base`/`Variant`/`Compound`.
    #[serde(default)]
    pub abstraction: String,
    /// Maturity: `Stable`/`Draft`/`Incomplete`/`Deprecated`.
    #[serde(default)]
    pub status: String,
    /// The weakness description (whitespace-normalized).
    #[serde(default)]
    pub description: String,
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
    /// What was found, rendered under the snippet policy.
    pub snippet: Snippet,
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

/// Whether a snippet may carry the matched value in the clear.
///
/// Redaction is the default because a finding outlives the scan: it is written
/// to the store, rendered into JSON and SARIF, uploaded to code scanning, and
/// pasted into tickets. A secrets scanner whose own output is a copy of the
/// secrets it found has moved the credential, not contained it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SnippetPolicy {
    /// Mask the matched value, keeping enough to recognise it.
    #[default]
    Redact,
    /// Render the matched value verbatim — for rotating a leaked credential,
    /// where you need the value to go and revoke it.
    ShowSecrets,
}

/// Longest snippet any finding may carry, in characters.
///
/// Without a bound the snippet is whatever the matched line happened to be, and
/// a minified bundle is one line: a 1 MB source file produced a 1 MB snippet,
/// stored per finding and repeated in full in every JSON and SARIF report.
pub const MAX_SNIPPET_CHARS: usize = 200;

/// Characters of surrounding line kept on each side of a match.
const CONTEXT_CHARS: usize = 80;

/// What a finding shows about what was found.
///
/// A newtype rather than a `String` because the snippet is the one field of a
/// [`Match`] with a *policy* attached, and there was previously nowhere to put
/// it: fifteen scanners each built a `Match` literal by hand, so the PII scanner
/// masked its values, the regex scanner stored the raw line unbounded, and
/// nothing could have made them agree. Every way of producing one is a named
/// constructor here, so the decision is made once and a new scanner has to say
/// which kind of snippet it is building.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Snippet(String);

impl Snippet {
    /// Prose the scanner wrote about what it found, e.g. `call to eval (code
    /// injection)`. Carries no unreviewed file content, so it passes through.
    pub fn describe(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// A located match shown in the context of its line: the matched value
    /// masked per `policy`, and the line windowed around it.
    ///
    /// `col` is the 1-based character column the match starts at, as
    /// [`Match::col`] records it.
    pub fn around(line: &str, col: u32, matched: &str, policy: SnippetPolicy) -> Self {
        let shown = match policy {
            SnippetPolicy::ShowSecrets => matched.to_string(),
            SnippetPolicy::Redact => redact(matched),
        };
        Self::render(line, col, matched, shown)
    }

    /// A located match whose matched text is a *keyword*, not a value — a log
    /// scanner matching `authentication failure`, say.
    ///
    /// Windowed like [`around`](Self::around) but never masked, because there
    /// is nothing secret to mask and redacting the keyword would leave a
    /// finding that does not say what it found.
    pub fn in_line(line: &str, col: u32, matched: &str) -> Self {
        Self::render(line, col, matched, matched.to_string())
    }

    /// Rebuild `line` with `shown` in place of the match, windowed around it.
    fn render(line: &str, col: u32, matched: &str, shown: String) -> Self {
        let chars: Vec<char> = line.chars().collect();
        let start = (col.saturating_sub(1) as usize).min(chars.len());
        let end = (start + matched.chars().count()).min(chars.len());
        let shown_len = shown.chars().count();

        // Window around the match, not around the start of the line: on a
        // minified file the match can sit a megabyte in, and the first 200
        // characters of the line say nothing about it.
        let from = start.saturating_sub(CONTEXT_CHARS);
        let to = (end + CONTEXT_CHARS).min(chars.len());
        let mut out = String::new();
        if from > 0 {
            out.push('…');
        }
        out.extend(&chars[from..start]);
        out.push_str(&shown);
        out.extend(&chars[end..to]);
        if to < chars.len() {
            out.push('…');
        }

        // A single enormous match (a long base64 blob) can still overrun the
        // window it sits inside, so clamp what the line assembled.
        let out = out.trim().to_string();
        if out.chars().count() > MAX_SNIPPET_CHARS.max(shown_len) {
            let kept: String = out.chars().take(MAX_SNIPPET_CHARS).collect();
            return Self(format!("{kept}…"));
        }
        Self(out)
    }

    /// A bare value shown masked under a label, e.g. `email address:
    /// a•••@•••.com` — for scanners that report a *value* rather than a place
    /// in a line.
    pub fn mask_value(label: &str, value: &str) -> Self {
        Self(format!("{label}: {}", redact(value)))
    }

    /// Text used exactly as given, bypassing the policy.
    ///
    /// Deliberately verbose to type and easy to grep for: it is correct for
    /// content already masked by a domain rule (a card number reduced to its
    /// last four) and for test fixtures, and wrong for anything read out of a
    /// scanned file.
    pub fn verbatim(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// Whether there is nothing to show.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The rendered text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Snippet {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Snippet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Mask a value, keeping a recognisable head and tail.
///
/// Enough survives to tell two findings apart and to match the value against a
/// credential you are rotating; not enough to use it. Short values become all
/// bullets, since keeping two of six characters is not masking.
fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len().max(1));
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    // Capped so a long value cannot inflate the snippet with bullets alone.
    let hidden = (chars.len() - 8).min(12);
    format!("{head}{}{tail}", "•".repeat(hidden))
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

/// The final component of a path, treating the container marker `!` as a
/// separator alongside `/` and `\`.
///
/// Files expanded from a container carry a display path like
/// `archive.zip!inner/app.py`, and `Path::file_name` knows nothing about `!`.
/// For a file at a container's *root* — `archive.zip!package.json` — it
/// therefore returns the whole string, so a scanner gating on
/// `name == "package.json"` silently skips it while finding the identical file
/// one directory deeper. Every filename gate should use this instead.
pub fn leaf_name(path: &std::path::Path) -> Option<&str> {
    let s = path.to_str()?;
    Some(s.rsplit(['/', '\\', '!']).next().unwrap_or(s))
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
    /// Modification time since the Unix epoch, as [`mtime_stamp`] renders it
    /// (stringly, for portability across stores).
    pub mtime: String,
    /// blake3 of the contents (hex); used as the file's content-addressed id.
    pub hash: String,
}

/// The modification stamp recorded for a file — the sole producer of the
/// `mtime` written to [`FileMeta`] and compared by the incremental fast path.
///
/// Rendered at nanosecond precision, because the stamp is not a display value:
/// it is half of the evidence for "this file did not change, so its stored
/// findings still stand". Truncating to whole seconds made that claim false for
/// any edit that kept the file's length and landed in the same second as the
/// previous scan — a same-size in-place edit, which is exactly what writing a
/// credential over a placeholder looks like. Sub-second resolution costs
/// nothing and removes the window.
///
/// `None` when the platform cannot supply a usable time (no `mtime`, or one
/// before the epoch). A file with no stamp can never be certified unchanged,
/// so absence must read as "changed" — see [`FileStat::still_matches`].
///
/// [`FileStat::still_matches`]: ../exfil_store/struct.FileStat.html#method.still_matches
pub fn mtime_stamp(md: &std::fs::Metadata) -> Option<String> {
    let d = md
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(format!("{}.{:09}", d.as_secs(), d.subsec_nanos()))
}

#[cfg(test)]
mod snippet_tests {
    use super::*;

    const KEY: &str = "AKIA0123456789ABCDEF";

    #[test]
    fn a_match_is_masked_but_still_recognisable() {
        let line = format!("export AWS_ACCESS_KEY_ID={KEY}");
        let s = Snippet::around(&line, 26, KEY, SnippetPolicy::Redact);
        assert_eq!(s.as_str(), "export AWS_ACCESS_KEY_ID=AKIA••••••••••••CDEF");
        assert!(!s.contains(KEY), "the credential must not survive: {s}");
    }

    #[test]
    fn show_secrets_renders_the_value_verbatim() {
        let line = format!("export AWS_ACCESS_KEY_ID={KEY}");
        let s = Snippet::around(&line, 26, KEY, SnippetPolicy::ShowSecrets);
        assert!(s.contains(KEY), "{s}");
    }

    /// Regression: the snippet was the whole matched line, so one minified file
    /// produced a snippet as large as the file — stored per finding and
    /// repeated in full in every JSON and SARIF report.
    #[test]
    fn a_very_long_line_is_windowed_around_the_match() {
        let line = format!("{}{KEY}{}", "x".repeat(500_000), "y".repeat(500_000));
        let s = Snippet::around(&line, 500_001, KEY, SnippetPolicy::Redact);
        assert!(
            s.chars().count() <= MAX_SNIPPET_CHARS + 1,
            "{} chars",
            s.chars().count()
        );
        // The window is around the match, not the start of the line.
        assert!(s.contains("AKIA••••••••••••CDEF"), "{s}");
        assert!(s.starts_with('…'), "{s}");
    }

    #[test]
    fn a_short_line_keeps_its_whole_context_without_ellipses() {
        let s = Snippet::around(
            "key = secretvalue1",
            7,
            "secretvalue1",
            SnippetPolicy::Redact,
        );
        assert_eq!(s.as_str(), "key = secr••••lue1");
        assert!(!s.contains('…'), "{s}");
    }

    #[test]
    fn short_values_become_all_bullets() {
        // Keeping four of six characters would not be masking.
        let s = Snippet::around("pw = hunter", 6, "hunter", SnippetPolicy::Redact);
        assert_eq!(s.as_str(), "pw = ••••••");
    }

    #[test]
    fn a_keyword_match_is_windowed_but_not_masked() {
        let line = format!("{} authentication failure for root", "log ".repeat(60));
        let col = line.find("authentication").unwrap() as u32 + 1;
        let s = Snippet::in_line(&line, col, "authentication failure");
        assert!(s.contains("authentication failure"), "{s}");
        assert!(s.chars().count() <= MAX_SNIPPET_CHARS + 1);
    }

    #[test]
    fn described_and_masked_snippets_render_as_written() {
        assert_eq!(
            Snippet::describe("call to eval (code injection)").as_str(),
            "call to eval (code injection)"
        );
        let m = Snippet::mask_value("email address", "alice@example.com");
        assert!(m.starts_with("email address: "), "{m}");
        assert!(!m.contains("alice@example.com"), "{m}");
    }

    #[test]
    fn a_snippet_serializes_as_a_plain_string() {
        let s = Snippet::describe("hello");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hello\"");
        let back: Snippet = serde_json::from_str("\"hello\"").unwrap();
        assert_eq!(back, s);
        assert!(Snippet::default().is_empty());
    }
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
    #[test]
    fn leaf_name_treats_the_container_marker_as_a_separator() {
        use std::path::Path;
        let leaf = |p: &str| leaf_name(Path::new(p)).unwrap().to_string();
        // The bug this exists for: a manifest at a container's root.
        assert_eq!(leaf("archive.zip!package.json"), "package.json");
        assert_eq!(leaf("disc.iso!Cargo.toml"), "Cargo.toml");
        // …and the case that already worked, unchanged.
        assert_eq!(leaf("archive.zip!inner/package.json"), "package.json");
        // Ordinary paths behave exactly as before.
        assert_eq!(leaf("/home/u/proj/package.json"), "package.json");
        assert_eq!(leaf("package.json"), "package.json");
        assert_eq!(leaf(r"C:\\proj\\package.json"), "package.json");
        // Nested containers resolve to the innermost entry.
        assert_eq!(leaf("a.zip!b.iso!requirements.txt"), "requirements.txt");
    }
}
