//! Format-aware feed ingestion — the orchestration behind a URL feed catalog.
//!
//! A *feed* is a URL that publishes detection data in some format. This module
//! turns one into an exfil [`Dataset`] (a set of [`Rule`]s) through a small
//! pipeline: **fetch → decompress → detect format → parse → normalize**.
//!
//! - **Decompress** — `.gz`, `.zip`, `.tar`, `.tar.gz`/`.tgz` are unpacked into
//!   member files; a plain file is its own single member. Nested formats
//!   (`feed.csv.gz`) are resolved by peeling the outer extension.
//! - **Detect** — each member's format is guessed from its filename extension.
//! - **Parse** — JSON (native dataset), CSV/TSV (a header row maps columns to
//!   rule fields), and newline-delimited IOCs (one domain/IP/hash per line).
//!
//! The parsing is pure (bytes → rules), so every format is unit-testable
//! without the network; [`fetch_feed`] is the thin download layer on top.
//! Adding a format (RSS, YARA, gitleaks TOML, …) is a new arm here — the
//! catalog, storage, and CLI don't change.

use std::io::Read;

use anyhow::{bail, Context, Result};
use exfil_core::{Dataset, Rule, Severity};

/// A feed's payload format (after any decompression).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    /// Native exfil dataset JSON (`{ "name", "rules": [...] }`).
    Json,
    /// Comma-separated rules with a header row (`name,pattern,severity,cwe,…`).
    Csv,
    /// Tab-separated rules with a header row.
    Tsv,
    /// One indicator per line (domain / IP / sha256); `#` comments skipped.
    Iocs,
}

impl FeedFormat {
    /// Guess a member's format from its filename extension. Unknown extensions
    /// fall back to newline-delimited IOCs (the most common raw-feed shape).
    pub fn from_name(name: &str) -> FeedFormat {
        let path = name.split(['?', '#']).next().unwrap_or(name);
        match path
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => FeedFormat::Json,
            "csv" => FeedFormat::Csv,
            "tsv" | "tab" => FeedFormat::Tsv,
            _ => FeedFormat::Iocs,
        }
    }
}

/// Download `url`, decompress, and parse every member into one [`Dataset`]
/// named `name`. Members that fail to parse are skipped with a warning, so one
/// bad file in an archive doesn't sink the whole feed.
pub async fn fetch_feed(name: &str, url: &str) -> Result<Dataset> {
    let bytes = reqwest::get(url)
        .await
        .with_context(|| format!("download feed {url}"))?
        .error_for_status()
        .context("feed download failed")?
        .bytes()
        .await
        .context("read feed body")?;
    let dataset = ingest(name, filename_of(url), &bytes)?;
    Ok(dataset)
}

/// The pure core of [`fetch_feed`]: given the payload bytes and the source
/// filename, decompress + parse into a [`Dataset`]. Testable without I/O.
pub fn ingest(name: &str, filename: &str, bytes: &[u8]) -> Result<Dataset> {
    let mut rules = Vec::new();
    for (member, data) in decompress(filename, bytes)? {
        let format = FeedFormat::from_name(&member);
        match parse(name, format, &data) {
            Ok(rs) => rules.extend(rs),
            Err(e) => eprintln!("[feed] {name}: skip {member:?}: {e:#}"),
        }
    }
    Ok(Dataset {
        name: name.to_string(),
        rules,
    })
}

/// Parse one member's bytes in `format` into rules, tagged under the feed `name`.
pub fn parse(name: &str, format: FeedFormat, bytes: &[u8]) -> Result<Vec<Rule>> {
    match format {
        FeedFormat::Json => Ok(serde_json::from_slice::<Dataset>(bytes)
            .context("parse dataset JSON")?
            .rules),
        FeedFormat::Csv => parse_delimited(&String::from_utf8_lossy(bytes), ',', name),
        FeedFormat::Tsv => parse_delimited(&String::from_utf8_lossy(bytes), '\t', name),
        FeedFormat::Iocs => Ok(parse_iocs(&String::from_utf8_lossy(bytes), name)),
    }
}

/// Parse header-driven CSV/TSV rules. The first non-empty line is a header;
/// `name` and `pattern` columns are required, `severity`/`cwe`/`description`
/// optional. Rows missing a name or pattern are skipped.
fn parse_delimited(text: &str, delim: char, feed: &str) -> Result<Vec<Rule>> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines
        .next()
        .with_context(|| format!("{feed}: empty feed"))?;
    let cols: Vec<String> = header
        .split(delim)
        .map(|c| c.trim().to_ascii_lowercase())
        .collect();
    let idx = |key: &str| cols.iter().position(|c| c == key);
    let (Some(ni), Some(pi)) = (idx("name"), idx("pattern")) else {
        bail!("{feed}: CSV/TSV needs 'name' and 'pattern' header columns");
    };
    let (si, ci, di) = (idx("severity"), idx("cwe"), idx("description"));

    let mut rules = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(delim).collect();
        let get = |i: Option<usize>| {
            i.and_then(|i| fields.get(i))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        let (Some(rule_name), Some(pattern)) = (get(Some(ni)), get(Some(pi))) else {
            continue;
        };
        rules.push(Rule {
            name: rule_name,
            pattern,
            description: get(di).unwrap_or_default(),
            severity: get(si).and_then(|s| parse_severity(&s)),
            cwe: get(ci),
            cve: None,
        });
    }
    Ok(rules)
}

/// Parse newline-delimited indicators into IOC rules. Each line is classified
/// as a sha256 hash, an IP, or a domain and emitted as a `sha256:`/`ip:`/
/// `domain:` pattern; blank lines, `#` comments, and unclassifiable lines are
/// skipped.
fn parse_iocs(text: &str, feed: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let pattern = if is_sha256(value) {
            format!("sha256:{}", value.to_ascii_lowercase())
        } else if value.parse::<std::net::IpAddr>().is_ok() {
            format!("ip:{value}")
        } else if is_domain(value) {
            format!("domain:{}", value.to_ascii_lowercase())
        } else {
            continue;
        };
        rules.push(Rule {
            name: format!("{feed}-ioc"),
            pattern,
            description: format!("indicator from feed {feed}"),
            severity: Some(Severity::High),
            cwe: Some("CWE-506".into()),
            cve: None,
        });
    }
    rules
}

/// Decompress a fetched payload into `(member_name, bytes)` pairs. Recognizes
/// `.zip`, `.tar`, `.tar.gz`/`.tgz`, and `.gz`; anything else is one member
/// (itself).
pub fn decompress(name: &str, bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        unzip(bytes)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        untar(&gunzip(bytes)?)
    } else if lower.ends_with(".tar") {
        untar(bytes)
    } else if lower.ends_with(".gz") {
        let inner_name = lower.strip_suffix(".gz").unwrap_or(&lower).to_string();
        Ok(vec![(inner_name, gunzip(bytes)?)])
    } else {
        Ok(vec![(name.to_string(), bytes.to_vec())])
    }
}

/// gunzip a single stream.
fn gunzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .context("gunzip")?;
    Ok(out)
}

/// Read every regular file from a tar archive.
fn untar(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = tar::Archive::new(bytes);
    let mut members = Vec::new();
    for entry in archive.entries().context("read tar")? {
        let mut entry = entry.context("tar entry")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).context("read tar entry")?;
        members.push((path, data));
    }
    Ok(members)
}

/// Read every file from a zip archive.
fn unzip(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("open zip")?;
    let mut members = Vec::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("zip entry")?;
        if !file.is_file() {
            continue;
        }
        let name = file.name().to_string();
        let mut data = Vec::new();
        file.read_to_end(&mut data).context("read zip entry")?;
        members.push((name, data));
    }
    Ok(members)
}

/// A lowercase severity word to a [`Severity`], if recognized.
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" | "med" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}

/// Whether `s` is a 64-character hex string (a sha256 digest).
fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A permissive domain check: at least one dot, and every label is
/// alphanumeric or a hyphen (rejects URLs, IPs, and free text).
fn is_domain(s: &str) -> bool {
    s.contains('.')
        && !s.contains(['/', ':', ' ', '@'])
        && s.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && s.split('.')
            .next_back()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_alphabetic()))
}

/// The last path segment of a URL (its filename), for format detection.
fn filename_of(url: &str) -> &str {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_detection_by_extension() {
        assert_eq!(FeedFormat::from_name("feed.json"), FeedFormat::Json);
        assert_eq!(FeedFormat::from_name("rules.CSV"), FeedFormat::Csv);
        assert_eq!(FeedFormat::from_name("a.tsv"), FeedFormat::Tsv);
        assert_eq!(FeedFormat::from_name("domains.txt"), FeedFormat::Iocs);
        assert_eq!(FeedFormat::from_name("no-ext"), FeedFormat::Iocs);
    }

    #[test]
    fn parses_csv_rules_with_header() {
        let csv = "name,pattern,severity,cwe\n\
                   aws-key,AKIA[0-9A-Z]{16},critical,CWE-798\n\
                   ,skipme,,\n\
                   gh-token,ghp_[A-Za-z0-9]{36},high,";
        let rules = parse("feed", FeedFormat::Csv, csv.as_bytes()).unwrap();
        assert_eq!(rules.len(), 2, "the row with no name is skipped");
        assert_eq!(rules[0].name, "aws-key");
        assert_eq!(rules[0].severity, Some(Severity::Critical));
        assert_eq!(rules[0].cwe.as_deref(), Some("CWE-798"));
        assert_eq!(rules[1].name, "gh-token");
        assert_eq!(rules[1].cwe, None);
    }

    #[test]
    fn tsv_requires_name_and_pattern_columns() {
        let tsv = "foo\tbar\nx\ty";
        assert!(parse("feed", FeedFormat::Tsv, tsv.as_bytes()).is_err());
    }

    #[test]
    fn parses_iocs_by_kind() {
        let text = "# a comment\n\
                    evil.example.com\n\
                    203.0.113.9\n\
                    2001:db8::1\n\
                    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
                    not an indicator!!\n";
        let rules = parse_iocs(text, "threats");
        let pats: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(pats.contains(&"domain:evil.example.com"));
        assert!(pats.contains(&"ip:203.0.113.9"));
        assert!(pats.contains(&"ip:2001:db8::1"));
        assert!(pats.iter().any(|p| p.starts_with("sha256:e3b0c442")));
        assert_eq!(rules.len(), 4, "comment and free text are skipped");
        assert!(rules.iter().all(|r| r.name == "threats-ioc"));
    }

    #[test]
    fn ingest_json_dataset() {
        let json = br#"{"name":"x","rules":[{"name":"r","pattern":"p","severity":"low"}]}"#;
        let ds = ingest("secrets", "feed.json", json).unwrap();
        assert_eq!(ds.name, "secrets");
        assert_eq!(ds.rules.len(), 1);
        assert_eq!(ds.rules[0].name, "r");
    }

    #[test]
    fn ingest_gzipped_csv() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let csv = b"name,pattern\naws,AKIA[0-9A-Z]{16}\n";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(csv).unwrap();
        let gz = enc.finish().unwrap();
        // The source filename ends `.csv.gz`, so it's gunzipped then parsed CSV.
        let ds = ingest("feed", "rules.csv.gz", &gz).unwrap();
        assert_eq!(ds.rules.len(), 1);
        assert_eq!(ds.rules[0].name, "aws");
    }
}
