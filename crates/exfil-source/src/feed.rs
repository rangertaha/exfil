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
//!   rule fields), newline-delimited IOCs (one domain/IP/hash per line),
//!   RSS/Atom (indicators mined from item text), YARA (`.yar` rule blocks
//!   compiled into the YARA scanner), and gitleaks TOML (`[[rules]]` regexes).
//!
//! The parsing is pure (bytes → rules), so every format is unit-testable
//! without the network; [`fetch_feed`] is the thin download layer on top.
//! Adding a format (STIX, MISP, …) is a new arm here — the catalog, storage,
//! and CLI don't change.

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
    /// RSS/Atom XML — indicators are mined from item titles, links, and bodies.
    Rss,
    /// YARA rules (`.yar`/`.yara`) — one detection rule per `rule { … }` block.
    Yara,
    /// A gitleaks config TOML — its `[[rules]]` become regex rules.
    GitleaksToml,
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
            "rss" | "atom" | "xml" => FeedFormat::Rss,
            "yar" | "yara" => FeedFormat::Yara,
            "toml" => FeedFormat::GitleaksToml,
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
        FeedFormat::Rss => Ok(parse_rss(bytes, name)),
        FeedFormat::Yara => Ok(parse_yara(&String::from_utf8_lossy(bytes), name)),
        FeedFormat::GitleaksToml => parse_gitleaks(bytes, name),
    }
}

/// Parse a [gitleaks](https://github.com/gitleaks/gitleaks) config TOML: each
/// `[[rules]]` entry (`id`, `description`, `regex`) becomes a regex [`Rule`].
/// Rules without a regex are skipped; patterns using regex features Rust's
/// engine lacks (lookahead, …) simply fail to compile later and are dropped.
fn parse_gitleaks(bytes: &[u8], feed: &str) -> Result<Vec<Rule>> {
    #[derive(serde::Deserialize)]
    struct Config {
        #[serde(default)]
        rules: Vec<GitleaksRule>,
    }
    #[derive(serde::Deserialize)]
    struct GitleaksRule {
        #[serde(default)]
        id: String,
        #[serde(default)]
        description: String,
        #[serde(default)]
        regex: String,
    }
    let text = std::str::from_utf8(bytes).context("gitleaks TOML is not UTF-8")?;
    let config: Config = toml::from_str(text).context("parse gitleaks TOML")?;
    if config.rules.is_empty() {
        bail!("{feed}: no [[rules]] in gitleaks TOML");
    }
    Ok(config
        .rules
        .into_iter()
        .filter(|r| !r.regex.trim().is_empty())
        .map(|r| Rule {
            name: if r.id.trim().is_empty() {
                format!("{feed}-rule")
            } else {
                r.id
            },
            pattern: r.regex,
            description: r.description,
            severity: None,
            cwe: None,
            cve: None,
        })
        .collect())
}

/// Mine indicators out of an RSS/Atom feed's text (item titles, links, bodies)
/// and emit them as IOC rules. Reuses the pipeline's indicator extractor, so
/// domains/IPs/URLs/hashes embedded in advisory prose are captured.
fn parse_rss(bytes: &[u8], feed: &str) -> Vec<Rule> {
    let text = xml_text(bytes);
    let indicators = exfil_scan::indicator::extract(text.as_bytes());
    iocs_from_indicators(&indicators, feed)
}

/// Join every text node of an XML document (falls back to the raw bytes when it
/// doesn't parse), so indicators can be extracted from any element.
fn xml_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| roxmltree::Document::parse(s).ok())
    {
        Some(doc) => doc
            .descendants()
            .filter(roxmltree::Node::is_text)
            .filter_map(|n| n.text())
            .collect::<Vec<_>>()
            .join(" "),
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Build IOC rules from extracted observables (domains/IPs/URLs/hashes).
fn iocs_from_indicators(ind: &exfil_task::Indicators, feed: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut push = |pattern: String| {
        rules.push(Rule {
            name: format!("{feed}-ioc"),
            pattern,
            description: format!("indicator from feed {feed}"),
            severity: Some(Severity::High),
            cwe: Some("CWE-506".into()),
            cve: None,
        });
    };
    for d in &ind.domains {
        push(format!("domain:{d}"));
    }
    for ip in &ind.ips {
        push(format!("ip:{ip}"));
    }
    for url in &ind.urls {
        push(format!("url:{url}"));
    }
    for hash in &ind.hashes {
        let scheme = match hash.len() {
            32 => "md5",
            40 => "sha1",
            64 => "sha256",
            _ => continue,
        };
        push(format!("{scheme}:{}", hash.to_ascii_lowercase()));
    }
    rules
}

/// Parse a YARA source file into one rule per `rule <name> { … }` block. Each
/// becomes a `Rule` whose pattern is `yara:<block source>`; the scan pipeline
/// collects those and compiles them into the YARA scanner.
fn parse_yara(source: &str, feed: &str) -> Vec<Rule> {
    split_yara_rules(source)
        .into_iter()
        .map(|(name, block)| Rule {
            name: format!("yara:{name}"),
            pattern: format!("yara:{block}"),
            description: format!("YARA rule from feed {feed}"),
            severity: Some(Severity::High),
            cwe: None,
            cve: None,
        })
        .collect()
}

/// Split YARA source into `(rule_name, block_source)` pairs by matching braces,
/// skipping braces inside strings and `//` / `/* */` comments. Robust enough
/// for real rule files without a full YARA parser.
fn split_yara_rules(source: &str) -> Vec<(String, String)> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        // Find a `rule` keyword at a word boundary.
        let Some(kw) = find_keyword(&chars, i, "rule") else {
            break;
        };
        // Read the identifier after `rule`.
        let mut j = kw + 4;
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }
        let name_start = j;
        while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
            j += 1;
        }
        let name: String = chars[name_start..j].iter().collect();
        // Find the opening brace, then its balanced close (string/comment aware).
        while j < chars.len() && chars[j] != '{' {
            j += 1;
        }
        if j >= chars.len() {
            break;
        }
        let end = match_braces(&chars, j);
        let block: String = chars[kw..end].iter().collect();
        if !name.is_empty() {
            out.push((name, block.trim().to_string()));
        }
        i = end;
    }
    out
}

/// Whether `word` starts at index `at` in `chars` on a word boundary.
fn find_keyword(chars: &[char], from: usize, word: &str) -> Option<usize> {
    let w: Vec<char> = word.chars().collect();
    let mut i = from;
    while i + w.len() <= chars.len() {
        let before_ok = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        let after = i + w.len();
        let after_ok =
            after >= chars.len() || !(chars[after].is_alphanumeric() || chars[after] == '_');
        if before_ok && after_ok && chars[i..after] == w[..] {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Given the index of `{`, return the index just past its matching `}`, tracking
/// nesting while ignoring braces in strings and comments.
fn match_braces(chars: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 1;
            }
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    chars.len()
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
    fn rss_mines_indicators_from_item_text() {
        let rss = r#"<?xml version="1.0"?>
        <rss><channel>
          <item>
            <title>New C2 at evil.example.com</title>
            <description>Beacon seen from 203.0.113.9 (hash
              e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)</description>
          </item>
        </channel></rss>"#;
        let rules = parse("threats", FeedFormat::Rss, rss.as_bytes());
        let rules = rules.unwrap();
        let pats: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(pats.contains(&"domain:evil.example.com"), "{pats:?}");
        assert!(pats.contains(&"ip:203.0.113.9"), "{pats:?}");
        assert!(
            pats.iter().any(|p| p.starts_with("sha256:e3b0c442")),
            "{pats:?}"
        );
        assert!(rules.iter().all(|r| r.name == "threats-ioc"));
    }

    #[test]
    fn yara_splits_into_per_rule_blocks() {
        let yara = r#"
        // a comment with a brace } inside
        rule Detect_Evil {
            strings: $a = "EVIL} not a close"
            condition: $a
        }
        rule Detect_Two {
            condition: true
        }
        "#;
        let rules = parse("mal", FeedFormat::Yara, yara.as_bytes()).unwrap();
        assert_eq!(
            rules.len(),
            2,
            "two rules split despite braces in strings/comments"
        );
        assert_eq!(rules[0].name, "yara:Detect_Evil");
        assert!(
            rules[0].pattern.starts_with("yara:rule Detect_Evil"),
            "{}",
            rules[0].pattern
        );
        assert!(rules[0].pattern.contains("EVIL} not a close"));
        assert_eq!(rules[1].name, "yara:Detect_Two");
    }

    #[test]
    fn format_detection_rss_yara_and_toml() {
        assert_eq!(FeedFormat::from_name("feed.rss"), FeedFormat::Rss);
        assert_eq!(FeedFormat::from_name("f.atom"), FeedFormat::Rss);
        assert_eq!(FeedFormat::from_name("rules.yar"), FeedFormat::Yara);
        assert_eq!(FeedFormat::from_name("x.yara"), FeedFormat::Yara);
        assert_eq!(
            FeedFormat::from_name("gitleaks.toml"),
            FeedFormat::GitleaksToml
        );
    }

    #[test]
    fn parses_gitleaks_toml_rules() {
        let toml = r#"
            title = "gitleaks config"

            [[rules]]
            id = "aws-access-key"
            description = "AWS Access Key ID"
            regex = '''AKIA[0-9A-Z]{16}'''
            keywords = ["AKIA"]

            [[rules]]
            id = "no-regex-skipped"
            description = "should be skipped"

            [[rules]]
            description = "unnamed falls back to feed name"
            regex = '''ghp_[A-Za-z0-9]{36}'''
        "#;
        let rules = parse("gitleaks", FeedFormat::GitleaksToml, toml.as_bytes()).unwrap();
        assert_eq!(rules.len(), 2, "the regex-less rule is dropped");
        assert_eq!(rules[0].name, "aws-access-key");
        assert_eq!(rules[0].pattern, "AKIA[0-9A-Z]{16}");
        assert_eq!(rules[0].description, "AWS Access Key ID");
        assert_eq!(rules[1].name, "gitleaks-rule"); // unnamed → feed-derived name
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
