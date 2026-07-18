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
//!   compiled into the YARA scanner), gitleaks TOML (`[[rules]]` regexes), and
//!   the JSON threat-intel formats STIX 2.x and MISP (IOCs from indicator
//!   patterns / event attributes), and OpenIOC XML (`IndicatorItem` context +
//!   content). A `.json` feed is content-sniffed between a native dataset,
//!   STIX, and MISP; a `.xml` feed between OpenIOC and RSS/Atom.
//!
//! The parsing is pure (bytes → rules), so every format is unit-testable
//! without the network; [`fetch_feed`] is the thin download layer on top.
//! Adding a format is a new arm here — the catalog, storage, and CLI don't
//! change.
//!
//! A feed URL prefixed `taxii2+` is polled over the TAXII 2.x transport (a
//! collection's `objects/` endpoint, paginated) instead of downloaded, and its
//! STIX objects flow through the same STIX normalizer.

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
    /// STIX 2.x JSON — indicators are read from `indicator` objects' patterns.
    Stix,
    /// MISP JSON — indicators are read from event `Attribute` values.
    Misp,
    /// OpenIOC XML (`.ioc`) — indicators from `IndicatorItem` context + content.
    OpenIoc,
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
            "ioc" | "openioc" => FeedFormat::OpenIoc,
            "yar" | "yara" => FeedFormat::Yara,
            "toml" => FeedFormat::GitleaksToml,
            "stix" => FeedFormat::Stix,
            "misp" => FeedFormat::Misp,
            _ => FeedFormat::Iocs,
        }
    }
}

/// A `taxii2+` URL prefix marks a feed served over the TAXII 2.x transport
/// rather than a plain file download (`taxii2+https://server/…/objects/`).
const TAXII_PREFIX: &str = "taxii2+";

/// Download `url`, decompress, and parse every member into one [`Dataset`]
/// named `name`. Members that fail to parse are skipped with a warning, so one
/// bad file in an archive doesn't sink the whole feed. A `taxii2+…` URL is
/// polled over the TAXII 2.x API instead ([`fetch_taxii`]).
pub async fn fetch_feed(name: &str, url: &str) -> Result<Dataset> {
    if let Some(endpoint) = url.strip_prefix(TAXII_PREFIX) {
        return fetch_taxii(name, endpoint).await;
    }
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

/// Poll a TAXII 2.x collection's `objects/` endpoint and normalize the STIX
/// objects it returns into IOC rules. `endpoint` is the collection URL with the
/// `taxii2+` prefix already stripped. Sends the TAXII media type, follows
/// `more`/`next` pagination (bounded), and applies HTTP basic auth from any
/// `user:pass@` in the URL, so a private collection works with credentials
/// embedded in the feed URL.
async fn fetch_taxii(name: &str, endpoint: &str) -> Result<Dataset> {
    const ACCEPT_TAXII: &str = "application/taxii+json;version=2.1";
    const MAX_PAGES: usize = 50;
    let client = reqwest::Client::new();
    let mut rules = Vec::new();
    let mut page_url = endpoint.to_string();
    for _ in 0..MAX_PAGES {
        let parsed =
            reqwest::Url::parse(&page_url).with_context(|| format!("bad TAXII url {page_url}"))?;
        let mut req = client
            .get(parsed.clone())
            .header(reqwest::header::ACCEPT, ACCEPT_TAXII);
        if !parsed.username().is_empty() {
            req = req.basic_auth(parsed.username(), parsed.password());
        }
        let bytes = req
            .send()
            .await
            .with_context(|| format!("TAXII request {page_url}"))?
            .error_for_status()
            .context("TAXII request failed")?
            .bytes()
            .await
            .context("read TAXII body")?;
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).context("parse TAXII envelope")?;
        rules.extend(stix_iocs(&body, name));
        let more = body.get("more").and_then(|m| m.as_bool()).unwrap_or(false);
        match body.get("next").and_then(|n| n.as_str()) {
            Some(next) if more && !next.is_empty() => page_url = taxii_next(endpoint, next)?,
            _ => break,
        }
    }
    dedup_rules(&mut rules);
    Ok(Dataset {
        name: name.to_string(),
        rules,
    })
}

/// Set (or replace) the `next` pagination cursor on a TAXII endpoint URL.
fn taxii_next(base: &str, next: &str) -> Result<String> {
    let mut u = reqwest::Url::parse(base).with_context(|| format!("bad TAXII url {base}"))?;
    let kept: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| k != "next")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    u.query_pairs_mut()
        .clear()
        .extend_pairs(&kept)
        .append_pair("next", next);
    Ok(u.to_string())
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
    dedup_rules(&mut rules);
    Ok(Dataset {
        name: name.to_string(),
        rules,
    })
}

/// Drop duplicate rules in place, keeping first-seen order. Threat-intel feeds
/// overlap heavily (the same domain/IP appears across members, pages, and
/// sources), so this keeps the stored count and the "pulled N rules" report
/// honest. The key is `(name, pattern)` — the same pair the store content-
/// addresses a rule by, so two identical rules would collapse there anyway.
fn dedup_rules(rules: &mut Vec<Rule>) {
    let mut seen = std::collections::HashSet::new();
    rules.retain(|r| seen.insert((r.name.clone(), r.pattern.clone())));
}

/// Parse one member's bytes in `format` into rules, tagged under the feed `name`.
pub fn parse(name: &str, format: FeedFormat, bytes: &[u8]) -> Result<Vec<Rule>> {
    match format {
        FeedFormat::Json => parse_json(name, bytes),
        FeedFormat::Csv => parse_delimited(&String::from_utf8_lossy(bytes), ',', name),
        FeedFormat::Tsv => parse_delimited(&String::from_utf8_lossy(bytes), '\t', name),
        FeedFormat::Iocs => Ok(parse_iocs(&String::from_utf8_lossy(bytes), name)),
        FeedFormat::Rss => Ok(parse_xml_feed(bytes, name)),
        FeedFormat::OpenIoc => Ok(parse_openioc(bytes, name)),
        FeedFormat::Yara => Ok(parse_yara(&String::from_utf8_lossy(bytes), name)),
        FeedFormat::GitleaksToml => parse_gitleaks(bytes, name),
        FeedFormat::Stix => Ok(stix_iocs(
            &serde_json::from_slice(bytes).context("parse STIX JSON")?,
            name,
        )),
        FeedFormat::Misp => {
            let value = serde_json::from_slice(bytes).context("parse MISP JSON")?;
            let mut rules = Vec::new();
            misp_iocs(&value, name, &mut rules);
            Ok(rules)
        }
    }
}

/// Parse a `.json` feed, sniffing its shape: a native exfil dataset (has
/// `rules`), a STIX 2.x bundle, a MISP export, or (fallback) a native dataset.
fn parse_json(feed: &str, bytes: &[u8]) -> Result<Vec<Rule>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).context("parse JSON feed")?;
    if value.get("rules").is_some() {
        return Ok(serde_json::from_value::<Dataset>(value)
            .context("dataset JSON")?
            .rules);
    }
    if is_stix(&value) {
        return Ok(stix_iocs(&value, feed));
    }
    if is_misp(&value) {
        let mut rules = Vec::new();
        misp_iocs(&value, feed, &mut rules);
        return Ok(rules);
    }
    Ok(serde_json::from_value::<Dataset>(value)
        .map(|d| d.rules)
        .unwrap_or_default())
}

/// Whether a JSON value looks like STIX 2.x (a bundle or indicator objects).
fn is_stix(v: &serde_json::Value) -> bool {
    v.get("type").and_then(|t| t.as_str()) == Some("bundle")
        || v.get("spec_version").is_some()
        || v.get("objects")
            .and_then(|o| o.as_array())
            .is_some_and(|a| {
                a.iter()
                    .any(|o| o.get("type").and_then(|t| t.as_str()) == Some("indicator"))
            })
}

/// Whether a JSON value looks like a MISP export.
fn is_misp(v: &serde_json::Value) -> bool {
    v.get("Event").is_some() || v.get("response").is_some() || v.get("Attribute").is_some()
}

/// IOC rules from a STIX bundle: read each `indicator` object's `pattern`
/// (STIX patterning) and pull out domains, IPs, URLs, and file hashes.
fn stix_iocs(v: &serde_json::Value, feed: &str) -> Vec<Rule> {
    let objects: Vec<&serde_json::Value> = match v.get("objects").and_then(|o| o.as_array()) {
        Some(arr) => arr.iter().collect(),
        None => vec![v],
    };
    let mut rules = Vec::new();
    for obj in objects {
        if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
            continue;
        }
        if let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) {
            rules.extend(stix_pattern_iocs(pattern, feed));
        }
    }
    rules
}

/// Extract IOCs from one STIX pattern string, e.g.
/// `[domain-name:value = 'evil.com' OR file:hashes.'SHA-256' = 'ab…']`.
fn stix_pattern_iocs(pattern: &str, feed: &str) -> Vec<Rule> {
    use regex::Regex;
    use std::sync::OnceLock;
    static NET: OnceLock<Regex> = OnceLock::new();
    static HASH: OnceLock<Regex> = OnceLock::new();
    let net = NET.get_or_init(|| {
        Regex::new(r"(domain-name|ipv4-addr|ipv6-addr|url):value\s*=\s*'([^']+)'").unwrap()
    });
    let hash = HASH
        .get_or_init(|| Regex::new(r"file:hashes\.'?([A-Za-z0-9-]+)'?\s*=\s*'([^']+)'").unwrap());

    let mut rules = Vec::new();
    for cap in net.captures_iter(pattern) {
        let scheme = match &cap[1] {
            "domain-name" => "domain",
            "ipv4-addr" | "ipv6-addr" => "ip",
            "url" => "url",
            _ => continue,
        };
        rules.push(ioc_rule(feed, format!("{scheme}:{}", &cap[2])));
    }
    for cap in hash.captures_iter(pattern) {
        let algo = cap[1].to_ascii_lowercase().replace('-', "");
        let scheme = match algo.as_str() {
            "sha256" => "sha256",
            "sha1" => "sha1",
            "md5" => "md5",
            _ => continue,
        };
        rules.push(ioc_rule(
            feed,
            format!("{scheme}:{}", cap[2].to_ascii_lowercase()),
        ));
    }
    rules
}

/// IOC rules from a MISP export: walk the JSON and, for every attribute object
/// (`{ "type": …, "value": … }`), map recognized types to IOC rules.
fn misp_iocs(v: &serde_json::Value, feed: &str, rules: &mut Vec<Rule>) {
    match v {
        serde_json::Value::Object(map) => {
            if let (Some(ty), Some(value)) = (
                map.get("type").and_then(|x| x.as_str()),
                map.get("value").and_then(|x| x.as_str()),
            ) {
                if let Some(scheme) = misp_scheme(ty) {
                    rules.push(ioc_rule(feed, format!("{scheme}:{value}")));
                }
            }
            for child in map.values() {
                misp_iocs(child, feed, rules);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                misp_iocs(item, feed, rules);
            }
        }
        _ => {}
    }
}

/// Map a MISP attribute type to an IOC pattern scheme.
fn misp_scheme(ty: &str) -> Option<&'static str> {
    match ty {
        "domain" | "hostname" => Some("domain"),
        "ip-src" | "ip-dst" | "ip" => Some("ip"),
        "url" | "uri" | "link" => Some("url"),
        "md5" => Some("md5"),
        "sha1" => Some("sha1"),
        "sha256" => Some("sha256"),
        _ => None,
    }
}

/// Construct a high-severity IOC rule with a scheme-prefixed pattern.
fn ioc_rule(feed: &str, pattern: String) -> Rule {
    Rule {
        name: format!("{feed}-ioc"),
        pattern,
        description: format!("indicator from feed {feed}"),
        severity: Some(Severity::High),
        cwe: Some("CWE-506".into()),
        cve: None,
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

/// Parse an XML feed, sniffing OpenIOC (Mandiant `<ioc>` documents) apart from
/// RSS/Atom. OpenIOC carries explicit typed indicators, so it's read directly;
/// anything else falls back to mining indicators from item text.
fn parse_xml_feed(bytes: &[u8], feed: &str) -> Vec<Rule> {
    if is_openioc(bytes) {
        parse_openioc(bytes, feed)
    } else {
        parse_rss(bytes, feed)
    }
}

/// Whether XML looks like OpenIOC — an `<ioc>` root or any `<IndicatorItem>`.
fn is_openioc(bytes: &[u8]) -> bool {
    let Some(doc) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| roxmltree::Document::parse(s).ok())
    else {
        return false;
    };
    doc.root_element().has_tag_name("ioc")
        || doc.descendants().any(|n| n.has_tag_name("IndicatorItem"))
}

/// IOC rules from an [OpenIOC](https://github.com/mandiant/OpenIOC_1.1) document.
/// Each `IndicatorItem` pairs a `Context` (a search path like `Network/DNS` or
/// `FileItem/Sha256sum`) with a `Content` value; the path (or the content type)
/// picks the IOC scheme — domain / IP / URL / md5 / sha1 / sha256.
fn parse_openioc(bytes: &[u8], feed: &str) -> Vec<Rule> {
    let Some(doc) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| roxmltree::Document::parse(s).ok())
    else {
        return Vec::new();
    };
    let mut rules = Vec::new();
    for item in doc
        .descendants()
        .filter(|n| n.has_tag_name("IndicatorItem"))
    {
        let search = item
            .descendants()
            .find(|n| n.has_tag_name("Context"))
            .and_then(|c| c.attribute("search"))
            .unwrap_or_default();
        let content = item.descendants().find(|n| n.has_tag_name("Content"));
        let ctype = content
            .and_then(|c| c.attribute("type"))
            .unwrap_or_default();
        let value = content.and_then(|c| c.text()).unwrap_or_default().trim();
        if value.is_empty() {
            continue;
        }
        if let Some(scheme) = openioc_scheme(search, ctype) {
            rules.push(ioc_rule(feed, format!("{scheme}:{value}")));
        }
    }
    rules
}

/// Map an OpenIOC context search path (and content type) to an IOC scheme.
fn openioc_scheme(search: &str, ctype: &str) -> Option<&'static str> {
    let s = search.to_ascii_lowercase();
    let t = ctype.to_ascii_lowercase();
    if t == "sha256" || s.contains("sha256") || s.contains("sha-256") {
        Some("sha256")
    } else if t == "sha1" || s.contains("sha1") || s.contains("sha-1") {
        Some("sha1")
    } else if t == "md5" || s.contains("md5") {
        Some("md5")
    } else if s.contains("uri") || s.contains("url") {
        Some("url")
    } else if s.contains("ip") {
        Some("ip")
    } else if s.contains("dns") || s.contains("domain") || s.contains("host") {
        Some("domain")
    } else {
        None
    }
}

/// Build IOC rules from extracted observables (domains/IPs/URLs/hashes).
fn iocs_from_indicators(ind: &exfil_task::Indicators, feed: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut push = |pattern: String| rules.push(ioc_rule(feed, pattern));
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
    fn ingest_dedups_overlapping_iocs() {
        // The same indicator repeated across a feed collapses to one rule,
        // keeping first-seen order.
        let text = "evil.example.com\n203.0.113.9\nevil.example.com\n";
        let ds = ingest("threats", "list.txt", text.as_bytes()).unwrap();
        let pats: Vec<&str> = ds.rules.iter().map(|r| r.pattern.as_str()).collect();
        assert_eq!(pats, vec!["domain:evil.example.com", "ip:203.0.113.9"]);
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
    fn parses_stix_bundle_indicators() {
        let stix = r#"{
          "type": "bundle", "id": "bundle--1",
          "objects": [
            {"type":"indicator","pattern":"[domain-name:value = 'evil.example.com']"},
            {"type":"indicator","pattern":"[ipv4-addr:value = '203.0.113.9']"},
            {"type":"indicator","pattern":"[file:hashes.'SHA-256' = 'ABCDEF']"},
            {"type":"identity","name":"ignore me"}
          ]
        }"#;
        // Sniffed as STIX through the .json path.
        let rules = parse("intel", FeedFormat::Json, stix.as_bytes()).unwrap();
        let pats: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(pats.contains(&"domain:evil.example.com"), "{pats:?}");
        assert!(pats.contains(&"ip:203.0.113.9"), "{pats:?}");
        assert!(pats.contains(&"sha256:abcdef"), "{pats:?}");
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn taxii_envelope_objects_become_iocs() {
        // A TAXII 2.1 response is an envelope of STIX objects — the same shape
        // stix_iocs already reads, just delivered over the transport.
        let envelope = r#"{
          "objects": [
            {"type":"indicator","pattern":"[domain-name:value = 'taxii.evil.test']"},
            {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.4']"}
          ],
          "more": false
        }"#;
        let v: serde_json::Value = serde_json::from_str(envelope).unwrap();
        let pats: Vec<String> = stix_iocs(&v, "taxii")
            .into_iter()
            .map(|r| r.pattern)
            .collect();
        assert!(
            pats.contains(&"domain:taxii.evil.test".to_string()),
            "{pats:?}"
        );
        assert!(pats.contains(&"ip:198.51.100.4".to_string()), "{pats:?}");
    }

    #[test]
    fn taxii_next_cursor_is_set_and_replaced() {
        // Cursor added to a bare endpoint.
        let a = taxii_next("https://s/api/collections/c/objects/", "abc").unwrap();
        assert!(a.ends_with("next=abc"), "{a}");
        // Existing cursor replaced, other params kept.
        let b = taxii_next(
            "https://s/api/collections/c/objects/?limit=100&next=old",
            "new",
        )
        .unwrap();
        assert!(b.contains("limit=100"), "{b}");
        assert!(b.contains("next=new"), "{b}");
        assert!(!b.contains("next=old"), "{b}");
    }

    #[test]
    fn parses_misp_event_attributes() {
        let misp = r#"{
          "Event": { "info": "campaign",
            "Attribute": [
              {"type":"domain","value":"bad.test"},
              {"type":"ip-dst","value":"198.51.100.7"},
              {"type":"sha256","value":"DEADBEEF"},
              {"type":"comment","value":"not an ioc"}
            ]
          }
        }"#;
        let rules = parse("misp", FeedFormat::Json, misp.as_bytes()).unwrap();
        let pats: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(pats.contains(&"domain:bad.test"), "{pats:?}");
        assert!(pats.contains(&"ip:198.51.100.7"), "{pats:?}");
        assert!(pats.contains(&"sha256:DEADBEEF"), "{pats:?}");
        assert_eq!(rules.len(), 3, "the 'comment' attribute is skipped");
    }

    #[test]
    fn native_dataset_json_still_wins_the_sniff() {
        let json = br#"{"name":"x","rules":[{"name":"r","pattern":"p"}]}"#;
        let rules = parse("x", FeedFormat::Json, json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "r");
    }

    #[test]
    fn parses_openioc_indicator_items() {
        let ioc = r#"<?xml version="1.0"?>
        <ioc xmlns="http://schemas.mandiant.com/2010/ioc" id="1">
          <definition>
            <Indicator operator="OR">
              <IndicatorItem condition="is">
                <Context document="Network" search="Network/DNS" type="mir"/>
                <Content type="string">evil.example.com</Content>
              </IndicatorItem>
              <IndicatorItem condition="is">
                <Context document="PortItem" search="PortItem/remoteIP" type="mir"/>
                <Content type="IP">203.0.113.9</Content>
              </IndicatorItem>
              <IndicatorItem condition="is">
                <Context document="FileItem" search="FileItem/Sha256sum" type="mir"/>
                <Content type="sha256">DEADBEEF</Content>
              </IndicatorItem>
              <IndicatorItem condition="is">
                <Context document="Snort" search="Snort/Snort" type="mir"/>
                <Content type="string">alert tcp any</Content>
              </IndicatorItem>
            </Indicator>
          </definition>
        </ioc>"#;
        // The .xml path sniffs OpenIOC apart from RSS.
        let rules = parse("intel", FeedFormat::Rss, ioc.as_bytes()).unwrap();
        let pats: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(pats.contains(&"domain:evil.example.com"), "{pats:?}");
        assert!(pats.contains(&"ip:203.0.113.9"), "{pats:?}");
        assert!(pats.contains(&"sha256:DEADBEEF"), "{pats:?}");
        assert_eq!(rules.len(), 3, "the unmappable Snort item is skipped");
        assert!(rules.iter().all(|r| r.name == "intel-ioc"));
    }

    #[test]
    fn openioc_detected_by_extension_and_content() {
        assert_eq!(FeedFormat::from_name("threat.ioc"), FeedFormat::OpenIoc);
        assert!(is_openioc(b"<ioc><IndicatorItem/></ioc>"));
        assert!(!is_openioc(b"<rss><channel/></rss>"));
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
