//! Reporters: pluggable renderers that turn an [`Analysis`] of the findings
//! graph into output. Each [`Reporter`] handles one format; [`reporter_for`]
//! picks one by name. This is the terminal stage of a run: fetch → scan →
//! **report**.
//!
//! # Rust notes
//!
//! - `report(&self, w: &mut dyn Write, …)` writes into *any* sink implementing
//!   `std::io::Write` — a file, stdout, or an in-memory `Vec<u8>` (as the
//!   tests do). `dyn Write` means the reporter doesn't care which; that's how
//!   Rust keeps I/O code testable without touching real files.
//! - `write!`/`writeln!` return a `Result`; the `?` after each propagates any
//!   I/O error to the caller.

pub mod fit;
pub mod pdf;

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Result;
use exfil_core::{Match, Severity};

/// A snapshot of the findings graph to render: the findings plus a few
/// whole-store counts the engine gathered.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    /// Findings to report (already filtered/queried by the caller).
    pub findings: Vec<Match>,
    /// Total files recorded in the store.
    pub files: u64,
    /// Total scan runs recorded.
    pub scans: u64,
}

impl Analysis {
    /// Count findings per severity, worst-first, skipping empty buckets.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        let order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];
        let mut tally: BTreeMap<u32, usize> = BTreeMap::new();
        for f in &self.findings {
            if let Some(s) = f.severity {
                *tally.entry(s.weight()).or_default() += 1;
            }
        }
        order
            .into_iter()
            .filter_map(|s| {
                let n = self
                    .findings
                    .iter()
                    .filter(|f| f.severity == Some(s))
                    .count();
                (n > 0).then_some((s, n))
            })
            .collect()
    }

    /// Aggregate risk score: the sum of every finding's severity weight.
    pub fn risk_score(&self) -> u32 {
        self.findings
            .iter()
            .filter_map(|f| f.severity.map(|s| s.weight()))
            .sum()
    }

    /// Where the findings are concentrated: the directories holding the most,
    /// worst-first, with each one's share of the total.
    ///
    /// A flat list of findings tells you *what* is wrong; this tells you
    /// *where* to start, which is usually the more actionable question — one
    /// directory holding 40% of a scan's findings is a different problem from
    /// forty directories holding one each.
    ///
    /// Grouped by each finding's parent directory. Findings carry a full path,
    /// so this is derivable at report time; it needs no directory records in
    /// the store. Ties break on the directory name, so the same findings always
    /// produce the same report.
    pub fn hotspots(&self, limit: usize) -> Vec<Hotspot> {
        let total = self.findings.len();
        if total == 0 {
            return Vec::new();
        }
        let mut by_dir: BTreeMap<&str, (usize, u32)> = BTreeMap::new();
        for f in &self.findings {
            // Split on both separators so a Windows path groups correctly.
            let dir = match f.path.rfind(['/', '\\']) {
                Some(i) if i > 0 => &f.path[..i],
                Some(_) => "/",
                None => ".",
            };
            let entry = by_dir.entry(dir).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += f.severity.map(|s| s.weight()).unwrap_or(0);
        }
        let mut rows: Vec<Hotspot> = by_dir
            .into_iter()
            .map(|(dir, (findings, risk))| Hotspot {
                directory: dir.to_string(),
                findings,
                risk,
                share: findings as f64 / total as f64,
            })
            .collect();
        rows.sort_by(|a, b| {
            b.findings
                .cmp(&a.findings)
                .then_with(|| b.risk.cmp(&a.risk))
                .then_with(|| a.directory.cmp(&b.directory))
        });
        rows.truncate(limit);
        rows
    }
}

/// One directory's share of a scan's findings.
#[derive(Debug, Clone, PartialEq)]
pub struct Hotspot {
    /// The parent directory the findings sit in.
    pub directory: String,
    /// How many findings are in it.
    pub findings: usize,
    /// Summed severity weight, used to break ties between equal counts — ten
    /// criticals in one directory outrank ten infos in another.
    pub risk: u32,
    /// Fraction of all findings in this report, in `0.0..=1.0`.
    pub share: f64,
}

/// How many directories a report lists before stopping.
pub const HOTSPOT_LIMIT: usize = 10;

/// Render a hotspot table, or nothing when there is only one directory to
/// name — a breakdown that says "100% of findings are in the one place they
/// could be" is noise.
/// `fit` is the window width to lay the table out in, or `None` for the
/// unconstrained default.
fn write_hotspots(w: &mut dyn Write, a: &Analysis, fit: Option<usize>) -> Result<()> {
    let rows = a.hotspots(HOTSPOT_LIMIT);
    if rows.len() < 2 {
        return Ok(());
    }
    let (root, names) = strip_common_prefix(&rows);
    writeln!(w)?;
    match &root {
        Some(root) => {
            // The stripped root is an absolute path and can be longer than the
            // whole window on its own, so it is elided like any other path.
            const HEADER: usize = "findings by directory (under ):".len();
            let root = match fit {
                Some(width) => fit::elide_left(root, width.saturating_sub(HEADER)),
                None => root.clone(),
            };
            writeln!(w, "findings by directory (under {root}):")?
        }
        None => writeln!(w, "findings by directory:")?,
    }

    // A row is `··name···NNNNN··PPP%··bar`: two leading spaces, the name, the
    // count and percentage columns, then the bar. Everything but the name and
    // the bar is fixed, so those two share whatever the window leaves.
    const FIXED: usize = 2 + 1 + 5 + 1 + 5 + 1 + 2;
    let (name_cap, bar_cap) = match fit {
        Some(width) => {
            let room = width.saturating_sub(FIXED);
            // Give the bar a quarter of the room, the name the rest — the name
            // identifies the directory, the bar only ranks it.
            let bar = (room / 4).clamp(4, 20);
            (room.saturating_sub(bar).max(8), bar)
        }
        None => (48, 20),
    };
    let width = names
        .iter()
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0)
        .min(name_cap);
    for (r, name) in rows.iter().zip(&names) {
        let bar = "█".repeat(((r.share * bar_cap as f64).round() as usize).max(1));
        writeln!(
            w,
            "  {:<width$} {:>5} {:>5.0}%  {}",
            fit::elide_left(name, width),
            r.findings,
            r.share * 100.0,
            bar,
            width = width
        )?;
    }
    Ok(())
}

/// Drop the directory prefix every hotspot shares, returning it once alongside
/// the shortened names.
///
/// Scanning an absolute path makes every row start with the same forty
/// characters, which crowds out the part that actually distinguishes them. The
/// shared root is stated once in the heading instead. Compared component-wise,
/// never mid-component, so `src/authz` and `src/auth` share `src` rather than
/// a meaningless `src/auth`.
fn strip_common_prefix(rows: &[Hotspot]) -> (Option<String>, Vec<String>) {
    let split = |s: &str| -> Vec<String> {
        s.split(['/', '\\'])
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect()
    };
    let first = split(&rows[0].directory);
    let mut shared = first.len();
    for r in &rows[1..] {
        let parts = split(&r.directory);
        shared = shared.min(parts.iter().zip(&first).take_while(|(a, b)| a == b).count());
    }
    // Strip every shared component. Keeping one back for context would just
    // repeat it on every row, which is the crowding this exists to remove.
    let keep_from = shared;
    if keep_from == 0 {
        let names = rows.iter().map(|r| r.directory.clone()).collect();
        return (None, names);
    }
    let root = first[..keep_from].join("/");
    let names = rows
        .iter()
        .map(|r| {
            let parts = split(&r.directory);
            if parts.len() > keep_from {
                parts[keep_from..].join("/")
            } else {
                // This row *is* the shared root — one directory holding
                // findings directly, alongside others holding them deeper.
                ".".to_string()
            }
        })
        .collect();
    let root = if rows[0].directory.starts_with(['/', '\\']) {
        format!("/{root}")
    } else {
        root
    };
    (Some(root), names)
}

/// A pluggable output renderer for one format.
pub trait Reporter {
    /// Format name, e.g. `text`, `json`, `markdown`.
    fn name(&self) -> &str;

    /// Render `analysis` into `w`.
    fn report(&self, w: &mut dyn Write, analysis: &Analysis) -> Result<()>;
}

/// The reporter for a format name, or `None` if unknown. Accepts a couple of
/// common aliases (`md`, `txt`).
pub fn reporter_for(format: &str) -> Option<Box<dyn Reporter>> {
    match format {
        "text" | "txt" => Some(Box::new(TextReporter::default())),
        "json" => Some(Box::new(JsonReporter)),
        "markdown" | "md" => Some(Box::new(MarkdownReporter)),
        "junit" | "junit-xml" => Some(Box::new(JunitReporter)),
        "sarif" => Some(Box::new(SarifReporter)),
        "pdf" => Some(Box::new(PdfReporter)),
        _ => None,
    }
}

/// The format names [`reporter_for`] accepts (canonical spellings).
pub const FORMATS: &[&str] = &["text", "json", "markdown", "junit", "sarif", "pdf"];

/// PDF report, for handing a scan's result to someone who will read it.
pub struct PdfReporter;

impl Reporter for PdfReporter {
    fn name(&self) -> &str {
        "pdf"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        w.write_all(&pdf::render(a))?;
        Ok(())
    }
}

/// Human-readable plain-text report.
///
/// `width` is the window to fit lines to, or `None` for full-length output.
/// [`reporter_for`] builds the `None` form: a report that is redirected to a
/// file or piped is a machine interface, and truncating it there would corrupt
/// whatever reads it. Only a caller that knows it is writing to a terminal —
/// the CLI — asks for a width.
#[derive(Debug, Clone, Copy, Default)]
pub struct TextReporter {
    /// Columns to fit each finding line into, or `None` to never truncate.
    pub width: Option<usize>,
}

impl TextReporter {
    /// A text reporter that fits its output to `width` columns.
    pub fn fitted(width: usize) -> Self {
        Self { width: Some(width) }
    }
}

impl Reporter for TextReporter {
    fn name(&self) -> &str {
        "text"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        for m in &a.findings {
            writeln!(w, "{}", fit::line(m, self.width))?;
        }
        writeln!(w)?;
        write_summary(w, a, self.width)
    }
}

/// The tail of a text report: the counts, the per-severity tally and the
/// directory hotspots — everything except the finding list.
///
/// Shared with [`SummaryReporter`] so the glance and the full document cannot
/// disagree about the same scan.
fn write_summary(w: &mut dyn Write, a: &Analysis, width: Option<usize>) -> Result<()> {
    writeln!(
        w,
        "{} finding(s) across {} file(s), {} scan(s); risk score {}",
        a.findings.len(),
        a.files,
        a.scans,
        a.risk_score()
    )?;
    for (sev, n) in a.severity_counts() {
        writeln!(w, "  {:<8} {}", format!("{sev:?}").to_lowercase(), n)?;
    }
    write_hotspots(w, a, width)
}

/// Just the shape of a scan — counts, severities, where they cluster — with no
/// finding list.
///
/// What `exfil analyze` prints. The finding list is what `search` and `report`
/// are for; repeating it here made `analyze` a slower `report` rather than a
/// glance at the state of things.
#[derive(Debug, Clone, Copy, Default)]
pub struct SummaryReporter {
    /// Columns to fit to, or `None` to never truncate.
    pub width: Option<usize>,
}

impl Reporter for SummaryReporter {
    fn name(&self) -> &str {
        "summary"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        write_summary(w, a, self.width)
    }
}

/// Machine-readable JSON report (findings plus summary counts).
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn name(&self) -> &str {
        "json"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        let severity: serde_json::Map<String, serde_json::Value> = a
            .severity_counts()
            .into_iter()
            .map(|(s, n)| (format!("{s:?}").to_lowercase(), serde_json::json!(n)))
            .collect();
        let doc = serde_json::json!({
            "summary": {
                "findings": a.findings.len(),
                "files": a.files,
                "scans": a.scans,
                "risk_score": a.risk_score(),
                "severity": severity,
            },
            "findings": a.findings,
            "hotspots": a.hotspots(HOTSPOT_LIMIT)
                .into_iter()
                .map(|h| serde_json::json!({
                    "directory": h.directory,
                    "findings": h.findings,
                    "risk": h.risk,
                    "share": h.share,
                }))
                .collect::<Vec<_>>(),
        });
        writeln!(w, "{}", serde_json::to_string_pretty(&doc)?)?;
        Ok(())
    }
}

/// Markdown report suitable for pasting into a PR or issue.
pub struct MarkdownReporter;

impl Reporter for MarkdownReporter {
    fn name(&self) -> &str {
        "markdown"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        writeln!(w, "# exfil findings\n")?;
        writeln!(
            w,
            "**{}** finding(s) across **{}** file(s) in **{}** scan(s). Risk score **{}**.\n",
            a.findings.len(),
            a.files,
            a.scans,
            a.risk_score()
        )?;
        let counts = a.severity_counts();
        if !counts.is_empty() {
            writeln!(w, "| Severity | Count |")?;
            writeln!(w, "|---|---|")?;
            for (sev, n) in counts {
                writeln!(w, "| {} | {} |", format!("{sev:?}").to_lowercase(), n)?;
            }
            writeln!(w)?;
        }
        let hotspots = a.hotspots(HOTSPOT_LIMIT);
        if hotspots.len() > 1 {
            writeln!(w, "### Findings by directory")?;
            writeln!(w)?;
            writeln!(w, "| Directory | Findings | Share |")?;
            writeln!(w, "|---|---:|---:|")?;
            for h in &hotspots {
                writeln!(
                    w,
                    "| `{}` | {} | {:.0}% |",
                    h.directory,
                    h.findings,
                    h.share * 100.0
                )?;
            }
            writeln!(w)?;
        }
        if !a.findings.is_empty() {
            writeln!(w, "| Rule | Severity | Location | Snippet |")?;
            writeln!(w, "|---|---|---|---|")?;
            for m in &a.findings {
                let sev = m
                    .severity
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_else(|| "-".into());
                writeln!(
                    w,
                    "| {} | {} | {}:{} | `{}` |",
                    md_cell(&m.rule),
                    sev,
                    md_cell(&m.path),
                    m.line,
                    md_cell(&m.snippet)
                )?;
            }
        }
        Ok(())
    }
}

/// JUnit XML report: each finding becomes a failing `<testcase>`, so CI systems
/// that ingest JUnit (Jenkins, GitLab CI, GitHub Actions test reporters) can gate
/// a build on findings. A scan with no findings is a passing suite (zero
/// failures), so the build goes green when clean.
pub struct JunitReporter;

/// Escape a rule name, path or snippet for XML text and attribute values.
///
/// Escaping the five metacharacters is not enough. Snippets are arbitrary bytes
/// from a scanned file — an ANSI-coloured log, a file whose NUL sits past the
/// 8 KiB binary sniff — and **C0 control characters are illegal in XML 1.0 at
/// any escaping**. Emitting one produces a document every parser rejects, from
/// a command that exited 0, so the CI ingest fails rather than the build gate.
/// Tab, newline and carriage return are the three C0 characters XML allows.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            // Illegal in XML 1.0 and unrepresentable by a character reference.
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a value for one cell of a Markdown table.
///
/// Every field in a row is untrusted: a `|` in a path (legal on Linux) adds a
/// column and shifts every cell after it, a backtick inside a code span closes
/// it early, and a newline ends the row. Escaping only the snippet — which is
/// what this did before — left the rule name and path free to break the table.
fn md_cell(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '`' => out.push_str("\\`"),
            // A row is one line; a literal newline would split it in two.
            '\n' | '\r' => out.push(' '),
            c if (c as u32) < 0x20 => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

impl Reporter for JunitReporter {
    fn name(&self) -> &str {
        "junit"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        let total = a.findings.len();
        writeln!(w, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
        writeln!(
            w,
            r#"<testsuites name="exfil" tests="{total}" failures="{total}">"#
        )?;
        writeln!(
            w,
            r#"  <testsuite name="exfil" tests="{total}" failures="{total}">"#
        )?;
        for m in &a.findings {
            let sev = m
                .severity
                .map(|s| format!("{s:?}").to_lowercase())
                .unwrap_or_else(|| "info".into());
            // Testcase name identifies the finding; classname carries its file
            // so CI groups findings by file.
            let name = xml_escape(&format!("{} at {}:{}:{}", m.rule, m.path, m.line, m.col));
            let classname = xml_escape(&m.path);
            let message = xml_escape(&format!(
                "[{}] {}{}",
                m.rule,
                sev,
                m.cwe
                    .as_deref()
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default()
            ));
            writeln!(w, r#"    <testcase name="{name}" classname="{classname}">"#)?;
            writeln!(
                w,
                r#"      <failure message="{message}" type="{sev}">{}</failure>"#,
                xml_escape(&m.snippet)
            )?;
            writeln!(w, "    </testcase>")?;
        }
        writeln!(w, "  </testsuite>")?;
        writeln!(w, "</testsuites>")?;
        Ok(())
    }
}

/// SARIF 2.1.0 report — the OASIS standard for static-analysis results. GitHub
/// code scanning ingests it to annotate findings inline on pull requests, and
/// most SAST dashboards read it too. Each finding becomes a `result`; the
/// distinct rules that fired are emitted once in the tool driver.
pub struct SarifReporter;

/// Map a severity to a SARIF result level (`error`/`warning`/`note`). Findings
/// without a severity default to `warning`.
fn sarif_level(sev: Option<Severity>) -> &'static str {
    match sev {
        Some(Severity::Critical | Severity::High) => "error",
        Some(Severity::Medium) => "warning",
        Some(Severity::Low | Severity::Info) => "note",
        None => "warning",
    }
}

impl Reporter for SarifReporter {
    fn name(&self) -> &str {
        "sarif"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        // Distinct rules that fired, in first-seen order, emitted once each.
        let mut rule_index: BTreeMap<&str, usize> = BTreeMap::new();
        let mut rules = Vec::new();
        for m in &a.findings {
            if !rule_index.contains_key(m.rule.as_str()) {
                rule_index.insert(m.rule.as_str(), rules.len());
                let mut rule = serde_json::json!({
                    "id": m.rule,
                    "name": m.rule,
                    "shortDescription": { "text": m.rule },
                });
                if let Some(cwe) = &m.cwe {
                    rule["properties"] = serde_json::json!({ "cwe": cwe, "tags": [cwe] });
                }
                rules.push(rule);
            }
        }

        let results: Vec<serde_json::Value> = a
            .findings
            .iter()
            .map(|m| {
                // SARIF regions are 1-based; a 0 line means "no specific line",
                // so attach a region only when we have a real position.
                let mut physical = serde_json::json!({
                    "artifactLocation": { "uri": m.path },
                });
                if m.line >= 1 {
                    let mut region = serde_json::json!({ "startLine": m.line });
                    if m.col >= 1 {
                        region["startColumn"] = serde_json::json!(m.col);
                    }
                    if !m.snippet.is_empty() {
                        region["snippet"] = serde_json::json!({ "text": m.snippet });
                    }
                    physical["region"] = region;
                }
                serde_json::json!({
                    "ruleId": m.rule,
                    "ruleIndex": rule_index[m.rule.as_str()],
                    "level": sarif_level(m.severity),
                    "message": { "text": if m.snippet.is_empty() { m.rule.clone() } else { m.snippet.clone() } },
                    "locations": [ { "physicalLocation": physical } ],
                })
            })
            .collect();

        let doc = serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [ {
                "tool": { "driver": {
                    "name": "exfil",
                    "informationUri": "https://github.com/rangertaha/exfil",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                } },
                "results": results,
            } ],
        });
        writeln!(w, "{}", serde_json::to_string_pretty(&doc)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity) -> Match {
        Match {
            rule: rule.into(),
            path: "a.env".into(),
            line: 1,
            col: 1,
            snippet: "k = v | x".into(),
            severity: Some(sev),
            cwe: None,
            cve: None,
        }
    }

    fn sample() -> Analysis {
        Analysis {
            findings: vec![
                finding("aws-key", Severity::Critical),
                finding("http-url", Severity::Low),
                finding("gh-token", Severity::Critical),
            ],
            files: 10,
            scans: 2,
        }
    }

    fn render(r: &dyn Reporter, a: &Analysis) -> String {
        let mut buf = Vec::new();
        r.report(&mut buf, a).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn severity_counts_and_risk_score() {
        let a = sample();
        assert_eq!(
            a.severity_counts(),
            vec![(Severity::Critical, 2), (Severity::Low, 1)]
        );
        assert_eq!(a.risk_score(), 10 + 10 + 1);
    }

    #[test]
    fn reporter_for_names_and_aliases() {
        assert_eq!(reporter_for("text").unwrap().name(), "text");
        assert_eq!(reporter_for("txt").unwrap().name(), "text");
        assert_eq!(reporter_for("md").unwrap().name(), "markdown");
        assert_eq!(reporter_for("json").unwrap().name(), "json");
        assert!(reporter_for("xml").is_none());
    }

    #[test]
    fn text_report_has_findings_and_summary() {
        let out = render(&TextReporter::default(), &sample());
        assert!(out.contains("[aws-key]"));
        assert!(out.contains("3 finding(s) across 10 file(s), 2 scan(s); risk score 21"));
        assert!(out.contains("critical 2"));
    }

    #[test]
    fn json_report_is_valid_and_structured() {
        let out = render(&JsonReporter, &sample());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["summary"]["findings"], 3);
        assert_eq!(v["summary"]["risk_score"], 21);
        assert_eq!(v["summary"]["severity"]["critical"], 2);
        assert_eq!(v["findings"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn markdown_escapes_pipes_in_snippets() {
        let out = render(&MarkdownReporter, &sample());
        assert!(out.contains("# exfil findings"));
        assert!(out.contains("| Rule | Severity | Location | Snippet |"));
        // The literal pipe in the snippet must be escaped, not left raw.
        assert!(out.contains("k = v \\| x"));
    }

    #[test]
    fn empty_analysis_still_renders() {
        let empty = Analysis::default();
        assert!(render(&TextReporter::default(), &empty).contains("0 finding(s)"));
        let v: serde_json::Value = serde_json::from_str(&render(&JsonReporter, &empty)).unwrap();
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn empty_markdown_omits_tables() {
        let out = render(&MarkdownReporter, &Analysis::default());
        assert!(out.contains("# exfil findings"));
        assert!(!out.contains("| Severity | Count |"));
        assert!(!out.contains("| Rule |"));
    }

    #[test]
    fn reporter_names_and_formats_are_stable() {
        assert_eq!(TextReporter::default().name(), "text");
        assert_eq!(TextReporter::fitted(80).name(), "text");
        assert_eq!(JsonReporter.name(), "json");
        assert_eq!(MarkdownReporter.name(), "markdown");
        assert_eq!(JunitReporter.name(), "junit");
        assert_eq!(SarifReporter.name(), "sarif");
        assert_eq!(
            FORMATS,
            ["text", "json", "markdown", "junit", "sarif", "pdf"]
        );
    }

    #[test]
    fn sarif_is_valid_2_1_0_and_maps_findings() {
        let out = render(&SarifReporter, &sample());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "exfil");
        // Three findings, three distinct rules → three results and three rules.
        assert_eq!(run["results"].as_array().unwrap().len(), 3);
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 3);
        let r0 = &run["results"][0];
        assert_eq!(r0["ruleId"], "aws-key");
        assert_eq!(r0["level"], "error"); // critical → error
        assert_eq!(r0["ruleIndex"], 0);
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "a.env"
        );
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
        // Low severity maps to note.
        assert_eq!(run["results"][1]["level"], "note");

        // Two findings sharing a rule collapse to one driver rule, both results
        // pointing at its index.
        let dup = Analysis {
            findings: vec![
                finding("aws-key", Severity::Critical),
                finding("aws-key", Severity::Critical),
            ],
            files: 1,
            scans: 1,
        };
        let v2: serde_json::Value = serde_json::from_str(&render(&SarifReporter, &dup)).unwrap();
        assert_eq!(
            v2["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(v2["runs"][0]["results"][1]["ruleIndex"], 0);
    }

    #[test]
    fn sarif_omits_region_for_unpositioned_findings() {
        let mut m = finding("threats-ioc", Severity::High);
        m.line = 0; // an IOC hit with no specific line
        m.cwe = Some("CWE-506".into());
        let a = Analysis {
            findings: vec![m],
            files: 1,
            scans: 1,
        };
        let out = render(&SarifReporter, &a);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let loc = &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert!(loc.get("region").is_none(), "no region when line is 0");
        assert_eq!(loc["artifactLocation"]["uri"], "a.env");
        // The CWE rides along as a rule property/tag.
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["cwe"],
            "CWE-506"
        );
    }

    #[test]
    fn junit_is_selectable_by_name_and_alias() {
        assert_eq!(reporter_for("junit").unwrap().name(), "junit");
        assert_eq!(reporter_for("junit-xml").unwrap().name(), "junit");
    }

    #[test]
    fn junit_report_has_one_failing_testcase_per_finding() {
        let out = render(&JunitReporter, &sample());
        assert!(out.starts_with("<?xml version=\"1.0\""));
        assert!(out.contains(r#"<testsuites name="exfil" tests="3" failures="3">"#));
        // One testcase per finding, each carrying a failure.
        assert_eq!(out.matches("<testcase ").count(), 3);
        assert_eq!(out.matches("<failure ").count(), 3);
        assert!(out.contains(r#"type="critical""#));
        // The pipe in the snippet is fine in XML but must be inside the element.
        assert!(out.contains("k = v | x</failure>"));
    }

    #[test]
    fn junit_escapes_xml_metacharacters() {
        let mut m = finding("rule<&>\"'", Severity::High);
        m.snippet = "a < b && c > d \"q\"".into();
        m.path = "x&y.env".into();
        let a = Analysis {
            findings: vec![m],
            files: 1,
            scans: 1,
        };
        let out = render(&JunitReporter, &a);
        // No raw metacharacter survives inside values/text.
        assert!(out.contains("a &lt; b &amp;&amp; c &gt; d &quot;q&quot;"));
        assert!(out.contains("x&amp;y.env"));
        assert!(!out.contains("rule<&>"));
    }

    #[test]
    fn junit_clean_scan_is_a_passing_suite() {
        let out = render(&JunitReporter, &Analysis::default());
        assert!(out.contains(r#"tests="0" failures="0""#));
        assert!(!out.contains("<testcase"));
    }
    /// Findings spread across directories, so hotspots have something to say.
    fn spread() -> Analysis {
        let at = |path: &str, sev: Severity| Match {
            rule: "r".into(),
            path: path.into(),
            line: 1,
            col: 1,
            snippet: "x".into(),
            severity: Some(sev),
            cwe: None,
            cve: None,
        };
        Analysis {
            findings: vec![
                at("src/auth/token.rs", Severity::Critical),
                at("src/auth/login.rs", Severity::Critical),
                at("src/auth/session.rs", Severity::High),
                at("config/prod.toml", Severity::High),
                at("config/dev.toml", Severity::Low),
                at("README.md", Severity::Info),
            ],
            files: 20,
            scans: 1,
        }
    }

    #[test]
    fn hotspots_rank_directories_by_share() {
        let rows = spread().hotspots(HOTSPOT_LIMIT);
        assert_eq!(rows[0].directory, "src/auth");
        assert_eq!(rows[0].findings, 3);
        assert!((rows[0].share - 0.5).abs() < 1e-9, "{:?}", rows[0]);
        assert_eq!(rows[1].directory, "config");
        // A file at the root groups under ".", not the empty string.
        assert!(rows.iter().any(|r| r.directory == "."), "{rows:?}");
        // Shares total 1.0 — every finding lands in exactly one bucket.
        let total: f64 = rows.iter().map(|r| r.share).sum();
        assert!((total - 1.0).abs() < 1e-9, "shares sum to {total}");
    }

    #[test]
    fn hotspots_break_ties_by_risk_then_name() {
        let at = |path: &str, sev: Severity| Match {
            rule: "r".into(),
            path: path.into(),
            line: 1,
            col: 1,
            snippet: "x".into(),
            severity: Some(sev),
            cwe: None,
            cve: None,
        };
        // Equal counts: the more severe directory must come first.
        let a = Analysis {
            findings: vec![
                at("zzz/a.rs", Severity::Critical),
                at("aaa/b.rs", Severity::Info),
            ],
            ..Default::default()
        };
        let rows = a.hotspots(HOTSPOT_LIMIT);
        assert_eq!(rows[0].directory, "zzz", "severity should break the tie");

        // Equal counts and equal risk fall back to the name, so the report is
        // reproducible rather than dependent on iteration order.
        let b = Analysis {
            findings: vec![at("zzz/a.rs", Severity::Low), at("aaa/b.rs", Severity::Low)],
            ..Default::default()
        };
        assert_eq!(b.hotspots(HOTSPOT_LIMIT)[0].directory, "aaa");
    }

    #[test]
    fn hotspots_are_omitted_when_there_is_nothing_to_compare() {
        // Every finding in one directory: a "100%" table teaches nothing.
        let text = render(&TextReporter::default(), &sample());
        assert!(!text.contains("findings by directory"), "{text}");
        // …and an empty report has no hotspots at all.
        assert!(Analysis::default().hotspots(HOTSPOT_LIMIT).is_empty());
    }

    #[test]
    fn hotspots_reach_every_human_facing_format() {
        let a = spread();
        let text = render(&TextReporter::default(), &a);
        assert!(text.contains("findings by directory"), "{text}");
        assert!(text.contains("src/auth"), "{text}");
        assert!(text.contains("50%"), "{text}");

        let md = render(&MarkdownReporter, &a);
        assert!(md.contains("### Findings by directory"), "{md}");
        assert!(md.contains("| `src/auth` | 3 | 50% |"), "{md}");

        let json = render(&JsonReporter, &a);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hotspots"][0]["directory"], "src/auth");
        assert_eq!(v["hotspots"][0]["findings"], 3);
    }

    #[test]
    fn a_fitted_text_report_stays_inside_the_window() {
        // Long paths, long snippets and a hotspot table, all in 80 columns.
        let mut a = sample();
        for (i, m) in a.findings.iter_mut().enumerate() {
            m.path = format!("/a/deeply/nested/tree/of/directories/number{i}/config.yaml");
            m.snippet = "password = \"https://user:hunter2@example.com/long/path\"".into();
        }
        let fitted = render(&TextReporter::fitted(fit::MAX_WIDTH), &a);
        for line in fitted.lines() {
            assert!(
                fit::width_of(line) <= fit::MAX_WIDTH,
                "{} cols — {line}",
                fit::width_of(line)
            );
        }

        // The default reporter is the machine interface and is never shortened.
        let full = render(&TextReporter::default(), &a);
        assert!(
            full.lines().any(|l| fit::width_of(l) > fit::MAX_WIDTH),
            "unfitted output should keep its long lines"
        );
    }

    #[test]
    fn a_long_directory_is_shortened_from_the_left() {
        // The tail identifies a path; the prefix is usually shared boilerplate.
        assert_eq!(fit::elide_left("short", 10), "short");
        let long = fit::elide_left("/a/very/deeply/nested/path/to/somewhere", 12);
        assert_eq!(long.chars().count(), 12);
        assert!(
            long.starts_with('…') && long.ends_with("somewhere"),
            "{long}"
        );
    }
    #[test]
    fn a_shared_root_is_stated_once_instead_of_on_every_row() {
        let at = |path: &str| Match {
            rule: "r".into(),
            path: path.into(),
            line: 1,
            col: 1,
            snippet: "x".into(),
            severity: Some(Severity::High),
            cwe: None,
            cve: None,
        };
        let a = Analysis {
            findings: vec![
                at("/home/u/proj/src/auth/a.rs"),
                at("/home/u/proj/src/auth/b.rs"),
                at("/home/u/proj/config/c.toml"),
                at("/home/u/proj/vendor/v.js"),
            ],
            ..Default::default()
        };
        let text = render(&TextReporter::default(), &a);
        // Scope the checks to the hotspot table: the finding list above it
        // legitimately prints full paths.
        let table = text
            .split_once("findings by directory")
            .expect("hotspot table")
            .1;
        assert!(table.starts_with(" (under /home/u/proj):"), "{table}");
        assert!(table.contains("src/auth"), "{table}");
        assert!(table.contains("vendor"), "{table}");
        // The shared prefix is stated once, never repeated on the rows.
        assert!(!table.contains("/home/u/proj/"), "{table}");
    }

    #[test]
    fn the_prefix_is_compared_by_component_not_by_character() {
        let rows = vec![
            Hotspot {
                directory: "src/auth".into(),
                findings: 2,
                risk: 10,
                share: 0.5,
            },
            Hotspot {
                directory: "src/authz".into(),
                findings: 2,
                risk: 10,
                share: 0.5,
            },
        ];
        // A character-wise prefix would wrongly share "src/auth".
        let (root, names) = strip_common_prefix(&rows);
        assert_eq!(root.as_deref(), Some("src"));
        // A character-wise prefix would wrongly share "src/auth".
        assert_eq!(names, vec!["auth", "authz"]);
    }

    #[test]
    fn unrelated_directories_keep_their_full_names() {
        let rows = vec![
            Hotspot {
                directory: "etc".into(),
                findings: 1,
                risk: 1,
                share: 0.5,
            },
            Hotspot {
                directory: "var/log".into(),
                findings: 1,
                risk: 1,
                share: 0.5,
            },
        ];
        let (root, names) = strip_common_prefix(&rows);
        assert_eq!(root, None);
        assert_eq!(names, vec!["etc", "var/log"]);
    }

    #[test]
    fn a_row_that_is_the_shared_root_is_named_dot() {
        let rows = vec![
            Hotspot {
                directory: "src/auth".into(),
                findings: 2,
                risk: 10,
                share: 0.66,
            },
            Hotspot {
                directory: "src".into(),
                findings: 1,
                risk: 5,
                share: 0.34,
            },
        ];
        let (root, names) = strip_common_prefix(&rows);
        assert_eq!(root.as_deref(), Some("src"));
        assert_eq!(names, vec!["auth", "."]);
    }

    /// Every reporter, walked with one deliberately hostile finding.
    ///
    /// Escaping is per-format and each format got it separately — and each one
    /// was separately incomplete: JUnit passed C0 controls that are illegal in
    /// XML at any escaping, Markdown escaped the snippet's pipes but left the
    /// rule and path free to add columns, and the PDF dropped the `…` that
    /// marks an elision so truncated paths read as whole. A per-format fix
    /// leaves the next format to rediscover the same list, so this walks
    /// `FORMATS` itself: a new reporter that forgets fails here.
    #[test]
    fn every_format_survives_hostile_finding_text() {
        let hostile = Match {
            // Untrusted in all three fields, not just the snippet.
            rule: "rule|with<pipe>&amp".into(),
            path: "/tmp/a|b/<script>/c.env".into(),
            line: 1,
            col: 1,
            snippet: "tok=\u{1b}[0m\u{0}\u{7} `code` | \"q\" <x> & \u{2026}".into(),
            severity: Some(Severity::Critical),
            cwe: Some("CWE-798".into()),
            cve: None,
        };
        let a = Analysis {
            findings: vec![hostile],
            files: 1,
            scans: 1,
        };

        for format in FORMATS {
            let reporter = reporter_for(format).expect("every listed format resolves");
            let mut buf = Vec::new();
            reporter
                .report(&mut buf, &a)
                .unwrap_or_else(|e| panic!("{format} failed to render: {e}"));
            assert!(!buf.is_empty(), "{format} produced nothing");

            match *format {
                "json" | "sarif" => {
                    serde_json::from_slice::<serde_json::Value>(&buf)
                        .unwrap_or_else(|e| panic!("{format} emitted invalid JSON: {e}"));
                }
                "junit" => {
                    let text = String::from_utf8(buf).expect("junit is utf-8");
                    // C0 controls are illegal in XML 1.0 however they are
                    // escaped, so their absence is the assertion.
                    let illegal: Vec<u32> = text
                        .chars()
                        .map(|c| c as u32)
                        .filter(|c| (*c < 0x20 && ![0x09, 0x0a, 0x0d].contains(c)) || *c == 0x7f)
                        .collect();
                    assert!(
                        illegal.is_empty(),
                        "junit emitted illegal XML chars {illegal:x?}"
                    );
                    // And the markup must not have been broken open.
                    assert!(!text.contains("<script>"), "junit leaked raw markup");
                }
                "markdown" => {
                    let text = String::from_utf8(buf).expect("markdown is utf-8");
                    for row in text
                        .lines()
                        .filter(|l| l.starts_with("| `") || l.starts_with("| rule"))
                    {
                        // A row must keep its column count: 4 cells, 5 pipes.
                        let bars =
                            row.chars().filter(|c| *c == '|').count() - row.matches("\\|").count();
                        assert_eq!(bars, 5, "markdown row broke its columns: {row}");
                    }
                }
                "pdf" => {
                    assert!(buf.starts_with(b"%PDF-"), "pdf lacks its header");
                }
                _ => {}
            }
        }
    }
}
