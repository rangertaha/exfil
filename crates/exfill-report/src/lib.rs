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

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Result;
use exfill_core::{Match, Severity};

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
        "text" | "txt" => Some(Box::new(TextReporter)),
        "json" => Some(Box::new(JsonReporter)),
        "markdown" | "md" => Some(Box::new(MarkdownReporter)),
        _ => None,
    }
}

/// The format names [`reporter_for`] accepts (canonical spellings).
pub const FORMATS: &[&str] = &["text", "json", "markdown"];

/// Human-readable plain-text report.
pub struct TextReporter;

impl Reporter for TextReporter {
    fn name(&self) -> &str {
        "text"
    }

    fn report(&self, w: &mut dyn Write, a: &Analysis) -> Result<()> {
        for m in &a.findings {
            writeln!(
                w,
                "{}:{}:{} [{}] {}",
                m.path, m.line, m.col, m.rule, m.snippet
            )?;
        }
        writeln!(w)?;
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
        Ok(())
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
        writeln!(w, "# exfill findings\n")?;
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
        if !a.findings.is_empty() {
            writeln!(w, "| Rule | Severity | Location | Snippet |")?;
            writeln!(w, "|---|---|---|---|")?;
            for m in &a.findings {
                let sev = m
                    .severity
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_else(|| "-".into());
                // Escape pipes so a snippet can't break the table.
                let snippet = m.snippet.replace('|', "\\|");
                writeln!(
                    w,
                    "| {} | {} | {}:{} | `{}` |",
                    m.rule, sev, m.path, m.line, snippet
                )?;
            }
        }
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
        let out = render(&TextReporter, &sample());
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
        assert!(out.contains("# exfill findings"));
        assert!(out.contains("| Rule | Severity | Location | Snippet |"));
        // The literal pipe in the snippet must be escaped, not left raw.
        assert!(out.contains("k = v \\| x"));
    }

    #[test]
    fn empty_analysis_still_renders() {
        let empty = Analysis::default();
        assert!(render(&TextReporter, &empty).contains("0 finding(s)"));
        let v: serde_json::Value = serde_json::from_str(&render(&JsonReporter, &empty)).unwrap();
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    }
}
