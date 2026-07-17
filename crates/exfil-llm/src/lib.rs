//! Finding enrichment — a triage note written onto each finding.
//!
//! An [`Enricher`] turns a [`Match`] into a short triage summary. The default
//! [`RuleBasedEnricher`] needs no model: it composes advice from the finding's
//! severity, CWE, and rule. The [`Enricher`] trait is the seam for a future
//! offline LLM (Candle GGUF): drop in an impl whose [`available`](Enricher::available)
//! is true only when a model is present, and [`run`] uses it instead — every
//! call remains a no-op when no enricher is available.
//!
//! [`run`] writes the note to each finding's `triage` field via the store, so
//! it shows up in `search`/`get`/the TUI viewer like any other field.

use anyhow::{Context, Result};
use exfil_core::{Match, Severity};
use exfil_store::Store;

/// Produces a triage note for a finding.
pub trait Enricher: Send + Sync {
    /// Stable identifier (shown in logs).
    fn name(&self) -> &str;

    /// Whether this enricher can produce notes (a model is loaded, etc.).
    fn available(&self) -> bool;

    /// A short triage note for `finding`, or `None` to leave it unenriched.
    fn triage(&self, finding: &Match) -> Option<String>;
}

/// A model-free enricher: advice composed from severity, CWE, and rule. Always
/// available, so `enrich` does something useful without downloading anything.
pub struct RuleBasedEnricher;

impl Enricher for RuleBasedEnricher {
    fn name(&self) -> &str {
        "rule-based"
    }

    fn available(&self) -> bool {
        true
    }

    fn triage(&self, finding: &Match) -> Option<String> {
        let urgency = match finding.severity {
            Some(Severity::Critical) => "Act now",
            Some(Severity::High) => "Investigate promptly",
            Some(Severity::Medium) => "Review",
            _ => "Note",
        };
        let context = match finding.cwe.as_deref() {
            Some("CWE-798") | Some("CWE-522") => {
                "leaked credential — rotate the secret and purge it from history"
            }
            Some("CWE-78") => "possible command injection — ensure input can't reach a shell",
            Some("CWE-95") => "possible code injection — avoid evaluating untrusted input",
            Some("CWE-502") => "unsafe deserialization — use a safe loader on untrusted data",
            Some("CWE-506") => "known-bad indicator — treat the host/file as compromised",
            Some("CWE-829") => "supply-chain risk — verify the dependency's integrity",
            Some(cwe) => return Some(format!("{urgency}: {} ({cwe}).", finding.rule)),
            None => "review the flagged pattern",
        };
        Some(format!("{urgency}: {}.", context))
    }
}

/// The default enricher when no model is configured.
pub fn default_enricher() -> Box<dyn Enricher> {
    Box::new(RuleBasedEnricher)
}

/// Run the enrichment pass: for every finding, compute a triage note and write
/// it to the finding's `triage` field. Returns the number of findings enriched.
/// A no-op (returns 0) when the enricher is unavailable.
pub async fn run(store: &Store, enricher: &dyn Enricher) -> Result<usize> {
    if !enricher.available() {
        return Ok(0);
    }

    // Findings with their ids so we can write back to each record.
    #[derive(serde::Deserialize)]
    struct Row {
        // Aliased `fid` (not `id`) because `OMIT id` would otherwise drop the
        // stringified id alongside the RecordId.
        fid: String,
        #[serde(flatten)]
        m: Match,
    }
    let mut res = store
        .db()
        .query("SELECT type::string(id) AS fid, * OMIT id FROM finding")
        .await
        .context("load findings for enrich")?;
    let rows: Vec<Row> = res.take(0)?;

    let mut count = 0;
    for row in rows {
        if let Some(note) = enricher.triage(&row.m) {
            store
                .set_field(&row.fid, "triage", serde_json::Value::String(note))
                .await?;
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity, cwe: Option<&str>) -> Match {
        Match {
            rule: rule.into(),
            path: "a.env".into(),
            line: 1,
            col: 1,
            snippet: "hit".into(),
            severity: Some(sev),
            cwe: cwe.map(Into::into),
            cve: None,
        }
    }

    #[test]
    fn rule_based_notes_reflect_cwe_and_severity() {
        let e = RuleBasedEnricher;
        assert!(e.available());
        let secret = e
            .triage(&finding("aws-key", Severity::Critical, Some("CWE-798")))
            .unwrap();
        assert!(
            secret.contains("Act now") && secret.contains("rotate"),
            "{secret}"
        );
        let cmd = e
            .triage(&finding("os-cmd", Severity::High, Some("CWE-78")))
            .unwrap();
        assert!(cmd.contains("command injection"), "{cmd}");
        // Unknown CWE still yields a note naming the rule.
        let other = e
            .triage(&finding("x", Severity::Low, Some("CWE-1234")))
            .unwrap();
        assert!(other.contains("CWE-1234") && other.contains("x"));
    }

    struct Off;
    impl Enricher for Off {
        fn name(&self) -> &str {
            "off"
        }
        fn available(&self) -> bool {
            false
        }
        fn triage(&self, _f: &Match) -> Option<String> {
            panic!("must not be called when unavailable")
        }
    }

    #[tokio::test]
    async fn run_writes_triage_and_noop_when_unavailable() {
        let dir = std::env::temp_dir().join(format!("exfil-llm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir, exfil_store::DB_FINDINGS).await.unwrap();
        let meta = exfil_core::FileMeta {
            path: "a.env".into(),
            abs: "a.env".into(),
            host: "h".into(),
            mode: 0,
            uid: 0,
            gid: 0,
            user: String::new(),
            group: String::new(),
            size: 1,
            mtime: String::new(),
            hash: "aaa".into(),
        };
        store.upsert_file(&meta).await.unwrap();
        store
            .add_finding(
                &finding("aws-key", Severity::Critical, Some("CWE-798")),
                "aaa",
            )
            .await
            .unwrap();

        // Unavailable enricher is a no-op.
        assert_eq!(run(&store, &Off).await.unwrap(), 0);

        // Rule-based enricher writes a triage note onto the finding.
        let n = run(&store, &RuleBasedEnricher).await.unwrap();
        assert_eq!(n, 1);
        let findings = store.search_findings("").await.unwrap();
        // The note is now stored (visible in the record).
        let mut res = store
            .db()
            .query("SELECT triage FROM finding LIMIT 1")
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = res.take(0).unwrap();
        assert!(rows[0]["triage"].as_str().unwrap().contains("Act now"));
        assert_eq!(findings.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
