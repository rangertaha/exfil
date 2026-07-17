//! User scripting via [Rhai](https://rhai.rs) — pure Rust, sandboxed, no C.
//!
//! [`ScriptEnricher`] runs a user script over each finding to produce a triage
//! note, plugging into the same [`Enricher`](exfil_llm::Enricher) trait as the
//! built-in rule-based one. The script receives the finding as a map
//! (`finding.rule`, `.path`, `.line`, `.severity`, `.cwe`, `.snippet`) and
//! returns a string note, or `()` to leave the finding unenriched:
//!
//! ```rhai
//! if finding.severity == "critical" {
//!     "URGENT — " + finding.rule + " in " + finding.path
//! } else { () }
//! ```
//!
//! Rhai is sandboxed (no filesystem/network access from a script) and bounded
//! by operation limits, so running an untrusted rule set is safe.

use anyhow::{Context, Result};
use exfil_core::Match;
use exfil_llm::Enricher;
use rhai::{Dynamic, Engine, Map, Scope, AST};

/// An [`Enricher`] backed by a compiled Rhai script.
pub struct ScriptEnricher {
    engine: Engine,
    ast: AST,
    name: String,
}

impl ScriptEnricher {
    /// Compile `source` into an enricher named `name`. Syntax errors fail here,
    /// before any finding is processed.
    pub fn from_source(name: impl Into<String>, source: &str) -> Result<Self> {
        let mut engine = Engine::new();
        // Bound runaway scripts (untrusted rules): cap work and nesting.
        engine.set_max_operations(500_000);
        engine.set_max_expr_depths(64, 64);
        let ast = engine
            .compile(source)
            .context("compile Rhai enrichment script")?;
        Ok(Self {
            engine,
            ast,
            name: name.into(),
        })
    }

    /// Load an enricher from a `.rhai` file.
    pub fn from_file(path: &str) -> Result<Self> {
        let src = std::fs::read_to_string(path).with_context(|| format!("read script {path}"))?;
        Self::from_source(path.to_string(), &src)
    }

    /// Build the `finding` map the script sees.
    fn finding_map(m: &Match) -> Map {
        let mut map = Map::new();
        map.insert("rule".into(), m.rule.clone().into());
        map.insert("path".into(), m.path.clone().into());
        map.insert("line".into(), (m.line as i64).into());
        map.insert("col".into(), (m.col as i64).into());
        map.insert("snippet".into(), m.snippet.clone().into());
        map.insert(
            "severity".into(),
            m.severity
                .map(|s| format!("{s:?}").to_lowercase())
                .unwrap_or_default()
                .into(),
        );
        map.insert("cwe".into(), m.cwe.clone().unwrap_or_default().into());
        map.insert("cve".into(), m.cve.clone().unwrap_or_default().into());
        map
    }
}

impl Enricher for ScriptEnricher {
    fn name(&self) -> &str {
        &self.name
    }

    fn available(&self) -> bool {
        true
    }

    fn triage(&self, finding: &Match) -> Option<String> {
        let mut scope = Scope::new();
        scope.push("finding", Self::finding_map(finding));
        // A runtime error (or a non-string result) yields no note rather than
        // aborting the whole enrichment pass.
        let result: Dynamic = self
            .engine
            .eval_ast_with_scope(&mut scope, &self.ast)
            .ok()?;
        if result.is_string() {
            let s = result.into_string().ok()?;
            (!s.is_empty()).then_some(s)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfil_core::Severity;

    fn finding(rule: &str, sev: Severity, path: &str) -> Match {
        Match {
            rule: rule.into(),
            path: path.into(),
            line: 7,
            col: 1,
            snippet: "hit".into(),
            severity: Some(sev),
            cwe: Some("CWE-798".into()),
            cve: None,
        }
    }

    #[test]
    fn script_produces_note_from_finding_fields() {
        let e = ScriptEnricher::from_source(
            "test",
            r#"if finding.severity == "critical" {
                   "URGENT — " + finding.rule + " @ " + finding.path + ":" + finding.line
               } else { () }"#,
        )
        .unwrap();
        assert!(e.available());
        let note = e
            .triage(&finding("aws-key", Severity::Critical, "a.env"))
            .unwrap();
        assert_eq!(note, "URGENT — aws-key @ a.env:7");
        // Non-critical → the script returns () → no note.
        assert!(e.triage(&finding("x", Severity::Low, "b")).is_none());
    }

    #[test]
    fn script_can_use_cwe_and_snippet() {
        let e = ScriptEnricher::from_source(
            "cwe",
            r#"if finding.cwe == "CWE-798" { "secret: " + finding.snippet } else { () }"#,
        )
        .unwrap();
        assert_eq!(
            e.triage(&finding("r", Severity::High, "p")).unwrap(),
            "secret: hit"
        );
    }

    #[test]
    fn syntax_error_fails_at_compile() {
        let err = match ScriptEnricher::from_source("bad", "if finding { ") {
            Ok(_) => panic!("expected a compile error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("compile Rhai"), "{err}");
    }

    #[test]
    fn runtime_error_yields_no_note_not_a_crash() {
        // Calling a missing function errors at runtime → None, not a panic.
        let e = ScriptEnricher::from_source("rt", "no_such_function(finding)").unwrap();
        assert!(e.triage(&finding("r", Severity::High, "p")).is_none());
    }

    #[test]
    fn non_string_result_is_ignored() {
        let e = ScriptEnricher::from_source("num", "42").unwrap();
        assert!(e.triage(&finding("r", Severity::High, "p")).is_none());
    }
}
