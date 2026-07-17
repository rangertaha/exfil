//! Common Information Model (CIM): normalize heterogeneous findings onto one
//! small set of standard fields, the way Splunk's CIM lets diverse sources be
//! queried with shared field names.
//!
//! Every scanner in exfill emits a [`Match`] with its own rule vocabulary
//! (`log-auth-failure`, `taint-command-injection`, `pii-ssn`, `ioc-net`…).
//! [`normalize`] maps each onto a [`CimEvent`] with a common **category** and
//! **action**, plus a source address extracted from the snippet where present.
//! Persisted as `event` nodes, these let you ask cross-source questions like
//! "every authentication failure" or "every data exposure" regardless of which
//! plugin produced them.

use std::sync::OnceLock;

use exfill_core::Match;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// A normalized security event: the CIM view of a [`Match`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CimEvent {
    /// Broad datamodel category (authentication, vulnerability, malware…).
    pub category: String,
    /// What happened (failure, success, detected, exposed…).
    pub action: String,
    /// The originating rule id (the "signature").
    pub signature: String,
    /// Severity, lowercased (`critical`…`info`).
    pub severity: String,
    /// Source address, if one was recoverable from the finding.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub src: String,
}

/// Map a finding onto its CIM category and action from the rule id.
fn categorize(rule: &str) -> (&'static str, &'static str) {
    match rule {
        // Authentication / access (log events).
        "log-auth-failure" | "log-invalid-user" | "log-su-failure" => ("authentication", "failure"),
        "log-auth-success" => ("authentication", "success"),
        "log-sudo-command" | "log-root-session" => ("privilege", "escalation"),
        // Injection / dangerous code (AST + taint).
        r if r.starts_with("taint-") => ("vulnerability", "exploit-path"),
        r if r.starts_with("ast-") => ("vulnerability", "detected"),
        // Malware / known-bad indicators.
        "clamav" | "ioc-hash" => ("malware", "detected"),
        "ioc-net" | "breach-email" => ("threat", "detected"),
        // Phishing / brand.
        "typosquat-domain" | "brand-subdomain" => ("phishing", "detected"),
        // Supply chain.
        r if r.starts_with("supply-chain") => ("supply-chain", "detected"),
        // Data exposure (PII + secrets).
        r if r.starts_with("pii-") => ("data-exposure", "exposed"),
        // DNS.
        "dns-private-resolution" => ("network", "anomaly"),
        // Everything else (regex secrets, yara, …) is a generic detection.
        _ => ("detection", "detected"),
    }
}

/// Extract a source IPv4 address from a finding's snippet, if present (log lines
/// and network findings often carry one).
fn extract_src(snippet: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
    re.find(snippet)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

/// Normalize a [`Match`] into a [`CimEvent`].
pub fn normalize(m: &Match) -> CimEvent {
    let (category, action) = categorize(&m.rule);
    CimEvent {
        category: category.to_string(),
        action: action.to_string(),
        signature: m.rule.clone(),
        severity: m
            .severity
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_else(|| "info".into()),
        src: extract_src(&m.snippet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfill_core::Severity;

    fn m(rule: &str, snippet: &str) -> Match {
        Match {
            rule: rule.into(),
            path: "f".into(),
            line: 1,
            col: 1,
            snippet: snippet.into(),
            severity: Some(Severity::High),
            cwe: None,
            cve: None,
        }
    }

    #[test]
    fn maps_categories_and_actions() {
        assert_eq!(
            (
                normalize(&m("log-auth-failure", "")).category.as_str(),
                normalize(&m("log-auth-failure", "")).action.as_str()
            ),
            ("authentication", "failure")
        );
        assert_eq!(
            normalize(&m("taint-command-injection", "")).category,
            "vulnerability"
        );
        assert_eq!(normalize(&m("ast-eval", "")).action, "detected");
        assert_eq!(normalize(&m("pii-ssn", "")).category, "data-exposure");
        assert_eq!(normalize(&m("ioc-net", "")).category, "threat");
        assert_eq!(normalize(&m("typosquat-domain", "")).category, "phishing");
        assert_eq!(
            normalize(&m("supply-chain-typosquat", "")).category,
            "supply-chain"
        );
        // Unknown rules fall back to a generic detection.
        assert_eq!(normalize(&m("aws-access-key-id", "")).category, "detection");
    }

    #[test]
    fn extracts_source_ip_from_snippet() {
        let e = normalize(&m(
            "log-auth-failure",
            "Failed password for admin from 203.0.113.9 port 22",
        ));
        assert_eq!(e.src, "203.0.113.9");
        // No IP in the snippet → empty src.
        assert!(normalize(&m("pii-ssn", "US SSN: •••••1234")).src.is_empty());
    }

    #[test]
    fn severity_is_lowercased() {
        assert_eq!(normalize(&m("ast-eval", "")).severity, "high");
    }
}
