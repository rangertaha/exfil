//! The built-in security ruleset: a small, high-signal set of secret and
//! dangerous-pattern rules used when no dataset is configured. Downloaded
//! datasets (gitleaks etc.) supersede these once `pull`/`update` land (M2).

use exfil_core::{Rule, Severity};

fn rule(
    name: &str,
    pattern: &str,
    description: &str,
    severity: Severity,
    cwe: Option<&str>,
) -> Rule {
    Rule {
        name: name.into(),
        pattern: pattern.into(),
        description: description.into(),
        severity: Some(severity),
        cwe: cwe.map(Into::into),
        cve: None,
    }
}

/// The embedded fallback rules.
pub fn builtin_rules() -> Vec<Rule> {
    vec![
        rule(
            "aws-access-key-id",
            r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
            "AWS access key ID",
            Severity::Critical,
            Some("CWE-798"),
        ),
        rule(
            "private-key-block",
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
            "PEM private key material",
            Severity::Critical,
            Some("CWE-798"),
        ),
        rule(
            "github-token",
            r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b",
            "GitHub personal access token",
            Severity::Critical,
            Some("CWE-798"),
        ),
        rule(
            "slack-token",
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
            "Slack API token",
            Severity::High,
            Some("CWE-798"),
        ),
        rule(
            "generic-api-key",
            r#"(?i)\b(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\b\s*[:=]\s*['"][0-9A-Za-z_\-]{16,}['"]"#,
            "Hard-coded API key or secret assignment",
            Severity::High,
            Some("CWE-798"),
        ),
        rule(
            "password-in-url",
            r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@",
            "Credentials embedded in a URL",
            Severity::High,
            Some("CWE-522"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RegexScanner;

    #[test]
    fn builtin_rules_all_compile() {
        let scanner = RegexScanner::new(builtin_rules()).expect("builtin rules must compile");
        assert!(scanner.rule_count() >= 6);
    }
}
