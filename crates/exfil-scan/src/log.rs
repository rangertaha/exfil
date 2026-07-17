//! Log parsing: recognize security-relevant events in log files by pattern.
//!
//! A [`LogScanner`] applies a library of named patterns (auth failures, invalid
//! users, privilege use, accepted logins) to log lines and emits a [`Match`]
//! per event, tagged with the event type and any captured field (user, source
//! IP) in the snippet. It is a `Bytes → Matches` [`Scanner`](crate::Scanner),
//! fully offline.
//!
//! It targets log files only — by extension (`.log`) or well-known names
//! (`auth.log`, `secure`, `syslog`, `messages`) — so it never fires on source
//! code or config. This is the pattern-detection core; mapping the captured
//! fields onto a normalized event model (Splunk-CIM style) is a later step.

use std::path::Path;

use anyhow::Result;
use exfil_core::{Match, Severity};
use regex::Regex;

use crate::Scanner;

/// One log event pattern and how to classify a line that matches it.
struct LogPattern {
    rule: &'static str,
    re: Regex,
    severity: Severity,
    cwe: &'static str,
}

/// Detects security events in log files.
pub struct LogScanner {
    patterns: Vec<LogPattern>,
}

impl Default for LogScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LogScanner {
    /// Build the scanner with its built-in event patterns.
    pub fn new() -> Self {
        let p = |rule, pat: &str, severity, cwe| LogPattern {
            rule,
            re: Regex::new(pat).expect("valid built-in log pattern"),
            severity,
            cwe,
        };
        let patterns = vec![
            // SSH / PAM authentication.
            p(
                "log-auth-failure",
                r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)",
                Severity::Medium,
                "CWE-287",
            ),
            p(
                "log-invalid-user",
                r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)",
                Severity::Medium,
                "CWE-287",
            ),
            p(
                "log-auth-failure",
                r"authentication failure;.*\buser=(\S+)",
                Severity::Medium,
                "CWE-287",
            ),
            p(
                "log-auth-success",
                r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)",
                Severity::Info,
                "CWE-287",
            ),
            // Privilege use / escalation.
            p(
                "log-sudo-command",
                r"sudo:.*COMMAND=(\S.*)$",
                Severity::Low,
                "CWE-250",
            ),
            p(
                "log-root-session",
                r"session opened for user root(?:\(uid=0\))? by",
                Severity::Low,
                "CWE-250",
            ),
            p(
                "log-su-failure",
                r"FAILED su for (\S+)",
                Severity::Medium,
                "CWE-287",
            ),
        ];
        Self { patterns }
    }
}

impl Scanner for LogScanner {
    fn name(&self) -> &str {
        "log"
    }

    fn applies(&self, path: &Path) -> bool {
        let is_log_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("log"));
        let known_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| matches!(n, "auth.log" | "secure" | "syslog" | "messages"));
        is_log_ext || known_name
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        let text = String::from_utf8_lossy(content);
        let path_str = path.to_string_lossy().into_owned();
        let mut matches = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            for p in &self.patterns {
                if p.re.is_match(line) {
                    matches.push(Match {
                        rule: p.rule.into(),
                        path: path_str.clone(),
                        line: idx as u32 + 1,
                        col: 1,
                        snippet: line.trim().to_string(),
                        severity: Some(p.severity),
                        cwe: Some(p.cwe.into()),
                        cve: None,
                    });
                }
            }
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(name: &str, src: &str) -> Vec<Match> {
        LogScanner::new()
            .scan(Path::new(name), src.as_bytes())
            .unwrap()
    }

    fn rules(m: &[Match]) -> Vec<&str> {
        m.iter().map(|x| x.rule.as_str()).collect()
    }

    #[test]
    fn applies_only_to_log_files() {
        let s = LogScanner::new();
        assert!(s.applies(Path::new("/var/log/auth.log")));
        assert!(s.applies(Path::new("app.log")));
        assert!(s.applies(Path::new("/var/log/secure")));
        assert!(!s.applies(Path::new("main.rs")));
        assert!(!s.applies(Path::new("config.toml")));
    }

    #[test]
    fn flags_ssh_auth_failure_and_invalid_user() {
        let m = scan(
            "auth.log",
            "May 1 sshd[1]: Failed password for invalid user admin from 10.0.0.9 port 22\n\
             May 1 sshd[1]: Invalid user oracle from 203.0.113.5\n",
        );
        let r = rules(&m);
        assert!(r.contains(&"log-auth-failure"), "{r:?}");
        assert!(r.contains(&"log-invalid-user"), "{r:?}");
    }

    #[test]
    fn flags_accepted_login_as_info() {
        let m = scan(
            "auth.log",
            "sshd[1]: Accepted publickey for deploy from 10.0.0.2 port 22\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "log-auth-success");
        assert_eq!(m[0].severity, Some(Severity::Info));
    }

    #[test]
    fn flags_sudo_and_root_session() {
        let m = scan(
            "auth.log",
            "sudo:    bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow\n\
             systemd: pam_unix(login:session): session opened for user root(uid=0) by (uid=0)\n",
        );
        let r = rules(&m);
        assert!(r.contains(&"log-sudo-command"), "{r:?}");
        assert!(r.contains(&"log-root-session"), "{r:?}");
    }

    #[test]
    fn ordinary_log_lines_are_quiet() {
        let m = scan(
            "app.log",
            "INFO server started on :8080\nDEBUG cache warm\n",
        );
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn metadata() {
        let s = LogScanner::new();
        assert_eq!(s.name(), "log");
    }
}
