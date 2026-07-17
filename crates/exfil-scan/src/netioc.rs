//! Network IOC matching: flag files that reference known-bad domains, IPs, or
//! URLs from a threat feed.
//!
//! Where [`HashIocScanner`](crate::ioc) matches a *file's* hash, this checker
//! matches the *observables inside* a file — so it is an `Indicators → Matches`
//! task consuming the [`IndicatorExtractor`](crate::indicator)'s output. Feeds
//! provide indicators as [`Rule`]s whose pattern is `domain:<host>`,
//! `ip:<addr>`, or `url:<url>`; everything else is left to the other scanners.
//!
//! Offline once a feed is pulled: matching is a set lookup. Domain IOCs also
//! match subdomains (`evil.com` matches `login.evil.com`), the way feeds intend.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use exfil_core::{Match, Rule, Severity};
use exfil_task::{Artifact, ArtifactKind, FileTask, Indicators};

/// Parse a rule pattern as a network IOC: `domain:<host>`, `ip:<addr>`, or
/// `url:<url>`. Shared with the regex scanner, which skips these (they are not
/// content regexes). Values are lowercased for domains/IPs.
pub fn is_network_ioc(pattern: &str) -> Option<(&'static str, String)> {
    let (scheme, value) = pattern.split_once(':')?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match scheme.to_ascii_lowercase().as_str() {
        "domain" => Some(("domain", value.to_ascii_lowercase())),
        "ip" => Some(("ip", value.to_ascii_lowercase())),
        // URLs keep their case (paths can be case-sensitive).
        "url" => Some(("url", value.to_string())),
        _ => None,
    }
}

/// Metadata carried onto a match from the matching IOC rule.
struct IocMeta {
    name: String,
    severity: Severity,
    cwe: String,
}

/// Flags references to known-bad network indicators.
pub struct NetworkIocScanner {
    domains: HashMap<String, IocMeta>,
    ips: HashMap<String, IocMeta>,
    urls: HashMap<String, IocMeta>,
}

impl NetworkIocScanner {
    /// Build from a rule set, keeping only the network-IOC rules.
    pub fn new(rules: &[Rule]) -> Self {
        let (mut domains, mut ips, mut urls) = (HashMap::new(), HashMap::new(), HashMap::new());
        for rule in rules {
            let Some((kind, value)) = is_network_ioc(&rule.pattern) else {
                continue;
            };
            let meta = IocMeta {
                name: rule.name.clone(),
                severity: rule.severity.unwrap_or(Severity::Critical),
                cwe: rule.cwe.clone().unwrap_or_else(|| "CWE-506".into()),
            };
            match kind {
                "domain" => {
                    domains.insert(value, meta);
                }
                "ip" => {
                    ips.insert(value, meta);
                }
                "url" => {
                    urls.insert(value, meta);
                }
                _ => {}
            }
        }
        Self { domains, ips, urls }
    }

    /// Whether any network IOCs are loaded (else the task is inert).
    fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty() && self.urls.is_empty()
    }

    /// The domain IOC matching `host` — exact, or a parent domain of it (so
    /// `evil.com` matches `a.b.evil.com`).
    fn domain_hit(&self, host: &str) -> Option<&IocMeta> {
        if let Some(m) = self.domains.get(host) {
            return Some(m);
        }
        // Walk parent domains: a.b.evil.com → b.evil.com → evil.com.
        let mut rest = host;
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(m) = self.domains.get(parent) {
                return Some(m);
            }
            rest = parent;
        }
        None
    }

    fn analyze(&self, ind: &Indicators, path: &str) -> Vec<Match> {
        let mut matches = Vec::new();
        let mut hit = |meta: &IocMeta, kind: &str, value: &str| {
            matches.push(Match {
                rule: meta.name.clone(),
                path: path.to_string(),
                line: 0,
                col: 1,
                snippet: format!("known-bad {kind}: {value}"),
                severity: Some(meta.severity),
                cwe: Some(meta.cwe.clone()),
                cve: None,
            });
        };
        for d in &ind.domains {
            if let Some(m) = self.domain_hit(d) {
                hit(m, "domain", d);
            }
        }
        for ip in &ind.ips {
            if let Some(m) = self.ips.get(ip) {
                hit(m, "ip", ip);
            }
        }
        for url in &ind.urls {
            if let Some(m) = self.urls.get(url) {
                hit(m, "url", url);
            }
        }
        matches
    }
}

impl FileTask for NetworkIocScanner {
    fn name(&self) -> &str {
        "ioc-net"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Indicators
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Matches
    }

    fn applies(&self, _path: &Path) -> bool {
        !self.is_empty()
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Indicators(ind) = input else {
            anyhow::bail!("ioc-net: expected Indicators input");
        };
        Ok(Artifact::Matches(
            self.analyze(ind, &path.to_string_lossy()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, pattern: &str) -> Rule {
        Rule {
            name: name.into(),
            pattern: pattern.into(),
            description: String::new(),
            severity: Some(Severity::Critical),
            cwe: Some("CWE-506".into()),
            cve: None,
        }
    }

    fn ind(domains: &[&str], ips: &[&str], urls: &[&str]) -> Indicators {
        Indicators {
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
            urls: urls.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn is_network_ioc_parses_and_rejects() {
        assert_eq!(
            is_network_ioc("domain:Evil.COM"),
            Some(("domain", "evil.com".into()))
        );
        assert_eq!(is_network_ioc("ip:1.2.3.4"), Some(("ip", "1.2.3.4".into())));
        assert!(is_network_ioc("url:http://bad/x").is_some());
        assert!(is_network_ioc("sha256:abcd").is_none());
        assert!(is_network_ioc("AKIA[0-9]+").is_none());
    }

    #[test]
    fn matches_domain_including_subdomains() {
        let s = NetworkIocScanner::new(&[rule("c2-domain", "domain:evil.com")]);
        let m = s.analyze(&ind(&["login.evil.com"], &[], &[]), "f");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "c2-domain");
        assert!(m[0].snippet.contains("login.evil.com"));
    }

    #[test]
    fn matches_ip_and_url_exact() {
        let s = NetworkIocScanner::new(&[
            rule("c2-ip", "ip:203.0.113.9"),
            rule("c2-url", "url:http://bad.test/beacon"),
        ]);
        let m = s.analyze(
            &ind(&[], &["203.0.113.9"], &["http://bad.test/beacon"]),
            "f",
        );
        let rules: Vec<&str> = m.iter().map(|x| x.rule.as_str()).collect();
        assert!(
            rules.contains(&"c2-ip") && rules.contains(&"c2-url"),
            "{rules:?}"
        );
    }

    #[test]
    fn clean_indicators_no_match() {
        let s = NetworkIocScanner::new(&[rule("c2", "domain:evil.com")]);
        assert!(s
            .analyze(&ind(&["good.com"], &["8.8.8.8"], &[]), "f")
            .is_empty());
    }

    #[test]
    fn inert_without_iocs() {
        let s = NetworkIocScanner::new(&[rule("secret", "AKIA[0-9]+")]);
        assert!(s.is_empty());
        assert!(!s.applies(Path::new("f")));
    }

    #[test]
    fn wrong_input_errors() {
        let s = NetworkIocScanner::new(&[rule("c2", "domain:evil.com")]);
        let err = s.run(Path::new("f"), &Artifact::Bytes(vec![])).unwrap_err();
        assert!(err.to_string().contains("expected Indicators"), "{err}");
    }

    #[test]
    fn task_surface_exact_hit_and_ioc_parsing_edges() {
        // is_network_ioc rejects an empty value.
        assert!(is_network_ioc("domain:").is_none());

        // new() ignores non-network patterns (the `_ => {}` arm).
        let s =
            NetworkIocScanner::new(&[rule("c2", "domain:evil.com"), rule("noise", "AKIA[0-9]+")]);
        assert_eq!(s.name(), "ioc-net");

        // Exact registrable-domain hit (not only subdomains).
        let exact = s.analyze(&ind(&["evil.com"], &[], &[]), "f");
        assert_eq!(exact.len(), 1, "{exact:?}");

        // FileTask run over Indicators yields the same Matches.
        let out = s
            .run(
                Path::new("f"),
                &Artifact::Indicators(ind(&["evil.com"], &[], &[])),
            )
            .unwrap();
        assert!(matches!(out, Artifact::Matches(m) if m.len() == 1));
    }
}
