//! Indicator extraction: pull observables — emails, domains, IPs, URLs, and
//! file hashes — out of a file's content.
//!
//! Unlike the scanners, this task produces no findings on its own. It is the
//! `Bytes → Indicators` producer whose output feeds the graph (so you can see
//! and navigate what a file references) and future *checker* plugins that
//! consume `Indicators → Matches` (DNS, whois, network-IOC, breach-leak,
//! domain-typosquat). Extracting once and letting many checkers reuse the
//! result is the same "parse once, analyze many" idea as the AST chain.
//!
//! Extraction is deliberately conservative and normalized: values are
//! lowercased where case-insensitive (domains, emails, hashes), de-duplicated,
//! and each list is capped so a pathological file can't produce an unbounded
//! blob.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use exfill_task::{Artifact, ArtifactKind, FileTask, Indicators};
use regex::Regex;

/// Per-list cap: at most this many unique values of each kind per file.
const MAX_PER_KIND: usize = 1024;

/// Compiled extraction patterns, built once.
struct Patterns {
    email: Regex,
    url: Regex,
    ipv4: Regex,
    domain: Regex,
    hash: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        email: Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
        url: Regex::new(r#"\b(?:https?|ftp)://[^\s"'<>)\]]+"#).unwrap(),
        ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        domain: Regex::new(
            r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        )
        .unwrap(),
        hash: Regex::new(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b").unwrap(),
    })
}

/// Collect unique matches of `re` in `text`, normalized by `norm`, capped.
fn collect(re: &Regex, text: &str, norm: impl Fn(&str) -> Option<String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for m in re.find_iter(text) {
        if let Some(v) = norm(m.as_str()) {
            set.insert(v);
            if set.len() >= MAX_PER_KIND {
                break;
            }
        }
    }
    set.into_iter().collect()
}

/// True if every dotted octet of an IPv4 candidate is 0–255.
fn valid_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

/// Extract all indicators from `content`.
pub fn extract(content: &[u8]) -> Indicators {
    let text = String::from_utf8_lossy(content);
    let p = patterns();

    let emails = collect(&p.email, &text, |s| Some(s.to_ascii_lowercase()));
    let urls = collect(&p.url, &text, |s| Some(s.to_string()));
    let ips = collect(&p.ipv4, &text, |s| valid_ipv4(s).then(|| s.to_string()));
    let hashes = collect(&p.hash, &text, |s| Some(s.to_ascii_lowercase()));
    // A domain that is really an IPv4 (all-numeric labels) is dropped — it is
    // already captured as an IP.
    let domains = collect(&p.domain, &text, |s| {
        let low = s.to_ascii_lowercase();
        (!valid_ipv4(&low)).then_some(low)
    });

    Indicators {
        emails,
        domains,
        ips,
        urls,
        hashes,
    }
}

/// Extracts observables from file content into an [`Indicators`] artifact.
pub struct IndicatorExtractor;

impl FileTask for IndicatorExtractor {
    fn name(&self) -> &str {
        "indicators"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Bytes
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Indicators
    }

    fn run(&self, _path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Bytes(bytes) = input else {
            anyhow::bail!("indicators: expected Bytes input");
        };
        Ok(Artifact::Indicators(extract(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_each_kind_and_normalizes() {
        let src = b"Contact Alice@Example.COM or visit https://evil.test/path\n\
                    Resolves to 203.0.113.7 on Evil.Test\n\
                    sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
        let ind = extract(src);
        assert!(
            ind.emails.contains(&"alice@example.com".to_string()),
            "{ind:?}"
        );
        assert!(
            ind.urls.iter().any(|u| u.starts_with("https://evil.test")),
            "{ind:?}"
        );
        assert!(ind.ips.contains(&"203.0.113.7".to_string()), "{ind:?}");
        assert!(ind.domains.contains(&"evil.test".to_string()), "{ind:?}");
        assert_eq!(
            ind.domains.iter().filter(|d| *d == "evil.test").count(),
            1,
            "deduped"
        );
        assert!(
            ind.hashes.contains(
                &"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
            ),
            "{ind:?}"
        );
    }

    #[test]
    fn invalid_ipv4_octets_rejected() {
        let ind = extract(b"not an ip 999.1.2.3 but 10.0.0.1 is\n");
        assert!(ind.ips.contains(&"10.0.0.1".to_string()), "{ind:?}");
        assert!(!ind.ips.iter().any(|i| i == "999.1.2.3"), "{ind:?}");
    }

    #[test]
    fn ipv4_not_double_counted_as_domain() {
        let ind = extract(b"8.8.8.8\n");
        assert!(ind.ips.contains(&"8.8.8.8".to_string()));
        assert!(ind.domains.is_empty(), "{ind:?}");
    }

    #[test]
    fn empty_when_nothing_present() {
        let ind = extract(b"just plain words here\n");
        assert!(ind.is_empty(), "{ind:?}");
    }

    #[test]
    fn task_metadata_and_wrong_input() {
        assert_eq!(IndicatorExtractor.name(), "indicators");
        assert_eq!(IndicatorExtractor.needs(), ArtifactKind::Bytes);
        assert_eq!(IndicatorExtractor.provides(), ArtifactKind::Indicators);
        let err = IndicatorExtractor
            .run(Path::new("f"), &Artifact::Matches(vec![]))
            .unwrap_err();
        assert!(err.to_string().contains("expected Bytes"), "{err}");
    }
}
