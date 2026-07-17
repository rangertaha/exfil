//! Domain typosquatting / brand-impersonation detection.
//!
//! This is the first *checker* plugin built on the [`Indicators`] seam: it is an
//! `Indicators → Matches` task (like the taint scanner is `Ast → Matches`), so
//! it reuses the domains the [`IndicatorExtractor`](crate::indicator) already
//! pulled from a file — no re-scan. It flags two phishing patterns against a
//! list of protected brands:
//!
//! 1. **Lookalike registrable domain** — `paypa1.com`, `g00gle.com`,
//!    `micrsoft.com`: the registrable label is a homoglyph or single-edit
//!    variant of a brand.
//! 2. **Brand as a subdomain of another domain** — `paypal.secure-login.com`:
//!    the brand name appears as a subdomain label while the actual registrable
//!    domain belongs to someone else.
//!
//! It is fully offline. Detection favors precision: exact brand domains and
//! their real subdomains never fire.

use std::path::Path;

use anyhow::Result;
use exfil_core::{Match, Severity};
use exfil_task::{Artifact, ArtifactKind, FileTask, Indicators};

/// Registrable labels of high-value brands frequently impersonated. Compared
/// against the second-level label of each observed domain.
const BRANDS: &[&str] = &[
    "google",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "github",
    "gitlab",
    "linkedin",
    "twitter",
    "dropbox",
    "adobe",
    "oracle",
    "cisco",
    "coinbase",
    "binance",
    "wellsfargo",
    "bankofamerica",
    "chase",
    "citibank",
    "outlook",
    "office365",
    "docusign",
];

/// Flags domains that impersonate a protected brand.
pub struct DomainTyposquatScanner {
    brands: Vec<String>,
}

impl Default for DomainTyposquatScanner {
    fn default() -> Self {
        Self {
            brands: BRANDS.iter().map(|b| b.to_string()).collect(),
        }
    }
}

impl DomainTyposquatScanner {
    /// Use a custom brand list (registrable labels, e.g. `"acme"`).
    pub fn with_brands(brands: Vec<String>) -> Self {
        Self { brands }
    }

    /// Classify one domain against the brand list, if it looks like an
    /// impersonation. Returns `(rule, description)`.
    fn classify(&self, domain: &str) -> Option<(&'static str, String)> {
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return None;
        }
        let reg_label = labels[labels.len() - 2];
        let sub_labels = &labels[..labels.len() - 2];

        for brand in &self.brands {
            // Exact registrable brand (or a legitimate subdomain of it) is fine.
            if reg_label == brand {
                return None;
            }
            // Lookalike registrable label.
            if is_lookalike(reg_label, brand) {
                return Some((
                    "typosquat-domain",
                    format!("domain {domain:?} mimics brand {brand:?}"),
                ));
            }
            // Brand used as a subdomain of a different registrable domain.
            if sub_labels.contains(&brand.as_str()) {
                return Some((
                    "brand-subdomain",
                    format!("brand {brand:?} used as a subdomain in {domain:?}"),
                ));
            }
        }
        None
    }

    /// Run over an [`Indicators`] set, one finding per suspicious domain.
    fn analyze(&self, indicators: &Indicators, path: &str) -> Vec<Match> {
        let mut matches = Vec::new();
        for domain in &indicators.domains {
            if let Some((rule, what)) = self.classify(domain) {
                matches.push(Match {
                    rule: rule.into(),
                    path: path.to_string(),
                    line: 0,
                    col: 1,
                    snippet: what,
                    severity: Some(Severity::High),
                    cwe: Some("CWE-1007".into()),
                    cve: None,
                });
            }
        }
        matches
    }
}

impl FileTask for DomainTyposquatScanner {
    fn name(&self) -> &str {
        "typosquat"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Indicators
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Matches
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Indicators(ind) = input else {
            anyhow::bail!("typosquat: expected Indicators input");
        };
        Ok(Artifact::Matches(
            self.analyze(ind, &path.to_string_lossy()),
        ))
    }
}

/// Whether `label` is a homoglyph or single-edit lookalike of `brand` (but not
/// an exact match). Brands shorter than 4 chars are skipped to avoid noise.
fn is_lookalike(label: &str, brand: &str) -> bool {
    if brand.len() < 4 || label == brand {
        return false;
    }
    // Homoglyph fold catches multi-char digit swaps (g00gle → google) that a
    // single-edit check would miss.
    if normalize_homoglyphs(label) == brand {
        return true;
    }
    osa_distance(label, brand) == 1
}

/// Fold common homoglyph substitutions to a canonical letter form: lookalike
/// digits to letters, and the `rn`/`vv` ligature tricks.
fn normalize_homoglyphs(s: &str) -> String {
    let s = s.replace("rn", "m").replace("vv", "w");
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '9' => 'g',
            other => other,
        })
        .collect()
}

/// Optimal string alignment (Damerau-Levenshtein with adjacent transpositions)
/// distance between `a` and `b`.
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind(domains: &[&str]) -> Indicators {
        Indicators {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        }
    }

    fn run(domains: &[&str]) -> Vec<Match> {
        DomainTyposquatScanner::default().analyze(&ind(domains), "f")
    }

    #[test]
    fn flags_single_edit_typosquat() {
        let m = run(&["paypa1.com"]); // 1 vs l → edit distance 1
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "typosquat-domain");
        assert!(m[0].snippet.contains("paypal"), "{}", m[0].snippet);
    }

    #[test]
    fn flags_homoglyph_digit_swap() {
        let m = run(&["g00gle.com"]); // 00 → oo, edit distance 2 but homoglyph 0
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "typosquat-domain");
    }

    #[test]
    fn flags_brand_as_subdomain() {
        let m = run(&["paypal.secure-login.com"]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "brand-subdomain");
    }

    #[test]
    fn legitimate_brand_and_subdomain_not_flagged() {
        let m = run(&["paypal.com", "login.paypal.com", "www.google.com"]);
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn unrelated_domain_not_flagged() {
        let m = run(&["example.com", "rust-lang.org"]);
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn task_metadata_and_wrong_input() {
        let s = DomainTyposquatScanner::default();
        assert_eq!(s.name(), "typosquat");
        assert_eq!(s.needs(), ArtifactKind::Indicators);
        assert_eq!(s.provides(), ArtifactKind::Matches);
        let err = s
            .run(Path::new("f"), &Artifact::Matches(vec![]))
            .unwrap_err();
        assert!(err.to_string().contains("expected Indicators"), "{err}");
    }

    #[test]
    fn osa_distance_basics() {
        assert_eq!(osa_distance("paypal", "paypa1"), 1);
        assert_eq!(osa_distance("ab", "ba"), 1); // transposition
        assert_eq!(osa_distance("abc", "abc"), 0);
    }
}
