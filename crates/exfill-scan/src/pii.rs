//! PII detection: find personally identifiable information in file content.
//!
//! A [`PiiScanner`] flags emails, US Social Security numbers, credit-card
//! numbers, phone numbers, and IBANs. It is fully **offline** — plain pattern
//! matching plus structural validation, no network, no feeds. It plugs into the
//! same [`Scanner`](crate::Scanner) trait as the regex and IOC scanners
//! (`Bytes → Matches`).
//!
//! Two design choices keep it useful rather than noisy:
//!
//! - **Validation, not just patterns.** Credit-card candidates must pass the
//!   Luhn checksum; SSNs must satisfy the SSA's structural rules (no `000`/`666`
//!   area, etc.). A bare regex for "16 digits" would flag every order number;
//!   the checksum cuts almost all of that.
//! - **Masked snippets.** The finding's snippet shows a *masked* form of the
//!   match (`j••••@••••.com`, `••••••••••••1234`), never the raw PII — so the
//!   findings store and reports don't themselves become a PII leak.

use std::path::Path;

use anyhow::Result;
use exfill_core::{Match, Severity};
use regex::Regex;

use crate::Scanner;

/// One kind of PII, with how to detect and classify it.
struct Pattern {
    /// Rule id carried onto the finding, e.g. `pii-email`.
    rule: &'static str,
    /// What it detects (for the finding snippet prefix).
    label: &'static str,
    /// The compiled detector.
    re: Regex,
    /// Extra structural check on the raw match (Luhn, SSA rules). `None` = the
    /// pattern alone is sufficient.
    validate: Option<fn(&str) -> bool>,
    severity: Severity,
    cwe: &'static str,
}

/// Flags personally identifiable information (PII) in text content.
pub struct PiiScanner {
    patterns: Vec<Pattern>,
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiScanner {
    /// Build the scanner with its built-in PII patterns.
    pub fn new() -> Self {
        // These patterns are deliberately simple; the false-positive control is
        // the `validate` checksum/structure pass, not regex cleverness.
        let patterns = vec![
            Pattern {
                rule: "pii-email",
                label: "email address",
                re: Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
                validate: None,
                severity: Severity::Medium,
                cwe: "CWE-359",
            },
            Pattern {
                rule: "pii-ssn",
                label: "US SSN",
                re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                validate: Some(ssn_valid),
                severity: Severity::High,
                cwe: "CWE-359",
            },
            Pattern {
                rule: "pii-credit-card",
                label: "credit card number",
                // 13–19 digits, optionally single-space/dash separated.
                re: Regex::new(r"\b\d(?:[ \-]?\d){12,18}\b").unwrap(),
                validate: Some(luhn_valid),
                severity: Severity::High,
                cwe: "CWE-359",
            },
            Pattern {
                rule: "pii-phone",
                // Require separators/parens so bare digit runs (IDs) don't match.
                label: "phone number",
                re: Regex::new(r"\b(?:\+?1[ .\-])?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b").unwrap(),
                validate: None,
                severity: Severity::Low,
                cwe: "CWE-359",
            },
            Pattern {
                rule: "pii-iban",
                label: "IBAN",
                re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
                validate: Some(iban_valid),
                severity: Severity::Medium,
                cwe: "CWE-359",
            },
        ];
        Self { patterns }
    }
}

impl Scanner for PiiScanner {
    fn name(&self) -> &str {
        "pii"
    }

    fn applies(&self, _path: &Path) -> bool {
        true
    }

    fn scan(&self, path: &Path, content: &[u8]) -> Result<Vec<Match>> {
        let text = String::from_utf8_lossy(content);
        let path_str = path.to_string_lossy().into_owned();
        let mut matches = Vec::new();

        for (idx, line) in text.lines().enumerate() {
            for p in &self.patterns {
                for m in p.re.find_iter(line) {
                    let raw = m.as_str();
                    if let Some(check) = p.validate {
                        if !check(raw) {
                            continue;
                        }
                    }
                    let col = line[..m.start()].chars().count() as u32 + 1;
                    matches.push(Match {
                        rule: p.rule.into(),
                        path: path_str.clone(),
                        line: idx as u32 + 1,
                        col,
                        // Masked so the finding never stores the raw PII.
                        snippet: format!("{}: {}", p.label, mask(raw)),
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

/// Mask a PII value: keep the first and last visible characters, replace the
/// middle with bullets (credit cards keep the last four, PCI-style). Runs of
/// mask characters are capped so a long value can't produce a huge snippet.
fn mask(raw: &str) -> String {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    // Card-like: keep last 4.
    if digits.len() >= 13
        && raw
            .chars()
            .all(|c| c.is_ascii_digit() || c == ' ' || c == '-')
    {
        let keep = &digits[digits.len() - 4..];
        return format!("{}{}", "•".repeat(12), keep);
    }
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 4 {
        return "•".repeat(chars.len());
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    let mid = (chars.len() - 4).min(8);
    format!("{head}{}{tail}", "•".repeat(mid))
}

/// Luhn checksum over the digits of `raw` (ignoring spaces/dashes). Valid card
/// numbers are 13–19 digits and satisfy Luhn.
fn luhn_valid(raw: &str) -> bool {
    let ds: Vec<u32> = raw.chars().filter_map(|c| c.to_digit(10)).collect();
    if ds.len() < 13 || ds.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in ds.iter().rev() {
        let mut x = d;
        if double {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// US SSA structural rules: area is not `000`/`666`/`900–999`, group is not
/// `00`, serial is not `0000`. Cuts obvious placeholders like `123-45-6789`'s
/// invalid cousins and sequential test data.
fn ssn_valid(raw: &str) -> bool {
    let parts: Vec<&str> = raw.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let (Ok(area), Ok(group), Ok(serial)) = (
        parts[0].parse::<u32>(),
        parts[1].parse::<u32>(),
        parts[2].parse::<u32>(),
    ) else {
        return false;
    };
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// IBAN mod-97 validation (ISO 7064): move the first four chars to the end,
/// convert letters to numbers (A=10…Z=35), and check the big number ≡ 1 mod 97.
fn iban_valid(raw: &str) -> bool {
    if raw.len() < 15 || raw.len() > 34 {
        return false;
    }
    let rearranged: String = raw[4..].chars().chain(raw[..4].chars()).collect();
    let mut remainder = 0u32;
    for c in rearranged.chars() {
        let value = if c.is_ascii_digit() {
            c as u32 - '0' as u32
        } else if c.is_ascii_uppercase() {
            c as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        // Fold digit by digit to avoid overflow on long IBANs.
        if value >= 10 {
            remainder = (remainder * 100 + value) % 97;
        } else {
            remainder = (remainder * 10 + value) % 97;
        }
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(src: &str) -> Vec<Match> {
        PiiScanner::new()
            .scan(Path::new("f.txt"), src.as_bytes())
            .unwrap()
    }

    fn rules(m: &[Match]) -> Vec<&str> {
        m.iter().map(|x| x.rule.as_str()).collect()
    }

    #[test]
    fn flags_email_with_masked_snippet() {
        let m = scan("contact: alice@example.com please\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "pii-email");
        // The raw address must NOT appear; a masked form must.
        assert!(
            !m[0].snippet.contains("alice@example.com"),
            "{}",
            m[0].snippet
        );
        assert!(m[0].snippet.contains('•'), "{}", m[0].snippet);
        assert_eq!(m[0].line, 1);
    }

    #[test]
    fn valid_ssn_flagged_invalid_rejected() {
        // 001-01-0001 is structurally valid; 000-12-3456 (area 000) is not.
        let m = scan("ssn 001-01-0001 here\nbad 000-12-3456\n666-01-0001\n");
        let r = rules(&m);
        assert_eq!(r.iter().filter(|x| **x == "pii-ssn").count(), 1, "{m:?}");
    }

    #[test]
    fn credit_card_requires_luhn() {
        // 4111 1111 1111 1111 is a Luhn-valid Visa test number; the +1 variant is not.
        let ok = scan("card 4111 1111 1111 1111 end\n");
        assert!(rules(&ok).contains(&"pii-credit-card"), "{ok:?}");
        let bad = scan("num 4111 1111 1111 1112 end\n");
        assert!(!rules(&bad).contains(&"pii-credit-card"), "{bad:?}");
    }

    #[test]
    fn credit_card_snippet_keeps_last_four_only() {
        let m = scan("4111 1111 1111 1111\n");
        let cc = m.iter().find(|x| x.rule == "pii-credit-card").unwrap();
        assert!(cc.snippet.ends_with("1111"), "{}", cc.snippet);
        assert!(!cc.snippet.contains("4111"), "{}", cc.snippet);
    }

    #[test]
    fn phone_needs_separators() {
        let m = scan("call +1 415-555-0132 now\n");
        assert!(rules(&m).contains(&"pii-phone"), "{m:?}");
        // A bare 10-digit id must not match as a phone.
        let id = scan("order 4155550132 shipped\n");
        assert!(!rules(&id).contains(&"pii-phone"), "{id:?}");
    }

    #[test]
    fn iban_mod97_validates() {
        // A canonical valid IBAN vs a corrupted one.
        let ok = scan("iban GB82WEST12345698765432 ok\n");
        assert!(rules(&ok).contains(&"pii-iban"), "{ok:?}");
        let bad = scan("iban GB82WEST12345698765431 no\n");
        assert!(!rules(&bad).contains(&"pii-iban"), "{bad:?}");
    }

    #[test]
    fn clean_text_produces_nothing() {
        let m = scan("just some ordinary prose with no secrets\n");
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn scanner_metadata() {
        let s = PiiScanner::new();
        assert_eq!(s.name(), "pii");
        assert!(s.applies(Path::new("anything")));
    }
}
