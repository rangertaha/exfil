//! What a scan is allowed to spend, and what it should look at first.
//!
//! A [`ScanPlan`] carries an optional path model and an optional [`Budget`].
//! With neither, a scan behaves exactly as it always has: walk everything, in
//! whatever order the filesystem hands it over. With a model it walks
//! worst-first; with a budget it stops early.
//!
//! Ordering and stopping are deliberately separate. Ordering alone changes
//! nothing about the *results* — the same files are scanned, just sooner — so
//! it is safe to turn on by default once a model exists. Stopping early changes
//! what is examined at all, which is a claim about coverage the caller has to
//! opt into and the summary has to state out loud.
//!
//! # Rust notes
//!
//! [`Budget`] parses from a suffixed string (`30s`, `20%`, `500mb`, `2000`)
//! via [`FromStr`], which is what lets clap accept it with a one-line
//! `value_parser` and report a good error for free.

use std::str::FromStr;
use std::time::Duration;

use exfil_hmm::Hmm;

/// How much work a scan may do before it stops.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Budget {
    /// Wall-clock time.
    Time(Duration),
    /// A fraction of the files found, in `0.0..=1.0`.
    Fraction(f64),
    /// Bytes read for content scanning.
    Bytes(u64),
    /// A number of files.
    Files(u64),
    /// Stop once the scanned files account for this share of the *expected*
    /// findings, as a fraction in `0.0..=1.0`.
    ///
    /// The other budgets cap cost; this one caps uncertainty. It self-adjusts
    /// to the tree — a repository whose risk is concentrated in a few files
    /// stops early, one where it is spread thin keeps going — which no fixed
    /// percentage can do. Only meaningful with a calibrated model: it sums
    /// probabilities, so if those are not probabilities the target is not
    /// either.
    Confidence(f64),
}

impl Budget {
    /// Whether this budget could stop a scan short of the whole tree. A 100%
    /// fraction is a full scan expressed awkwardly, not a partial one.
    pub fn is_partial(&self) -> bool {
        match self {
            Budget::Fraction(f) => *f < 1.0,
            Budget::Confidence(c) => *c < 1.0,
            _ => true,
        }
    }

    /// How many of `total` files this budget allows, when it can be expressed
    /// as a file count up front. Time and byte budgets can't be, and return
    /// `None` — they are enforced as the scan runs.
    pub fn file_limit(&self, total: u64) -> Option<u64> {
        match self {
            Budget::Fraction(f) => Some((total as f64 * f).ceil() as u64),
            Budget::Files(n) => Some(*n),
            // Confidence depends on the scores, so it is resolved by the
            // engine once candidates are ranked, not from a count alone.
            Budget::Time(_) | Budget::Bytes(_) | Budget::Confidence(_) => None,
        }
    }
}

impl std::fmt::Display for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Budget::Time(d) => write!(f, "{}s", d.as_secs()),
            Budget::Fraction(x) => write!(f, "{:.0}%", x * 100.0),
            Budget::Bytes(b) => write!(f, "{b} bytes"),
            Budget::Files(n) => write!(f, "{n} files"),
            Budget::Confidence(c) => write!(f, "{:.0}% confidence", c * 100.0),
        }
    }
}

impl FromStr for Budget {
    type Err = String;

    /// `30s` / `5m` time · `20%` fraction · `500mb` bytes · bare number files.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim().to_ascii_lowercase();
        if raw.is_empty() {
            return Err("empty budget".into());
        }
        let num = |v: &str| -> Result<f64, String> {
            v.parse::<f64>().map_err(|_| {
                format!("{s:?} is not a number with an optional s/m/h/%/kb/mb/gb suffix")
            })
        };

        // `90%c` / `90c` — confidence, distinguished from a plain `90%` file
        // fraction because the two mean very different things.
        if let Some(v) = raw.strip_suffix("%c").or_else(|| raw.strip_suffix('c')) {
            let pct = num(v.trim_end_matches('%'))?;
            if !(0.0..=100.0).contains(&pct) {
                return Err(format!("{pct}% is outside 0–100"));
            }
            return Ok(Budget::Confidence(pct / 100.0));
        }
        if let Some(v) = raw.strip_suffix('%') {
            let pct = num(v)?;
            if !(0.0..=100.0).contains(&pct) {
                return Err(format!("{pct}% is outside 0–100"));
            }
            return Ok(Budget::Fraction(pct / 100.0));
        }
        for (suffix, mult) in [("gb", 1u64 << 30), ("mb", 1 << 20), ("kb", 1 << 10)] {
            if let Some(v) = raw.strip_suffix(suffix) {
                return Ok(Budget::Bytes((num(v)?.max(0.0)) as u64 * mult));
            }
        }
        for (suffix, secs) in [("h", 3600.0), ("m", 60.0), ("s", 1.0)] {
            if let Some(v) = raw.strip_suffix(suffix) {
                let t = num(v)?;
                if t <= 0.0 {
                    return Err("a time budget must be positive".into());
                }
                return Ok(Budget::Time(Duration::from_secs_f64(t * secs)));
            }
        }
        let n = num(&raw)?;
        if n < 0.0 {
            return Err("a file budget must not be negative".into());
        }
        Ok(Budget::Files(n as u64))
    }
}

/// The model and budget a scan runs under.
#[derive(Default)]
pub struct ScanPlan {
    /// Trained path model used to rank what to scan first. `None` keeps the
    /// filesystem's own order.
    pub model: Option<Hmm>,
    /// Work limit. `None` scans everything.
    pub budget: Option<Budget>,
    /// Fingerprint of the ruleset this scan applies (see
    /// [`setup::ruleset_fingerprint`](crate::setup::ruleset_fingerprint)).
    ///
    /// When it differs from what the last scan recorded, the stat fast-path is
    /// bypassed: an unchanged file has still never been examined by rules that
    /// were pulled since. Empty means "unknown", which never invalidates.
    pub ruleset: String,
}

impl ScanPlan {
    /// Whether this plan needs the ranked two-phase walk at all. Without a
    /// model *and* without a budget there is nothing to order or stop, so the
    /// plain streaming walk is both simpler and faster.
    pub fn is_ranked(&self) -> bool {
        self.model.is_some() || self.budget.is_some()
    }
}

impl std::fmt::Debug for ScanPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanPlan")
            .field("model", &self.model.as_ref().map(|m| m.states()))
            .field("budget", &self.budget)
            .field("ruleset", &self.ruleset)
            .finish()
    }
}

/// How many of the ranked candidates are needed to account for `confidence` of
/// the total expected findings.
///
/// `scores` must already be in scan order. Sums the per-file probabilities
/// until the running total reaches the requested share of the whole, which is
/// where the curve of expected yield flattens.
pub fn confidence_limit(scores: &[f64], confidence: f64) -> usize {
    let total: f64 = scores.iter().sum();
    if total <= 0.0 {
        return scores.len();
    }
    let target = total * confidence.clamp(0.0, 1.0);
    let mut acc = 0.0;
    for (i, s) in scores.iter().enumerate() {
        acc += s;
        if acc >= target {
            return i + 1;
        }
    }
    scores.len()
}

/// The value of scanning one candidate file: how likely it is to yield a
/// finding, per unit of work.
///
/// Ranking by raw probability is the wrong objective — a 2 GB disk image at
/// p=0.9 is worse value than five hundred dotfiles at p=0.3. Dividing by cost
/// makes it a greedy knapsack by ratio. Cost is floored at one filesystem
/// block because reading a 12-byte file is not a thousand times cheaper than
/// reading a 12 KB one.
pub fn value(score: f64, size: u64) -> f64 {
    const BLOCK: f64 = 4096.0;
    score / (size as f64).max(BLOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_suffix() {
        assert_eq!("30s".parse(), Ok(Budget::Time(Duration::from_secs(30))));
        assert_eq!("2m".parse(), Ok(Budget::Time(Duration::from_secs(120))));
        assert_eq!("1h".parse(), Ok(Budget::Time(Duration::from_secs(3600))));
        assert_eq!("20%".parse(), Ok(Budget::Fraction(0.2)));
        assert_eq!("500mb".parse(), Ok(Budget::Bytes(500 << 20)));
        assert_eq!("4kb".parse(), Ok(Budget::Bytes(4096)));
        assert_eq!("2000".parse(), Ok(Budget::Files(2000)));
        // Case and surrounding space are not significant.
        assert_eq!(" 20% ".parse(), Ok(Budget::Fraction(0.2)));
        assert_eq!("500MB".parse(), Ok(Budget::Bytes(500 << 20)));
    }

    #[test]
    fn rejects_nonsense_with_a_useful_message() {
        for bad in ["", "abc", "-5", "150%", "0s", "12x"] {
            let err = bad.parse::<Budget>().unwrap_err();
            assert!(!err.is_empty(), "{bad:?} should explain itself");
        }
    }

    #[test]
    fn full_coverage_is_not_a_partial_scan() {
        assert!(!Budget::Fraction(1.0).is_partial());
        assert!(Budget::Fraction(0.2).is_partial());
        assert!(Budget::Files(10).is_partial());
        assert!(Budget::Time(Duration::from_secs(1)).is_partial());
    }

    #[test]
    fn file_limits_round_up_so_a_tiny_percent_still_scans_something() {
        assert_eq!(Budget::Fraction(0.2).file_limit(1000), Some(200));
        // 1% of 10 files is 0.1 — a budget that scans nothing is never useful.
        assert_eq!(Budget::Fraction(0.01).file_limit(10), Some(1));
        assert_eq!(Budget::Files(7).file_limit(1000), Some(7));
        assert_eq!(Budget::Bytes(10).file_limit(1000), None);
    }

    #[test]
    fn value_prefers_cheap_candidates_at_equal_probability() {
        assert!(value(0.5, 1_000) > value(0.5, 10_000_000));
        // …and a high enough probability still beats a cheap long shot.
        assert!(value(0.9, 4096) > value(0.1, 4096));
        // Below one block, size stops mattering.
        assert_eq!(value(0.5, 10), value(0.5, 4096));
    }

    #[test]
    fn a_plan_with_nothing_set_is_not_ranked() {
        assert!(!ScanPlan::default().is_ranked());
        assert!(ScanPlan {
            model: None,
            budget: Some(Budget::Fraction(0.5)),
            ..Default::default()
        }
        .is_ranked());
    }
    #[test]
    fn confidence_parses_and_is_distinct_from_a_file_fraction() {
        assert_eq!("90c".parse(), Ok(Budget::Confidence(0.9)));
        assert_eq!("90%c".parse(), Ok(Budget::Confidence(0.9)));
        // A bare percentage still means a share of *files*, not of findings.
        assert_eq!("90%".parse(), Ok(Budget::Fraction(0.9)));
        assert!("150c".parse::<Budget>().is_err());
        assert!(Budget::Confidence(0.9).is_partial());
        assert!(!Budget::Confidence(1.0).is_partial());
        // It cannot be resolved from a file count alone.
        assert_eq!(Budget::Confidence(0.9).file_limit(100), None);
    }

    #[test]
    fn confidence_stops_where_the_expected_yield_flattens() {
        // Risk concentrated in the first few files: 90% of the expected
        // findings sit in three of ten.
        let scores = vec![0.9, 0.8, 0.7, 0.02, 0.02, 0.02, 0.02, 0.02, 0.02, 0.02];
        let n = confidence_limit(&scores, 0.9);
        assert!(n <= 4, "took {n} of 10 for 90% of the expected findings");

        // Risk spread evenly: 90% needs nearly everything, which is the point —
        // the stop adapts to the tree instead of assuming a shape.
        let flat = vec![0.3; 10];
        assert!(confidence_limit(&flat, 0.9) >= 9);

        // Degenerate inputs must not divide by zero or run off the end.
        assert_eq!(confidence_limit(&[], 0.9), 0);
        assert_eq!(confidence_limit(&[0.0, 0.0], 0.9), 2);
        assert_eq!(confidence_limit(&scores, 1.0), scores.len());
    }
}
