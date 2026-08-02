//! Does the model actually help? Recall-at-budget, measured out of sample.
//!
//! Ranked scanning makes one claim: *at N% of the work, you recover far more
//! than N% of the findings*. That claim is cheap to check and easy to fool
//! yourself about, so this module measures it honestly:
//!
//! - **Out of sample.** Paths are split into train and test. Scoring the paths
//!   a model was fitted on flatters it — the model has already seen those
//!   labels, and the number you get back is a memorisation score, not a
//!   prediction one.
//! - **Against a real baseline.** "Better than random" is a low bar. The bar
//!   that matters is a *frequency prior over the parent directory* — thirty
//!   lines, no sequence modelling, and it captures a surprising amount. If the
//!   HMM doesn't clearly beat it, the sequence modelling isn't paying for
//!   itself and should go.
//! - **Against random.** At budget *b*, blind selection recovers *b* of the
//!   findings. That is the floor; anything at or below it means the model is
//!   contributing nothing.
//!
//! No new scanning is needed. Every full scan already in the graph is a
//! labelled corpus.
//!
//! # Rust notes
//!
//! The train/test split is by a deterministic hash of the path, not an RNG.
//! Re-running an evaluation must give the same answer, otherwise you cannot
//! tell a real improvement from a lucky split.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{tokenize, train, Hmm, TrainConfig};

/// Budgets the curve is measured at, as fractions of the files.
pub const BUDGETS: &[f64] = &[0.05, 0.10, 0.20, 0.30, 0.50, 0.75];

/// One budget's result: what each ranking recovered at that fraction of work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Point {
    /// Fraction of test files examined, in `0.0..=1.0`.
    pub budget: f64,
    /// Fraction of test findings the model's ranking recovered.
    pub model: f64,
    /// Fraction recovered by a parent-directory frequency prior.
    pub baseline: f64,
    /// Fraction a blind selection would recover — equal to `budget`.
    pub random: f64,
}

impl Point {
    /// How many times better than blind selection the model did. 1.0 means it
    /// contributed nothing.
    pub fn lift(&self) -> f64 {
        if self.random <= 0.0 {
            return 1.0;
        }
        self.model / self.random
    }
}

/// A full evaluation: the corpus it ran on and the curve it produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Paths used for fitting.
    pub train: usize,
    /// Paths held out for measurement.
    pub test: usize,
    /// Test paths that carry a finding.
    pub test_positives: usize,
    /// Recall at each budget.
    pub points: Vec<Point>,
}

impl Report {
    /// Whether the model beat the directory baseline at most budgets — the
    /// question the whole module exists to answer.
    pub fn beats_baseline(&self) -> bool {
        let wins = self
            .points
            .iter()
            .filter(|p| p.model > p.baseline + 1e-9)
            .count();
        wins * 2 > self.points.len()
    }

    /// Mean lift over blind selection across the measured budgets.
    pub fn mean_lift(&self) -> f64 {
        if self.points.is_empty() {
            return 1.0;
        }
        self.points.iter().map(Point::lift).sum::<f64>() / self.points.len() as f64
    }
}

/// A finding-rate prior over the parent directory — the baseline the sequence
/// model has to beat.
///
/// Deliberately the simplest thing that could work: no sequence, no states,
/// just "how often did files in a directory of this name carry a finding".
/// Laplace-smoothed, and falls back to the corpus base rate for a directory it
/// has never seen.
struct DirPrior {
    rate: BTreeMap<String, f64>,
    base: f64,
}

impl DirPrior {
    fn fit(samples: &[(String, bool)]) -> Self {
        let mut hits: BTreeMap<String, f64> = BTreeMap::new();
        let mut totals: BTreeMap<String, f64> = BTreeMap::new();
        let mut found = 0.0;
        for (path, is_hit) in samples {
            let key = parent(path);
            *totals.entry(key.clone()).or_insert(2.0) += 1.0; // Laplace
            let h = hits.entry(key).or_insert(1.0);
            if *is_hit {
                *h += 1.0;
                found += 1.0;
            }
        }
        let rate = totals
            .iter()
            .map(|(k, t)| (k.clone(), hits.get(k).copied().unwrap_or(1.0) / t))
            .collect();
        Self {
            rate,
            base: if samples.is_empty() {
                0.5
            } else {
                found / samples.len() as f64
            },
        }
    }

    fn score(&self, path: &str) -> f64 {
        self.rate.get(&parent(path)).copied().unwrap_or(self.base)
    }
}

/// The last directory component of a path — what the baseline keys on.
fn parent(path: &str) -> String {
    let t = tokenize(path);
    // tokenize replaces the leaf with its extension, so the component before it
    // is the parent directory.
    if t.len() >= 2 {
        t[t.len() - 2].clone()
    } else {
        ".".to_string()
    }
}

/// Deterministically assign a path to the test set.
///
/// A hash rather than an RNG so the same corpus always splits the same way:
/// re-running an evaluation has to give the same answer, or a lucky split is
/// indistinguishable from a real improvement.
fn in_test(path: &str, holdout: f64) -> bool {
    let mut h: u64 = 1469598103934665603;
    for b in path.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    ((h >> 11) % 10_000) as f64 / 10_000.0 < holdout
}

/// Fraction of positives recovered by taking the top `budget` share of `ranked`.
///
/// `ranked` is ordered best-first as `(score, is_positive)`.
fn recall_at(ranked: &[(f64, bool)], budget: f64, positives: usize) -> f64 {
    if positives == 0 || ranked.is_empty() {
        return 0.0;
    }
    let take = ((ranked.len() as f64 * budget).ceil() as usize).min(ranked.len());
    let hit = ranked[..take].iter().filter(|(_, p)| *p).count();
    hit as f64 / positives as f64
}

/// Fit on part of `samples` and measure recall-at-budget on the rest.
///
/// `holdout` is the fraction reserved for measurement (0.3 is a reasonable
/// default). Returns `None` when the split leaves either side unusable — with
/// no test positives there is nothing to recover, and a recall of "0%" would
/// be an artefact of the corpus rather than a fact about the model.
pub fn evaluate(samples: &[(String, bool)], cfg: &TrainConfig, holdout: f64) -> Option<Report> {
    let holdout = holdout.clamp(0.05, 0.95);
    let (test, train_set): (Vec<_>, Vec<_>) = samples
        .iter()
        .cloned()
        .partition(|(p, _)| in_test(p, holdout));

    let test_positives = test.iter().filter(|(_, f)| *f).count();
    let train_positives = train_set.iter().filter(|(_, f)| *f).count();
    if test_positives == 0
        || train_positives == 0
        || train_positives == train_set.len()
        || test.len() < 2
    {
        return None;
    }

    let model: Hmm = train(&train_set, cfg);
    let prior = DirPrior::fit(&train_set);

    let rank = |score: &dyn Fn(&str) -> f64| -> Vec<(f64, bool)> {
        let mut v: Vec<(f64, bool)> = test.iter().map(|(p, f)| (score(p), *f)).collect();
        // Descending by score; ties by label-independent order so a tie can
        // never be silently resolved in the model's favour.
        v.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        v
    };
    let by_model = rank(&|p| model.score(p));
    let by_prior = rank(&|p| prior.score(p));

    let points = BUDGETS
        .iter()
        .map(|&b| Point {
            budget: b,
            model: recall_at(&by_model, b, test_positives),
            baseline: recall_at(&by_prior, b, test_positives),
            random: b,
        })
        .collect();

    Some(Report {
        train: train_set.len(),
        test: test.len(),
        test_positives,
        points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A corpus where the path genuinely predicts the label.
    fn learnable(n: usize) -> Vec<(String, bool)> {
        let mut s = Vec::new();
        for i in 0..n {
            s.push((format!("/srv/app/secrets/k{i}.env"), true));
            s.push((format!("/srv/app/docs/d{i}.md"), false));
            s.push((format!("/srv/app/vendor/v{i}.js"), false));
            s.push((format!("/srv/app/build/o{i}.o"), false));
        }
        s
    }

    #[test]
    fn a_learnable_corpus_beats_random_by_a_wide_margin() {
        let r = evaluate(&learnable(80), &TrainConfig::default(), 0.3).unwrap();
        assert!(r.test > 10 && r.test_positives > 0, "{r:?}");
        // At 30% of the work the model should recover far more than 30%.
        let p = r.points.iter().find(|p| p.budget == 0.30).unwrap();
        assert!(
            p.model > 0.8,
            "recall {:.2} at 30% budget is too low",
            p.model
        );
        assert!(
            p.lift() > 2.0,
            "lift {:.2} is not worth the complexity",
            p.lift()
        );
        assert!(r.mean_lift() > 1.5, "mean lift {:.2}", r.mean_lift());
    }

    #[test]
    fn random_is_reported_as_the_floor() {
        let r = evaluate(&learnable(60), &TrainConfig::default(), 0.3).unwrap();
        for p in &r.points {
            assert_eq!(p.random, p.budget, "random recall is the budget itself");
            assert!((0.0..=1.0).contains(&p.model), "{p:?}");
            assert!((0.0..=1.0).contains(&p.baseline), "{p:?}");
        }
    }

    /// The point of the baseline: a corpus where the parent directory alone
    /// explains everything should NOT show the sequence model winning big.
    #[test]
    fn a_directory_only_corpus_is_matched_by_the_baseline() {
        let r = evaluate(&learnable(80), &TrainConfig::default(), 0.3).unwrap();
        let p = r.points.iter().find(|p| p.budget == 0.30).unwrap();
        assert!(
            p.baseline > 0.8,
            "the baseline should also solve a directory-only corpus, got {:.2}",
            p.baseline
        );
    }

    #[test]
    fn evaluation_is_deterministic() {
        let a = evaluate(&learnable(50), &TrainConfig::default(), 0.3).unwrap();
        let b = evaluate(&learnable(50), &TrainConfig::default(), 0.3).unwrap();
        assert_eq!(a.train, b.train);
        assert_eq!(a.points, b.points);
    }

    #[test]
    fn a_corpus_with_nothing_to_measure_returns_none() {
        // No positives at all.
        let none: Vec<(String, bool)> = (0..40).map(|i| (format!("/a/b/f{i}.rs"), false)).collect();
        assert!(evaluate(&none, &TrainConfig::default(), 0.3).is_none());
        // Everything positive.
        let all: Vec<(String, bool)> = (0..40).map(|i| (format!("/a/b/f{i}.rs"), true)).collect();
        assert!(evaluate(&all, &TrainConfig::default(), 0.3).is_none());
        // Too small to split meaningfully.
        assert!(evaluate(&[], &TrainConfig::default(), 0.3).is_none());
    }

    #[test]
    fn the_split_holds_out_roughly_the_requested_share() {
        let s = learnable(200);
        let r = evaluate(&s, &TrainConfig::default(), 0.3).unwrap();
        let share = r.test as f64 / (r.train + r.test) as f64;
        assert!((0.2..0.4).contains(&share), "held out {share:.2}");
        // Train and test partition the corpus exactly — no path in both, none lost.
        assert_eq!(r.train + r.test, s.len());
    }
    /// The case the sequence model exists for: the *same* directory name means
    /// different things in different contexts. `config` under a deployment tree
    /// holds live credentials; `config` under a cache does not. A prior keyed
    /// on the parent directory alone cannot tell them apart; conditioning on
    /// what came before can.
    #[test]
    fn context_dependent_corpus_is_where_the_sequence_model_wins() {
        let mut s = Vec::new();
        for i in 0..60 {
            s.push((format!("/srv/deploy/config/c{i}.env"), true));
            s.push((format!("/srv/deploy/secrets/k{i}.env"), true));
            s.push((format!("/var/cache/config/c{i}.env"), false));
            s.push((format!("/var/cache/secrets/k{i}.env"), false));
        }
        let r = evaluate(&s, &TrainConfig::default(), 0.3).unwrap();
        let p = r.points.iter().find(|p| p.budget == 0.30).unwrap();

        // The baseline sees only `config`/`secrets`, which are half positive
        // and half negative, so it cannot do better than chance.
        assert!(
            p.baseline < 0.5,
            "the directory prior should be near chance here, got {:.2}",
            p.baseline
        );
        // The model has the prefix and should do markedly better.
        assert!(
            p.model > p.baseline + 0.15,
            "model {:.2} should clearly beat baseline {:.2}",
            p.model,
            p.baseline
        );
        assert!(r.beats_baseline(), "verdict should favour the model");
    }
}
