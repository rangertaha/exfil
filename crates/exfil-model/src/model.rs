//! The classifier: two Markov chains, a prior, and a calibration — plus the
//! training that fits all three.
//!
//! Fitting one chain and reading a per-state risk off it does **not** work, and
//! the reason is worth keeping in mind: Baum-Welch maximises likelihood, and
//! the labels take no part in it. A single chain will cheerfully learn one
//! state that emits `secrets`, `docs` and `vendor` with equal probability —
//! a perfectly good model of the corpus — after which no read-out can separate
//! those families. Making the label pick the chain is what gives training a
//! reason to tell them apart.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::calibrate::{fit_platt, identity_platt, logistic};
use crate::hmm::{Chain, FLOOR};
use crate::scorer::PathScorer;
use crate::tokens::{build_vocab, tokenize, UNK};

/// A trained path classifier: one Markov chain fitted to paths that yielded
/// findings, one to paths that did not, and the base rate that weighs them.
///
/// **Why two chains rather than one with per-state risk.** Baum-Welch maximises
/// *likelihood*, not discriminability — the labels play no part in fitting. A
/// single chain will happily learn one state that emits `secrets`, `docs` and
/// `vendor` with equal probability, because that models the corpus perfectly
/// well; no risk read-out over such a state can then tell those families apart.
/// Fitting a chain per class makes the label a first-class part of training,
/// and scoring becomes a likelihood ratio.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathModel {
    /// Token → observation index. Index [`UNK`] is reserved.
    pub vocab: BTreeMap<String, usize>,
    /// Chain fitted to paths that produced a finding.
    pub positive: Chain,
    /// Chain fitted to paths that did not.
    pub negative: Chain,
    /// `P(finding)` over the training corpus — the prior the ratio is weighed
    /// against, and the score returned when a path says nothing.
    pub prior: f64,
    /// How many paths the model was trained on.
    pub observations: u64,
    /// Fingerprint of the ruleset that produced the training labels. A model
    /// trained under one ruleset does not describe another: the labels *are*
    /// "what those rules happened to fire on".
    #[serde(default)]
    pub ruleset: String,
    /// Mean log-likelihood per path under the positive chain, for `model status`.
    #[serde(default)]
    pub log_likelihood: f64,
    /// Platt scaling `(slope, intercept)` mapping the raw log-odds onto a
    /// calibrated probability.
    ///
    /// A likelihood ratio between two chains is enormously confident on a
    /// separable corpus — raw scores pile up at 0.0 and 1.0, which ranks fine
    /// but is not a probability anyone should act on. Fitting a logistic on
    /// *held-out* log-odds rescales them so that "0.7" means roughly seven in
    /// ten. `(1.0, 0.0)` is the identity, used when there was too little data
    /// to fit anything.
    #[serde(default = "identity_platt")]
    pub platt: (f64, f64),
}

impl PathModel {
    /// Number of hidden states per chain.
    pub fn states(&self) -> usize {
        self.positive.states
    }

    /// Map a path to observation indices, with unknown tokens folded to [`UNK`].
    ///
    /// Indices are clamped to the emission matrix's width. A stored model whose
    /// vocabulary and matrices disagree — a truncated write, a hand edit, a
    /// version skew — would otherwise index out of bounds and panic the scanner
    /// mid-walk. A model that cannot be trusted should degrade to "I know
    /// nothing about this token", never take the process down.
    pub fn observe(&self, path: &str) -> Vec<usize> {
        let width = self.vocab_len();
        tokenize(path)
            .into_iter()
            .map(|t| self.vocab.get(&t).copied().unwrap_or(UNK))
            .map(|i| if i < width { i } else { UNK })
            .collect()
    }

    /// Vocabulary size (the emission matrices' second dimension).
    pub fn vocab_len(&self) -> usize {
        self.positive.emit.first().map(|r| r.len()).unwrap_or(0)
    }

    /// The uncalibrated log-odds of a finding: how much more likely the path is
    /// under the positive chain than the negative one, plus the base rate's
    /// log-odds. `None` when there is nothing to read (empty path, empty model).
    ///
    /// This is what [`score`](Self::score) calibrates. It is exposed because
    /// fitting the calibration needs the raw value, and because ranking only
    /// needs the ordering — which calibration cannot change, since a logistic
    /// with a positive slope is monotonic.
    pub fn log_odds(&self, path: &str) -> Option<f64> {
        let obs = self.observe(path);
        // An empty vocabulary leaves the emission rows empty, so there is no
        // index that could be read: say nothing rather than reach into them.
        if obs.is_empty() || self.states() == 0 || self.vocab_len() == 0 {
            return None;
        }
        let pos = self.positive.log_likelihood(&obs) + self.prior.max(FLOOR).ln();
        let neg = self.negative.log_likelihood(&obs) + (1.0 - self.prior).max(FLOOR).ln();
        Some(pos - neg)
    }

    /// Most likely state sequence under the positive chain, for explaining a
    /// score.
    pub fn viterbi(&self, obs: &[usize]) -> Vec<usize> {
        self.positive.viterbi(obs)
    }
}

impl PathScorer for PathModel {
    fn name(&self) -> &str {
        "path-hmm"
    }

    /// `P(finding | path)` — the posterior from a likelihood ratio between the
    /// two chains, weighed by the corpus base rate.
    ///
    /// Computed in log space and combined with a logistic: the likelihoods
    /// themselves are astronomically small for a long path, and only their
    /// ratio is meaningful.
    fn score(&self, path: &str) -> f64 {
        match self.log_odds(path) {
            Some(z) => {
                let (a, b) = self.platt;
                logistic(a * z + b)
            }
            None => self.prior,
        }
    }

    /// The unconditional finding rate the model was trained on — the score to
    /// fall back to when a path says nothing.
    fn base_rate(&self) -> f64 {
        self.prior
    }

    fn ruleset(&self) -> &str {
        &self.ruleset
    }

    /// Whether a calibration map was fitted at all, or [`score`](Self::score)
    /// is passing raw log-odds through the identity.
    ///
    /// This asks a different question from
    /// [`eval::Report::is_calibrated`](crate::eval::Report::is_calibrated).
    /// That one measures whether the probabilities *hold up* against held-out
    /// outcomes; this one only reports whether there was enough data to fit a
    /// map in the first place. A model can have a calibration and still be
    /// badly calibrated — but a model without one is certainly not producing
    /// probabilities, because an uncalibrated likelihood ratio saturates at 0
    /// and 1. Callers that read a score as a rank can ignore this; callers
    /// that read it as a probability cannot.
    fn has_calibration(&self) -> bool {
        self.platt != identity_platt()
    }

    /// Per-token evidence for a path: how much each component pushed the score
    /// toward "finding" (positive) or away from it (negative), in log-odds.
    ///
    /// This is what makes a probability inspectable rather than oracular: the
    /// sum of these is the log-odds the score came from.
    fn explain(&self, path: &str) -> Vec<(String, f64)> {
        let tokens = tokenize(path);
        let obs = self.observe(path);
        let mut out = Vec::with_capacity(tokens.len());
        for i in 0..tokens.len() {
            // Contribution of the prefix ending here, minus the prefix before.
            let upto = &obs[..=i];
            let before = &obs[..i];
            let delta = (self.positive.log_likelihood(upto) - self.negative.log_likelihood(upto))
                - (self.positive.log_likelihood(before) - self.negative.log_likelihood(before));
            out.push((tokens[i].clone(), delta));
        }
        out
    }
}

/// Training knobs.
#[derive(Debug, Clone)]
pub struct TrainConfig {
    /// Number of latent states to fit per chain.
    pub states: usize,
    /// Maximum Baum-Welch iterations.
    pub iterations: usize,
    /// Keep at most this many distinct tokens; the rest fold into [`UNK`].
    pub vocab_cap: usize,
    /// Stop early when the mean log-likelihood improves by less than this.
    pub tolerance: f64,
    /// Fingerprint of the ruleset that produced the labels.
    pub ruleset: String,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            states: 8,
            iterations: 30,
            vocab_cap: 4096,
            tolerance: 1e-4,
            ruleset: String::new(),
        }
    }
}

/// Fit a classifier to `samples` — `(path, produced_a_finding)` pairs, which is
/// exactly what the findings graph already holds.
pub fn train(samples: &[(String, bool)], cfg: &TrainConfig) -> PathModel {
    let mut model = train_chains_only(samples, cfg);
    // Safe to graft a map fitted elsewhere onto these chains: `fit_platt`
    // refuses a non-positive slope, and a logistic with a positive slope is
    // monotonic, so no calibration can reorder what the chains ranked.
    model.platt = fit_calibration(samples, cfg);
    model
}

/// Fit both chains and the prior, leaving the calibration at identity.
fn train_chains_only(samples: &[(String, bool)], cfg: &TrainConfig) -> PathModel {
    let vocab = build_vocab(samples, cfg.vocab_cap);
    let v = vocab.len() + 1; // +1 for UNK at index 0
    let s = cfg.states.max(1);

    let encode = |p: &str| -> Vec<usize> {
        tokenize(p)
            .into_iter()
            .map(|t| vocab.get(&t).copied().unwrap_or(UNK))
            .collect()
    };
    let positives: Vec<Vec<usize>> = samples
        .iter()
        .filter(|(_, found)| *found)
        .map(|(p, _)| encode(p))
        .filter(|o: &Vec<usize>| !o.is_empty())
        .collect();
    let negatives: Vec<Vec<usize>> = samples
        .iter()
        .filter(|(_, found)| !*found)
        .map(|(p, _)| encode(p))
        .filter(|o: &Vec<usize>| !o.is_empty())
        .collect();

    let labelled = positives.len() + negatives.len();
    let prior = if labelled == 0 {
        0.5
    } else {
        (positives.len() as f64 / labelled as f64).clamp(FLOOR, 1.0 - FLOOR)
    };

    // Different salts so the two chains do not start identical — otherwise
    // they would fit the same structure and the ratio would be flat.
    let positive = Chain::fit(&positives, s, v, cfg, 0);
    let negative = Chain::fit(&negatives, s, v, cfg, 7_919);

    let log_likelihood = if positives.is_empty() {
        0.0
    } else {
        positives
            .iter()
            .map(|o| positive.log_likelihood(o))
            .sum::<f64>()
            / positives.len() as f64
    };

    PathModel {
        vocab,
        positive,
        negative,
        prior,
        observations: samples.len() as u64,
        ruleset: cfg.ruleset.clone(),
        log_likelihood,
        platt: identity_platt(),
    }
}

/// Fit the calibration map on **out-of-fold** log-odds.
///
/// The chains above are fitted on everything, which is what you want for
/// ranking quality. But calibrating on those same paths would be circular: the
/// model has already seen their labels, its log-odds on them are unrealistically
/// confident, and the resulting map would bake that overconfidence in rather
/// than correct it.
///
/// So a throwaway model is fitted on one part of the corpus and scored on the
/// other, and the calibration is learned from *those* predictions — an honest
/// estimate of how confident the model is on paths it has not seen. The map is
/// then applied to the full-data chains.
fn fit_calibration(samples: &[(String, bool)], cfg: &TrainConfig) -> (f64, f64) {
    // A cheap deterministic split; same idea as the evaluation harness.
    let held = |p: &str| -> bool {
        let mut h: u64 = 1469598103934665603;
        for b in p.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(1099511628211);
        }
        (h >> 13).is_multiple_of(4) // ~25% held out
    };
    let fit_set: Vec<(String, bool)> = samples.iter().filter(|(p, _)| !held(p)).cloned().collect();
    let calib: Vec<&(String, bool)> = samples.iter().filter(|(p, _)| held(p)).collect();

    let usable = |v: &[(String, bool)]| {
        let pos = v.iter().filter(|(_, y)| *y).count();
        pos >= 2 && v.len() - pos >= 2
    };
    if !usable(&fit_set) || calib.len() < 8 {
        // Too little to hold anything out. Leave the scores uncalibrated rather
        // than fit a map on the model's own training data.
        return identity_platt();
    }

    // A throwaway model, deliberately cheaper: calibration needs the *shape* of
    // the log-odds distribution, not a maximally converged fit.
    let quick = TrainConfig {
        iterations: cfg.iterations.min(10),
        ..cfg.clone()
    };
    let holdout_model = {
        let mut m = train_chains_only(&fit_set, &quick);
        m.platt = identity_platt();
        m
    };
    let pairs: Vec<(f64, bool)> = calib
        .iter()
        .filter_map(|(p, y)| holdout_model.log_odds(p).map(|z| (z, *y)))
        .collect();
    fit_platt(&pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two clearly separable families of paths: the model should learn that
    /// the risky family scores higher than the safe one.
    fn corpus() -> Vec<(String, bool)> {
        let mut s = Vec::new();
        for i in 0..40 {
            s.push((format!("/home/u/secrets/app{i}/key.pem"), true));
            s.push((format!("/home/u/secrets/app{i}/creds.env"), true));
            s.push((format!("/usr/share/doc/pkg{i}/readme.md"), false));
            s.push((format!("/usr/share/doc/pkg{i}/notes.txt"), false));
        }
        s
    }

    /// An identity map is not a fitted one, and the difference is what a
    /// confidence budget turns on. (That the map, when there is one, never
    /// reorders is pinned by `eval::tests::calibration_preserves_the_ranking`.)
    #[test]
    fn has_calibration_distinguishes_a_fitted_map_from_the_identity() {
        let tiny = vec![
            ("/home/u/secrets/key.pem".to_string(), true),
            ("/usr/share/doc/readme.md".to_string(), false),
        ];
        let model = train(&tiny, &TrainConfig::default());
        assert!(!model.has_calibration(), "too small to hold anything out");
        assert_eq!(model.platt, (1.0, 0.0));

        let model = train(&corpus(), &TrainConfig::default());
        assert!(model.has_calibration(), "big enough to fit a map");
    }

    #[test]
    fn training_separates_risky_paths_from_safe_ones() {
        let model = train(&corpus(), &TrainConfig::default());
        let risky = model.score("/home/u/secrets/app99/key.pem");
        let safe = model.score("/usr/share/doc/pkg99/readme.md");
        assert!(
            risky > safe,
            "risky {risky:.3} should outrank safe {safe:.3}"
        );
        // And the separation should be decisive, not marginal.
        assert!(risky > 0.7, "risky={risky:.3}");
        assert!(safe < 0.3, "safe={safe:.3}");
    }

    /// Real corpora share a long absolute prefix (`/home/u/proj/...`) and have
    /// more than two families. The discriminating tokens are then a small tail
    /// of a long sequence, which is exactly where a final-position-only risk
    /// estimate falls over.
    #[test]
    fn separates_families_that_share_a_long_prefix() {
        let prefix = "/tmp/claude-1001/-home-tsd-rangertaha-exfil/640fb983/scratchpad/e2e/tree";
        let mut samples = Vec::new();
        for i in 0..20 {
            samples.push((format!("{prefix}/secrets/k{i}.env"), true));
            samples.push((format!("{prefix}/docs/d{i}.md"), false));
            samples.push((format!("{prefix}/vendor/v{i}.js"), false));
        }
        let model = train(&samples, &TrainConfig::default());

        let risky = model.score(&format!("{prefix}/secrets/new.env"));
        let safe = model.score(&format!("{prefix}/docs/new.md"));
        let vendor = model.score(&format!("{prefix}/vendor/new.js"));

        assert!(
            risky > safe && risky > vendor,
            "risky {risky:.4} must outrank safe {safe:.4} and vendor {vendor:.4}"
        );
        assert!(
            risky - safe > 0.2,
            "separation too weak: risky {risky:.4} vs safe {safe:.4}"
        );
    }

    #[test]
    fn probabilities_stay_normalized_and_finite() {
        let model = train(&corpus(), &TrainConfig::default());
        let close = |x: f64| (x - 1.0).abs() < 1e-6;
        for chain in [&model.positive, &model.negative] {
            assert!(close(chain.init.iter().sum::<f64>()), "init");
            for (i, row) in chain.trans.iter().enumerate() {
                assert!(close(row.iter().sum::<f64>()), "trans row {i}");
            }
            for (i, row) in chain.emit.iter().enumerate() {
                assert!(close(row.iter().sum::<f64>()), "emit row {i}");
            }
        }
        assert!((0.0..=1.0).contains(&model.prior));
        assert!(model.log_likelihood.is_finite());
        // Scores are probabilities for any path, seen or not.
        for p in ["/home/u/secrets/app1/key.pem", "/zzz/qqq.xyzzy", "/etc"] {
            let s = model.score(p);
            assert!(s.is_finite() && (0.0..=1.0).contains(&s), "{p} -> {s}");
        }
    }

    #[test]
    fn long_paths_do_not_underflow() {
        let model = train(&corpus(), &TrainConfig::default());
        // 400 components: unscaled forward-backward would be 0.0 well before
        // this, taking the score with it.
        let deep = format!("/home/u/{}/key.pem", vec!["nested"; 400].join("/"));
        let score = model.score(&deep);
        assert!(score.is_finite() && score > 0.0, "score={score}");
    }

    #[test]
    fn unknown_tokens_and_empty_paths_fall_back_to_the_base_rate() {
        let model = train(&corpus(), &TrainConfig::default());
        // A path of entirely unseen tokens is uninformative, not impossible.
        let alien = model.score("/zzz/qqq/wwww/vvvv.xyzzy");
        assert!(alien.is_finite() && alien > 0.0 && alien < 1.0, "{alien}");
        assert_eq!(model.score(""), model.base_rate());
    }

    #[test]
    fn training_is_deterministic() {
        let a = train(&corpus(), &TrainConfig::default());
        let b = train(&corpus(), &TrainConfig::default());
        assert_eq!(
            a.positive.init, b.positive.init,
            "same corpus must give the same model"
        );
        assert_eq!(a.negative.emit, b.negative.emit);
        assert_eq!(a.prior, b.prior);
        let p = "/home/u/secrets/app5/key.pem";
        assert_eq!(a.score(p), b.score(p));
    }

    #[test]
    fn viterbi_labels_every_position() {
        let model = train(&corpus(), &TrainConfig::default());
        let obs = model.observe("/home/u/secrets/app1/key.pem");
        let path = model.viterbi(&obs);
        assert_eq!(path.len(), obs.len());
        assert!(path.iter().all(|s| *s < model.states()));
        assert!(model.viterbi(&[]).is_empty());
    }

    #[test]
    fn empty_corpus_yields_a_usable_model() {
        let model = train(&[], &TrainConfig::default());
        assert_eq!(model.observations, 0);
        let s = model.score("/anything/at/all.rs");
        assert!(s.is_finite(), "score={s}");
    }

    #[test]
    fn model_round_trips_through_json() {
        let model = train(&corpus(), &TrainConfig::default());
        let json = serde_json::to_string(&model).unwrap();
        let back: PathModel = serde_json::from_str(&json).unwrap();
        let p = "/home/u/secrets/app3/creds.env";
        assert!((model.score(p) - back.score(p)).abs() < 1e-12);
    }
    /// A stored model whose vocabulary outruns its matrices must not panic the
    /// scanner mid-walk — a corrupt or version-skewed model should degrade to
    /// "I know nothing", not take the process down.
    #[test]
    fn a_model_with_an_oversized_vocab_degrades_instead_of_panicking() {
        let mut model = train(&corpus(), &TrainConfig::default());
        // Simulate skew: a token indexed past the emission matrix's width.
        let width = model.vocab_len();
        model.vocab.insert("bogus".into(), width + 50);
        assert!(model.observe("/bogus/x.pem").iter().all(|i| *i < width));
        let s = model.score("/bogus/thing/x.pem");
        assert!(s.is_finite() && (0.0..=1.0).contains(&s), "score={s}");

        // An empty vocabulary leaves nothing to index at all.
        model.vocab.clear();
        model.positive.emit = vec![Vec::new(); model.positive.states];
        model.negative.emit = vec![Vec::new(); model.negative.states];
        assert_eq!(model.score("/anything/at/all.rs"), model.prior);
    }
    /// A corpus with only one class cannot separate anything — the missing
    /// chain is fitted on nothing. The model must stay usable (finite scores,
    /// no panic) so callers can report the situation rather than crash.
    #[test]
    fn a_single_class_corpus_still_yields_a_usable_model() {
        for all_found in [true, false] {
            let samples: Vec<(String, bool)> = (0..20)
                .map(|i| (format!("/t/dir{i}/f{i}.rs"), all_found))
                .collect();
            let model = train(&samples, &TrainConfig::default());
            let s = model.score("/t/dir1/other.rs");
            assert!(
                s.is_finite() && (0.0..=1.0).contains(&s),
                "all_found={all_found} score={s}"
            );
            // The prior reflects the corpus it saw, clamped off the extremes.
            assert!(
                model.prior > 0.0 && model.prior < 1.0,
                "prior={}",
                model.prior
            );
        }
    }
}
