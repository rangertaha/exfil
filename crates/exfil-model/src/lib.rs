//! A hidden Markov model over filesystem paths, used to rank what a scan
//! should look at first.
//!
//! A path is a *sequence*: `/home/tsd/proj/node_modules/.bin/x` is six
//! observations, not one bag of words. That sequence structure is the whole
//! point — `.ssh` under a user's home means something different from `.ssh`
//! under `/tmp/build-1234`, and only a model that conditions on what came
//! before can tell them apart.
//!
//! The hidden states are *learned*, not hand-written, and training needs no
//! labelled roles — only the scans you have already run, where a file carrying
//! a finding is a positive and one that doesn't is a negative.
//!
//! Two chains are fitted, one per class, and a path is scored by the ratio
//! between them:
//!
//! ```text
//!   /home/u/proj/secrets/key.pem
//!    └─┬┘ └┬┘ └┬─┘ └──┬──┘ └─┬──┘        observations (path tokens)
//!      │                                 │
//!      ├──► positive chain ──► log P(path | finding)      ┐
//!      └──► negative chain ──► log P(path | no finding)   ┘
//!                                        │
//!                    P(finding | path) = σ(Δ + log-odds of the base rate)
//! ```
//!
//! Fitting one chain and reading a per-state risk off it does **not** work, and
//! the reason is worth keeping in mind: Baum-Welch maximises likelihood, and
//! the labels take no part in it. A single chain will cheerfully learn one
//! state that emits `secrets`, `docs` and `vendor` with equal probability —
//! a perfectly good model of the corpus — after which no read-out can separate
//! those families. Making the label pick the chain is what gives training a
//! reason to tell them apart.
//!
//! # Rust notes
//!
//! - The forward-backward recursions are **scaled**: multiplying hundreds of
//!   probabilities underflows `f64` to zero within a few dozen steps, so each
//!   timestep is normalised and the scale factors are kept to recover the
//!   log-likelihood. This is the standard Rabiner formulation.
//! - Matrices are `Vec<Vec<f64>>` rather than a flat array with index maths:
//!   the sizes here are tiny (states² and states × vocab) and the clarity is
//!   worth more than the cache locality.

pub mod eval;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Vocabulary index reserved for tokens the model never saw in training.
pub const UNK: usize = 0;

/// Smallest probability allowed anywhere in the model, so no transition or
/// emission is ever *impossible* — an unseen combination should be unlikely,
/// not fatal to the whole sequence's likelihood.
const FLOOR: f64 = 1e-9;

/// Split a path into the token sequence the model observes: lowercased path
/// components, with the final component replaced by its extension.
///
/// The filename itself is deliberately dropped. Filenames are near-unique, so
/// they carry almost no transferable signal and would bloat the vocabulary;
/// the extension is what generalises (`.pem` and `.env` mean something
/// everywhere, `report-2024-final-v3.pem` means something only here).
pub fn tokenize(path: &str) -> Vec<String> {
    // `!` separates a container from what is inside it
    // (`archive.zip!inner/app.py`). Splitting on it as well gives the model the
    // container as its own observation — "this file came out of an archive" is
    // real signal — and stops an extensionless entry at a container root from
    // yielding a junk token like `<ext:zip!readme>`.
    let parts: Vec<&str> = path
        .split(['/', '\\', '!'])
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let mut out: Vec<String> = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        if i + 1 == parts.len() {
            // The leaf: emit its extension (or a marker when it has none).
            let ext = part.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
            out.push(if ext.is_empty() || ext == *part {
                "<noext>".to_string()
            } else {
                format!("<ext:{}>", ext.to_lowercase())
            });
        } else {
            out.push(part.to_lowercase());
        }
    }
    out
}

/// One trained Markov chain over path tokens: the parameters Baum-Welch fits.
///
/// Two of these make a classifier — see [`PathModel`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    /// Number of hidden states.
    pub states: usize,
    /// Initial state distribution, `[states]`.
    pub init: Vec<f64>,
    /// Transition matrix, `[states][states]`.
    pub trans: Vec<Vec<f64>>,
    /// Emission matrix, `[states][vocab]`.
    pub emit: Vec<Vec<f64>>,
}

impl Chain {
    /// A deterministic starting point with each state tilted differently.
    fn seeded(states: usize, vocab: usize, salt: usize) -> Self {
        Self {
            states,
            init: seeded_row(states, salt),
            trans: (0..states)
                .map(|i| seeded_row(states, salt + i + 1))
                .collect(),
            emit: (0..states)
                .map(|i| seeded_row(vocab, salt + i + 101))
                .collect(),
        }
    }

    /// Scaled forward pass. Returns `(alpha, scales)`; the sequence
    /// log-likelihood is `-Σ ln(scale)`.
    fn forward(&self, obs: &[usize]) -> (Vec<Vec<f64>>, Vec<f64>) {
        let s = self.states;
        let mut alpha = vec![vec![0.0; s]; obs.len()];
        let mut scales = vec![1.0; obs.len()];
        if obs.is_empty() {
            return (alpha, scales);
        }
        for (i, a) in alpha[0].iter_mut().enumerate() {
            *a = self.init[i] * self.emit[i][obs[0]];
        }
        scales[0] = normalize(&mut alpha[0]);
        for t in 1..obs.len() {
            for j in 0..s {
                let sum: f64 = (0..s).map(|i| alpha[t - 1][i] * self.trans[i][j]).sum();
                alpha[t][j] = sum * self.emit[j][obs[t]];
            }
            scales[t] = normalize(&mut alpha[t]);
        }
        (alpha, scales)
    }

    /// Scaled backward pass, reusing the forward pass's scale factors.
    fn backward(&self, obs: &[usize], scales: &[f64]) -> Vec<Vec<f64>> {
        let s = self.states;
        let n = obs.len();
        let mut beta = vec![vec![0.0; s]; n];
        if n == 0 {
            return beta;
        }
        beta[n - 1].fill(scales[n - 1]);
        for t in (0..n - 1).rev() {
            for i in 0..s {
                beta[t][i] = (0..s)
                    .map(|j| self.trans[i][j] * self.emit[j][obs[t + 1]] * beta[t + 1][j])
                    .sum::<f64>()
                    * scales[t];
            }
        }
        beta
    }

    /// Log-likelihood of one observation sequence under this chain.
    pub fn log_likelihood(&self, obs: &[usize]) -> f64 {
        if obs.is_empty() {
            return 0.0;
        }
        let (_, scales) = self.forward(obs);
        scales.iter().map(|c| -c.max(FLOOR).ln()).sum()
    }

    /// Most likely hidden-state sequence (Viterbi), for explaining a score.
    pub fn viterbi(&self, obs: &[usize]) -> Vec<usize> {
        let s = self.states;
        if obs.is_empty() || s == 0 {
            return Vec::new();
        }
        // In logs: Viterbi multiplies along a whole path, so the same underflow
        // that forces scaling in forward-backward applies here too.
        let mut delta = vec![vec![f64::NEG_INFINITY; s]; obs.len()];
        let mut psi = vec![vec![0usize; s]; obs.len()];
        for (i, d) in delta[0].iter_mut().enumerate() {
            *d = self.init[i].max(FLOOR).ln() + self.emit[i][obs[0]].max(FLOOR).ln();
        }
        for t in 1..obs.len() {
            for j in 0..s {
                let (best, arg) = (0..s)
                    .map(|i| (delta[t - 1][i] + self.trans[i][j].max(FLOOR).ln(), i))
                    .fold((f64::NEG_INFINITY, 0), |a, b| if b.0 > a.0 { b } else { a });
                delta[t][j] = best + self.emit[j][obs[t]].max(FLOOR).ln();
                psi[t][j] = arg;
            }
        }
        let last = obs.len() - 1;
        let mut path = vec![0usize; obs.len()];
        path[last] = (0..s).fold(0, |a, i| {
            if delta[last][i] > delta[last][a] {
                i
            } else {
                a
            }
        });
        for t in (0..last).rev() {
            path[t] = psi[t + 1][path[t + 1]];
        }
        path
    }

    /// One Baum-Welch pass over `sequences`, returning the refitted chain and
    /// the total log-likelihood before the update.
    fn reestimate(&self, sequences: &[Vec<usize>], vocab: usize) -> (Chain, f64) {
        let s = self.states;
        let mut init_acc = vec![0.0; s];
        let mut trans_num = vec![vec![0.0; s]; s];
        let mut trans_den = vec![0.0; s];
        let mut emit_num = vec![vec![0.0; vocab]; s];
        let mut emit_den = vec![0.0; s];
        let mut total_ll = 0.0;

        for obs in sequences {
            let (alpha, scales) = self.forward(obs);
            let beta = self.backward(obs, &scales);
            total_ll += scales.iter().map(|c| -c.max(FLOOR).ln()).sum::<f64>();

            let n = obs.len();
            let mut gamma = vec![vec![0.0; s]; n];
            for t in 0..n {
                for i in 0..s {
                    gamma[t][i] = alpha[t][i] * beta[t][i];
                }
                normalize(&mut gamma[t]);
            }
            for i in 0..s {
                init_acc[i] += gamma[0][i];
            }
            for t in 0..n {
                for i in 0..s {
                    emit_num[i][obs[t]] += gamma[t][i];
                    emit_den[i] += gamma[t][i];
                    if t + 1 < n {
                        trans_den[i] += gamma[t][i];
                    }
                }
            }
            // ξ_t(i,j): the scaled formulation drops the 1/P(O) term, because
            // alpha and beta already carry the per-timestep scale factors.
            for t in 0..n.saturating_sub(1) {
                for i in 0..s {
                    for j in 0..s {
                        trans_num[i][j] += alpha[t][i]
                            * self.trans[i][j]
                            * self.emit[j][obs[t + 1]]
                            * beta[t + 1][j];
                    }
                }
            }
        }

        let next = Chain {
            states: s,
            init: finish_row(init_acc),
            trans: (0..s)
                .map(|i| finish_scaled(&trans_num[i], trans_den[i]))
                .collect(),
            emit: (0..s)
                .map(|i| finish_scaled(&emit_num[i], emit_den[i]))
                .collect(),
        };
        (next, total_ll)
    }

    /// Fit a chain to `sequences` by Baum-Welch.
    fn fit(
        sequences: &[Vec<usize>],
        states: usize,
        vocab: usize,
        cfg: &TrainConfig,
        salt: usize,
    ) -> Chain {
        let mut chain = Chain::seeded(states, vocab, salt);
        if sequences.is_empty() {
            return chain;
        }
        let mut prev = f64::NEG_INFINITY;
        for _ in 0..cfg.iterations {
            let (next, ll) = chain.reestimate(sequences, vocab);
            chain = next;
            let mean = ll / sequences.len() as f64;
            if (mean - prev).abs() < cfg.tolerance {
                break;
            }
            prev = mean;
        }
        chain
    }
}

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

/// The identity calibration: pass the raw log-odds straight through.
fn identity_platt() -> (f64, f64) {
    (1.0, 0.0)
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

    /// `P(finding | path)` — the posterior from a likelihood ratio between the
    /// two chains, weighed by the corpus base rate.
    ///
    /// Computed in log space and combined with a logistic: the likelihoods
    /// themselves are astronomically small for a long path, and only their
    /// ratio is meaningful.
    pub fn score(&self, path: &str) -> f64 {
        match self.log_odds(path) {
            Some(z) => {
                let (a, b) = self.platt;
                logistic(a * z + b)
            }
            None => self.prior,
        }
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

    /// The unconditional finding rate the model was trained on — the score to
    /// fall back to when a path says nothing.
    pub fn base_rate(&self) -> f64 {
        self.prior
    }

    /// Most likely state sequence under the positive chain, for explaining a
    /// score.
    pub fn viterbi(&self, obs: &[usize]) -> Vec<usize> {
        self.positive.viterbi(obs)
    }

    /// Per-token evidence for a path: how much each component pushed the score
    /// toward "finding" (positive) or away from it (negative), in log-odds.
    ///
    /// This is what makes a probability inspectable rather than oracular: the
    /// sum of these is the log-odds the score came from.
    pub fn explain(&self, path: &str) -> Vec<(String, f64)> {
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
    model.platt = fit_calibration(samples, cfg, &model);
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
fn fit_calibration(samples: &[(String, bool)], cfg: &TrainConfig, full: &PathModel) -> (f64, f64) {
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
    let (a, b) = fit_platt(&pairs);

    // Sanity: the map must not flip the ranking the full model produces.
    let _ = full;
    (a, b)
}

/// The logistic function, guarded against overflow at the tails.
fn logistic(z: f64) -> f64 {
    if z > 700.0 {
        return 1.0;
    }
    if z < -700.0 {
        return 0.0;
    }
    1.0 / (1.0 + (-z).exp())
}

/// Fit Platt scaling: the `(slope, intercept)` of a logistic regression of the
/// label on the raw log-odds.
///
/// Plain gradient descent on cross-entropy — a two-parameter fit, so there is
/// no need for anything cleverer. The labels are smoothed toward the interior
/// (Platt's own correction) so a perfectly separable calibration set drives the
/// slope to infinity instead of converging.
///
/// Returns the identity when there is too little to fit, or when the fit
/// produced a non-finite or non-monotonic result: a calibration that reorders
/// the ranking would be worse than none at all.
fn fit_platt(pairs: &[(f64, bool)]) -> (f64, f64) {
    let pos = pairs.iter().filter(|(_, y)| *y).count();
    let neg = pairs.len() - pos;
    if pos < 2 || neg < 2 {
        return identity_platt();
    }
    // Platt's label smoothing: targets sit just inside 0 and 1.
    let hi = (pos as f64 + 1.0) / (pos as f64 + 2.0);
    let lo = 1.0 / (neg as f64 + 2.0);

    // The raw log-odds can be in the hundreds; scale the input so a fixed
    // learning rate behaves for any corpus.
    let scale = pairs
        .iter()
        .map(|(z, _)| z.abs())
        .fold(1.0f64, f64::max)
        .max(1.0);

    let (mut a, mut b) = (1.0f64, 0.0f64);
    let n = pairs.len() as f64;
    for _ in 0..2_000 {
        let (mut ga, mut gb) = (0.0, 0.0);
        for (z, y) in pairs {
            let x = z / scale;
            let t = if *y { hi } else { lo };
            let err = logistic(a * x + b) - t;
            ga += err * x;
            gb += err;
        }
        a -= 0.5 * ga / n;
        b -= 0.5 * gb / n;
        if !a.is_finite() || !b.is_finite() {
            return identity_platt();
        }
    }
    // Undo the input scaling so the parameters apply to the raw log-odds.
    let a = a / scale;
    if !a.is_finite() || !b.is_finite() || a <= 0.0 {
        // A non-positive slope would invert the ranking — refuse it.
        return identity_platt();
    }
    (a, b)
}

/// Normalize a distribution in place, returning the scale factor applied.
fn normalize(row: &mut [f64]) -> f64 {
    let sum: f64 = row.iter().sum();
    if sum <= 0.0 {
        let uniform = 1.0 / row.len() as f64;
        row.iter_mut().for_each(|v| *v = uniform);
        return 1.0;
    }
    row.iter_mut().for_each(|v| *v /= sum);
    1.0 / sum
}

/// The `vocab_cap` most frequent tokens, indexed from 1 ([`UNK`] holds 0).
fn build_vocab(samples: &[(String, bool)], cap: usize) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for (path, _) in samples {
        for token in tokenize(path) {
            *counts.entry(token).or_insert(0) += 1;
        }
    }
    let mut ranked: Vec<(String, u64)> = counts.into_iter().collect();
    // Frequency first, then the token itself, so a tie never depends on hash
    // order — the same corpus must always produce the same model.
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
        .into_iter()
        .take(cap)
        .enumerate()
        .map(|(i, (tok, _))| (tok, i + 1))
        .collect()
}

/// A deterministic, faintly uneven starting distribution.
///
/// Baum-Welch cannot break symmetry on its own: start every state identical and
/// they stay identical forever. A fixed integer hash gives each state a
/// different tilt while keeping training reproducible — no RNG, no seed to
/// thread through, same corpus always yields the same model.
fn seeded_row(len: usize, seed: usize) -> Vec<f64> {
    let mut row: Vec<f64> = (0..len)
        .map(|i| {
            let h = (i.wrapping_mul(2_654_435_761) ^ seed.wrapping_mul(40_503)) % 1000;
            1.0 + h as f64 / 1000.0
        })
        .collect();
    normalize(&mut row);
    row
}

/// Normalize an accumulator into a probability row, flooring zeros.
fn finish_row(mut acc: Vec<f64>) -> Vec<f64> {
    acc.iter_mut().for_each(|v| *v = v.max(FLOOR));
    normalize(&mut acc);
    acc
}

/// Normalize `num` by `den`, falling back to uniform when a state was never
/// visited (which happens when N states is larger than the data supports).
fn finish_scaled(num: &[f64], den: f64) -> Vec<f64> {
    if den <= 0.0 {
        let uniform = 1.0 / num.len() as f64;
        return vec![uniform; num.len()];
    }
    finish_row(num.iter().map(|n| n / den).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_drops_the_filename_but_keeps_its_extension() {
        assert_eq!(
            tokenize("/home/tsd/proj/key.pem"),
            vec!["home", "tsd", "proj", "<ext:pem>"]
        );
        // Windows separators and case are normalized to the same tokens.
        assert_eq!(
            tokenize(r"C:\Users\Tsd\Proj\KEY.PEM"),
            vec!["c:", "users", "tsd", "proj", "<ext:pem>"]
        );
        // An extensionless leaf still emits a marker, so the sequence length
        // still reflects depth.
        assert_eq!(tokenize("/etc/shadow"), vec!["etc", "<noext>"]);
        assert!(tokenize("").is_empty());
    }

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
    #[test]
    fn container_paths_split_on_the_bang_too() {
        // A file inside an archive: the container is its own observation, and
        // the leaf still yields a clean extension.
        assert_eq!(
            tokenize("archive.zip!inner/app.py"),
            vec!["archive.zip", "inner", "<ext:py>"]
        );
        // The case that used to produce a junk `<ext:zip!readme>` token.
        assert_eq!(
            tokenize("archive.zip!README"),
            vec!["archive.zip", "<noext>"]
        );
        // Nested containers nest.
        assert_eq!(
            tokenize("outer.iso!inner.zip!x/key.pem"),
            vec!["outer.iso", "inner.zip", "x", "<ext:pem>"]
        );
    }
}
