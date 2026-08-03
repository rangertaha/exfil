//! A scaled hidden Markov chain: forward-backward, Viterbi, and Baum-Welch.
//!
//! Nothing here knows about paths, findings, or exfil. It fits a chain to
//! sequences of observation indices and reports likelihoods — the sequence
//! machinery on its own, so the classifier above it is only the part that is
//! about filesystems.
//!
//! # Rust notes
//!
//! The recursions are **scaled**: multiplying hundreds of probabilities
//! underflows `f64` to zero within a few dozen steps, so each timestep is
//! normalised and the scale factors are kept to recover the log-likelihood.
//! This is the standard Rabiner formulation.

use serde::{Deserialize, Serialize};

use crate::TrainConfig;

/// Smallest probability allowed anywhere in the model, so no transition or
/// emission is ever *impossible* — an unseen combination should be unlikely,
/// not fatal to the whole sequence's likelihood.
pub const FLOOR: f64 = 1e-9;

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
    pub fn fit(
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
