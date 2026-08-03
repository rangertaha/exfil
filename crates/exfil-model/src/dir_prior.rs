//! The other path scorer: a finding-rate prior over the parent directory.
//!
//! Deliberately the simplest thing that could work — no sequence, no hidden
//! states, no calibration. Just "how often did files in a directory of this
//! name carry a finding", Laplace-smoothed, falling back to the corpus base
//! rate for a directory it has never seen.
//!
//! It exists for two reasons, and only one of them is benchmarking. It is the
//! bar [`eval`](crate::eval) holds the sequence model to: thirty lines that
//! capture a surprising amount, so if the HMM cannot clearly beat this, the
//! sequence modelling is not paying for itself. And on the corpora where it
//! *does* tie, it is the model you should actually be scanning with — which is
//! why it implements [`PathScorer`] rather than hiding inside the harness.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::scorer::PathScorer;
use crate::tokens::tokenize;

/// A finding rate per parent-directory name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirPrior {
    /// Directory name → smoothed finding rate.
    pub rate: BTreeMap<String, f64>,
    /// Corpus-wide finding rate, used for unseen directories.
    pub base: f64,
    /// How many paths it was fitted on.
    #[serde(default)]
    pub observations: u64,
    /// Fingerprint of the ruleset that produced the labels.
    #[serde(default)]
    pub ruleset: String,
}

impl DirPrior {
    /// Fit the prior to `(path, produced_a_finding)` pairs — the same corpus
    /// [`train`](crate::train) takes, so the two are directly comparable.
    pub fn fit(samples: &[(String, bool)]) -> Self {
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
            observations: samples.len() as u64,
            ruleset: String::new(),
        }
    }

    /// Record the ruleset the labels came from.
    pub fn with_ruleset(mut self, ruleset: &str) -> Self {
        self.ruleset = ruleset.to_string();
        self
    }
}

impl PathScorer for DirPrior {
    fn name(&self) -> &str {
        "dir-prior"
    }

    fn score(&self, path: &str) -> f64 {
        self.rate.get(&parent(path)).copied().unwrap_or(self.base)
    }

    fn base_rate(&self) -> f64 {
        self.base
    }

    fn ruleset(&self) -> &str {
        &self.ruleset
    }

    /// A smoothed frequency *is* a probability — it was never a likelihood
    /// ratio, so there is nothing to rescale. This scorer is calibrated by
    /// construction, which is the one thing it has over the sequence model.
    fn has_calibration(&self) -> bool {
        true
    }

    /// One directory decided the whole score, so the attribution is exact
    /// rather than apportioned.
    fn explain(&self, path: &str) -> Vec<(String, f64)> {
        let dir = parent(path);
        let p = self.score(path).clamp(1e-9, 1.0 - 1e-9);
        vec![(dir, (p / (1.0 - p)).ln())]
    }
}

/// The last directory component of a path — what the prior keys on.
pub fn parent(path: &str) -> String {
    let t = tokenize(path);
    // tokenize replaces the leaf with its extension, so the component before it
    // is the parent directory.
    if t.len() >= 2 {
        t[t.len() - 2].clone()
    } else {
        ".".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_that_always_leaks_outranks_one_that_never_does() {
        let samples: Vec<(String, bool)> = (0..20)
            .flat_map(|i| {
                [
                    (format!("/srv/secrets/k{i}.env"), true),
                    (format!("/srv/docs/d{i}.md"), false),
                ]
            })
            .collect();
        let prior = DirPrior::fit(&samples);
        assert!(prior.score("/srv/secrets/new.env") > prior.score("/srv/docs/new.md"));
    }

    #[test]
    fn an_unseen_directory_falls_back_to_the_base_rate() {
        let samples = vec![
            ("/srv/secrets/k.env".to_string(), true),
            ("/srv/docs/d.md".to_string(), false),
        ];
        let prior = DirPrior::fit(&samples);
        assert_eq!(
            prior.score("/somewhere/entirely/else.txt"),
            prior.base_rate()
        );
    }
}
