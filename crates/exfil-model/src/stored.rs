//! How a fitted scorer is written down, so more than one kind can be.
//!
//! A model in the catalog used to be a bare [`PathModel`] — the JSON *was* the
//! struct, which works exactly as long as there is one kind of model. Now that
//! [`PathScorer`] has two implementations, a stored model has to say which one
//! it is, or loading it is a guess.
//!
//! So the stored form is tagged:
//!
//! ```json
//! { "kind": "path-hmm",  "vocab": {…}, "positive": {…}, … }
//! { "kind": "dir-prior", "rate": {…}, "base": 0.11, … }
//! ```
//!
//! The tag is the same string [`PathScorer::name`] returns, so what a model
//! calls itself and what it is stored as cannot drift apart.
//!
//! # Reading what was written before the tag existed
//!
//! Deserialization accepts an untagged document and reads it as a `path-hmm`,
//! because that is what every model written before this change is. A user's
//! trained model keeps working across the upgrade with no migration step, and
//! is re-written in tagged form the next time they train.
//!
//! That fallback is declarative — a `#[serde(untagged)]` shim that tries the
//! tagged form first — so this crate describes the *format* without depending
//! on any particular encoding of it. Whoever persists a model chooses that.

use serde::{Deserialize, Serialize};

use crate::dir_prior::DirPrior;
use crate::model::{train, PathModel, TrainConfig};
use crate::scorer::PathScorer;

/// Which scorer to fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScorerKind {
    /// The sequence model: two Markov chains over path tokens.
    #[default]
    PathHmm,
    /// The frequency prior over the parent directory.
    DirPrior,
}

impl ScorerKind {
    /// Every kind, for listing choices.
    pub const ALL: &'static [ScorerKind] = &[ScorerKind::PathHmm, ScorerKind::DirPrior];

    /// The stable name: the tag in storage and the value on the command line.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScorerKind::PathHmm => "path-hmm",
            ScorerKind::DirPrior => "dir-prior",
        }
    }

    /// One line on what this kind is and when to prefer it.
    pub fn about(&self) -> &'static str {
        match self {
            ScorerKind::PathHmm => {
                "sequence model over path tokens — conditions on what came before, \
                 so `.ssh` under a home directory differs from `.ssh` under /tmp"
            }
            ScorerKind::DirPrior => {
                "finding rate per parent directory — no sequence, no states, \
                 calibrated by construction; worth using when `model eval` says \
                 it ties"
            }
        }
    }
}

impl std::str::FromStr for ScorerKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "path-hmm" | "hmm" | "path" => Ok(ScorerKind::PathHmm),
            "dir-prior" | "dir" | "prior" | "baseline" => Ok(ScorerKind::DirPrior),
            other => Err(format!("unknown model {other:?} (path-hmm|dir-prior)")),
        }
    }
}

impl std::fmt::Display for ScorerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A fitted scorer in the shape it is stored and loaded in.
///
/// # Rust notes
///
/// `#[serde(tag = "kind")]` is an *internally tagged* enum: the discriminant
/// becomes one more field alongside the variant's own, rather than wrapping it
/// in another object. That keeps the stored document flat — and keeps an old
/// untagged document one missing field away from a valid new one, which is
/// what makes the fallback in [`from_value`](Self::from_value) a two-line
/// affair instead of a migration.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StoredScorer {
    /// The sequence model.
    PathHmm(PathModel),
    /// The directory prior.
    DirPrior(DirPrior),
}

impl StoredScorer {
    /// Fit `kind` to `(path, produced_a_finding)` pairs.
    ///
    /// Both kinds take the same corpus and record the same ruleset fingerprint,
    /// because both are labelled by what the rules happened to fire on — a
    /// model of either kind stops describing the tree the moment that changes.
    pub fn fit(kind: ScorerKind, samples: &[(String, bool)], cfg: &TrainConfig) -> Self {
        match kind {
            ScorerKind::PathHmm => StoredScorer::PathHmm(train(samples, cfg)),
            ScorerKind::DirPrior => {
                StoredScorer::DirPrior(DirPrior::fit(samples).with_ruleset(&cfg.ruleset))
            }
        }
    }

    /// Which kind this is.
    pub fn kind(&self) -> ScorerKind {
        match self {
            StoredScorer::PathHmm(_) => ScorerKind::PathHmm,
            StoredScorer::DirPrior(_) => ScorerKind::DirPrior,
        }
    }

    /// Borrow it as a scorer.
    pub fn as_scorer(&self) -> &dyn PathScorer {
        match self {
            StoredScorer::PathHmm(m) => m,
            StoredScorer::DirPrior(p) => p,
        }
    }

    /// Take it as an owned scorer, for handing to a scan.
    pub fn into_scorer(self) -> Box<dyn PathScorer> {
        match self {
            StoredScorer::PathHmm(m) => Box::new(m),
            StoredScorer::DirPrior(p) => Box::new(p),
        }
    }

    /// How many paths it was fitted on.
    pub fn observations(&self) -> u64 {
        match self {
            StoredScorer::PathHmm(m) => m.observations,
            StoredScorer::DirPrior(p) => p.observations,
        }
    }
}

impl<'de> Deserialize<'de> for StoredScorer {
    /// Accepts the tagged form, or an untagged document as the one kind that
    /// existed before the tag did.
    ///
    /// # Rust notes
    ///
    /// `#[serde(untagged)]` buffers the input and tries each variant in order,
    /// which is what lets the fallback be a declaration rather than a
    /// hand-written retry — and keeps it working for any self-describing
    /// format, not just JSON. `Tagged` mirrors [`StoredScorer`]'s variants
    /// because a type cannot both derive `Deserialize` and hand-write it; the
    /// mirror is the price of the custom impl, and the `From` below is what
    /// keeps the two from drifting silently.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "kebab-case")]
        enum Tagged {
            PathHmm(PathModel),
            DirPrior(DirPrior),
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Compat {
            Tagged(Tagged),
            /// No `kind` field: written before there was more than one.
            Legacy(PathModel),
        }

        Ok(match Compat::deserialize(d)? {
            Compat::Tagged(Tagged::PathHmm(m)) | Compat::Legacy(m) => StoredScorer::PathHmm(m),
            Compat::Tagged(Tagged::DirPrior(p)) => StoredScorer::DirPrior(p),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<(String, bool)> {
        (0..30)
            .flat_map(|i| {
                [
                    (format!("/srv/app/secrets/k{i}.env"), true),
                    (format!("/srv/app/docs/d{i}.md"), false),
                ]
            })
            .collect()
    }

    #[test]
    fn every_kind_round_trips_through_its_tag() {
        let cfg = TrainConfig {
            ruleset: "abc123".into(),
            ..TrainConfig::default()
        };
        for &kind in ScorerKind::ALL {
            let fitted = StoredScorer::fit(kind, &corpus(), &cfg);
            assert_eq!(fitted.kind(), kind);
            assert_eq!(fitted.as_scorer().name(), kind.as_str());
            assert_eq!(fitted.as_scorer().ruleset(), "abc123");

            let json = serde_json::to_value(&fitted).unwrap();
            assert_eq!(json["kind"], kind.as_str(), "the tag is the scorer's name");

            let back: StoredScorer = serde_json::from_value(json).unwrap();
            assert_eq!(back.kind(), kind);
            let p = "/srv/app/secrets/new.env";
            assert!((back.as_scorer().score(p) - fitted.as_scorer().score(p)).abs() < 1e-12);
        }
    }

    #[test]
    fn an_untagged_document_still_loads_as_the_kind_it_was() {
        // Exactly what a pre-tag catalog holds: a bare PathModel.
        let model = train(&corpus(), &TrainConfig::default());
        let legacy = serde_json::to_value(&model).unwrap();
        assert!(legacy.get("kind").is_none(), "the old form has no tag");

        let loaded: StoredScorer = serde_json::from_value(legacy).unwrap();
        assert_eq!(loaded.kind(), ScorerKind::PathHmm);
        let p = "/srv/app/secrets/new.env";
        assert!((loaded.as_scorer().score(p) - model.score(p)).abs() < 1e-12);
    }

    #[test]
    fn a_document_that_is_neither_kind_nor_legacy_is_an_error() {
        let junk = serde_json::json!({ "nonsense": true });
        assert!(serde_json::from_value::<StoredScorer>(junk).is_err());
    }

    #[test]
    fn kinds_parse_from_what_a_user_would_type() {
        use std::str::FromStr;
        assert_eq!(ScorerKind::from_str("dir-prior"), Ok(ScorerKind::DirPrior));
        assert_eq!(ScorerKind::from_str("DIR_PRIOR"), Ok(ScorerKind::DirPrior));
        assert_eq!(ScorerKind::from_str("hmm"), Ok(ScorerKind::PathHmm));
        assert!(ScorerKind::from_str("neural-net").is_err());
    }
}
