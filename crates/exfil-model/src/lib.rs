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
//! # The layers
//!
//! Each of these is usable on its own, and each knows only about the one below
//! it — so a different featurization, a different sequence model, or a
//! different calibration is a change to one file rather than to the crate:
//!
//! | Module | What it owns |
//! |---|---|
//! | [`tokens`] | What the model observes — a path reduced to tokens, and their vocabulary |
//! | [`hmm`] | A scaled Markov chain: forward-backward, Viterbi, Baum-Welch. Knows nothing about paths |
//! | [`calibrate`] | Turning a likelihood ratio into a probability |
//! | [`model`] | The classifier: two chains, a prior, a calibration — and the training that fits them |
//! | [`scorer`] | The [`PathScorer`] seam every consumer talks to |
//! | [`dir_prior`] | The other scorer: a frequency prior over the parent directory |
//! | [`eval`] | Does any of it help? Recall-at-budget, measured out of sample |
//!
//! # Rust notes
//!
//! Matrices are `Vec<Vec<f64>>` rather than a flat array with index maths: the
//! sizes here are tiny (states² and states × vocab) and the clarity is worth
//! more than the cache locality.

pub mod calibrate;
pub mod dir_prior;
pub mod eval;
pub mod hmm;
pub mod model;
pub mod scorer;
pub mod tokens;

// The crate's own surface, flattened. Callers say `exfil_model::PathModel`,
// not `exfil_model::model::PathModel` — the module layout is how the crate is
// built, not how it is used.
pub use dir_prior::DirPrior;
pub use hmm::Chain;
pub use model::{train, PathModel, TrainConfig};
pub use scorer::PathScorer;
pub use tokens::{tokenize, UNK};
