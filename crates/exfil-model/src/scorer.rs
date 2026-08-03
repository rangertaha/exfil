//! The seam every consumer of a path model talks to.
//!
//! Ranking a scan needs one thing from a model — `P(finding | path)` — and
//! everything else it might offer (how it was fitted, what it was trained
//! under, how to explain a score) is either optional or specific to one
//! implementation. This trait is that one thing, plus the two questions a
//! caller has to be able to ask about an answer before acting on it.
//!
//! There are two implementations today and they disagree about which is
//! better, which is the point: [`PathModel`](crate::PathModel) is a sequence
//! model over path tokens, [`DirPrior`](crate::DirPrior) is a frequency prior
//! over the parent directory that takes thirty lines. On some corpora the
//! second ties the first — [`eval`](crate::eval) exists to find out — and
//! "then use the cheap one" should be a choice a user can make rather than a
//! result they can only read about.
//!
//! # Rust notes
//!
//! `Send + Sync` is required because the ranked scan scores candidates from
//! several threads. The compiler proves it: a scorer holding non-thread-safe
//! state simply will not go into a [`ScanPlan`](../../exfil_engine/plan/struct.ScanPlan.html).

/// Something that can say how likely a path is to carry a finding.
pub trait PathScorer: Send + Sync {
    /// Stable identifier, used in reports and to name a stored model.
    fn name(&self) -> &str;

    /// `P(finding | path)`, in `0.0..=1.0`.
    ///
    /// A scorer that has nothing to say about a path should return its base
    /// rate rather than 0 or 0.5 — "I don't know" is the corpus average, not
    /// "no" and not a coin flip.
    fn score(&self, path: &str) -> f64;

    /// The unconditional finding rate this scorer was fitted on: what
    /// [`score`](Self::score) falls back to when a path says nothing.
    fn base_rate(&self) -> f64;

    /// Fingerprint of the ruleset whose findings labelled this scorer's
    /// training data, or empty when nothing was recorded.
    ///
    /// A scorer's labels are "what those rules happened to fire on", so a
    /// scorer stops describing a tree the moment the ruleset moves — whatever
    /// algorithm produced it. Empty means "unknown", which never invalidates.
    fn ruleset(&self) -> &str {
        ""
    }

    /// Whether [`score`](Self::score) may be read as a probability, or only as
    /// a rank.
    ///
    /// Ranking is indifferent to this — a monotone rescaling cannot change an
    /// order — but anything that *sums* scores is not. Defaults to `false`, so
    /// a new scorer has to claim calibration deliberately rather than inherit
    /// the claim by omission.
    fn has_calibration(&self) -> bool {
        false
    }

    /// Per-component evidence for a path: how much each pushed the score
    /// toward a finding (positive) or away from it (negative), in log-odds.
    ///
    /// Empty when a scorer cannot decompose its answer, which is honest —
    /// better than a made-up attribution.
    fn explain(&self, _path: &str) -> Vec<(String, f64)> {
        Vec::new()
    }
}
