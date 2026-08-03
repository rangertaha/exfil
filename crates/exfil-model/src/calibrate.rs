//! Turning a likelihood ratio into a probability.
//!
//! A ratio between two chains ranks well and calibrates badly: on a corpus that
//! separates, the raw log-odds run into the hundreds and the scores pile up at
//! 0 and 1. Platt scaling fits a two-parameter logistic that rescales them, so
//! "0.7" can mean roughly seven in ten.
//!
//! The map is only ever *applied* here. Deciding what to fit it on — which is
//! where the honesty lives, since fitting on the model's own training data
//! would bake in the overconfidence it is meant to correct — belongs to the
//! trainer.

/// The identity calibration: pass the raw log-odds straight through.
pub fn identity_platt() -> (f64, f64) {
    (1.0, 0.0)
}

/// The logistic function, guarded against overflow at the tails.
pub fn logistic(z: f64) -> f64 {
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
pub fn fit_platt(pairs: &[(f64, bool)]) -> (f64, f64) {
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
