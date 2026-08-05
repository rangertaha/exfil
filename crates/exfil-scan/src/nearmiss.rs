//! Is one name a near-miss of another?
//!
//! Two scanners ask this: [`typosquat`](crate::typosquat) about domains against
//! a brand list, and [`supply`](crate::supply) about dependencies against a
//! popular-package list. It is the same question — *does this name impersonate
//! that one?* — and it was answered by two copies of the same
//! dynamic-programming routine that had drifted apart.
//!
//! The drift was not cosmetic. The domain copy skipped protected names shorter
//! than four characters and folded homoglyphs before comparing; the package
//! copy did neither. So `g00gle.com` was caught but `l0dash` was not, and the
//! package check had no floor at all under a three-character name like `vue` —
//! whose one-edit neighbourhood contains `vuex`, the official Vue state
//! library. One implementation, one set of guards, both callers.
//!
//! What this module deliberately does *not* decide is whether the candidate is
//! legitimate. "One edit from `react`" is a fact about spelling; "and therefore
//! an attack" is a judgement that needs to know `preact` is a real framework
//! with millions of installs. That knowledge belongs to the caller's own
//! allowlist, next to the list it is protecting.

/// Protected names shorter than this are not checked at all.
///
/// At three characters the one-edit neighbourhood of a name is enormous and
/// almost entirely legitimate — `vue` alone catches `vuex`, and `syn` catches
/// `sync`. Below this length an edit-distance test reports coincidence, not
/// impersonation.
pub const MIN_PROTECTED_LEN: usize = 4;

/// Whether `candidate` impersonates `protected`: a homoglyph or single-edit
/// variant, and not the protected name itself.
///
/// Says nothing about whether `candidate` is a package or domain someone
/// legitimately owns — see the module docs.
pub fn impersonates(candidate: &str, protected: &str) -> bool {
    if protected.chars().count() < MIN_PROTECTED_LEN || candidate == protected {
        return false;
    }
    // Homoglyph folding first: it catches multi-character digit swaps
    // (`g00gle` → `google`, `l0dash` → `lodash`) that are two or more edits
    // away and so invisible to the distance test.
    if fold_homoglyphs(candidate) == protected {
        return true;
    }
    distance(candidate, protected) == 1
}

/// Fold common homoglyph substitutions to a canonical letter form: lookalike
/// digits to letters, and the `rn`/`vv` ligature tricks.
pub fn fold_homoglyphs(s: &str) -> String {
    let s = s.replace("rn", "m").replace("vv", "w");
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '9' => 'g',
            other => other,
        })
        .collect()
}

/// Optimal string alignment distance (Damerau-Levenshtein restricted to
/// adjacent transpositions) between `a` and `b`.
///
/// Transpositions count as one edit, which matters because they are what typing
/// errors actually look like: `lodahs` for `lodash`, `reqeusts` for `requests`.
/// Inputs are names, so the O(n·m) table costs nothing worth optimizing.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_counts_a_transposition_as_one_edit() {
        assert_eq!(distance("lodash", "lodash"), 0);
        assert_eq!(distance("lodahs", "lodash"), 1);
        assert_eq!(distance("reqeusts", "requests"), 1);
        assert_eq!(distance("lodas", "lodash"), 1);
        assert_eq!(distance("banana", "lodash"), 5);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("abc", ""), 3);
    }

    #[test]
    fn single_edits_and_homoglyphs_impersonate() {
        assert!(impersonates("paypa1", "paypal"));
        assert!(impersonates("g00gle", "google"));
        assert!(impersonates("lodahs", "lodash"));
        // Folding now reaches the package check too, which had no such test.
        assert!(impersonates("l0dash", "lodash"));
    }

    #[test]
    fn the_name_itself_never_impersonates_itself() {
        assert!(!impersonates("lodash", "lodash"));
        assert!(!impersonates("google", "google"));
    }

    /// The floor exists because a three-character name's one-edit neighbourhood
    /// is full of legitimate packages — `vuex` is the official Vue state
    /// library, not an attack on `vue`.
    #[test]
    fn short_protected_names_are_not_checked() {
        assert_eq!(distance("vuex", "vue"), 1, "it really is one edit away");
        assert!(!impersonates("vuex", "vue"));
        assert!(!impersonates("sync", "syn"));
    }

    #[test]
    fn unrelated_names_do_not_impersonate() {
        assert!(!impersonates("example", "google"));
        assert!(!impersonates("banana", "lodash"));
    }
}
