//! What the model actually observes: a path reduced to a token sequence, and
//! the vocabulary that indexes those tokens.
//!
//! This is the model's inductive bias, and it is deliberately small. A path is
//! split into components, lowercased, and its filename replaced by its
//! extension — everything the model can generalise from, and nothing it can
//! only memorise.

use std::collections::BTreeMap;

/// Vocabulary index reserved for tokens the model never saw in training.
pub const UNK: usize = 0;

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

/// The `vocab_cap` most frequent tokens, indexed from 1 ([`UNK`] holds 0).
pub fn build_vocab(samples: &[(String, bool)], cap: usize) -> BTreeMap<String, usize> {
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
