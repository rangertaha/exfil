//! Locating regex matches in a file's text.
//!
//! Every pattern scanner does the same three things before it can build a
//! [`Match`](exfil_core::Match): split the content into lines, find the pattern
//! in each, and convert the byte offset it gets back into a 1-based line and
//! column. That is one behaviour, so it lives here once rather than in each
//! scanner.
//!
//! # Why this is not just tidiness
//!
//! The copies had already drifted into a detection hole. The PII scanner
//! iterated every match on a line; the regex scanner — the primary secrets
//! detector — called `Regex::find`, which returns only the *first*. A line
//! holding two credentials reported one. Since a minified bundle is a single
//! line, one such file reported at most one finding per rule no matter how many
//! keys it contained.
//!
//! Line-oriented matching is a deliberate constraint, not an accident: it keeps
//! patterns from spanning a whole file and gives every finding a location a
//! human or an editor can jump to. [`hits`] is where that constraint is applied.

use regex::Regex;

/// One located regex match.
#[derive(Debug, Clone, Copy)]
pub struct Hit<'t> {
    /// 1-based line the match starts on.
    pub line: u32,
    /// 1-based column, counted in characters — not bytes, so a match after any
    /// non-ASCII text still points where a reader would put their finger.
    pub col: u32,
    /// The matched text itself.
    pub text: &'t str,
    /// The whole line the match sits on, as written.
    pub line_text: &'t str,
}

/// Every match of `re` in `content`, in document order.
///
/// Every match: a line with three hits yields three, and the caller decides
/// whether to keep them all. Reporting one and dropping the rest is not a
/// scanner's decision to make silently.
pub fn hits<'t>(content: &'t str, re: &'t Regex) -> impl Iterator<Item = Hit<'t>> + 't {
    content
        .lines()
        .enumerate()
        .flat_map(move |(idx, line_text)| {
            re.find_iter(line_text).map(move |m| Hit {
                line: idx as u32 + 1,
                col: line_text[..m.start()].chars().count() as u32 + 1,
                text: m.as_str(),
                line_text,
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_re() -> Regex {
        Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()
    }

    #[test]
    fn locates_a_match_by_line_and_column() {
        let re = key_re();
        let found: Vec<Hit> = hits("first\nkey = AKIA0123456789ABCDEF\n", &re).collect();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].line, found[0].col), (2, 7));
        assert_eq!(found[0].text, "AKIA0123456789ABCDEF");
        assert_eq!(found[0].line_text, "key = AKIA0123456789ABCDEF");
    }

    /// The regression this module exists for: `Regex::find` stopped at the
    /// first hit on a line, so a second credential beside it went unreported.
    #[test]
    fn reports_every_match_on_a_line() {
        let re = key_re();
        let found: Vec<Hit> =
            hits("k1=AKIA0123456789ABCDEF k2=AKIAZZZZZZZZZZZZZZZZ\n", &re).collect();
        assert_eq!(found.len(), 2, "both keys: {found:?}");
        assert_eq!(found[0].col, 4);
        assert_eq!(found[1].col, 28);
        assert_eq!(found[1].text, "AKIAZZZZZZZZZZZZZZZZ");
    }

    /// A minified bundle is one line. Line-oriented matching must still find
    /// every key in it, or the whole file reports a single finding.
    #[test]
    fn a_single_line_file_still_yields_every_match() {
        let re = key_re();
        let keys: Vec<String> = (0..5).map(|i| format!("AKIA{:016}", i)).collect();
        let content = format!("var c={{{}}};", keys.join(" "));
        let found: Vec<Hit> = hits(&content, &re).collect();
        assert_eq!(found.len(), 5);
        assert!(found.iter().all(|h| h.line == 1));
    }

    #[test]
    fn columns_count_characters_not_bytes() {
        let re = key_re();
        // Four 3-byte characters before the match: column 5, not column 13.
        let found: Vec<Hit> = hits("••••AKIA0123456789ABCDEF", &re).collect();
        assert_eq!(found[0].col, 5);
    }

    #[test]
    fn no_matches_yields_nothing() {
        let re = key_re();
        assert_eq!(hits("ordinary prose\nand more\n", &re).count(), 0);
        assert_eq!(hits("", &re).count(), 0);
    }
}
