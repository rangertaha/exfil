//! Fitting finding lines to a window.
//!
//! Findings carry absolute paths and arbitrary source snippets, so a single hit
//! can run to several hundred columns and wrap into an unreadable block. These
//! helpers lay one out in a fixed number of columns: the location gives up its
//! head (the shared boilerplate) and the snippet gives up its tail, so the file
//! name, line, severity and rule all survive.
//!
//! Fitting is a *display* decision and never applies to machine output — the
//! JSON/JUnit/SARIF reporters and piped text are always written in full, since
//! a truncated path would silently corrupt whatever consumes it.
//!
//! This lives here rather than in the CLI because two renderers need the same
//! layout — the live scan feed and the text report — and they must not drift.

use exfil_core::{Match, Severity};

/// The widest line display output should produce.
pub const MAX_WIDTH: usize = 80;

/// Below this there is no useful layout left, so stop shrinking and let the
/// terminal wrap — a 20-column window is not a case worth optimizing for.
pub const MIN_WIDTH: usize = 40;

/// A finding line always keeps at least this much snippet; below it the line
/// shows a location and nothing about what was actually found.
const MIN_SNIPPET: usize = 16;

/// A rule name longer than this is elided — no built-in rule comes close, but
/// feed-derived rules (YARA, gitleaks) can carry very long generated names.
const MAX_RULE: usize = 28;

/// Character count. Every width decision here is in terminal cells, and byte
/// length would over-truncate any line carrying non-ASCII (the PII masks use
/// `•`, and snippets come from arbitrary source files).
pub fn width_of(s: &str) -> usize {
    s.chars().count()
}

/// Take the last `max` characters of `s`, marking the cut with a leading `…`.
/// For paths, where the tail (the file name) carries the information.
pub fn elide_left(s: &str, max: usize) -> String {
    if width_of(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let tail: String = s.chars().skip(width_of(s) - keep).collect();
    format!("…{tail}")
}

/// Take the first `max` characters of `s`, marking the cut with a trailing `…`.
/// For snippets and rule names, which read left-to-right.
pub fn elide_right(s: &str, max: usize) -> String {
    if width_of(s) <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let head: String = s.chars().take(keep).collect();
    format!("{head}…")
}

/// Short severity tag for a finding line, or `None` when the rule carries no
/// severity so those lines keep their original shape.
pub fn severity_tag(sev: Option<Severity>) -> Option<&'static str> {
    Some(sev?.tag())
}

/// One finding as `path:line:col SEV [rule] snippet`, at full length. The
/// location stays at the front so editors and `grep` can parse it.
pub fn match_line(m: &Match) -> String {
    match severity_tag(m.severity) {
        Some(tag) => format!(
            "{}:{}:{} {tag} [{}] {}",
            m.path, m.line, m.col, m.rule, m.snippet
        ),
        None => format!("{}:{}:{} [{}] {}", m.path, m.line, m.col, m.rule, m.snippet),
    }
}

/// The pieces of a finding line, each already fitted to `width`:
/// `(location, tag, rule, snippet)`. Split out so a colored renderer can wrap
/// the tag in escapes without re-deciding the layout.
pub fn fit_parts(m: &Match, width: usize) -> (String, Option<&'static str>, String, String) {
    let tag = severity_tag(m.severity);
    let rule = elide_right(&m.rule, MAX_RULE);
    let loc = format!("{}:{}:{}", m.path, m.line, m.col);

    // Everything that is not the location or the snippet: the severity tag and
    // the bracketed rule, each with its separating space.
    let fixed = tag.map(|t| width_of(t) + 1).unwrap_or(0) + width_of(&rule) + 3;
    let budget = width.saturating_sub(fixed);

    // The location gives up room first, down to a floor — the file name and
    // line matter more than any single snippet, but not more than all of it.
    // The floor still cannot exceed the budget, or a narrow window would push
    // the line back over the width it was asked to fit.
    let max_loc = budget
        .saturating_sub(MIN_SNIPPET + 1)
        .max(MIN_SNIPPET)
        .min(budget);
    let loc = elide_left(&loc, max_loc);

    // Whatever the location left, minus its separating space. Under two columns
    // there is no room for even one character plus the `…`, so drop the snippet
    // rather than print a lone ellipsis that says nothing.
    let room = budget.saturating_sub(width_of(&loc) + 1);
    let snippet = if m.snippet.is_empty() || room < 2 {
        String::new()
    } else {
        elide_right(&m.snippet, room)
    };
    (loc, tag, rule, snippet)
}

/// Like [`match_line`], but fitted to `width` columns.
pub fn fitted_line(m: &Match, width: usize) -> String {
    let (loc, tag, rule, snippet) = fit_parts(m, width);
    let mut out = loc;
    if let Some(tag) = tag {
        out.push(' ');
        out.push_str(tag);
    }
    out.push_str(&format!(" [{rule}]"));
    if !snippet.is_empty() {
        out.push(' ');
        out.push_str(&snippet);
    }
    out
}

/// One finding line: fitted when a width is given, full length otherwise.
pub fn line(m: &Match, width: Option<usize>) -> String {
    match width {
        Some(width) => fitted_line(m, width),
        None => match_line(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit() -> Match {
        Match {
            rule: "aws-access-key-id".into(),
            path: "/a/very/deeply/nested/directory/tree/that/goes/on/config.yaml".into(),
            line: 2,
            col: 5,
            snippet: "password = \"https://user:hunter2@example.com/some/long/path\"".into(),
            severity: Some(Severity::Critical),
            cwe: None,
            cve: None,
        }
    }

    #[test]
    fn fitted_line_never_exceeds_the_window() {
        for width in [MIN_WIDTH, 60, MAX_WIDTH, 200] {
            let line = fitted_line(&hit(), width);
            assert!(
                width_of(&line) <= width,
                "width {width}: {} cols — {line}",
                width_of(&line)
            );
        }
    }

    #[test]
    fn fitted_line_keeps_the_file_name_line_and_rule() {
        let line = fitted_line(&hit(), MAX_WIDTH);
        assert!(line.starts_with('…'), "{line}");
        assert!(line.contains("config.yaml:2:5"), "{line}");
        assert!(line.contains("CRIT"), "{line}");
        assert!(line.contains("[aws-access-key-id]"), "{line}");
    }

    #[test]
    fn fitted_line_is_untouched_when_it_already_fits() {
        let mut m = hit();
        m.path = "a.env".into();
        m.rule = "aws".into();
        m.snippet = "hit".into();
        assert_eq!(fitted_line(&m, MAX_WIDTH), match_line(&m));
    }

    #[test]
    fn fitted_line_elides_a_runaway_rule_name() {
        let mut m = hit();
        m.path = "a.env".into();
        m.rule = "y".repeat(120);
        let line = fitted_line(&m, MAX_WIDTH);
        assert!(width_of(&line) <= MAX_WIDTH, "{line}");
        assert!(line.contains('…'), "{line}");
    }

    #[test]
    fn fitting_counts_characters_not_bytes() {
        // PII snippets carry `•` masks (3 bytes each); a byte-length cap would
        // truncate them to a third of the room they actually occupy.
        let mut m = hit();
        m.path = "a.env".into();
        m.snippet = "•".repeat(200);
        let line = fitted_line(&m, MAX_WIDTH);
        assert!(width_of(&line) <= MAX_WIDTH, "{}", width_of(&line));
        assert!(
            width_of(&line) > MAX_WIDTH / 2,
            "snippet was over-truncated"
        );
    }

    #[test]
    fn line_without_a_width_is_the_full_match_line() {
        assert_eq!(line(&hit(), None), match_line(&hit()));
    }

    #[test]
    fn elide_helpers_mark_the_cut_and_respect_the_cap() {
        assert_eq!(elide_left("abcdef", 4), "…def");
        assert_eq!(elide_left("abc", 4), "abc");
        assert_eq!(elide_right("abcdef", 4), "abc…");
        assert_eq!(elide_right("abc", 4), "abc");
    }

    #[test]
    fn match_line_shape_matches_the_documented_format() {
        let mut m = hit();
        m.path = "a.env".into();
        m.rule = "aws".into();
        m.snippet = "x".into();
        assert_eq!(match_line(&m), "a.env:2:5 CRIT [aws] x");
        m.severity = None;
        assert_eq!(match_line(&m), "a.env:2:5 [aws] x");
    }
}
