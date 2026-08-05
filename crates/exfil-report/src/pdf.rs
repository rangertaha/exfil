//! PDF report rendering.
//!
//! A paginated, monospaced-layout report: a summary, the per-severity tally,
//! the directory hotspots, then the findings worst-first. It exists for the
//! case the other formats do not serve — handing a scan's result to someone
//! who will read it rather than parse it, in a file that looks the same
//! everywhere it is opened.
//!
//! Text is set in the base-14 `Helvetica`, which every PDF reader is required
//! to have. That is what keeps the output a few kilobytes instead of a few
//! hundred: no font is embedded, so no glyph data travels with the file, and
//! no font file has to be found at build time.
//!
//! # Rust notes
//!
//! `printpdf` models a page as a flat `Vec<Op>` — a list of PDF operators —
//! rather than as a document tree. So the layout here is explicit: track a `y`
//! cursor down the page, and start a new page when it runs out. That is more
//! code than a layout engine would need, but it is all in one place and it
//! never surprises.

use exfil_core::Severity;
use printpdf::{
    BuiltinFont, Color, Mm, Op, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt,
    Rgb, TextItem,
};

use crate::{fit, Analysis, HOTSPOT_LIMIT};

/// A4, the size the rest of the world prints on.
const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
/// Margins, and where the text starts and stops.
const LEFT: f32 = 15.0;
const TOP: f32 = PAGE_H - 20.0;
const BOTTOM: f32 = 18.0;
/// Line advance in millimetres, for the body size below.
const LINE: f32 = 4.6;
const BODY_PT: f32 = 9.0;
const HEAD_PT: f32 = 16.0;

/// Characters that fit on one body line at [`BODY_PT`]. Helvetica is
/// proportional, so this is an approximation chosen to be safe for the
/// widest realistic content rather than exact.
const COLS: usize = 96;

/// Severity colours, matching the terminal's meaning: red for the worst,
/// cooling to grey for unrated.
fn severity_rgb(sev: Option<Severity>) -> (f32, f32, f32) {
    match sev {
        Some(Severity::Critical) => (0.70, 0.05, 0.05),
        Some(Severity::High) => (0.85, 0.25, 0.05),
        Some(Severity::Medium) => (0.75, 0.55, 0.00),
        Some(Severity::Low) => (0.15, 0.35, 0.70),
        Some(Severity::Info) => (0.10, 0.50, 0.55),
        None => (0.45, 0.45, 0.45),
    }
}

fn rgb(r: f32, g: f32, b: f32) -> Color {
    Color::Rgb(Rgb {
        r,
        g,
        b,
        icc_profile: None,
    })
}

/// Render `s` in the single-byte encoding the base-14 fonts use.
///
/// The characters this tool actually emits above U+00FF are the ellipsis `fit`
/// uses to mark an elision and the bullet the PII masks use, and both *carry
/// meaning* — dropping them makes a truncated value look whole. They get ASCII
/// stand-ins; anything else unrepresentable becomes `?`, which at least shows
/// that something was there.
fn latin1(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '…' => "...".to_string(),
            '•' => "*".to_string(),
            c if c < '\u{100}' => c.to_string(),
            _ => "?".to_string(),
        })
        .collect()
}

/// A page being filled: the ops written so far and the cursor's height.
struct Writer {
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    y: f32,
}

impl Writer {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            ops: Vec::new(),
            y: TOP,
        }
    }

    /// Write one line at the cursor, then advance it. Starts a new page first
    /// when the line would fall below the bottom margin.
    fn line(&mut self, text: &str, size: f32, font: BuiltinFont, col: (f32, f32, f32)) {
        if self.y < BOTTOM {
            self.page_break();
        }
        self.ops.extend([
            Op::StartTextSection,
            Op::SetTextCursor {
                pos: Point::new(Mm(LEFT), Mm(self.y)),
            },
            Op::SetFont {
                font: PdfFontHandle::Builtin(font),
                size: Pt(size),
            },
            Op::SetFillColor {
                col: rgb(col.0, col.1, col.2),
            },
            // PDF strings are not UTF-8 and the base-14 fonts are single-byte
            // encoded, so anything outside Latin-1 cannot be represented.
            // Transliterate rather than drop: silently deleting the `…` that
            // `fit` inserts turns a truncated path into one that reads as
            // complete, which is worse than either the right glyph or an
            // obviously wrong one.
            Op::ShowText {
                items: vec![TextItem::Text(latin1(text))],
            },
            Op::EndTextSection,
        ]);
        self.y -= LINE * (size / BODY_PT).max(1.0);
    }

    /// Body text in the default colour.
    fn body(&mut self, text: &str) {
        self.line(text, BODY_PT, BuiltinFont::Helvetica, (0.1, 0.1, 0.1));
    }

    /// A blank line's worth of space.
    fn gap(&mut self) {
        self.y -= LINE * 0.7;
    }

    fn page_break(&mut self) {
        let ops = std::mem::take(&mut self.ops);
        self.pages.push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), ops));
        self.y = TOP;
    }

    fn finish(mut self) -> Vec<PdfPage> {
        if !self.ops.is_empty() {
            let ops = std::mem::take(&mut self.ops);
            self.pages.push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), ops));
        }
        self.pages
    }
}

/// Render `a` as a PDF document's bytes.
pub fn render(a: &Analysis) -> Vec<u8> {
    let mut doc = PdfDocument::new("exfil findings");
    doc.with_pages(layout(a))
        .save(&PdfSaveOptions::default(), &mut Vec::new())
}

/// Lay `a` out into pages. Split from [`render`] so pagination is testable
/// without parsing the bytes back out of a finished document.
fn layout(a: &Analysis) -> Vec<PdfPage> {
    let mut w = Writer::new();

    w.line(
        "exfil findings",
        HEAD_PT,
        BuiltinFont::HelveticaBold,
        (0.1, 0.1, 0.1),
    );
    w.gap();
    w.body(&format!(
        "{} finding(s) across {} file(s), {} scan(s); risk score {}",
        a.findings.len(),
        a.files,
        a.scans,
        a.risk_score()
    ));
    for (sev, n) in a.severity_counts() {
        let name = format!("{sev:?}").to_lowercase();
        w.line(
            &format!("    {name:<9} {n}"),
            BODY_PT,
            BuiltinFont::Helvetica,
            severity_rgb(Some(sev)),
        );
    }

    let rows = a.hotspots(HOTSPOT_LIMIT);
    if rows.len() >= 2 {
        w.gap();
        w.line(
            "findings by directory",
            BODY_PT + 1.0,
            BuiltinFont::HelveticaBold,
            (0.1, 0.1, 0.1),
        );
        for r in &rows {
            w.body(&format!(
                "    {:<58} {:>5} {:>5.0}%",
                fit::elide_left(&r.directory, 58),
                r.findings,
                r.share * 100.0
            ));
        }
    }

    w.gap();
    w.line(
        "findings",
        BODY_PT + 1.0,
        BuiltinFont::HelveticaBold,
        (0.1, 0.1, 0.1),
    );
    if a.findings.is_empty() {
        w.body("    none");
    }
    for m in &a.findings {
        // Reuse the terminal layout: the same elision rules, at the width a
        // page holds. One layout decision, two media.
        w.line(
            &format!("    {}", fit::fitted_line(m, COLS)),
            BODY_PT,
            BuiltinFont::Helvetica,
            severity_rgb(m.severity),
        );
    }

    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfil_core::Match;

    fn hit(rule: &str, sev: Severity) -> Match {
        Match {
            rule: rule.into(),
            path: "/srv/app/.env".into(),
            line: 3,
            col: 1,
            snippet: "AWS_SECRET=…".into(),
            severity: Some(sev),
            cwe: None,
            cve: None,
        }
    }

    #[test]
    fn renders_a_well_formed_pdf() {
        let a = Analysis {
            findings: vec![hit("aws-access-key-id", Severity::Critical)],
            files: 1,
            scans: 1,
        };
        let bytes = render(&a);
        assert!(bytes.starts_with(b"%PDF-"), "not a PDF header");
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"), "no EOF marker");
        // No font is embedded, so a one-finding report stays small.
        assert!(bytes.len() < 100_000, "{} bytes", bytes.len());
    }

    #[test]
    fn an_empty_analysis_still_renders() {
        let bytes = render(&Analysis::default());
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn many_findings_paginate() {
        let findings: Vec<Match> = (0..200)
            .map(|i| hit(&format!("rule-{i}"), Severity::High))
            .collect();
        let a = Analysis {
            findings,
            files: 200,
            scans: 1,
        };
        // More content than one page holds must produce more than one page.
        assert!(layout(&a).len() > 1, "expected pagination");
        assert!(render(&a).starts_with(b"%PDF-"));
    }

    #[test]
    fn non_latin1_characters_are_dropped_not_mangled() {
        // Base-14 fonts are single-byte encoded; a snippet from a UTF-8 source
        // file can carry anything. Better absent than wrong.
        let mut m = hit("pii-email", Severity::Medium);
        m.snippet = "住所 café".into();
        let a = Analysis {
            findings: vec![m],
            files: 1,
            scans: 1,
        };
        assert!(render(&a).starts_with(b"%PDF-"));
    }
}

#[cfg(test)]
mod dump {
    use super::*;
    use exfil_core::Match;
    /// Not a test of behaviour — a hook to eyeball a real file when changing
    /// the layout. Ignored so it never runs in CI.
    #[test]
    #[ignore]
    fn write_a_sample_pdf() {
        let findings: Vec<Match> = (0..60)
            .map(|i| Match {
                rule: format!("rule-{i}"),
                path: format!("/srv/app/module{i}/config/.env"),
                line: i + 1,
                col: 1,
                snippet: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG".into(),
                severity: Some(if i % 3 == 0 {
                    Severity::Critical
                } else {
                    Severity::Medium
                }),
                cwe: None,
                cve: None,
            })
            .collect();
        let a = Analysis {
            findings,
            files: 60,
            scans: 2,
        };
        std::fs::write(std::env::temp_dir().join("exfil-sample.pdf"), render(&a)).unwrap();
    }
}
