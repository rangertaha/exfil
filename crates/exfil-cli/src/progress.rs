//! Live scan progress rendering.
//!
//! The engine reports [`ScanEvent`]s over a channel; this module drains that
//! channel and renders it one of two ways:
//!
//! - **Plain** — when stdout is not a terminal (pipes, CI, tests): matches are
//!   printed as `path:line:col [rule] snippet` lines, nothing else.
//! - **Ratatui** — on a real terminal: an *inline viewport* shows a gauge with
//!   file counts while match lines are inserted above it, so they stay in the
//!   terminal's scrollback after the bar disappears.
//!
//! The event-accounting ([`ProgressState`]) and rendering are split from the
//! thread/terminal plumbing so both can be tested without a real TTY.
//!
//! # Rust notes
//!
//! The renderer runs on its own OS thread (`std::thread::spawn`) so drawing
//! never blocks the async scan. `recv_timeout` gives the loop a heartbeat: it
//! wakes at least every 100 ms to redraw even when no events arrive, and exits
//! when the channel disconnects (the engine dropping its sender *is* the
//! shutdown signal — no flag needed).

use std::io::{IsTerminal, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use exfil_core::{Match, Severity};
use exfil_engine::ScanEvent;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Gauge, Widget};
use ratatui::{Terminal, TerminalOptions, Viewport};

/// Short severity tag shown in a finding line, or `None` when the rule carries
/// no severity so those lines keep their original shape. Delegates to
/// [`Severity::tag`] for the canonical abbreviation.
fn severity_tag(sev: Option<Severity>) -> Option<&'static str> {
    Some(sev?.tag())
}

/// ANSI escape that colors a severity tag on a terminal (bright red for the
/// worst, cooling down to cyan for info).
fn severity_color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "\x1b[1;91m", // bold bright red
        Severity::High => "\x1b[91m",       // bright red
        Severity::Medium => "\x1b[33m",     // yellow
        Severity::Low => "\x1b[34m",        // blue
        Severity::Info => "\x1b[36m",       // cyan
    }
}

/// Format one match as plain text: `path:line:col SEV [rule] snippet`, with the
/// severity omitted when the rule has none. `path:line:col` stays at the front
/// so editors and `grep` can still parse it. Used for pipes, the TUI, and as
/// the base for the colored [`styled_line`].
pub fn match_line(m: &Match) -> String {
    match severity_tag(m.severity) {
        Some(tag) => format!(
            "{}:{}:{} {tag} [{}] {}",
            m.path, m.line, m.col, m.rule, m.snippet
        ),
        None => format!("{}:{}:{} [{}] {}", m.path, m.line, m.col, m.rule, m.snippet),
    }
}

/// Row style for a finding's severity in ratatui widgets — the live scan feed
/// and the TUI index — mirroring the ANSI colors used in plain output: bold
/// red for critical, cooling to gray for unrated rules.
pub fn severity_style(sev: Option<Severity>) -> Style {
    match sev {
        Some(Severity::Critical) => Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
        Some(Severity::High) => Style::default().fg(Color::Red),
        Some(Severity::Medium) => Style::default().fg(Color::Yellow),
        Some(Severity::Low) => Style::default().fg(Color::Blue),
        Some(Severity::Info) => Style::default().fg(Color::Cyan),
        None => Style::default().fg(Color::Gray),
    }
}

/// When to emit ANSI color, set once from the `--color` flag. `Auto` (the
/// default) detects a terminal and honors `NO_COLOR`.
#[derive(Clone, Copy)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

// Process-wide color choice: 0=auto, 1=always, 2=never. A plain atomic keeps
// `use_color()` callable from anywhere (including the render thread) without
// threading the choice through every signature.
static COLOR: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Record the `--color` choice for the rest of the run.
pub fn set_color_choice(choice: ColorChoice) {
    let v = match choice {
        ColorChoice::Auto => 0,
        ColorChoice::Always => 1,
        ColorChoice::Never => 2,
    };
    COLOR.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Whether to emit ANSI color. `always`/`never` force the answer; `auto` emits
/// color only when stdout is a terminal and `NO_COLOR` is unset (the de-facto
/// standard opt-out).
pub fn use_color() -> bool {
    match COLOR.load(std::sync::atomic::Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    }
}

/// Like [`match_line`], but colors the severity tag on a terminal. Falls back
/// to the plain line when color is disabled or the rule has no severity, so
/// piped and redirected output is never polluted with escape codes.
pub fn styled_line(m: &Match) -> String {
    match m.severity {
        Some(sev) if use_color() => {
            let tag = severity_tag(Some(sev)).unwrap_or("");
            let (color, reset) = (severity_color(sev), "\x1b[0m");
            format!(
                "{}:{}:{} {color}{tag}{reset} [{}] {}",
                m.path, m.line, m.col, m.rule, m.snippet
            )
        }
        _ => match_line(m),
    }
}

/// A one-line severity tally for a set of findings, worst-first and colored on
/// a terminal: `CRIT 2  HIGH 5  MED 1`. Returns `None` when nothing is rated,
/// so callers can skip an empty line. Zero-count severities are omitted.
pub fn severity_summary(findings: &[Match]) -> Option<String> {
    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let color = use_color();
    let parts: Vec<String> = order
        .into_iter()
        .filter_map(|sev| {
            let n = findings.iter().filter(|m| m.severity == Some(sev)).count();
            if n == 0 {
                return None;
            }
            let tag = severity_tag(Some(sev)).unwrap_or("");
            Some(if color {
                format!("{}{tag} {n}\x1b[0m", severity_color(sev))
            } else {
                format!("{tag} {n}")
            })
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("  "))
}

/// Per-severity match counts accumulated during one scan, indexed by rank
/// (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical). Returned by the renderer so
/// the caller can print an accurate breakdown of the matches it just streamed.
pub type SevCounts = [u64; 5];

/// Fold a match's severity into the running counts.
fn tally(counts: &mut SevCounts, sev: Option<Severity>) {
    let i = match sev {
        Some(Severity::Info) => 0,
        Some(Severity::Low) => 1,
        Some(Severity::Medium) => 2,
        Some(Severity::High) => 3,
        Some(Severity::Critical) => 4,
        None => return,
    };
    counts[i] += 1;
}

/// Format scan counts as `CRIT 2  HIGH 5`, worst-first and colored on a
/// terminal. `None` when nothing was rated, so the caller can skip the line.
pub fn tally_line(counts: &SevCounts) -> Option<String> {
    let order = [
        (4, Severity::Critical),
        (3, Severity::High),
        (2, Severity::Medium),
        (1, Severity::Low),
        (0, Severity::Info),
    ];
    let color = use_color();
    let parts: Vec<String> = order
        .into_iter()
        .filter_map(|(i, sev)| {
            let n = counts[i];
            if n == 0 {
                return None;
            }
            Some(if color {
                format!("{}{} {n}\x1b[0m", severity_color(sev), sev.tag())
            } else {
                format!("{} {n}", sev.tag())
            })
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("  "))
}

/// Running tallies for the progress gauge, updated from [`ScanEvent`]s.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProgressState {
    /// Total files the walk will visit.
    pub total: u64,
    /// Files processed so far.
    pub done: u64,
    /// Matches found so far.
    pub matches: u64,
}

impl ProgressState {
    /// Fold one event into the tallies.
    pub fn apply(&mut self, event: &ScanEvent) {
        match event {
            ScanEvent::Total(n) => self.total = *n,
            ScanEvent::FileDone => self.done += 1,
            ScanEvent::Match(_) => self.matches += 1,
        }
    }

    /// Completion fraction in `0.0..=1.0` (0 when the total is unknown).
    pub fn ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.done as f64 / self.total as f64).clamp(0.0, 1.0)
        }
    }

    /// The gauge's text label.
    pub fn label(&self) -> String {
        format!(
            "{}/{} files · {} matches",
            self.done, self.total, self.matches
        )
    }
}

/// Spawn the progress renderer for a scan. Returns the handle to join once the
/// scan is finished (the thread ends when the event channel closes); joining
/// yields the per-severity counts of the matches it streamed.
pub fn spawn(rx: Receiver<ScanEvent>) -> JoinHandle<SevCounts> {
    if std::io::stdout().is_terminal() {
        std::thread::spawn(move || render_tui(rx))
    } else {
        std::thread::spawn(move || {
            let mut out = std::io::stdout();
            render_plain(rx, &mut out)
        })
    }
}

/// Pipe-friendly rendering: write each match as a line into `w`. Returns the
/// per-severity counts of the matches seen.
fn render_plain<W: Write>(rx: Receiver<ScanEvent>, w: &mut W) -> SevCounts {
    let mut counts = SevCounts::default();
    // A blocking `for` over a Receiver ends when the sender is dropped.
    for event in rx {
        if let ScanEvent::Match(m) = event {
            tally(&mut counts, m.severity);
            let _ = writeln!(w, "{}", match_line(&m));
        }
    }
    counts
}

/// Draw the gauge for `state` into `terminal`. Backend-generic so tests can
/// render into a `TestBackend` buffer.
fn draw_gauge<B: Backend>(terminal: &mut Terminal<B>, state: &ProgressState) {
    let ratio = state.ratio();
    let label = state.label();
    let _ = terminal.draw(|frame| {
        let gauge = Gauge::default()
            .ratio(ratio)
            .label(label)
            .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray));
        frame.render_widget(gauge, frame.area());
    });
}

/// Drive the gauge over `terminal` until the event channel disconnects,
/// inserting each match line above the inline gauge. Backend-generic so it can
/// be tested against a `TestBackend`.
fn pump<B: Backend>(terminal: &mut Terminal<B>, rx: Receiver<ScanEvent>) -> SevCounts {
    let mut state = ProgressState::default();
    let mut counts = SevCounts::default();
    loop {
        // Drain everything queued, then redraw once.
        let mut disconnected = false;
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                let mut pending = Some(ev);
                while let Some(ev) = pending.take() {
                    if let ScanEvent::Match(m) = &ev {
                        tally(&mut counts, m.severity);
                        let style = severity_style(m.severity);
                        let line = match_line(m);
                        let _ = terminal.insert_before(1, |buf| {
                            Line::styled(line, style).render(buf.area, buf);
                        });
                    }
                    state.apply(&ev);
                    pending = rx.try_recv().ok();
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => disconnected = true,
        }

        draw_gauge(terminal, &state);
        if disconnected {
            break;
        }
    }
    counts
}

/// Terminal rendering: match lines scroll above an inline progress gauge.
fn render_tui(rx: Receiver<ScanEvent>) -> SevCounts {
    let backend = CrosstermBackend::new(std::io::stdout());
    let Ok(mut terminal) = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Inline(1),
        },
    ) else {
        // Terminal setup failed; degrade to plain output.
        let mut out = std::io::stdout();
        return render_plain(rx, &mut out);
    };
    let counts = pump(&mut terminal, rx);
    // Leave the completed gauge in place and move to a fresh line below it.
    println!();
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn m(rule: &str) -> Match {
        Match {
            rule: rule.into(),
            path: "a.env".into(),
            line: 2,
            col: 5,
            snippet: "hit".into(),
            severity: None,
            cwe: None,
            cve: None,
        }
    }

    #[test]
    fn match_line_format() {
        assert_eq!(match_line(&m("r")), "a.env:2:5 [r] hit");
    }

    #[test]
    fn match_line_includes_severity_tag() {
        let mut hit = m("aws");
        hit.severity = Some(Severity::Critical);
        assert_eq!(match_line(&hit), "a.env:2:5 CRIT [aws] hit");
    }

    #[test]
    fn severity_style_is_color_coded_by_rank() {
        assert_eq!(
            severity_style(Some(Severity::Critical)).fg,
            Some(Color::LightRed)
        );
        assert!(severity_style(Some(Severity::Critical))
            .add_modifier
            .contains(Modifier::BOLD));
        assert_eq!(
            severity_style(Some(Severity::Medium)).fg,
            Some(Color::Yellow)
        );
        assert_eq!(severity_style(None).fg, Some(Color::Gray));
    }

    #[test]
    fn severity_color_ansi_per_rank() {
        // The ANSI escapes used for colored terminal output (never reached in
        // tests via styled_line, since stdout isn't a TTY there).
        assert_eq!(severity_color(Severity::Critical), "\x1b[1;91m");
        assert_eq!(severity_color(Severity::High), "\x1b[91m");
        assert_eq!(severity_color(Severity::Medium), "\x1b[33m");
        assert_eq!(severity_color(Severity::Low), "\x1b[34m");
        assert_eq!(severity_color(Severity::Info), "\x1b[36m");
    }

    #[test]
    fn severity_summary_tallies_worst_first() {
        let mut crit = m("aws");
        crit.severity = Some(Severity::Critical);
        let mut med = m("pii");
        med.severity = Some(Severity::Medium);
        // Two criticals, one medium, one unrated → "CRIT 2  MED 1".
        let findings = vec![crit.clone(), crit, med, m("plain")];
        assert_eq!(
            severity_summary(&findings).as_deref(),
            Some("CRIT 2  MED 1")
        );
        assert_eq!(severity_summary(&[]), None);
    }

    #[test]
    fn styled_line_is_plain_without_a_tty() {
        // Under `cargo test` stdout is not a terminal, so styled_line must not
        // emit ANSI escapes — it should equal the plain match_line.
        let mut hit = m("aws");
        hit.severity = Some(Severity::Critical);
        assert_eq!(styled_line(&hit), match_line(&hit));
        assert!(!styled_line(&hit).contains('\x1b'));
    }

    #[test]
    fn state_folds_events() {
        let mut s = ProgressState::default();
        for ev in [
            ScanEvent::Total(4),
            ScanEvent::FileDone,
            ScanEvent::FileDone,
            ScanEvent::Match(m("r")),
        ] {
            s.apply(&ev);
        }
        assert_eq!((s.total, s.done, s.matches), (4, 2, 1));
        assert_eq!(s.ratio(), 0.5);
        assert_eq!(s.label(), "2/4 files · 1 matches");
    }

    #[test]
    fn ratio_is_zero_without_total_and_clamps() {
        let mut s = ProgressState::default();
        assert_eq!(s.ratio(), 0.0);
        s.total = 2;
        s.done = 9; // more done than total shouldn't exceed 1.0
        assert_eq!(s.ratio(), 1.0);
    }

    #[test]
    fn render_plain_writes_only_matches() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(ScanEvent::Total(2)).unwrap();
        tx.send(ScanEvent::Match(m("aws"))).unwrap();
        tx.send(ScanEvent::FileDone).unwrap();
        tx.send(ScanEvent::Match(m("gh"))).unwrap();
        drop(tx);
        let mut buf = Vec::new();
        render_plain(rx, &mut buf);
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out.lines().count(), 2, "{out:?}");
        assert!(out.contains("[aws]") && out.contains("[gh]"));
    }

    #[test]
    fn pump_drains_events_and_renders_final_gauge() {
        let (tx, rx) = std::sync::mpsc::channel();
        for ev in [
            ScanEvent::Total(2),
            ScanEvent::Match(m("aws")),
            ScanEvent::FileDone,
            ScanEvent::FileDone,
        ] {
            tx.send(ev).unwrap();
        }
        drop(tx); // disconnect ends the loop
        let mut terminal = Terminal::new(TestBackend::new(40, 4)).unwrap();
        pump(&mut terminal, rx);
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().chars().next().unwrap_or(' '))
            .collect();
        assert!(text.contains("2/2 files"), "{text:?}");
    }

    #[test]
    fn spawn_plain_path_consumes_events_and_joins() {
        // Under `cargo test` stdout is not a TTY, so spawn() takes the plain
        // renderer path; the thread must drain events and exit when tx drops.
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = spawn(rx);
        tx.send(ScanEvent::Total(1)).unwrap();
        tx.send(ScanEvent::Match(m("aws"))).unwrap();
        tx.send(ScanEvent::FileDone).unwrap();
        drop(tx);
        handle.join().expect("renderer thread joins");
    }

    #[test]
    fn draw_gauge_renders_label_into_buffer() {
        let backend = TestBackend::new(40, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = ProgressState {
            total: 10,
            done: 5,
            matches: 3,
        };
        draw_gauge(&mut terminal, &state);
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().chars().next().unwrap_or(' '))
            .collect();
        assert!(text.contains("5/10 files"), "{text:?}");
    }
}
