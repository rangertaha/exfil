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

use exfill_core::Match;
use exfill_engine::ScanEvent;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Gauge, Widget};
use ratatui::{Terminal, TerminalOptions, Viewport};

/// Format one match the same way everywhere (plain mode, TUI, search output).
pub fn match_line(m: &Match) -> String {
    format!("{}:{}:{} [{}] {}", m.path, m.line, m.col, m.rule, m.snippet)
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

/// Spawn the progress renderer for a scan. Returns the handle to join once
/// the scan is finished (the thread ends when the event channel closes).
pub fn spawn(rx: Receiver<ScanEvent>) -> JoinHandle<()> {
    if std::io::stdout().is_terminal() {
        std::thread::spawn(move || render_tui(rx))
    } else {
        std::thread::spawn(move || {
            let mut out = std::io::stdout();
            render_plain(rx, &mut out);
        })
    }
}

/// Pipe-friendly rendering: write each match as a line into `w`.
fn render_plain<W: Write>(rx: Receiver<ScanEvent>, w: &mut W) {
    // A blocking `for` over a Receiver ends when the sender is dropped.
    for event in rx {
        if let ScanEvent::Match(m) = event {
            let _ = writeln!(w, "{}", match_line(&m));
        }
    }
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
fn pump<B: Backend>(terminal: &mut Terminal<B>, rx: Receiver<ScanEvent>) {
    let mut state = ProgressState::default();
    loop {
        // Drain everything queued, then redraw once.
        let mut disconnected = false;
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                let mut pending = Some(ev);
                while let Some(ev) = pending.take() {
                    if let ScanEvent::Match(m) = &ev {
                        let line = match_line(m);
                        let _ = terminal.insert_before(1, |buf| {
                            Line::raw(line).render(buf.area, buf);
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
}

/// Terminal rendering: match lines scroll above an inline progress gauge.
fn render_tui(rx: Receiver<ScanEvent>) {
    let backend = CrosstermBackend::new(std::io::stdout());
    let Ok(mut terminal) = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Inline(1),
        },
    ) else {
        // Terminal setup failed; degrade to plain output.
        let mut out = std::io::stdout();
        render_plain(rx, &mut out);
        return;
    };
    pump(&mut terminal, rx);
    // Leave the completed gauge in place and move to a fresh line below it.
    println!();
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
