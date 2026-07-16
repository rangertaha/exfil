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
//! # Rust notes
//!
//! The renderer runs on its own OS thread (`std::thread::spawn`) so drawing
//! never blocks the async scan. `recv_timeout` gives the loop a heartbeat: it
//! wakes at least every 100 ms to redraw even when no events arrive, and exits
//! when the channel disconnects (the engine dropping its sender *is* the
//! shutdown signal — no flag needed).

use std::io::IsTerminal;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use exfill_core::Match;
use exfill_engine::ScanEvent;
use ratatui::backend::CrosstermBackend;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Gauge, Widget};
use ratatui::{Terminal, TerminalOptions, Viewport};

/// Format one match the same way everywhere (plain mode, TUI, search output).
pub fn match_line(m: &Match) -> String {
    format!("{}:{}:{} [{}] {}", m.path, m.line, m.col, m.rule, m.snippet)
}

/// Spawn the progress renderer for a scan. Returns the handle to join once
/// the scan is finished (the thread ends when the event channel closes).
pub fn spawn(rx: Receiver<ScanEvent>) -> JoinHandle<()> {
    if std::io::stdout().is_terminal() {
        std::thread::spawn(move || render_tui(rx))
    } else {
        std::thread::spawn(move || render_plain(rx))
    }
}

/// Pipe-friendly rendering: just the match lines.
fn render_plain(rx: Receiver<ScanEvent>) {
    // A blocking `for` over a Receiver ends when the sender is dropped.
    for event in rx {
        if let ScanEvent::Match(m) = event {
            println!("{}", match_line(&m));
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
        render_plain(rx);
        return;
    };

    let mut total = 0u64;
    let mut done = 0u64;
    let mut matches = 0u64;

    loop {
        // Drain everything queued, then redraw once.
        let mut disconnected = false;
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                let mut pending = Some(ev);
                while let Some(ev) = pending.take() {
                    match ev {
                        ScanEvent::Total(n) => total = n,
                        ScanEvent::FileDone => done += 1,
                        ScanEvent::Match(m) => {
                            matches += 1;
                            let line = match_line(&m);
                            let _ = terminal.insert_before(1, |buf| {
                                Line::raw(line).render(buf.area, buf);
                            });
                        }
                    }
                    pending = rx.try_recv().ok();
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => disconnected = true,
        }

        let ratio = if total == 0 {
            0.0
        } else {
            (done as f64 / total as f64).clamp(0.0, 1.0)
        };
        let label = format!("{done}/{total} files · {matches} matches");
        let _ = terminal.draw(|frame| {
            let gauge = Gauge::default()
                .ratio(ratio)
                .label(label)
                .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray));
            frame.render_widget(gauge, frame.area());
        });

        if disconnected {
            break;
        }
    }

    // Leave the completed gauge in place and move to a fresh line below it.
    println!();
}
