//! `exfill tui` — a mutt-style, full-screen workbench over the findings graph.
//!
//! The layout follows mutt: a one-line **help bar** at the top, the full-width
//! **index** of findings below it, a reverse-video **status bar**, and a
//! **message/prompt line** at the very bottom. `Enter` opens the selected
//! finding in a full-screen **pager** (its fields plus the file record it was
//! found in — a hop through the graph), and `q`/`i` returns to the index.
//!
//! ## Keys (index)
//!
//! - `j`/`k`, arrows — move; `g`/`G` — first/last
//! - `Enter` — open the finding in the pager (with its file record)
//! - `/` — *limit* the index (mutt-style filter): empty shows all,
//!   `severity=high`, `cwe=CWE-798`, `path=...`, or free text on rule names
//! - `:` — command: `scan [path]`, `rules`, `get <id>`, `clean`, `quit`
//! - `s` — scan the current directory (shortcut for `:scan .`)
//! - `r` — reload findings from the store
//! - `q` — quit
//!
//! ## Keys (pager)
//!
//! - `j`/`k`, arrows — scroll; `q`/`i`/`Esc` — back to the index
//!
//! # Rust notes
//!
//! The UI loop is a plain blocking thread (terminals are synchronous), while
//! the database and scans are async. The bridge is a [`tokio::runtime::Handle`]:
//! `handle.block_on(...)` runs one async operation to completion from this
//! thread, and `handle.spawn(...)` launches a scan in the background while the
//! loop keeps drawing. Scan progress arrives over the same `ScanEvent` channel
//! the plain CLI uses — the engine doesn't know or care which UI is attached.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use exfill_core::{Match, Severity};
use exfill_engine::{ScanEvent, Summary};
use exfill_store::Store;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

/// A command typed into the `:` bar, parsed into an executable action.
#[derive(Debug, PartialEq)]
enum Action {
    Scan(PathBuf),
    Search(String),
    Rules,
    Get(String),
    Clean,
    Quit,
    /// Unrecognized input; the string is the error shown on the message line.
    Invalid(String),
}

/// Parse one command-bar line. Kept as a pure function so it's unit-testable
/// without a terminal.
fn parse_command(input: &str) -> Action {
    let input = input.trim();
    let (cmd, rest) = match input.split_once(char::is_whitespace) {
        Some((c, r)) => (c, r.trim()),
        None => (input, ""),
    };
    match cmd {
        "scan" => Action::Scan(PathBuf::from(if rest.is_empty() { "." } else { rest })),
        "search" | "limit" => Action::Search(rest.to_string()),
        "rules" => Action::Rules,
        "get" => {
            if rest.is_empty() {
                Action::Invalid("usage: get <table:key>".into())
            } else {
                Action::Get(rest.to_string())
            }
        }
        "clean" => Action::Clean,
        "q" | "quit" | "exit" => Action::Quit,
        other => Action::Invalid(format!("unknown command {other:?}")),
    }
}

/// Mutt-style one-letter flag for the index column.
fn severity_flag(sev: Option<Severity>) -> char {
    match sev {
        Some(Severity::Critical) => 'C',
        Some(Severity::High) => 'H',
        Some(Severity::Medium) => 'M',
        Some(Severity::Low) => 'L',
        Some(Severity::Info) => 'I',
        None => ' ',
    }
}

/// Tally findings per severity for the status bar, worst-first.
fn severity_counts(findings: &[Match]) -> Vec<(Severity, usize)> {
    let all = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    all.into_iter()
        .map(|sev| {
            let n = findings.iter().filter(|m| m.severity == Some(sev)).count();
            (sev, n)
        })
        .filter(|(_, n)| *n > 0)
        .collect()
}

/// One mutt-like index row: `  3 C aws-access-key-id   .env:1  export AWS_…`.
fn index_row(n: usize, m: &Match) -> String {
    format!(
        "{n:>4} {} {:<22} {}:{}  {}",
        severity_flag(m.severity),
        m.rule,
        m.path,
        m.line,
        m.snippet
    )
}

/// Which screen is showing, mutt-style.
enum Mode {
    Index,
    /// Full-screen view of one finding; the field is the scroll offset.
    Pager(u16),
}

/// What the bottom prompt line is currently collecting, if anything.
enum Prompt {
    /// `:` — a command.
    Command(String),
    /// `/` — a limit (search filter).
    Limit(String),
}

/// A scan running in the background, with its live progress.
struct RunningScan {
    events: Receiver<ScanEvent>,
    task: JoinHandle<Result<Summary>>,
    total: u64,
    done: u64,
}

/// The whole TUI state.
struct App {
    store: Store,
    store_dir: PathBuf,
    findings: Vec<Match>,
    list: ListState,
    mode: Mode,
    /// Content of the pager, built when a finding is opened.
    pager: Vec<String>,
    /// Transient one-line message (last action's outcome), mutt's bottom line.
    message: String,
    /// Active `:` or `/` prompt, if the user is typing one.
    prompt: Option<Prompt>,
    /// The active limit, shown in the status bar (empty = all).
    limit: String,
    scan: Option<RunningScan>,
    quit: bool,
}

impl App {
    fn selected(&self) -> Option<&Match> {
        self.list.selected().and_then(|i| self.findings.get(i))
    }

    fn select_delta(&mut self, delta: isize) {
        if self.findings.is_empty() {
            return;
        }
        let cur = self.list.selected().unwrap_or(0) as isize;
        let max = self.findings.len() as isize - 1;
        self.list
            .select(Some(cur.saturating_add(delta).clamp(0, max) as usize));
    }

    fn refresh_findings(&mut self, handle: &Handle, query: &str) {
        match handle.block_on(self.store.search_findings(query)) {
            Ok(found) => {
                self.message = format!("{} finding(s)", found.len());
                self.limit = query.to_string();
                self.findings = found;
                self.list.select(if self.findings.is_empty() {
                    None
                } else {
                    Some(0)
                });
            }
            Err(e) => self.message = format!("search failed: {e:#}"),
        }
    }

    /// Build the pager for the selected finding: its fields plus the `file`
    /// record it was found in (the finding → file hop through the graph).
    fn open_pager(&mut self, handle: &Handle) {
        let Some(m) = self.selected() else {
            self.message = "no finding selected".into();
            return;
        };
        let mut lines = vec![
            format!("Rule:     {}", m.rule),
            format!("Path:     {}", m.path),
            format!("Location: line {}, column {}", m.line, m.col),
            format!(
                "Severity: {}",
                m.severity
                    .map(|s| format!("{s:?}"))
                    .unwrap_or_else(|| "-".into())
            ),
            format!("CWE:      {}", m.cwe.as_deref().unwrap_or("-")),
            format!("CVE:      {}", m.cve.as_deref().unwrap_or("-")),
            String::new(),
            format!("> {}", m.snippet),
            String::new(),
            "── file record ──".into(),
        ];
        let path = m.path.clone();
        let res = handle.block_on(async {
            let mut r = self
                .store
                .db()
                .query("SELECT * OMIT id FROM file WHERE path = $p LIMIT 1")
                .bind(("p", path.clone()))
                .await?;
            let rows: Vec<serde_json::Value> = r.take(0)?;
            anyhow::Ok(rows.into_iter().next())
        });
        match res {
            Ok(Some(v)) => {
                let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
                lines.extend(pretty.lines().map(String::from));
            }
            Ok(None) => lines.push(format!("(no file record for {path})")),
            Err(e) => lines.push(format!("(lookup failed: {e:#})")),
        }
        self.pager = lines;
        self.mode = Mode::Pager(0);
    }

    fn execute(&mut self, handle: &Handle, action: Action) {
        match action {
            Action::Quit => self.quit = true,
            Action::Search(q) => self.refresh_findings(handle, &q),
            Action::Rules => {
                self.pager = exfill_scan::builtin_rules()
                    .into_iter()
                    .map(|r| {
                        format!(
                            "{:<22} {:<9} {:<8} {}",
                            r.name,
                            r.severity.map(|s| format!("{s:?}")).unwrap_or_default(),
                            r.cwe.as_deref().unwrap_or("-"),
                            r.description
                        )
                    })
                    .collect();
                self.mode = Mode::Pager(0);
                self.message = "builtin rules".into();
            }
            Action::Get(id) => match handle.block_on(self.store.get_record(&id)) {
                Ok(Some(v)) => {
                    let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
                    self.pager = pretty.lines().map(String::from).collect();
                    self.mode = Mode::Pager(0);
                    self.message = id;
                }
                Ok(None) => self.message = format!("no record {id:?}"),
                Err(e) => self.message = format!("get failed: {e:#}"),
            },
            Action::Clean => {
                // The store is open (and its files locked) while the TUI runs,
                // so `clean` empties the tables instead of deleting the dir.
                let res = handle.block_on(async {
                    self.store
                        .db()
                        .query("DELETE finding; DELETE scan; DELETE file; DELETE ast;")
                        .await?
                        .check()?;
                    anyhow::Ok(())
                });
                match res {
                    Ok(()) => {
                        self.findings.clear();
                        self.list.select(None);
                        self.message = format!("cleared findings in {}", self.store_dir.display());
                    }
                    Err(e) => self.message = format!("clean failed: {e:#}"),
                }
            }
            Action::Scan(root) => {
                if self.scan.is_some() {
                    self.message = "a scan is already running".into();
                    return;
                }
                let (tx, rx) = mpsc::channel();
                let store = self.store.clone();
                let store_dir = self.store_dir.clone();
                let task = handle.spawn(async move {
                    let registry = exfill_scan::default_registry()?;
                    exfill_engine::scan(&root, &registry, &store, Some(&store_dir), Some(tx)).await
                });
                self.findings.clear();
                self.list.select(None);
                self.limit.clear();
                self.message = "scanning…".into();
                self.scan = Some(RunningScan {
                    events: rx,
                    task,
                    total: 0,
                    done: 0,
                });
            }
            Action::Invalid(msg) => self.message = msg,
        }
    }

    /// Drain scan progress; findings stream into the index as they are found.
    fn pump_scan(&mut self, handle: &Handle) {
        let Some(scan) = &mut self.scan else { return };
        while let Ok(ev) = scan.events.try_recv() {
            match ev {
                ScanEvent::Total(n) => scan.total = n,
                ScanEvent::FileDone => scan.done += 1,
                ScanEvent::Match(m) => {
                    self.findings.push(m);
                    if self.list.selected().is_none() {
                        self.list.select(Some(0));
                    }
                }
            }
        }
        if scan.task.is_finished() {
            let scan = self.scan.take().expect("scan present");
            self.message = match handle.block_on(scan.task) {
                Ok(Ok(s)) => format!(
                    "scanned {} files ({} unchanged): {} new matches, {} unreadable",
                    s.files, s.unchanged, s.matches, s.errors
                ),
                Ok(Err(e)) => format!("scan failed: {e:#}"),
                Err(e) => format!("scan panicked: {e}"),
            };
        }
    }

    /// The reverse-video status bar, mutt's `-*-` line.
    fn status_line(&self) -> String {
        let mut parts = vec![format!("exfill: {} findings", self.findings.len())];
        if !self.limit.is_empty() {
            parts.push(format!("limit: {}", self.limit));
        }
        let counts = severity_counts(&self.findings)
            .into_iter()
            .map(|(s, n)| format!("{}:{n}", severity_flag(Some(s))))
            .collect::<Vec<_>>()
            .join(" ");
        if !counts.is_empty() {
            parts.push(format!("[{counts}]"));
        }
        if let Some(scan) = &self.scan {
            parts.push(format!("scanning {}/{} files", scan.done, scan.total));
        }
        if let Some(i) = self.list.selected() {
            parts.push(format!("({}/{})", i + 1, self.findings.len()));
        }
        format!("-*- {} ", parts.join(" --- "))
    }

    fn draw(&mut self, frame: &mut Frame) {
        let [help, main, status, msg] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        let reversed = Style::default().add_modifier(Modifier::REVERSED);

        // Help bar (top, like mutt's `help=yes`).
        let help_text = match self.mode {
            Mode::Index => {
                "q:Quit  j/k:Move  Enter:View  /:Limit  ::Cmd  s:Scan  r:Reload  g/G:First/Last"
            }
            Mode::Pager(_) => "i:Exit  j/k:Scroll  q:Index",
        };
        frame.render_widget(Paragraph::new(help_text).style(reversed), help);

        // Main area: index or pager.
        match self.mode {
            Mode::Index => {
                let items: Vec<ListItem> = self
                    .findings
                    .iter()
                    .enumerate()
                    .map(|(i, m)| ListItem::new(index_row(i + 1, m)))
                    .collect();
                let list = List::new(items).highlight_style(reversed);
                frame.render_stateful_widget(list, main, &mut self.list);
            }
            Mode::Pager(scroll) => {
                let text: Vec<Line> = self.pager.iter().map(|l| Line::raw(l.as_str())).collect();
                frame.render_widget(Paragraph::new(text).scroll((scroll, 0)), main);
            }
        }

        // Status bar (reverse video) + message/prompt line.
        frame.render_widget(Paragraph::new(self.status_line()).style(reversed), status);
        let bottom = match &self.prompt {
            Some(Prompt::Command(s)) => format!(":{s}▏"),
            Some(Prompt::Limit(s)) => format!("/{s}▏"),
            None => self.message.clone(),
        };
        frame.render_widget(Paragraph::new(bottom), msg);
    }

    fn on_key(&mut self, handle: &Handle, code: KeyCode) {
        // An open prompt captures all typing first (mutt's bottom line).
        if let Some(prompt) = &mut self.prompt {
            let buf = match prompt {
                Prompt::Command(s) | Prompt::Limit(s) => s,
            };
            match code {
                KeyCode::Esc => self.prompt = None,
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Enter => {
                    let action = match self.prompt.take().expect("prompt open") {
                        Prompt::Command(s) => parse_command(&s),
                        Prompt::Limit(s) => Action::Search(s),
                    };
                    self.execute(handle, action);
                }
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return;
        }

        match &mut self.mode {
            Mode::Pager(scroll) => match code {
                KeyCode::Char('q') | KeyCode::Char('i') | KeyCode::Esc => {
                    self.mode = Mode::Index;
                }
                KeyCode::Char('j') | KeyCode::Down => *scroll = scroll.saturating_add(1),
                KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
                _ => {}
            },
            Mode::Index => match code {
                KeyCode::Char('q') => self.quit = true,
                KeyCode::Char(':') => self.prompt = Some(Prompt::Command(String::new())),
                KeyCode::Char('/') => self.prompt = Some(Prompt::Limit(String::new())),
                KeyCode::Char('j') | KeyCode::Down => self.select_delta(1),
                KeyCode::Char('k') | KeyCode::Up => self.select_delta(-1),
                KeyCode::Char('g') => self.select_delta(isize::MIN + 1),
                KeyCode::Char('G') => self.select_delta(isize::MAX),
                KeyCode::Char('r') => {
                    let limit = self.limit.clone();
                    self.refresh_findings(handle, &limit);
                }
                KeyCode::Char('s') => self.execute(handle, Action::Scan(PathBuf::from("."))),
                KeyCode::Enter => self.open_pager(handle),
                _ => {}
            },
        }
    }
}

/// Run the TUI until the user quits. Blocking; call from `spawn_blocking`.
pub fn run(handle: Handle, store_dir: &Path) -> Result<()> {
    let store = handle
        .block_on(Store::open_findings(store_dir))
        .context("open findings store")?;

    let mut app = App {
        store,
        store_dir: store_dir.to_path_buf(),
        findings: Vec::new(),
        list: ListState::default(),
        mode: Mode::Index,
        pager: Vec::new(),
        message: "ready — :scan to scan, / to limit, q to quit".into(),
        prompt: None,
        limit: String::new(),
        scan: None,
        quit: false,
    };
    app.refresh_findings(&handle, "");

    enable_raw_mode().context("enable raw mode")?;
    crossterm::execute!(std::io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    // Always restore the terminal, even if the loop errors.
    let result = (|| -> Result<()> {
        while !app.quit {
            app.pump_scan(&handle);
            terminal.draw(|f| app.draw(f))?;
            // Poll with a timeout so scan progress redraws even without input.
            if crossterm::event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = crossterm::event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.on_key(&handle, key.code);
                    }
                }
            }
        }
        Ok(())
    })();

    crossterm::execute!(std::io::stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_parse() {
        assert_eq!(parse_command("scan"), Action::Scan(PathBuf::from(".")));
        assert_eq!(
            parse_command("scan /srv"),
            Action::Scan(PathBuf::from("/srv"))
        );
        assert_eq!(
            parse_command("search severity=high"),
            Action::Search("severity=high".into())
        );
        assert_eq!(
            parse_command("limit cwe=CWE-798"),
            Action::Search("cwe=CWE-798".into())
        );
        assert_eq!(parse_command("search"), Action::Search(String::new()));
        assert_eq!(parse_command("rules"), Action::Rules);
        assert_eq!(
            parse_command("get file:abc"),
            Action::Get("file:abc".into())
        );
        assert_eq!(parse_command("clean"), Action::Clean);
        assert_eq!(parse_command("quit"), Action::Quit);
        assert_eq!(parse_command("  q  "), Action::Quit);
        assert!(matches!(parse_command("get"), Action::Invalid(_)));
        assert!(matches!(parse_command("frobnicate"), Action::Invalid(_)));
    }

    fn m(sev: Option<Severity>) -> Match {
        Match {
            rule: "aws-access-key-id".into(),
            path: ".env".into(),
            line: 1,
            col: 26,
            snippet: "export AWS_ACCESS_KEY_ID=AKIA…".into(),
            severity: sev,
            cwe: None,
            cve: None,
        }
    }

    #[test]
    fn severity_tally_is_worst_first_and_skips_zeroes() {
        let findings = vec![
            m(Some(Severity::High)),
            m(Some(Severity::Critical)),
            m(Some(Severity::High)),
            m(None),
        ];
        let counts = severity_counts(&findings);
        assert_eq!(counts, vec![(Severity::Critical, 1), (Severity::High, 2)]);
    }

    #[test]
    fn index_rows_look_muttish() {
        let row = index_row(3, &m(Some(Severity::Critical)));
        assert!(row.starts_with("   3 C aws-access-key-id"), "{row}");
        assert!(row.contains(".env:1"), "{row}");
    }

    #[test]
    fn severity_flags() {
        assert_eq!(severity_flag(Some(Severity::Critical)), 'C');
        assert_eq!(severity_flag(Some(Severity::Info)), 'I');
        assert_eq!(severity_flag(None), ' ');
    }
}
