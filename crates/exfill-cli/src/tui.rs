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
    /// Pluggable viewers that render nodes in the pager.
    viewers: exfill_view::Registry,
    quit: bool,
}

impl App {
    /// Build a fresh app over an open store. Shared by [`run`] and tests.
    fn new(store: Store, store_dir: PathBuf) -> Self {
        App {
            store,
            store_dir,
            findings: Vec::new(),
            list: ListState::default(),
            mode: Mode::Index,
            pager: Vec::new(),
            message: "ready — :scan to scan, / to limit, q to quit".into(),
            prompt: None,
            limit: String::new(),
            scan: None,
            viewers: exfill_view::Registry::new(),
            quit: false,
        }
    }

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

    /// Build the pager for the selected finding by rendering it — and the
    /// `file` node it hops to through the graph — with the pluggable viewer
    /// registry (the same "preview per node kind" model a graph workbench uses).
    fn open_pager(&mut self, handle: &Handle) {
        let Some(m) = self.selected() else {
            self.message = "no finding selected".into();
            return;
        };
        let finding_node = exfill_view::Node::new(
            "finding",
            "finding",
            serde_json::to_value(m).unwrap_or(serde_json::Value::Null),
        );
        let mut lines = self.viewers.render(&finding_node);

        // Graph hop: finding → the file it was found in.
        let path = m.path.clone();
        let file = handle.block_on(async {
            let mut r = self
                .store
                .db()
                .query("SELECT * OMIT id FROM file WHERE path = $p LIMIT 1")
                .bind(("p", path.clone()))
                .await?;
            let rows: Vec<serde_json::Value> = r.take(0)?;
            anyhow::Ok(rows.into_iter().next())
        });
        lines.push(String::new());
        lines.push("── file ──".into());
        match file {
            Ok(Some(v)) => {
                let node = exfill_view::Node::new("file", "file", v);
                lines.extend(self.viewers.render(&node));
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
                    let pipeline = exfill_scan::default_pipeline()?;
                    exfill_engine::scan(&root, &pipeline, &store, Some(&store_dir), Some(tx)).await
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

    let mut app = App::new(store, store_dir.to_path_buf());
    app.refresh_findings(&handle, "");

    enable_raw_mode().context("enable raw mode")?;
    crossterm::execute!(std::io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    // Always restore the terminal, even if the loop errors. The key source
    // polls crossterm; the loop body itself lives in `event_loop` so it can be
    // tested against a scripted source and a `TestBackend`.
    let result = event_loop(&mut app, &handle, &mut terminal, || {
        if crossterm::event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = crossterm::event::read() {
                if key.kind == KeyEventKind::Press {
                    return Some(key.code);
                }
            }
        }
        None
    });

    crossterm::execute!(std::io::stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    result
}

/// The TUI's main loop, factored out of [`run`] so it is backend-generic and
/// takes its keys from an injectable source. Each tick pumps scan progress,
/// redraws, then applies one key (if the source yields one). Ends when the
/// user quits.
fn event_loop<B: ratatui::backend::Backend>(
    app: &mut App,
    handle: &Handle,
    terminal: &mut Terminal<B>,
    mut next_key: impl FnMut() -> Option<KeyCode>,
) -> Result<()> {
    while !app.quit {
        app.pump_scan(handle);
        terminal.draw(|f| app.draw(f))?;
        if let Some(code) = next_key() {
            app.on_key(handle, code);
        }
    }
    Ok(())
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

    use ratatui::backend::TestBackend;

    /// Render the app once into a TestBackend and return the screen text.
    fn screen(app: &mut App) -> String {
        let mut term = Terminal::new(TestBackend::new(100, 24)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol().chars().next().unwrap_or(' '))
            .collect()
    }

    fn type_str(app: &mut App, handle: &Handle, s: &str) {
        for c in s.chars() {
            app.on_key(handle, KeyCode::Char(c));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn app_drives_index_pager_prompts_and_commands() {
        let handle = Handle::current();
        tokio::task::spawn_blocking(move || {
            let base = std::env::temp_dir().join(format!("exfill-tui-test-{}", std::process::id()));
            let tree = base.join("tree");
            let store_dir = base.join("store");
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

            // Seed the store by scanning the tree.
            let store = handle.block_on(Store::open_findings(&store_dir)).unwrap();
            let pipeline = exfill_scan::default_pipeline().unwrap();
            handle
                .block_on(exfill_engine::scan(
                    &tree,
                    &pipeline,
                    &store,
                    Some(&store_dir),
                    None,
                ))
                .unwrap();

            let mut app = App::new(store, store_dir.clone());
            app.refresh_findings(&handle, "");
            assert!(!app.findings.is_empty(), "seeded findings load");

            // Index navigation and a render.
            app.on_key(&handle, KeyCode::Char('j'));
            app.on_key(&handle, KeyCode::Char('k'));
            app.on_key(&handle, KeyCode::Char('G'));
            app.on_key(&handle, KeyCode::Char('g'));
            app.on_key(&handle, KeyCode::Down);
            app.on_key(&handle, KeyCode::Up);
            assert!(screen(&mut app).contains("exfill:"), "status bar renders");

            // Enter the pager, scroll, and leave it; render in pager mode too.
            app.on_key(&handle, KeyCode::Enter);
            assert!(matches!(app.mode, Mode::Pager(_)));
            assert!(screen(&mut app).contains("file record") || !app.pager.is_empty());
            app.on_key(&handle, KeyCode::Char('j'));
            app.on_key(&handle, KeyCode::Char('k'));
            app.on_key(&handle, KeyCode::Char('q'));
            assert!(matches!(app.mode, Mode::Index));

            // `:rules` command opens the pager with the ruleset.
            app.on_key(&handle, KeyCode::Char(':'));
            type_str(&mut app, &handle, "rules");
            app.on_key(&handle, KeyCode::Enter);
            assert!(matches!(app.mode, Mode::Pager(_)));
            assert!(app.pager.iter().any(|l| l.contains("aws-access-key-id")));
            app.on_key(&handle, KeyCode::Char('i')); // back to index

            // `/severity=low` limits to nothing; the limit shows in the status.
            app.on_key(&handle, KeyCode::Char('/'));
            type_str(&mut app, &handle, "severity=low");
            app.on_key(&handle, KeyCode::Enter);
            assert!(app.findings.is_empty());
            assert_eq!(app.limit, "severity=low");
            app.on_key(&handle, KeyCode::Char('r')); // reload keeps the limit

            // Prompt editing: type, backspace, escape.
            app.on_key(&handle, KeyCode::Char(':'));
            app.on_key(&handle, KeyCode::Char('x'));
            app.on_key(&handle, KeyCode::Backspace);
            app.on_key(&handle, KeyCode::Esc);
            assert!(app.prompt.is_none());

            // get (miss) and an invalid command set the message line.
            app.execute(&handle, Action::Get("file:doesnotexist".into()));
            assert!(app.message.contains("no record"));
            app.execute(&handle, Action::Invalid("boom".into()));
            assert_eq!(app.message, "boom");

            // Enter on an empty index reports nothing selected.
            app.list.select(None);
            app.open_pager(&handle);
            assert!(app.message.contains("no finding selected"));

            // Start a scan of the tree, then pressing 's' hits the
            // already-running guard; pump until it finishes.
            app.execute(&handle, Action::Scan(tree.clone()));
            assert!(app.scan.is_some());
            app.on_key(&handle, KeyCode::Char('s'));
            assert!(app.message.contains("already running"));
            for _ in 0..200 {
                app.pump_scan(&handle);
                let _ = screen(&mut app); // exercise the scanning-gauge header
                if app.scan.is_none() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(app.scan.is_none(), "scan finished");
            assert!(app.message.contains("scanned"), "{}", app.message);

            // Clean empties the findings via the graph.
            app.execute(&handle, Action::Clean);
            assert!(app.findings.is_empty());
            assert!(app.message.contains("cleared"));

            // Quit.
            app.on_key(&handle, KeyCode::Char('q'));
            assert!(app.quit);

            let _ = std::fs::remove_dir_all(&base);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_loop_runs_until_quit() {
        let handle = Handle::current();
        tokio::task::spawn_blocking(move || {
            let dir = std::env::temp_dir().join(format!("exfill-tui-loop-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let store = handle.block_on(Store::open_findings(&dir)).unwrap();
            let mut app = App::new(store, dir.clone());

            // Scripted keys: move down, open a prompt and cancel it, then quit.
            let mut keys = vec![
                KeyCode::Char('j'),
                KeyCode::Char(':'),
                KeyCode::Esc,
                KeyCode::Char('q'),
            ]
            .into_iter();
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            event_loop(&mut app, &handle, &mut terminal, || keys.next()).unwrap();
            assert!(app.quit, "loop exits when quit is set");

            let _ = std::fs::remove_dir_all(&dir);
        })
        .await
        .unwrap();
    }
}
