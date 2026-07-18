//! `exfil tui` — a full-screen, app-style workbench over the findings graph.
//!
//! The layout is app-like: an optional **stats bar** across the top (toggle with
//! `t`), a **left menu** listing the sections (findings, files, rules, …), the
//! main **data grid** for the active section, and a bottom bar that shows status
//! and doubles as the `:` command / `/` filter input line. On a finding, `Enter`
//! opens it in `$EDITOR` at its line, `v` shows the source in-TUI with every
//! finding marked, and `n` opens the **graph navigator**.
//!
//! ## Keys (index)
//!
//! - `j`/`k`, arrows — move; `g`/`G` — first/last; `Tab` — switch section
//! - `Enter` — open the finding in `$EDITOR` at its line
//! - `v` — view the source in-TUI, findings marked in the gutter
//! - `n` — open the finding's file in the graph navigator
//! - `/` — *limit* the grid (mutt-style filter): empty shows all,
//!   `severity=high`, `cwe=CWE-798`, `path=...`, or free text on rule names
//! - `:` — command: `scan [path]`, `rules`, `get <id>`, `clean`, `quit`
//! - `s` — scan the current directory · `t` — toggle the stats bar · `q` — quit
//!
//! ## Keys (graph navigator)
//!
//! Traversal renders as **cascading Miller columns**: a breadcrumb path on top,
//! then one panel per visited node (each listing its edges). Descending opens a
//! new panel on the right; older panels compress and drop off the left edge (kept
//! on the breadcrumb). The far-right pane previews the focused node's fields.
//!
//! - `j`/`k` — move the cursor in the focused (rightmost) panel
//! - `l`/`Enter` — **descend** into the selected edge (opens a panel on the right)
//! - `h`/`<` (or `Backspace`) — pop the rightmost panel; `>` — forward
//! - `c` — edit a field of the current node (`field=value`)
//! - `d` (on an edge) — delete that edge · `u`/`U` — undo / redo
//! - `q`/`i`/`Esc` — return to the index
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
use exfil_core::{Match, Severity};
use exfil_engine::{ScanEvent, Summary};
use exfil_store::Store;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState};
use ratatui::{Frame, Terminal};
use serde_json::Value;

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

/// The accent color of the standard theme (titles, active menu item, borders,
/// the status bar). One knob keeps the palette consistent across the app.
const ACCENT: Color = Color::Cyan;

/// Capitalize the first character (for menu/header labels).
fn cap(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Style for the reverse-video selection highlight.
fn selected_style() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// Style for the accent status/menu bar (dark text on the accent color).
fn bar_style() -> Style {
    Style::default().bg(ACCENT).fg(Color::Black)
}

/// Right-anchored Miller-column widths for `n` panels across `total` columns of
/// screen. The focused (rightmost) panel gets the full width; each older panel
/// to its left is narrower, down to a floor; when they no longer fit, the
/// oldest (leftmost) panels are dropped from view (still on the breadcrumb).
/// Returns `(hidden, widths)` — `hidden` leftmost panels are off-screen and
/// `widths` are for the visible panels, left to right.
fn column_layout(n: usize, total: u16) -> (usize, Vec<u16>) {
    const FULL: u16 = 34;
    const STEP: u16 = 6;
    const MIN: u16 = 16;
    if n == 0 || total == 0 {
        return (0, Vec::new());
    }
    // Width of a panel `d` columns left of the focused one.
    let width_at = |d: usize| FULL.saturating_sub(STEP.saturating_mul(d as u16)).max(MIN);
    let mut rev: Vec<u16> = Vec::new();
    let mut used = 0u16;
    for d in 0..n {
        let w = width_at(d);
        if !rev.is_empty() && used.saturating_add(w) > total {
            break; // no room for another panel on the left
        }
        let w = w.min(total - used); // clamp the focused panel to the screen
        rev.push(w);
        used += w;
        if used >= total {
            break;
        }
    }
    let shown = rev.len();
    rev.reverse();
    (n - shown, rev)
}

/// Open `path` in a terminal editor at `line`, inheriting the terminal. Tries
/// `$EDITOR`/`$VISUAL` first, then falls back to nvim/vim/vi/nano; the `+<line>`
/// argument (understood by all of them) jumps to the finding. Returns an error
/// only if no editor could be launched at all.
fn open_editor(path: &str, line: u32) -> Result<()> {
    let jump = format!("+{}", line.max(1));
    let mut candidates: Vec<String> = Vec::new();
    for var in ["VISUAL", "EDITOR"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                candidates.push(v);
            }
        }
    }
    candidates.extend(["nvim", "vim", "vi", "nano"].map(String::from));
    for cmd in &candidates {
        // Split so `EDITOR="code -w"`-style values still work.
        let mut parts = cmd.split_whitespace();
        let Some(bin) = parts.next() else { continue };
        let args: Vec<&str> = parts.collect();
        let mut command = std::process::Command::new(bin);
        command.args(&args).arg(&jump).arg(path);
        match command.status() {
            Ok(_) => return Ok(()),
            Err(_) => continue, // not found / not runnable — try the next
        }
    }
    anyhow::bail!("no editor found (set $EDITOR, or install vim/nano)")
}

/// A command typed into the `:` bar, parsed into an executable action.
#[derive(Debug, PartialEq)]
enum Action {
    Scan(PathBuf),
    Search(String),
    Rules,
    Get(String),
    Clean,
    /// Switch the index to another object type.
    Browse(ObjectType),
    Quit,
    /// Unrecognized input; the string is the error shown on the message line.
    Invalid(String),
}

/// Parse a scalar edit value: bool, integer, and float literals become typed
/// JSON; anything else is a string. Keeps `size=100` numeric but `path=/x` text.
fn parse_value(s: &str) -> Value {
    if let Ok(b) = s.parse::<bool>() {
        return Value::Bool(b);
    }
    if let Ok(i) = s.parse::<i64>() {
        return Value::from(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        return Value::from(f);
    }
    Value::String(s.to_string())
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
        "browse" | "type" => match ObjectType::from_name(rest) {
            Some(t) => Action::Browse(t),
            None => Action::Invalid(
                "usage: browse findings|files|indicators|rules|scans|datasets".into(),
            ),
        },
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

use crate::progress::severity_style;

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

/// The `?` help screen: a full key reference shown in the pager. Grouped by
/// context so a new user can learn the whole surface without leaving the TUI.
fn help_text() -> Vec<String> {
    [
        "exfil TUI — key reference",
        "",
        "Index (data grid — left menu selects the section)",
        "  j / k, ↓ / ↑      move selection",
        "  g / G, Home/End   first / last",
        "  PgUp / PgDn       move by a screen",
        "  Enter             open the finding in $EDITOR at its line",
        "  v                 view the source in-TUI, findings marked in the gutter",
        "  n                 open the finding's file in the graph navigator",
        "  c                 edit the selected row: field=value, or a bare severity word",
        "  Tab / Shift-Tab   switch section (findings, files, rules, …)",
        "  /                 limit: severity=high, cwe=CWE-798, path=…, or text",
        "  Esc               clear the active limit",
        "  :                 command: scan [path], search, rules, get <id>, browse, clean, quit",
        "  s                 scan the current directory",
        "  t                 show / hide the top stats bar",
        "  r                 reload from the store",
        "  ?                 this help",
        "  q                 quit",
        "",
        "Graph navigator (cascading columns — a breadcrumb path on top)",
        "  j / k             move the cursor in the focused (rightmost) panel",
        "  l / Enter         descend — open a new panel to the right",
        "  h / <             pop the rightmost panel (back)",
        "  >                 forward through the jumplist",
        "  c                 edit a field of the current node (field=value)",
        "  d                 delete the selected edge",
        "  u / U             undo / redo",
        "  q / i / Esc       return to the index",
        "",
        "Pager & help",
        "  j / k             scroll · g/G top/bottom · PgUp/PgDn by a screen",
        "  h / l             scroll left / right (wide content)",
        "  i / q / Esc       back to the index",
        "",
        "Findings are color-coded by severity; the status bar shows a per-severity tally.",
        "Docs: https://rangertaha.github.io/exfil/",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Which screen is showing, mutt-style.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Index,
    /// Full-screen text view (rules, a record); the field is the scroll offset.
    Pager(u16),
    /// Graph navigator: a node viewer beside its neighbors, with a back-stack.
    Nav,
}

/// Which kind of object the index is browsing. `Findings` keeps the classic
/// finding list (with the `/` severity/rule filter); the rest browse whole
/// record tables so any node can be an entry point into the navigator/editor.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ObjectType {
    Findings,
    Files,
    Indicators,
    Events,
    Rules,
    Scans,
    Datasets,
}

impl ObjectType {
    /// Browse order for the `Tab` cycle.
    const ALL: [ObjectType; 7] = [
        ObjectType::Findings,
        ObjectType::Files,
        ObjectType::Indicators,
        ObjectType::Events,
        ObjectType::Rules,
        ObjectType::Scans,
        ObjectType::Datasets,
    ];

    /// Display name in the status bar.
    fn title(self) -> &'static str {
        match self {
            ObjectType::Findings => "findings",
            ObjectType::Files => "files",
            ObjectType::Indicators => "indicators",
            ObjectType::Events => "events",
            ObjectType::Rules => "rules",
            ObjectType::Scans => "scans",
            ObjectType::Datasets => "datasets",
        }
    }

    /// Record table to list, or `None` for the special findings view.
    fn table(self) -> Option<&'static str> {
        match self {
            ObjectType::Findings => None,
            ObjectType::Files => Some("file"),
            ObjectType::Indicators => Some("indicators"),
            ObjectType::Events => Some("event"),
            ObjectType::Rules => Some("rule"),
            ObjectType::Scans => Some("scan"),
            ObjectType::Datasets => Some("dataset"),
        }
    }

    /// The next/previous type in the cycle (`step` = +1 or -1).
    fn cycle(self, step: isize) -> ObjectType {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0) as isize;
        let n = Self::ALL.len() as isize;
        Self::ALL[(i + step).rem_euclid(n) as usize]
    }

    /// Parse a `:browse <name>` argument.
    fn from_name(name: &str) -> Option<ObjectType> {
        Self::ALL.into_iter().find(|t| t.title() == name)
    }
}

/// One row in a non-findings browse list: a node id, its table, and a label.
struct IndexItem {
    id: String,
    kind: String,
    label: String,
}

/// One node in the navigation stack: its identity plus its rendered view and
/// the edges leading out of it.
struct NavNode {
    id: String,
    kind: String,
    label: String,
    lines: Vec<String>,
    neighbors: Vec<exfil_store::Neighbor>,
}

/// A reversible graph edit. Applying one returns its inverse, which powers the
/// undo/redo stacks — the "editing" half of the graph workbench.
#[derive(Debug, Clone)]
enum EditOp {
    /// Set `field` on `node_id` to `value`.
    SetField {
        node_id: String,
        field: String,
        value: serde_json::Value,
    },
    /// Create (`create=true`) or delete an edge `from -rel-> to`.
    Edge {
        rel: String,
        from: String,
        to: String,
        create: bool,
    },
}

/// The graph navigator's state: a back-stack (breadcrumbs), a forward-stack
/// (redo), the focused pane, scroll, neighbor cursor, and an edit undo/redo
/// history.
struct NavState {
    /// Visited nodes; the last is the current node (the breadcrumb trail).
    stack: Vec<NavNode>,
    /// Nodes stepped back from, for forward navigation.
    forward: Vec<NavNode>,
    /// Vertical scroll of the focused node's field preview.
    scroll: u16,
    /// Cursor into the focused (rightmost) panel's edge list.
    pick: usize,
    /// Inverse ops to replay on undo (newest last).
    undo: Vec<EditOp>,
    /// Inverse ops to replay on redo.
    redo: Vec<EditOp>,
}

impl NavState {
    fn current(&self) -> &NavNode {
        self.stack.last().expect("nav stack never empty")
    }
}

/// What the bottom prompt line is currently collecting, if anything.
enum Prompt {
    /// `:` — a command.
    Command(String),
    /// `/` — a limit (search filter).
    Limit(String),
    /// `c` in the navigator — a `field=value` edit of the current node.
    Edit(String),
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
    /// Which object type the index is browsing.
    browse: ObjectType,
    /// Record ids parallel to `findings`, so a finding row can be edited in
    /// place. Empty when browsing a non-findings section.
    finding_ids: Vec<String>,
    /// Rows for a non-findings browse type (empty when browsing findings).
    items: Vec<IndexItem>,
    /// Selection state for the data-grid index (findings or a browsed table).
    list: TableState,
    mode: Mode,
    /// Content of the pager, built when a finding is opened.
    pager: Vec<String>,
    /// Title shown on the pager's border (what's being viewed).
    pager_title: String,
    /// Height of the main content area from the last draw, for page scrolling.
    page: u16,
    /// Horizontal scroll offset for the pager (`h`/`l`), for wide content.
    pager_col: u16,
    /// Where to return when leaving the `?` help overlay (the mode it was
    /// opened from). `None` for an ordinary pager (rules, a record).
    help_return: Option<Mode>,
    /// Transient one-line message (last action's outcome), mutt's bottom line.
    message: String,
    /// Active `:` or `/` prompt, if the user is typing one.
    prompt: Option<Prompt>,
    /// The active limit, shown in the status bar (empty = all).
    limit: String,
    scan: Option<RunningScan>,
    /// Pluggable viewers that render nodes in the pager and navigator.
    viewers: exfil_view::Registry,
    /// Graph navigator state, present while in [`Mode::Nav`].
    nav: Option<NavState>,
    /// Configurable navigator key bindings.
    keymap: crate::keymap::Keymap,
    /// A pending "open in `$EDITOR`" request `(path, line, col)`, serviced by the
    /// run loop (which can suspend the terminal). `None` when nothing is queued.
    edit_request: Option<(String, u32, u32)>,
    /// Whether the top stats bar is shown (toggle with `t`).
    show_stats: bool,
    /// The record id being edited from the grid (`c`), set while its
    /// `field=value` prompt is open. `None` outside an index edit.
    edit_target: Option<String>,
    quit: bool,
}

impl App {
    /// Build a fresh app over an open store. Shared by [`run`] and tests.
    fn new(store: Store, store_dir: PathBuf, keymap: crate::keymap::Keymap) -> Self {
        App {
            store,
            store_dir,
            findings: Vec::new(),
            finding_ids: Vec::new(),
            browse: ObjectType::Findings,
            items: Vec::new(),
            list: TableState::default(),
            mode: Mode::Index,
            pager: Vec::new(),
            pager_title: String::new(),
            page: 1,
            pager_col: 0,
            help_return: None,
            message: "ready — Tab:type :scan / to limit q to quit".into(),
            prompt: None,
            limit: String::new(),
            scan: None,
            viewers: exfil_view::Registry::new(),
            nav: None,
            keymap,
            edit_request: None,
            show_stats: true,
            edit_target: None,
            quit: false,
        }
    }

    /// Queue the selected finding for opening in `$EDITOR` at its line. The run
    /// loop performs the terminal hand-off; here we only record the request.
    fn request_edit(&mut self) {
        let Some(m) = self.selected() else {
            self.message = "no finding selected".into();
            return;
        };
        let (path, line, col) = (m.path.clone(), m.line, m.col);
        self.message = format!("opening {path} in editor…");
        self.edit_request = Some((path, line, col));
    }

    fn selected(&self) -> Option<&Match> {
        self.list.selected().and_then(|i| self.findings.get(i))
    }

    /// Number of rows in the current index (findings or a browsed table).
    fn index_len(&self) -> usize {
        if self.browse == ObjectType::Findings {
            self.findings.len()
        } else {
            self.items.len()
        }
    }

    fn select_delta(&mut self, delta: isize) {
        let len = self.index_len();
        if len == 0 {
            return;
        }
        let cur = self.list.selected().unwrap_or(0) as isize;
        let max = len as isize - 1;
        self.list
            .select(Some(cur.saturating_add(delta).clamp(0, max) as usize));
    }

    /// Switch the index to another object type and load its rows.
    fn switch_browse(&mut self, handle: &Handle, to: ObjectType) {
        self.browse = to;
        self.refresh_index(handle);
    }

    /// (Re)load the current index: findings honor the active limit; other types
    /// list their whole table (capped).
    fn refresh_index(&mut self, handle: &Handle) {
        match self.browse.table() {
            None => {
                let limit = self.limit.clone();
                self.refresh_findings(handle, &limit);
            }
            Some(table) => match handle.block_on(self.store.list_records(table, 1000)) {
                Ok(rows) => {
                    self.items = rows
                        .into_iter()
                        .map(|(id, label)| IndexItem {
                            kind: table.to_string(),
                            id,
                            label,
                        })
                        .collect();
                    self.list.select((!self.items.is_empty()).then_some(0));
                    self.message = format!("{} {}", self.items.len(), self.browse.title());
                }
                Err(e) => self.message = format!("list failed: {e:#}"),
            },
        }
    }

    /// Open the navigator rooted at the selected browse item (any node type).
    fn open_selected_item(&mut self, handle: &Handle) {
        let Some(item) = self.list.selected().and_then(|i| self.items.get(i)) else {
            self.message = "nothing selected".into();
            return;
        };
        let (id, kind) = (item.id.clone(), item.kind.clone());
        match handle.block_on(self.store.get_record(&id)) {
            Ok(Some(data)) => {
                let node = self.build_nav_node(handle, id, kind, data);
                self.nav = Some(NavState {
                    stack: vec![node],
                    forward: Vec::new(),
                    scroll: 0,
                    pick: 0,
                    undo: Vec::new(),
                    redo: Vec::new(),
                });
                self.mode = Mode::Nav;
            }
            Ok(None) => self.message = format!("no record {id}"),
            Err(e) => self.message = format!("open failed: {e:#}"),
        }
    }

    fn refresh_findings(&mut self, handle: &Handle, query: &str) {
        // Load findings *with* their record ids so a row can be reclassified in
        // place (`c`). `findings_with_ids` doesn't sort, so order worst-first
        // here to match the rest of the UI.
        match handle.block_on(self.store.findings_with_ids(query)) {
            Ok(mut found) => {
                found.sort_by_key(|(_, m)| {
                    std::cmp::Reverse(m.severity.map(|s| s.weight() + 1).unwrap_or(0))
                });
                self.message = format!("{} finding(s)", found.len());
                self.limit = query.to_string();
                self.finding_ids = found.iter().map(|(id, _)| id.clone()).collect();
                self.findings = found.into_iter().map(|(_, m)| m).collect();
                self.list.select((!self.findings.is_empty()).then_some(0));
            }
            Err(e) => self.message = format!("search failed: {e:#}"),
        }
    }

    /// Enter the graph navigator rooted at the selected finding's file (the
    /// natural hub: from it you can hop to the finding, its AST, its container,
    /// and the scans that included it).
    fn open_nav(&mut self, handle: &Handle) {
        let Some(m) = self.selected() else {
            self.message = "no finding selected".into();
            return;
        };
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
        match file {
            Ok(Some(v)) => {
                // A file record's content hash is its key.
                let key = v.get("hash").and_then(|k| k.as_str()).unwrap_or_default();
                let node =
                    self.build_nav_node(handle, format!("file:{key}"), "file".into(), v.clone());
                self.nav = Some(NavState {
                    stack: vec![node],
                    forward: Vec::new(),
                    scroll: 0,
                    pick: 0,
                    undo: Vec::new(),
                    redo: Vec::new(),
                });
                self.mode = Mode::Nav;
            }
            Ok(None) => self.message = format!("no file record for {path}"),
            Err(e) => self.message = format!("lookup failed: {e:#}"),
        }
    }

    /// Open the selected finding's source file in the pager, with every finding
    /// in that file marked in the gutter and the view scrolled to the selected
    /// one. Falls back to the stored snippets when the file can't be read
    /// (deleted, scanned on a remote host, or a virtual archive member).
    fn open_source(&mut self, handle: &Handle) {
        let Some(m) = self.selected() else {
            self.message = "no finding selected".into();
            return;
        };
        let path = m.path.clone();
        let sel_line = m.line;

        // Every finding in this file (not just the current filter/selection),
        // so all of them are marked.
        let in_file = handle
            .block_on(self.store.search_findings(&format!("path={path}")))
            .unwrap_or_default();
        let tag = |s: Option<Severity>| s.map(|s| s.tag()).unwrap_or("-");
        let mut marks: std::collections::BTreeMap<u32, (Option<Severity>, String)> =
            Default::default();
        for f in &in_file {
            if f.line >= 1 {
                marks
                    .entry(f.line)
                    .or_insert_with(|| (f.severity, f.rule.clone()));
            }
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let mut lines: Vec<String> = content
                    .lines()
                    .enumerate()
                    .map(|(i, text)| {
                        let n = i as u32 + 1;
                        match marks.get(&n) {
                            Some((sev, rule)) => {
                                format!("▶{n:>5} │ {text}    ◀ {} [{rule}]", tag(*sev))
                            }
                            None => format!(" {n:>5} │ {text}"),
                        }
                    })
                    .collect();
                if lines.is_empty() {
                    lines.push("(empty file)".into());
                }
                // Scroll so the selected finding sits a few lines below the top.
                let scroll = sel_line.saturating_sub(4).min(u16::MAX as u32) as u16;
                self.pager = lines;
                self.pager_col = 0;
                self.pager_title = format!("{path}  ({} finding(s) marked)", marks.len());
                self.help_return = None;
                self.mode = Mode::Pager(scroll);
                self.message = format!("{}: showing source, {} finding(s)", path, in_file.len());
            }
            Err(e) => {
                let mut lines = vec![
                    format!("cannot read {path}: {e}"),
                    String::new(),
                    "The file may be deleted, on a remote host, or a virtual archive".into(),
                    "member. Showing the stored finding snippets instead:".into(),
                    String::new(),
                ];
                for f in &in_file {
                    lines.push(format!(
                        "{}:{}  {} [{}]  {}",
                        path,
                        f.line,
                        tag(f.severity),
                        f.rule,
                        f.snippet
                    ));
                }
                self.pager = lines;
                self.pager_col = 0;
                self.pager_title = format!("{path} (unreadable)");
                self.help_return = None;
                self.mode = Mode::Pager(0);
            }
        }
    }

    /// Build a navigable node: render its view and load its edges.
    fn build_nav_node(
        &self,
        handle: &Handle,
        id: String,
        kind: String,
        data: serde_json::Value,
    ) -> NavNode {
        let lines = self.viewers.render(&exfil_view::Node::new(
            id.clone(),
            kind.clone(),
            data.clone(),
        ));
        let neighbors = handle
            .block_on(self.store.neighbors(&id))
            .unwrap_or_default();
        let label = exfil_store::node_label(&kind, &data).unwrap_or_else(|| id.clone());
        NavNode {
            id,
            kind,
            label,
            lines,
            neighbors,
        }
    }

    /// Follow the selected neighbor edge to a new current node.
    fn nav_follow(&mut self, handle: &Handle) {
        let Some(nav) = &self.nav else { return };
        let Some(n) = nav.current().neighbors.get(nav.pick).cloned() else {
            return;
        };
        let node = self.build_nav_node(handle, n.id, n.kind, n.data);
        if let Some(nav) = &mut self.nav {
            nav.forward.clear();
            nav.stack.push(node);
            nav.scroll = 0;
            nav.pick = 0;
        }
    }

    /// Step back to the previous node (jumplist).
    fn nav_back(&mut self) {
        if let Some(nav) = &mut self.nav {
            if nav.stack.len() > 1 {
                let popped = nav.stack.pop().expect("len > 1");
                nav.forward.push(popped);
                nav.scroll = 0;
                nav.pick = 0;
            } else {
                // At the root: leave the navigator.
                self.mode = Mode::Index;
            }
        }
    }

    /// Step forward to a node stepped back from.
    fn nav_forward(&mut self) {
        if let Some(nav) = &mut self.nav {
            if let Some(node) = nav.forward.pop() {
                nav.stack.push(node);
                nav.scroll = 0;
                nav.pick = 0;
            }
        }
    }

    /// Rebuild the current node in place (its view and edges) after an edit.
    fn nav_refresh_current(&mut self, handle: &Handle) {
        let Some(nav) = &self.nav else { return };
        let cur = nav.current();
        let node = self.build_nav_node(handle, cur.id.clone(), cur.kind.clone(), Value::Null);
        // build_nav_node re-fetches edges but not data; re-fetch the record.
        let data = handle
            .block_on(self.store.get_record(&node.id))
            .ok()
            .flatten()
            .unwrap_or(Value::Null);
        let refreshed = self.build_nav_node(handle, node.id, node.kind, data);
        if let Some(nav) = &mut self.nav {
            let pick = nav.pick;
            *nav.stack.last_mut().expect("nonempty") = refreshed;
            nav.pick = pick.min(nav.current().neighbors.len().saturating_sub(1));
        }
    }

    /// Apply one edit against the store, returning its inverse (for undo).
    fn apply_edit(&self, handle: &Handle, op: EditOp) -> anyhow::Result<EditOp> {
        match op {
            EditOp::SetField {
                node_id,
                field,
                value,
            } => {
                let old = handle.block_on(self.store.set_field(&node_id, &field, value))?;
                Ok(EditOp::SetField {
                    node_id,
                    field,
                    value: old,
                })
            }
            EditOp::Edge {
                rel,
                from,
                to,
                create,
            } => {
                if create {
                    handle.block_on(self.store.create_edge(&rel, &from, &to))?;
                } else {
                    handle.block_on(self.store.delete_edge(&rel, &from, &to))?;
                }
                Ok(EditOp::Edge {
                    rel,
                    from,
                    to,
                    create: !create,
                })
            }
        }
    }

    /// Perform a user edit: apply it, record the inverse for undo, clear redo.
    fn nav_do(&mut self, handle: &Handle, op: EditOp) {
        match self.apply_edit(handle, op) {
            Ok(inverse) => {
                if let Some(nav) = &mut self.nav {
                    nav.undo.push(inverse);
                    nav.redo.clear();
                }
                self.nav_refresh_current(handle);
                self.message = "edited".into();
            }
            Err(e) => self.message = format!("edit failed: {e:#}"),
        }
    }

    /// Parse a `field=value` string and set that field on the current node.
    fn nav_edit_from_input(&mut self, handle: &Handle, input: &str) {
        let Some((field, value)) = input.split_once('=') else {
            self.message = "expected field=value".into();
            return;
        };
        let Some(nav) = &self.nav else { return };
        let node_id = nav.current().id.clone();
        self.nav_do(
            handle,
            EditOp::SetField {
                node_id,
                field: field.trim().to_string(),
                value: parse_value(value.trim()),
            },
        );
    }

    /// Apply a `field=value` edit to the record selected in the grid (the
    /// `edit_target` set when `c` was pressed): set its severity, add metadata,
    /// or change any field. Persists to the store and reloads the grid.
    fn index_edit_from_input(&mut self, handle: &Handle, input: &str) {
        // `field=value` sets any field; a bare severity word is a shortcut for
        // `severity=<word>` (the common "classify this" case).
        let (field, value) = match input.split_once('=') {
            Some((f, v)) => (f.trim().to_string(), parse_value(v.trim())),
            None => {
                let word = input.trim().to_ascii_lowercase();
                if ["critical", "high", "medium", "low", "info"].contains(&word.as_str()) {
                    ("severity".to_string(), Value::String(word))
                } else {
                    self.message = "expected field=value (or a severity word)".into();
                    return;
                }
            }
        };
        let Some(id) = self.edit_target.take() else {
            self.message = "no record selected to edit".into();
            return;
        };
        match handle.block_on(self.store.set_field(&id, &field, value)) {
            Ok(_) => {
                self.message = format!("set {field} on {id}");
                self.refresh_index(handle);
            }
            Err(e) => self.message = format!("edit failed: {e:#}"),
        }
    }

    /// Delete the currently selected edge to a neighbor.
    fn nav_delete_edge(&mut self, handle: &Handle) {
        let Some(nav) = &self.nav else { return };
        let cur = nav.current();
        let Some(n) = cur.neighbors.get(nav.pick) else {
            return;
        };
        // Store the edge as (in, out) regardless of display direction.
        let (from, to) = if n.outgoing {
            (cur.id.clone(), n.id.clone())
        } else {
            (n.id.clone(), cur.id.clone())
        };
        self.nav_do(
            handle,
            EditOp::Edge {
                rel: n.rel.clone(),
                from,
                to,
                create: false,
            },
        );
    }

    /// Undo the last edit (replays the recorded inverse; pushes to redo).
    fn nav_undo(&mut self, handle: &Handle) {
        let Some(op) = self.nav.as_mut().and_then(|n| n.undo.pop()) else {
            self.message = "nothing to undo".into();
            return;
        };
        match self.apply_edit(handle, op) {
            Ok(inverse) => {
                if let Some(nav) = &mut self.nav {
                    nav.redo.push(inverse);
                }
                self.nav_refresh_current(handle);
                self.message = "undo".into();
            }
            Err(e) => self.message = format!("undo failed: {e:#}"),
        }
    }

    /// Redo the last undone edit.
    fn nav_redo(&mut self, handle: &Handle) {
        let Some(op) = self.nav.as_mut().and_then(|n| n.redo.pop()) else {
            self.message = "nothing to redo".into();
            return;
        };
        match self.apply_edit(handle, op) {
            Ok(inverse) => {
                if let Some(nav) = &mut self.nav {
                    nav.undo.push(inverse);
                }
                self.nav_refresh_current(handle);
                self.message = "redo".into();
            }
            Err(e) => self.message = format!("redo failed: {e:#}"),
        }
    }

    fn execute(&mut self, handle: &Handle, action: Action) {
        match action {
            Action::Quit => self.quit = true,
            Action::Search(q) => self.refresh_findings(handle, &q),
            Action::Rules => {
                self.pager = exfil_scan::builtin_rules()
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
                self.pager_col = 0;
                self.pager_title = "builtin rules".into();
                self.message = "builtin rules".into();
            }
            Action::Get(id) => match handle.block_on(self.store.get_record(&id)) {
                Ok(Some(v)) => {
                    let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
                    self.pager = pretty.lines().map(String::from).collect();
                    self.mode = Mode::Pager(0);
                    self.pager_col = 0;
                    self.pager_title = id.clone();
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
                    let pipeline = exfil_scan::default_pipeline()?;
                    exfil_engine::scan(&root, &pipeline, &store, Some(&store_dir), Some(tx)).await
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
            Action::Browse(to) => self.switch_browse(handle, to),
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

    /// Guidance shown in the index when it has no rows, tailored to why it is
    /// empty: mid-scan, a filtered-out limit, a never-scanned store, or an
    /// empty browsed table.
    fn empty_index_message(&self) -> String {
        if self.scan.is_some() {
            return "Scanning…".into();
        }
        if self.browse == ObjectType::Findings {
            if self.limit.is_empty() {
                "No findings yet.\n\nPress  s  to scan the current directory\n\
                 :  for a command   ·   ?  for help"
                    .into()
            } else {
                format!(
                    "No findings match limit \"{}\".\n\nPress  /  to change the limit   ·   r  to reload",
                    self.limit
                )
            }
        } else {
            format!(
                "No {}.\n\nTab  switches type   ·   :  for a command   ·   ?  for help",
                self.browse.title()
            )
        }
    }

    /// App chrome: an optional top **stats bar**, the **body** (a left menu +
    /// content, or the full-width graph navigator), and a bottom **status bar**
    /// that doubles as the `:` command / `/` filter input line.
    fn draw(&mut self, frame: &mut Frame) {
        let stats_h = if self.show_stats { 1 } else { 0 };
        let [stats, body, statusbar] = Layout::vertical([
            Constraint::Length(stats_h),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        if self.show_stats {
            self.draw_stats(frame, stats);
        }

        match self.mode {
            // The graph navigator owns the full width (it has its own
            // breadcrumb path and cascading columns).
            Mode::Nav => {
                self.page = body.height.saturating_sub(1).max(1);
                self.draw_nav(frame, body);
            }
            // List/pager views get the left menu + a header + content.
            _ => {
                let [sidebar, right] =
                    Layout::horizontal([Constraint::Length(20), Constraint::Min(1)]).areas(body);
                self.draw_sidebar(frame, sidebar);
                let [header, content] =
                    Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(right);
                self.page = content.height.max(1);
                self.draw_header(frame, header);
                self.draw_content(frame, content);
            }
        }

        self.draw_statusbar(frame, statusbar);
    }

    /// The top summary bar: total findings and a colored per-severity tally.
    fn draw_stats(&self, frame: &mut Frame, area: Rect) {
        let counts = severity_counts(&self.findings);
        let mut spans = vec![Span::styled(
            format!(" {} findings ", self.findings.len()),
            Style::default().add_modifier(Modifier::BOLD),
        )];
        for (sev, n) in counts {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                format!("{} {n}", severity_flag(Some(sev))),
                severity_style(Some(sev)).add_modifier(Modifier::BOLD),
            ));
        }
        if let Some(scan) = &self.scan {
            let pct = (scan.done * 100)
                .checked_div(scan.total)
                .unwrap_or(0)
                .min(100);
            spans.push(Span::styled(
                format!("   scanning {}/{} ({pct}%)", scan.done, scan.total),
                Style::default().fg(ACCENT),
            ));
        }
        spans.push(Span::styled(
            "   (t hides)",
            Style::default().add_modifier(Modifier::DIM),
        ));
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// The left navigation menu: object types, the active one highlighted, with
    /// a footer of the most useful keys.
    fn draw_sidebar(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .title(" exfil ")
            .border_style(Style::default().fg(ACCENT))
            .title_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let mut lines: Vec<Line> = Vec::new();
        for t in ObjectType::ALL {
            let name = cap(t.title());
            if t == self.browse {
                lines.push(Line::styled(
                    format!(" ▸ {name} ({}) ", self.index_len()),
                    Style::default()
                        .fg(Color::Black)
                        .bg(ACCENT)
                        .add_modifier(Modifier::BOLD),
                ));
            } else {
                lines.push(Line::raw(format!("   {name}")));
            }
        }
        lines.push(Line::raw(""));
        for hint in ["Tab  switch", "/    filter", ":    command", "?    help"] {
            lines.push(Line::styled(
                format!(" {hint}"),
                Style::default().add_modifier(Modifier::DIM),
            ));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// The content header: what's being viewed, item count, and active limit.
    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let mut text = format!(
            " {} · {} item(s)",
            cap(self.browse.title()),
            self.index_len()
        );
        if self.browse == ObjectType::Findings && !self.limit.is_empty() {
            text.push_str(&format!(" · limit: {}", self.limit));
        }
        if let Some(i) = self.list.selected() {
            text.push_str(&format!("   [{}/{}]", i + 1, self.index_len()));
        }
        frame.render_widget(
            Paragraph::new(Line::styled(
                text,
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
            area,
        );
    }

    /// The main content: the index list, an empty-state cue, or the text pager.
    fn draw_content(&mut self, frame: &mut Frame, area: Rect) {
        match self.mode {
            Mode::Index if self.index_len() == 0 => {
                frame.render_widget(
                    Paragraph::new(self.empty_index_message()).alignment(Alignment::Center),
                    area,
                );
            }
            Mode::Index => {
                let header_style = Style::default().fg(ACCENT).add_modifier(Modifier::BOLD);
                let (header, widths, rows): (Row, Vec<Constraint>, Vec<Row>) =
                    if self.browse == ObjectType::Findings {
                        let rows = self
                            .findings
                            .iter()
                            .map(|m| {
                                Row::new(vec![
                                    Cell::from(severity_flag(m.severity).to_string())
                                        .style(severity_style(m.severity)),
                                    Cell::from(m.rule.clone()),
                                    Cell::from(format!("{}:{}", m.path, m.line)),
                                    Cell::from(m.snippet.clone()),
                                ])
                            })
                            .collect();
                        (
                            Row::new(vec!["S", "RULE", "LOCATION", "MATCH"]).style(header_style),
                            vec![
                                Constraint::Length(1),
                                Constraint::Length(22),
                                Constraint::Length(30),
                                Constraint::Min(10),
                            ],
                            rows,
                        )
                    } else {
                        let rows = self
                            .items
                            .iter()
                            .enumerate()
                            .map(|(i, it)| {
                                Row::new(vec![
                                    Cell::from(format!("{}", i + 1)),
                                    Cell::from(it.label.clone()),
                                ])
                            })
                            .collect();
                        (
                            Row::new(vec![Cell::from("#"), Cell::from(cap(self.browse.title()))])
                                .style(header_style),
                            vec![Constraint::Length(5), Constraint::Min(10)],
                            rows,
                        )
                    };
                let table = Table::new(rows, widths)
                    .header(header)
                    .row_highlight_style(selected_style())
                    .highlight_symbol("▐ ");
                frame.render_stateful_widget(table, area, &mut self.list);
            }
            Mode::Pager(scroll) => {
                let text: Vec<Line> = self.pager.iter().map(|l| Line::raw(l.as_str())).collect();
                let block = Block::bordered()
                    .title(format!(" {} ", self.pager_title))
                    .border_style(Style::default().fg(ACCENT));
                frame.render_widget(
                    Paragraph::new(text)
                        .scroll((scroll, self.pager_col))
                        .block(block),
                    area,
                );
            }
            Mode::Nav => {}
        }
    }

    /// The bottom bar: the `:`/`/` input while a prompt is open, otherwise the
    /// last message plus the current mode's key hints.
    fn draw_statusbar(&self, frame: &mut Frame, area: Rect) {
        let content = match &self.prompt {
            Some(Prompt::Command(s)) => format!(" :{s}▏"),
            Some(Prompt::Limit(s)) => format!(" /{s}▏"),
            Some(Prompt::Edit(s)) => format!(" set field=value: {s}▏"),
            None => {
                let hint = self.mode_hint();
                if self.message.is_empty() {
                    format!(" {hint}")
                } else {
                    format!(" {}   ·   {hint}", self.message)
                }
            }
        };
        frame.render_widget(Paragraph::new(content).style(bar_style()), area);
    }

    /// The key-hint string for the current mode, shown in the status bar.
    fn mode_hint(&self) -> &'static str {
        match self.mode {
            Mode::Index => {
                "Enter:edit-file v:view n:graph c:edit-row /:filter ::cmd Tab:type s:scan ?:help"
            }
            Mode::Pager(_) => "j/k:scroll  g/G:top/bottom  h/l:◂▸  PgUp/PgDn:page  i/q:back",
            Mode::Nav => "j/k:move  l/Enter:into  h/<:back  c:edit  d:del-edge  u/U:undo  q:index",
        }
    }

    /// Open the `?` help overlay, remembering the mode it was opened from so
    /// leaving the pager returns there (the index or the navigator).
    fn open_help(&mut self) {
        self.help_return = Some(self.mode);
        self.pager = help_text();
        self.pager_title = "help".into();
        self.pager_col = 0;
        self.mode = Mode::Pager(0);
        self.message = "help — i or q to return".into();
    }

    fn on_key(&mut self, handle: &Handle, code: KeyCode) {
        // An open prompt captures all typing first (mutt's bottom line).
        if let Some(prompt) = &mut self.prompt {
            let buf = match prompt {
                Prompt::Command(s) | Prompt::Limit(s) | Prompt::Edit(s) => s,
            };
            match code {
                KeyCode::Esc => self.prompt = None,
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Enter => match self.prompt.take().expect("prompt open") {
                    Prompt::Command(s) => self.execute(handle, parse_command(&s)),
                    Prompt::Limit(s) => self.execute(handle, Action::Search(s)),
                    Prompt::Edit(s) => {
                        if matches!(self.mode, Mode::Nav) {
                            self.nav_edit_from_input(handle, &s);
                        } else {
                            self.index_edit_from_input(handle, &s);
                        }
                    }
                },
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
            return;
        }

        // Page size and the pager's last scrollable line, read before the
        // mutable `self.mode` borrow below so both modes can page by a screen.
        let page = self.page.max(1);
        let max_scroll = (self.pager.len() as u16).saturating_sub(page);

        match &mut self.mode {
            Mode::Pager(scroll) => match code {
                KeyCode::Char('q') | KeyCode::Char('i') | KeyCode::Esc => {
                    // Return to where help was opened; ordinary pagers → index.
                    self.mode = self.help_return.take().unwrap_or(Mode::Index);
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    *scroll = scroll.saturating_add(1).min(max_scroll)
                }
                KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::Char('g') | KeyCode::Home => *scroll = 0,
                KeyCode::Char('G') | KeyCode::End => *scroll = max_scroll,
                KeyCode::PageDown => *scroll = scroll.saturating_add(page).min(max_scroll),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(page),
                KeyCode::Char('l') | KeyCode::Right => {
                    self.pager_col = self.pager_col.saturating_add(8)
                }
                KeyCode::Char('h') | KeyCode::Left => {
                    self.pager_col = self.pager_col.saturating_sub(8)
                }
                _ => {}
            },
            Mode::Index => match code {
                KeyCode::Char('q') => self.quit = true,
                KeyCode::Char(':') => self.prompt = Some(Prompt::Command(String::new())),
                KeyCode::Char('/') => self.prompt = Some(Prompt::Limit(String::new())),
                // Esc clears an active limit, restoring the full findings list.
                KeyCode::Esc if self.browse == ObjectType::Findings && !self.limit.is_empty() => {
                    self.refresh_findings(handle, "");
                    self.message = "limit cleared".into();
                }
                KeyCode::Char('j') | KeyCode::Down => self.select_delta(1),
                KeyCode::Char('k') | KeyCode::Up => self.select_delta(-1),
                KeyCode::Char('g') | KeyCode::Home => self.select_delta(isize::MIN + 1),
                KeyCode::Char('G') | KeyCode::End => self.select_delta(isize::MAX),
                KeyCode::PageDown => self.select_delta(page as isize),
                KeyCode::PageUp => self.select_delta(-(page as isize)),
                KeyCode::Tab => {
                    let to = self.browse.cycle(1);
                    self.switch_browse(handle, to);
                }
                KeyCode::BackTab => {
                    let to = self.browse.cycle(-1);
                    self.switch_browse(handle, to);
                }
                KeyCode::Char('r') => self.refresh_index(handle),
                KeyCode::Char('s') => self.execute(handle, Action::Scan(PathBuf::from("."))),
                KeyCode::Char('t') => self.show_stats = !self.show_stats,
                KeyCode::Char('?') => self.open_help(),
                // On a finding: Enter edits it in $EDITOR, `v` shows the source
                // in-TUI, `n` opens the graph navigator. Other types open the
                // selected node directly in the navigator.
                KeyCode::Enter => {
                    if self.browse == ObjectType::Findings {
                        self.request_edit();
                    } else {
                        self.open_selected_item(handle);
                    }
                }
                KeyCode::Char('v') if self.browse == ObjectType::Findings => {
                    self.open_source(handle)
                }
                KeyCode::Char('n') if self.browse == ObjectType::Findings => self.open_nav(handle),
                // `c` edits the selected record in place — set its severity,
                // add metadata, or change any field. Works on findings and on
                // any browsed record (indicators/domains, packages, rules, …).
                KeyCode::Char('c') => {
                    let target = self.list.selected().and_then(|i| {
                        if self.browse == ObjectType::Findings {
                            self.finding_ids.get(i).cloned()
                        } else {
                            self.items.get(i).map(|it| it.id.clone())
                        }
                    });
                    match target {
                        Some(id) => {
                            self.edit_target = Some(id);
                            self.message = "edit: field=value (e.g. severity=high)".into();
                            self.prompt = Some(Prompt::Edit(String::new()));
                        }
                        None => self.message = "nothing selected".into(),
                    }
                }
                _ => {}
            },
            Mode::Nav => self.on_nav_key(handle, code),
        }
    }

    /// Navigator keys: two focusable panes (the node view and its neighbors)
    /// plus back/forward through the jumplist.
    fn on_nav_key(&mut self, handle: &Handle, code: KeyCode) {
        use crate::keymap::NavAction;
        // `?` opens help from the navigator too; leaving it returns here.
        if code == KeyCode::Char('?') {
            self.open_help();
            return;
        }
        let Some(action) = self.keymap.nav_action(code) else {
            return;
        };
        // Focus-independent actions.
        match action {
            NavAction::Quit => {
                self.mode = Mode::Index;
                self.nav = None;
                return;
            }
            NavAction::Back => return self.nav_back(),
            NavAction::Forward => return self.nav_forward(),
            NavAction::Edit => {
                self.prompt = Some(Prompt::Edit(String::new()));
                return;
            }
            NavAction::DeleteEdge => return self.nav_delete_edge(handle),
            NavAction::Undo => return self.nav_undo(handle),
            NavAction::Redo => return self.nav_redo(handle),
            _ => {}
        }

        // Column motions: j/k move the cursor in the focused (rightmost) panel;
        // l/Enter descends into the selected edge (opens a new panel on the
        // right); h/< pops the rightmost panel.
        let Some(nav) = &mut self.nav else { return };
        match action {
            NavAction::Down => {
                let count = nav.current().neighbors.len();
                if count > 0 {
                    nav.pick = (nav.pick + 1).min(count - 1);
                }
            }
            NavAction::Up => nav.pick = nav.pick.saturating_sub(1),
            NavAction::Ascend => self.nav_back(),
            NavAction::Descend => self.nav_follow(handle),
            _ => {}
        }
    }

    /// Render the navigator: breadcrumb, node view, and neighbor list.
    /// Render the graph navigator as **cascading Miller columns**: a breadcrumb
    /// path on top, then one panel per visited node (each listing that node's
    /// edges), right-anchored so the focused panel is widest and older panels to
    /// its left compress — and drop off (onto the breadcrumb) when they no
    /// longer fit. A preview of the focused node's fields sits on the far right.
    fn draw_nav(&self, frame: &mut Frame, area: Rect) {
        let nav = self.nav.as_ref().expect("nav present in Nav mode");
        let [crumb, body] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);

        // Reserve a preview pane on the right when the terminal is wide enough.
        let preview_w = if body.width > 72 { 34u16 } else { 0 };
        let [cols_area, preview_area] =
            Layout::horizontal([Constraint::Min(1), Constraint::Length(preview_w)]).areas(body);

        let n = nav.stack.len();
        let (hidden, widths) = column_layout(n, cols_area.width);

        // Breadcrumb path (leading … when left panels are off-screen).
        let visible_trail = nav.stack[hidden..]
            .iter()
            .map(|x| x.label.as_str())
            .collect::<Vec<_>>()
            .join(" › ");
        let crumb_text = if hidden > 0 {
            format!(" … › {visible_trail}")
        } else {
            format!(" {visible_trail}")
        };
        frame.render_widget(
            Paragraph::new(Line::styled(
                crumb_text,
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
            crumb,
        );

        // One panel per visible node, each a list of that node's edges.
        if !widths.is_empty() {
            let constraints: Vec<Constraint> =
                widths.iter().map(|w| Constraint::Length(*w)).collect();
            let col_areas = Layout::horizontal(constraints).split(cols_area);
            for (i, col_area) in col_areas.iter().enumerate() {
                let idx = hidden + i;
                let node = &nav.stack[idx];
                let is_focused = idx == n - 1;
                let items: Vec<ListItem> = node
                    .neighbors
                    .iter()
                    .map(|nb| {
                        let arrow = if nb.outgoing { "→" } else { "←" };
                        ListItem::new(format!("{arrow} {}:{}", nb.kind, nb.label))
                    })
                    .collect();
                let border = if is_focused {
                    Style::default().fg(ACCENT)
                } else {
                    Style::default().add_modifier(Modifier::DIM)
                };
                let block = Block::bordered()
                    .title(format!(" {} ", node.label))
                    .border_style(border);
                // The focused (rightmost) panel shows a live selection cursor;
                // older panels are dimmed context.
                let mut st = ListState::default();
                if is_focused && !node.neighbors.is_empty() {
                    st.select(Some(nav.pick.min(node.neighbors.len() - 1)));
                }
                let list = List::new(items)
                    .block(block)
                    .highlight_style(selected_style())
                    .highlight_symbol("▸ ");
                frame.render_stateful_widget(list, *col_area, &mut st);
            }
        }

        // Preview of the focused node's rendered fields.
        if preview_w > 0 {
            let cur = nav.current();
            let text: Vec<Line> = cur.lines.iter().map(|l| Line::raw(l.as_str())).collect();
            let block = Block::bordered()
                .title(format!(" {} ", cur.kind))
                .border_style(Style::default().add_modifier(Modifier::DIM));
            frame.render_widget(
                Paragraph::new(text).scroll((nav.scroll, 0)).block(block),
                preview_area,
            );
        }
    }
}

/// Run the TUI until the user quits. Blocking; call from `spawn_blocking`.
pub fn run(handle: Handle, store_dir: &Path, keymap: crate::keymap::Keymap) -> Result<()> {
    let store = handle
        .block_on(Store::open_findings(store_dir))
        .context("open findings store")?;

    let mut app = App::new(store, store_dir.to_path_buf(), keymap);
    app.refresh_findings(&handle, "");

    enable_raw_mode().context("enable raw mode")?;
    crossterm::execute!(std::io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;

    // Always restore the terminal, even if the loop errors. The key source
    // polls crossterm; the loop body itself lives in `event_loop` so it can be
    // tested against a scripted source and a `TestBackend`.
    let result = event_loop(
        &mut app,
        &handle,
        &mut terminal,
        || {
            if crossterm::event::poll(Duration::from_millis(100)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = crossterm::event::read() {
                    if key.kind == KeyEventKind::Press {
                        return Some(key.code);
                    }
                }
            }
            None
        },
        // Hand the terminal to an external editor, then reclaim it. Restoring
        // raw mode + the alternate screen returns us to the TUI where we left.
        |path, line, _col| {
            let _ = disable_raw_mode();
            let _ = crossterm::execute!(std::io::stdout(), LeaveAlternateScreen);
            let outcome = open_editor(path, line);
            enable_raw_mode().ok();
            crossterm::execute!(std::io::stdout(), EnterAlternateScreen).ok();
            outcome
        },
    );

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
    mut edit: impl FnMut(&str, u32, u32) -> Result<()>,
) -> Result<()> {
    while !app.quit {
        app.pump_scan(handle);
        terminal.draw(|f| app.draw(f))?;
        if let Some(code) = next_key() {
            app.on_key(handle, code);
        }
        // Service a queued editor hand-off, then force a full redraw since the
        // child process owned the screen while it ran.
        if let Some((path, line, col)) = app.edit_request.take() {
            match edit(&path, line, col) {
                Ok(()) => app.message = format!("closed editor for {path}"),
                Err(e) => app.message = format!("editor failed: {e:#}"),
            }
            terminal.clear()?;
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
    fn column_layout_right_anchors_and_drops() {
        // Plenty of room: all panels shown, focused (last) is widest.
        let (hidden, widths) = column_layout(3, 200);
        assert_eq!(hidden, 0);
        assert_eq!(widths.len(), 3);
        assert!(
            widths[2] >= widths[1] && widths[1] >= widths[0],
            "focused panel widest: {widths:?}"
        );
        // Tight width: the oldest (leftmost) panels drop off-screen.
        let (hidden, widths) = column_layout(6, 40);
        assert!(hidden > 0, "some panels hidden when cramped");
        assert!(!widths.is_empty(), "the focused panel always shows");
        // A single panel always fits, clamped to the screen.
        let (hidden, widths) = column_layout(1, 10);
        assert_eq!((hidden, widths), (0, vec![10]));
    }

    #[test]
    fn severity_flags() {
        assert_eq!(severity_flag(Some(Severity::Critical)), 'C');
        assert_eq!(severity_flag(Some(Severity::Info)), 'I');
        assert_eq!(severity_flag(None), ' ');
    }

    #[test]
    fn parse_value_types() {
        assert_eq!(parse_value("true"), Value::Bool(true));
        assert_eq!(parse_value("42"), Value::from(42));
        assert_eq!(parse_value("3.5"), Value::from(3.5));
        assert_eq!(
            parse_value("/etc/passwd"),
            Value::String("/etc/passwd".into())
        );
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
            let base = std::env::temp_dir().join(format!("exfil-tui-test-{}", std::process::id()));
            let tree = base.join("tree");
            let store_dir = base.join("store");
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

            // Seed the store by scanning the tree.
            let store = handle.block_on(Store::open_findings(&store_dir)).unwrap();
            let pipeline = exfil_scan::default_pipeline().unwrap();
            handle
                .block_on(exfil_engine::scan(
                    &tree,
                    &pipeline,
                    &store,
                    Some(&store_dir),
                    None,
                ))
                .unwrap();

            let mut app = App::new(store, store_dir.clone(), crate::keymap::Keymap::defaults());
            app.refresh_findings(&handle, "");
            assert!(!app.findings.is_empty(), "seeded findings load");
            assert_eq!(
                app.finding_ids.len(),
                app.findings.len(),
                "findings carry ids for in-place edits"
            );

            // Reclassify a finding from the grid: `c` then a bare severity word
            // (`info`) is the classify shortcut, persisting to its record —
            // findings are editable too, not just browsed records.
            app.list.select(Some(0));
            let fid = app.finding_ids[0].clone();
            app.on_key(&handle, KeyCode::Char('c'));
            type_str(&mut app, &handle, "info");
            app.on_key(&handle, KeyCode::Enter);
            let stored = handle
                .block_on(app.store.get_record(&fid))
                .unwrap()
                .unwrap();
            assert_eq!(stored["severity"], "info", "finding reclassified");

            // Index navigation and a render.
            app.on_key(&handle, KeyCode::Char('j'));
            app.on_key(&handle, KeyCode::Char('k'));
            app.on_key(&handle, KeyCode::Char('G'));
            app.on_key(&handle, KeyCode::Char('g'));
            app.on_key(&handle, KeyCode::Down);
            app.on_key(&handle, KeyCode::Up);
            assert!(
                screen(&mut app).contains("Findings"),
                "sidebar/menu renders"
            );

            // `n` opens the graph navigator (rooted at the finding's file);
            // follow an edge to a neighbor, step back, and forward again.
            app.on_key(&handle, KeyCode::Char('n'));
            assert!(matches!(app.mode, Mode::Nav));
            let nav = app.nav.as_ref().unwrap();
            assert_eq!(nav.current().kind, "file");
            assert!(!nav.current().neighbors.is_empty(), "file has edges");
            let _ = screen(&mut app); // renders breadcrumb + view + edges
            let depth_before = app.nav.as_ref().unwrap().stack.len();
            app.on_key(&handle, KeyCode::Enter); // follow selected neighbor
            assert_eq!(app.nav.as_ref().unwrap().stack.len(), depth_before + 1);
            app.on_key(&handle, KeyCode::Char('<')); // back
            assert_eq!(app.nav.as_ref().unwrap().stack.len(), depth_before);
            app.on_key(&handle, KeyCode::Char('>')); // forward
            assert_eq!(app.nav.as_ref().unwrap().stack.len(), depth_before + 1);

            // Edit a field via the `c` prompt, then undo/redo it.
            app.on_key(&handle, KeyCode::Char('<')); // back to the file node
            let node_id = app.nav.as_ref().unwrap().current().id.clone();
            app.on_key(&handle, KeyCode::Char('c'));
            type_str(&mut app, &handle, "host=edited-host");
            app.on_key(&handle, KeyCode::Enter);
            let host = |app: &App, h: &Handle| {
                h.block_on(app.store.get_record(&node_id)).unwrap().unwrap()["host"]
                    .as_str()
                    .unwrap()
                    .to_string()
            };
            assert_eq!(host(&app, &handle), "edited-host");
            app.on_key(&handle, KeyCode::Char('u')); // undo → original host
            assert_ne!(host(&app, &handle), "edited-host");
            app.on_key(&handle, KeyCode::Char('U')); // redo → edited again
            assert_eq!(host(&app, &handle), "edited-host");

            // Delete the selected edge from the focused panel, then undo it.
            let edges_before = app.nav.as_ref().unwrap().current().neighbors.len();
            app.on_key(&handle, KeyCode::Char('d'));
            assert_eq!(
                app.nav.as_ref().unwrap().current().neighbors.len(),
                edges_before - 1
            );
            app.on_key(&handle, KeyCode::Char('u')); // undo restores the edge
            assert_eq!(
                app.nav.as_ref().unwrap().current().neighbors.len(),
                edges_before
            );

            // `?` opens help from the navigator and returns to it (not the index).
            app.on_key(&handle, KeyCode::Char('?'));
            assert!(matches!(app.mode, Mode::Pager(_)));
            app.on_key(&handle, KeyCode::Char('q'));
            assert!(
                matches!(app.mode, Mode::Nav),
                "help returns to the navigator"
            );

            app.on_key(&handle, KeyCode::Char('q')); // leave navigator
            assert!(matches!(app.mode, Mode::Index));

            // `:rules` command opens the pager with the ruleset.
            app.on_key(&handle, KeyCode::Char(':'));
            type_str(&mut app, &handle, "rules");
            app.on_key(&handle, KeyCode::Enter);
            assert!(matches!(app.mode, Mode::Pager(_)));
            assert!(app.pager.iter().any(|l| l.contains("aws-access-key-id")));
            app.on_key(&handle, KeyCode::Char('i')); // back to index

            // `?` opens the help overlay in the pager, then returns to the index.
            app.on_key(&handle, KeyCode::Char('?'));
            assert!(matches!(app.mode, Mode::Pager(_)));
            assert!(app.pager.iter().any(|l| l.contains("key reference")));
            assert!(screen(&mut app).contains("key reference"), "help renders");
            // Paging: G jumps to the bottom of the (long) help, g back to top.
            let _ = screen(&mut app); // sets the viewport height
            app.on_key(&handle, KeyCode::Char('G'));
            assert!(
                matches!(app.mode, Mode::Pager(s) if s > 0),
                "G scrolls to the bottom"
            );
            app.on_key(&handle, KeyCode::Char('g'));
            assert!(matches!(app.mode, Mode::Pager(0)), "g returns to the top");
            // Horizontal scroll: l moves right, h back to the left edge.
            app.on_key(&handle, KeyCode::Char('l'));
            assert!(app.pager_col > 0, "l scrolls right");
            app.on_key(&handle, KeyCode::Char('h'));
            assert_eq!(app.pager_col, 0, "h scrolls back to the left");
            app.on_key(&handle, KeyCode::Char('q')); // back to index
            assert!(matches!(app.mode, Mode::Index));

            // `/severity=low` limits to nothing; the limit shows in the status.
            app.on_key(&handle, KeyCode::Char('/'));
            type_str(&mut app, &handle, "severity=low");
            app.on_key(&handle, KeyCode::Enter);
            assert!(app.findings.is_empty());
            assert_eq!(app.limit, "severity=low");
            app.on_key(&handle, KeyCode::Char('r')); // reload keeps the limit
            assert_eq!(app.limit, "severity=low");

            // Esc clears the active limit and restores the full list.
            app.on_key(&handle, KeyCode::Esc);
            assert_eq!(app.limit, "");
            assert!(!app.findings.is_empty(), "limit cleared restores findings");

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
            app.open_nav(&handle);
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
    async fn browser_switches_types_and_opens_any_node() {
        let handle = Handle::current();
        tokio::task::spawn_blocking(move || {
            let base =
                std::env::temp_dir().join(format!("exfil-tui-browse-{}", std::process::id()));
            let tree = base.join("tree");
            let store_dir = base.join("store");
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&tree).unwrap();
            // Content with a secret (finding) and observables (indicators).
            std::fs::write(
                tree.join("app.env"),
                "AWS=AKIA0123456789ABCDEF\nURL=https://evil.example.com\nIP=203.0.113.9\n",
            )
            .unwrap();

            let store = handle.block_on(Store::open_findings(&store_dir)).unwrap();
            let pipeline = exfil_scan::default_pipeline().unwrap();
            handle
                .block_on(exfil_engine::scan(
                    &tree,
                    &pipeline,
                    &store,
                    Some(&store_dir),
                    None,
                ))
                .unwrap();

            let mut app = App::new(store, store_dir.clone(), crate::keymap::Keymap::defaults());
            app.refresh_index(&handle); // findings by default
            assert_eq!(app.browse, ObjectType::Findings);
            assert!(!app.findings.is_empty());

            // Tab cycles Findings → Files; the file table lists the scanned file.
            app.on_key(&handle, KeyCode::Tab);
            assert_eq!(app.browse, ObjectType::Files);
            assert!(!app.items.is_empty(), "files listed");
            assert!(
                app.items.iter().any(|i| i.label.ends_with("app.env")),
                "{:?}",
                app.items.iter().map(|i| &i.label).collect::<Vec<_>>()
            );
            assert!(screen(&mut app).contains("Files"), "sidebar shows type");

            // Opening a file node enters the navigator rooted at it.
            app.on_key(&handle, KeyCode::Enter);
            assert!(matches!(app.mode, Mode::Nav));
            assert_eq!(app.nav.as_ref().unwrap().current().kind, "file");
            app.on_key(&handle, KeyCode::Char('q'));

            // `:browse indicators` jumps directly; the node opens and renders.
            app.execute(&handle, Action::Browse(ObjectType::Indicators));
            assert_eq!(app.browse, ObjectType::Indicators);
            assert!(!app.items.is_empty(), "indicators listed");

            // Classify the selected record from the grid: `c` then `severity=high`
            // persists the field, so the store record carries the classification.
            app.list.select(Some(0));
            let rec_id = app.items[0].id.clone();
            app.on_key(&handle, KeyCode::Char('c'));
            assert!(
                matches!(app.prompt, Some(Prompt::Edit(_))),
                "edit prompt opens"
            );
            type_str(&mut app, &handle, "severity=high");
            app.on_key(&handle, KeyCode::Enter);
            let stored = handle
                .block_on(app.store.get_record(&rec_id))
                .unwrap()
                .unwrap();
            assert_eq!(stored["severity"], "high", "classification persisted");

            app.on_key(&handle, KeyCode::Enter);
            assert_eq!(app.nav.as_ref().unwrap().current().kind, "indicators");
            // The indicators viewer shows the extracted observables.
            let view = app.nav.as_ref().unwrap().current().lines.join("\n");
            assert!(
                view.contains("evil.example.com") || view.contains("203.0.113.9"),
                "{view}"
            );
            app.on_key(&handle, KeyCode::Char('q'));

            // BackTab cycles the other way; an unknown browse name is rejected.
            app.on_key(&handle, KeyCode::BackTab);
            assert!(matches!(
                parse_command("browse files"),
                Action::Browse(ObjectType::Files)
            ));
            assert!(matches!(parse_command("browse nope"), Action::Invalid(_)));

            let _ = std::fs::remove_dir_all(&base);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn event_loop_runs_until_quit() {
        let handle = Handle::current();
        tokio::task::spawn_blocking(move || {
            let dir = std::env::temp_dir().join(format!("exfil-tui-loop-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let store = handle.block_on(Store::open_findings(&dir)).unwrap();
            let mut app = App::new(store, dir.clone(), crate::keymap::Keymap::defaults());

            // A fresh store has no findings; the index shows onboarding guidance
            // rather than a blank screen.
            assert!(
                screen(&mut app).contains("No findings yet"),
                "empty-state guidance renders"
            );

            // Scripted keys: move down, open a prompt and cancel it, then quit.
            let mut keys = vec![
                KeyCode::Char('j'),
                KeyCode::Char(':'),
                KeyCode::Esc,
                KeyCode::Char('q'),
            ]
            .into_iter();
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            event_loop(
                &mut app,
                &handle,
                &mut terminal,
                || keys.next(),
                |_p, _l, _c| Ok(()),
            )
            .unwrap();
            assert!(app.quit, "loop exits when quit is set");

            let _ = std::fs::remove_dir_all(&dir);
        })
        .await
        .unwrap();
    }
}
