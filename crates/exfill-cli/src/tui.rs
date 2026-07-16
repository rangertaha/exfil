//! `exfill tui` — a mutt-style, full-screen workbench over the findings graph.
//!
//! The layout follows mutt: a one-line **help bar** at the top, the full-width
//! **index** of findings below it, a reverse-video **status bar**, and a
//! **message/prompt line** at the very bottom. `Enter` opens the selected
//! finding in the **graph navigator**, and `q`/`i` returns to the index.
//!
//! ## Keys (index)
//!
//! - `j`/`k`, arrows — move; `g`/`G` — first/last
//! - `Enter` — open the finding's file in the graph navigator
//! - `/` — *limit* the index (mutt-style filter): empty shows all,
//!   `severity=high`, `cwe=CWE-798`, `path=...`, or free text on rule names
//! - `:` — command: `scan [path]`, `rules`, `get <id>`, `clean`, `quit`
//! - `s` — scan the current directory (shortcut for `:scan .`)
//! - `r` — reload findings from the store
//! - `q` — quit
//!
//! ## Keys (graph navigator)
//!
//! Two panes — the node's rendered view (via the pluggable viewers) and its
//! **edges** (neighbors). Vim-style motions follow edges through the graph:
//!
//! - `j`/`k` — scroll the view / move the edge cursor (depending on focus)
//! - `h`/`l` (or `Tab`, arrows) — switch focus between view and edges
//! - `Enter`/`l` on an edge — **follow it** to the neighbor node
//! - `<` / `>` (or `Backspace`) — back / forward through the jumplist
//! - `c` — edit a field of the current node (`field=value`)
//! - `d` (on an edge) — delete that edge
//! - `u` / `U` — undo / redo the last edit
//! - `q`/`i`/`Esc` — return to the index (or step back at the root)
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
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use ratatui::{Frame, Terminal};
use serde_json::Value;

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
    Rules,
    Scans,
    Datasets,
}

impl ObjectType {
    /// Browse order for the `Tab` cycle.
    const ALL: [ObjectType; 6] = [
        ObjectType::Findings,
        ObjectType::Files,
        ObjectType::Indicators,
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

/// Which pane the navigator's keys act on.
#[derive(PartialEq)]
enum NavFocus {
    /// The node's rendered content (scroll with j/k).
    View,
    /// The neighbor list (move with j/k, follow with Enter).
    Neighbors,
}

/// One node in the navigation stack: its identity plus its rendered view and
/// the edges leading out of it.
struct NavNode {
    id: String,
    kind: String,
    label: String,
    lines: Vec<String>,
    neighbors: Vec<exfill_store::Neighbor>,
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
    focus: NavFocus,
    scroll: u16,
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
    /// Rows for a non-findings browse type (empty when browsing findings).
    items: Vec<IndexItem>,
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
    /// Pluggable viewers that render nodes in the pager and navigator.
    viewers: exfill_view::Registry,
    /// Graph navigator state, present while in [`Mode::Nav`].
    nav: Option<NavState>,
    /// Configurable navigator key bindings.
    keymap: crate::keymap::Keymap,
    quit: bool,
}

impl App {
    /// Build a fresh app over an open store. Shared by [`run`] and tests.
    fn new(store: Store, store_dir: PathBuf, keymap: crate::keymap::Keymap) -> Self {
        App {
            store,
            store_dir,
            findings: Vec::new(),
            browse: ObjectType::Findings,
            items: Vec::new(),
            list: ListState::default(),
            mode: Mode::Index,
            pager: Vec::new(),
            message: "ready — Tab:type :scan / to limit q to quit".into(),
            prompt: None,
            limit: String::new(),
            scan: None,
            viewers: exfill_view::Registry::new(),
            nav: None,
            keymap,
            quit: false,
        }
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
                    focus: NavFocus::Neighbors,
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
                    focus: NavFocus::Neighbors,
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

    /// Build a navigable node: render its view and load its edges.
    fn build_nav_node(
        &self,
        handle: &Handle,
        id: String,
        kind: String,
        data: serde_json::Value,
    ) -> NavNode {
        let lines = self.viewers.render(&exfill_view::Node::new(
            id.clone(),
            kind.clone(),
            data.clone(),
        ));
        let neighbors = handle
            .block_on(self.store.neighbors(&id))
            .unwrap_or_default();
        let label = exfill_store::node_label(&kind, &data).unwrap_or_else(|| id.clone());
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
            nav.focus = NavFocus::Neighbors;
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

    /// The reverse-video status bar, mutt's `-*-` line.
    fn status_line(&self) -> String {
        let mut parts = vec![format!(
            "exfill: {} {}",
            self.index_len(),
            self.browse.title()
        )];
        if self.browse == ObjectType::Findings && !self.limit.is_empty() {
            parts.push(format!("limit: {}", self.limit));
        }
        if self.browse == ObjectType::Findings {
            let counts = severity_counts(&self.findings)
                .into_iter()
                .map(|(s, n)| format!("{}:{n}", severity_flag(Some(s))))
                .collect::<Vec<_>>()
                .join(" ");
            if !counts.is_empty() {
                parts.push(format!("[{counts}]"));
            }
        }
        if let Some(scan) = &self.scan {
            parts.push(format!("scanning {}/{} files", scan.done, scan.total));
        }
        if let Some(i) = self.list.selected() {
            parts.push(format!("({}/{})", i + 1, self.index_len()));
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
                "q:Quit j/k:Move Tab:Type Enter:Open /:Limit ::Cmd s:Scan r:Reload g/G:First/Last"
            }
            Mode::Pager(_) => "i:Exit  j/k:Scroll  q:Index",
            Mode::Nav => {
                "q:Index j/k:Move h/l:Pane Enter:Follow </>:Back c:Edit d:DelEdge u/U:Undo/Redo"
            }
        };
        frame.render_widget(Paragraph::new(help_text).style(reversed), help);

        // Main area: index, text pager, or graph navigator.
        match self.mode {
            Mode::Index => {
                let rows: Vec<ListItem> = if self.browse == ObjectType::Findings {
                    self.findings
                        .iter()
                        .enumerate()
                        .map(|(i, m)| ListItem::new(index_row(i + 1, m)))
                        .collect()
                } else {
                    self.items
                        .iter()
                        .enumerate()
                        .map(|(i, it)| ListItem::new(format!("{:>4}  {}", i + 1, it.label)))
                        .collect()
                };
                let list = List::new(rows).highlight_style(reversed);
                frame.render_stateful_widget(list, main, &mut self.list);
            }
            Mode::Pager(scroll) => {
                let text: Vec<Line> = self.pager.iter().map(|l| Line::raw(l.as_str())).collect();
                frame.render_widget(Paragraph::new(text).scroll((scroll, 0)), main);
            }
            Mode::Nav => self.draw_nav(frame, main),
        }

        // Status bar (reverse video) + message/prompt line.
        frame.render_widget(Paragraph::new(self.status_line()).style(reversed), status);
        let bottom = match &self.prompt {
            Some(Prompt::Command(s)) => format!(":{s}▏"),
            Some(Prompt::Limit(s)) => format!("/{s}▏"),
            Some(Prompt::Edit(s)) => format!("set field=value: {s}▏"),
            None => self.message.clone(),
        };
        frame.render_widget(Paragraph::new(bottom), msg);
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
                    Prompt::Edit(s) => self.nav_edit_from_input(handle, &s),
                },
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
                // Findings root the navigator at their file; other types open
                // the selected node directly.
                KeyCode::Enter => {
                    if self.browse == ObjectType::Findings {
                        self.open_nav(handle);
                    } else {
                        self.open_selected_item(handle);
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

        // Motions, interpreted relative to the focused pane.
        let Some(nav) = &mut self.nav else { return };
        match (&nav.focus, action) {
            (NavFocus::View, NavAction::Down) => nav.scroll = nav.scroll.saturating_add(1),
            (NavFocus::View, NavAction::Up) => nav.scroll = nav.scroll.saturating_sub(1),
            (NavFocus::View, NavAction::Descend) => nav.focus = NavFocus::Neighbors,
            (NavFocus::View, NavAction::Ascend) => self.nav_back(),
            (NavFocus::Neighbors, NavAction::Down) => {
                let count = nav.current().neighbors.len();
                if count > 0 {
                    nav.pick = (nav.pick + 1).min(count - 1);
                }
            }
            (NavFocus::Neighbors, NavAction::Up) => nav.pick = nav.pick.saturating_sub(1),
            (NavFocus::Neighbors, NavAction::Ascend) => nav.focus = NavFocus::View,
            (NavFocus::Neighbors, NavAction::Descend) => self.nav_follow(handle),
            _ => {}
        }
    }

    /// Render the navigator: breadcrumb, node view, and neighbor list.
    fn draw_nav(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let nav = self.nav.as_ref().expect("nav present in Nav mode");
        let reversed = Style::default().add_modifier(Modifier::REVERSED);
        let [crumb, panes] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);

        // Breadcrumb trail of visited nodes.
        let trail = nav
            .stack
            .iter()
            .map(|n| n.label.as_str())
            .collect::<Vec<_>>()
            .join(" › ");
        frame.render_widget(Paragraph::new(format!("◆ {trail}")), crumb);

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                .areas(panes);

        // Node view (left).
        let view_focused = nav.focus == NavFocus::View;
        let view_title = format!(" {} · {} ", nav.current().kind, nav.current().id);
        let text: Vec<Line> = nav
            .current()
            .lines
            .iter()
            .map(|l| Line::raw(l.as_str()))
            .collect();
        frame.render_widget(
            Paragraph::new(text)
                .scroll((nav.scroll, 0))
                .block(bordered_focus(&view_title, view_focused)),
            left,
        );

        // Neighbor list (right).
        let items: Vec<ListItem> = nav
            .current()
            .neighbors
            .iter()
            .map(|n| {
                let arrow = if n.outgoing { "→" } else { "←" };
                ListItem::new(format!("{arrow} {:<12} {}:{}", n.rel, n.kind, n.label))
            })
            .collect();
        let mut list_state = ListState::default();
        if !nav.current().neighbors.is_empty() {
            list_state.select(Some(nav.pick.min(nav.current().neighbors.len() - 1)));
        }
        let title = format!(" edges ({}) ", nav.current().neighbors.len());
        let list = List::new(items)
            .block(bordered_focus(&title, nav.focus == NavFocus::Neighbors))
            .highlight_style(reversed);
        frame.render_stateful_widget(list, right, &mut list_state);
    }
}

/// A bordered block whose title marks focus.
fn bordered_focus(title: &str, focused: bool) -> Block<'_> {
    let mark = if focused { "●" } else { "○" };
    Block::bordered().title(format!("{mark}{title}"))
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

            let mut app = App::new(store, store_dir.clone(), crate::keymap::Keymap::defaults());
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

            // Enter the graph navigator (rooted at the finding's file), follow
            // an edge to a neighbor, step back, and leave.
            app.on_key(&handle, KeyCode::Enter);
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

            // Delete an edge from the neighbor pane, then undo it.
            app.on_key(&handle, KeyCode::Char('l')); // focus neighbors
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

            app.on_key(&handle, KeyCode::Char('q')); // leave navigator
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
                std::env::temp_dir().join(format!("exfill-tui-browse-{}", std::process::id()));
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
            assert!(screen(&mut app).contains("files"), "status shows type");

            // Opening a file node enters the navigator rooted at it.
            app.on_key(&handle, KeyCode::Enter);
            assert!(matches!(app.mode, Mode::Nav));
            assert_eq!(app.nav.as_ref().unwrap().current().kind, "file");
            app.on_key(&handle, KeyCode::Char('q'));

            // `:browse indicators` jumps directly; the node opens and renders.
            app.execute(&handle, Action::Browse(ObjectType::Indicators));
            assert_eq!(app.browse, ObjectType::Indicators);
            assert!(!app.items.is_empty(), "indicators listed");
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
            let dir = std::env::temp_dir().join(format!("exfill-tui-loop-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let store = handle.block_on(Store::open_findings(&dir)).unwrap();
            let mut app = App::new(store, dir.clone(), crate::keymap::Keymap::defaults());

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
