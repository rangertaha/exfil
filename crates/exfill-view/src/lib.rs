//! Pluggable viewers — the "preview pane" layer for a graph workbench.
//!
//! A [`Node`] is any graph record (a finding, file, ast, rule, …) carrying its
//! kind and its JSON data. A [`Viewer`] renders one kind of node into display
//! lines; a [`Registry`] dispatches a node to the first viewer that
//! [`handles`](Viewer::handles) it, falling back to a JSON dump. This is the
//! same registry pattern the scanners and sources use, so new node types get a
//! viewer without touching the navigator — the yazi-style "different preview
//! per file type", generalized to graph nodes.
//!
//! Viewers render from the node's stored data alone (pure, terminal-agnostic,
//! trivially testable). A future content-preview viewer can read a file's
//! bytes off disk for a hexdump; that's an additive viewer, not a change here.

use serde_json::Value;

/// A graph node to display: its id, kind tag, and record data.
#[derive(Debug, Clone)]
pub struct Node {
    /// Full record id, e.g. `finding:…` or `file:<hash>`.
    pub id: String,
    /// Node kind: `finding`, `file`, `ast`, `rule`, `dataset`, ….
    pub kind: String,
    /// The record's fields as JSON.
    pub data: Value,
}

impl Node {
    /// Construct a node from an id, kind, and JSON data.
    pub fn new(id: impl Into<String>, kind: impl Into<String>, data: Value) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            data,
        }
    }

    /// A string field from the node's data, or `""`.
    fn field(&self, key: &str) -> &str {
        self.data.get(key).and_then(Value::as_str).unwrap_or("")
    }
}

/// Renders one class of node into display lines.
pub trait Viewer: Send + Sync {
    /// Stable identifier, shown in the status line and config.
    fn name(&self) -> &str;

    /// Whether this viewer renders nodes of `kind`.
    fn handles(&self, kind: &str) -> bool;

    /// Render `node` to display lines (no ANSI; the caller styles).
    fn render(&self, node: &Node) -> Vec<String>;
}

/// An ordered set of viewers with a JSON fallback.
pub struct Registry {
    viewers: Vec<Box<dyn Viewer>>,
}

impl Registry {
    /// The default viewer lineup: finding, file, ast, rule.
    pub fn new() -> Self {
        Self {
            viewers: vec![
                Box::new(FindingViewer),
                Box::new(FileViewer),
                Box::new(AstViewer),
                Box::new(RuleViewer),
            ],
        }
    }

    /// Register an additional viewer (checked before the built-ins that follow
    /// it, after those already registered).
    pub fn register(&mut self, viewer: Box<dyn Viewer>) {
        self.viewers.push(viewer);
    }

    /// The name of the viewer that would handle `kind`, or `"json"` fallback.
    pub fn viewer_for(&self, kind: &str) -> &str {
        self.viewers
            .iter()
            .find(|v| v.handles(kind))
            .map(|v| v.name())
            .unwrap_or("json")
    }

    /// Render `node` with the first handling viewer, or a pretty JSON dump.
    pub fn render(&self, node: &Node) -> Vec<String> {
        for v in &self.viewers {
            if v.handles(&node.kind) {
                return v.render(node);
            }
        }
        json_lines(node)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Pretty-print a node's JSON as fallback display lines.
fn json_lines(node: &Node) -> Vec<String> {
    let mut out = vec![format!("[{}] {}", node.kind, node.id)];
    match serde_json::to_string_pretty(&node.data) {
        Ok(s) => out.extend(s.lines().map(String::from)),
        Err(_) => out.push("<unrenderable>".into()),
    }
    out
}

/// Viewer for `finding` nodes: the rule, location, classification, snippet.
pub struct FindingViewer;

impl Viewer for FindingViewer {
    fn name(&self) -> &str {
        "finding"
    }
    fn handles(&self, kind: &str) -> bool {
        kind == "finding"
    }
    fn render(&self, node: &Node) -> Vec<String> {
        let d = &node.data;
        let num = |k: &str| d.get(k).and_then(Value::as_u64).unwrap_or(0);
        vec![
            format!("Rule:     {}", node.field("rule")),
            format!("Path:     {}", node.field("path")),
            format!("Location: line {}, column {}", num("line"), num("col")),
            format!("Severity: {}", node.field("severity")),
            format!("CWE:      {}", opt(node.field("cwe"))),
            format!("CVE:      {}", opt(node.field("cve"))),
            String::new(),
            format!("> {}", node.field("snippet")),
        ]
    }
}

/// Viewer for `file` nodes: path, host, size, ownership, content hash.
pub struct FileViewer;

impl Viewer for FileViewer {
    fn name(&self) -> &str {
        "file"
    }
    fn handles(&self, kind: &str) -> bool {
        kind == "file"
    }
    fn render(&self, node: &Node) -> Vec<String> {
        let d = &node.data;
        let num = |k: &str| d.get(k).and_then(Value::as_u64).unwrap_or(0);
        vec![
            format!("Path:  {}", node.field("path")),
            format!("Host:  {}", node.field("host")),
            format!("Size:  {} bytes", num("size")),
            format!("Mode:  {:o}", num("mode")),
            format!("Owner: {}:{}", num("uid"), num("gid")),
            format!("Hash:  {}", node.field("hash")),
        ]
    }
}

/// Viewer for `ast` nodes: the language and its extracted symbols.
pub struct AstViewer;

impl Viewer for AstViewer {
    fn name(&self) -> &str {
        "ast"
    }
    fn handles(&self, kind: &str) -> bool {
        kind == "ast"
    }
    fn render(&self, node: &Node) -> Vec<String> {
        let mut out = vec![format!("Language: {}", node.field("lang")), String::new()];
        if let Some(symbols) = node.data.get("symbols").and_then(Value::as_array) {
            out.push(format!("Symbols ({}):", symbols.len()));
            for s in symbols {
                let kind = s.get("kind").and_then(Value::as_str).unwrap_or("?");
                let name = s.get("name").and_then(Value::as_str).unwrap_or("?");
                let line = s.get("line").and_then(Value::as_u64).unwrap_or(0);
                out.push(format!("  {kind:<10} {name}  (line {line})"));
            }
        }
        out
    }
}

/// Viewer for `rule` nodes: name, pattern, classification.
pub struct RuleViewer;

impl Viewer for RuleViewer {
    fn name(&self) -> &str {
        "rule"
    }
    fn handles(&self, kind: &str) -> bool {
        kind == "rule"
    }
    fn render(&self, node: &Node) -> Vec<String> {
        vec![
            format!("Rule:     {}", node.field("name")),
            format!("Severity: {}", opt(node.field("severity"))),
            format!("CWE:      {}", opt(node.field("cwe"))),
            String::new(),
            format!("Pattern:  {}", node.field("pattern")),
            String::new(),
            node.field("description").to_string(),
        ]
    }
}

/// Render an empty string as `-`.
fn opt(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dispatches_by_kind() {
        let reg = Registry::new();
        assert_eq!(reg.viewer_for("finding"), "finding");
        assert_eq!(reg.viewer_for("file"), "file");
        assert_eq!(reg.viewer_for("ast"), "ast");
        assert_eq!(reg.viewer_for("rule"), "rule");
        assert_eq!(reg.viewer_for("dataset"), "json"); // fallback
    }

    #[test]
    fn finding_viewer_renders_fields() {
        let node = Node::new(
            "finding:1",
            "finding",
            json!({"rule":"aws-key","path":"a.env","line":2,"col":5,
                   "severity":"critical","cwe":"CWE-798","snippet":"KEY=..."}),
        );
        let lines = Registry::new().render(&node);
        assert!(lines.iter().any(|l| l.contains("Rule:     aws-key")));
        assert!(lines.iter().any(|l| l.contains("line 2, column 5")));
        assert!(lines.iter().any(|l| l.contains("CWE-798")));
        assert!(lines.iter().any(|l| l.contains("> KEY=...")));
    }

    #[test]
    fn file_viewer_formats_mode_octal() {
        let node = Node::new(
            "file:abc",
            "file",
            json!({"path":"/x","host":"h","size":42,"mode":420,"uid":1000,"gid":1000,"hash":"abc"}),
        );
        let lines = Registry::new().render(&node);
        assert!(lines.iter().any(|l| l.contains("Size:  42 bytes")));
        assert!(lines.iter().any(|l| l.contains("Mode:  644")), "{lines:?}");
    }

    #[test]
    fn ast_viewer_lists_symbols() {
        let node = Node::new(
            "ast:x",
            "ast",
            json!({"lang":"python","symbols":[
                {"kind":"call","name":"os.system","line":3}]}),
        );
        let lines = Registry::new().render(&node);
        assert!(lines.iter().any(|l| l.contains("Language: python")));
        assert!(lines
            .iter()
            .any(|l| l.contains("os.system") && l.contains("line 3")));
    }

    #[test]
    fn unknown_kind_falls_back_to_json() {
        let node = Node::new("dataset:sec", "dataset", json!({"name":"security"}));
        let lines = Registry::new().render(&node);
        assert!(lines[0].contains("[dataset] dataset:sec"));
        assert!(lines.iter().any(|l| l.contains("\"name\": \"security\"")));
    }

    #[test]
    fn custom_viewer_takes_precedence_for_its_kind() {
        struct HexViewer;
        impl Viewer for HexViewer {
            fn name(&self) -> &str {
                "hex"
            }
            fn handles(&self, kind: &str) -> bool {
                kind == "blob"
            }
            fn render(&self, _n: &Node) -> Vec<String> {
                vec!["00 01 02".into()]
            }
        }
        let mut reg = Registry::new();
        reg.register(Box::new(HexViewer));
        assert_eq!(reg.viewer_for("blob"), "hex");
        let node = Node::new("blob:1", "blob", json!({}));
        assert_eq!(reg.render(&node), vec!["00 01 02".to_string()]);
    }
}
