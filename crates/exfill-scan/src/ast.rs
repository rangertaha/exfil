//! Structural analysis: parse source with tree-sitter and reason over its
//! syntax tree instead of raw text.
//!
//! Two tasks make the DAG's `Bytes → Ast → Matches` chain concrete:
//!
//! - [`AstExtractor`] (`Bytes → Ast`) parses a supported source file and pulls
//!   out its call sites and function definitions as [`Symbol`]s.
//! - [`DangerousCallScanner`] (`Ast → Matches`) flags calls to dangerous sinks
//!   (`eval`, `os.system`, `child_process.exec`, …) — a text regex can't tell a
//!   real call from the same word in a comment or string, but the parse tree
//!   can.
//!
//! The [`Pipeline`](exfill_task::Pipeline) schedules the extractor before the
//! scanner automatically, purely from their declared artifact kinds — nobody
//! wires them together by hand.
//!
//! Languages today: Python and JavaScript. Adding one is a single [`LangSpec`]
//! entry (a grammar plus the two node-kind names its calls and functions use).

use std::path::Path;

use anyhow::Result;
use exfill_core::{Match, Severity, Symbol};
use exfill_task::{Artifact, ArtifactKind, Ast, FileTask};
use tree_sitter::{Node, Parser};

/// A supported language: how to load its grammar and the node kinds that name
/// its call expressions and function definitions.
struct LangSpec {
    /// Language tag stored on the [`Ast`].
    lang: &'static str,
    /// File extensions that select this language.
    extensions: &'static [&'static str],
    /// Load the tree-sitter grammar.
    language: fn() -> tree_sitter::Language,
    /// Grammar node kind for a call expression (its `function` field is the
    /// callee).
    call_kind: &'static str,
    /// Grammar node kind for a function definition (its `name` field).
    func_kind: &'static str,
}

/// The languages this build understands.
fn specs() -> &'static [LangSpec] {
    &[
        LangSpec {
            lang: "python",
            extensions: &["py", "pyi"],
            language: || tree_sitter_python::LANGUAGE.into(),
            call_kind: "call",
            func_kind: "function_definition",
        },
        LangSpec {
            lang: "javascript",
            extensions: &["js", "jsx", "mjs", "cjs"],
            language: || tree_sitter_javascript::LANGUAGE.into(),
            call_kind: "call_expression",
            func_kind: "function_declaration",
        },
    ]
}

/// The language spec for a path's extension, if supported.
fn spec_for(path: &Path) -> Option<&'static LangSpec> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    specs()
        .iter()
        .find(|s| s.extensions.contains(&ext.as_str()))
}

/// Parses supported source files into an [`Ast`] of call and function symbols.
pub struct AstExtractor;

impl AstExtractor {
    /// Parse `content` under `spec` and collect its symbols.
    fn extract(spec: &LangSpec, content: &[u8]) -> Ast {
        let mut parser = Parser::new();
        if parser.set_language(&(spec.language)()).is_err() {
            return Ast::default();
        }
        let Some(tree) = parser.parse(content, None) else {
            return Ast::default();
        };
        let mut symbols = Vec::new();
        walk(tree.root_node(), content, spec, &mut symbols);
        Ast {
            lang: spec.lang.to_string(),
            symbols,
        }
    }
}

/// Depth-first walk collecting call and function-definition symbols. A call's
/// name is the full callee text (`os.system`, `child_process.exec`), so dotted
/// sinks are recognizable downstream.
fn walk(node: Node, src: &[u8], spec: &LangSpec, out: &mut Vec<Symbol>) {
    let kind = node.kind();
    if kind == spec.call_kind {
        if let Some(callee) = node.child_by_field_name("function") {
            if let Ok(name) = callee.utf8_text(src) {
                out.push(Symbol {
                    kind: "call".into(),
                    name: name.to_string(),
                    line: callee.start_position().row as u32 + 1,
                });
            }
        }
    } else if kind == spec.func_kind {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(src) {
                out.push(Symbol {
                    kind: "function".into(),
                    name: name.to_string(),
                    line: name_node.start_position().row as u32 + 1,
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, src, spec, out);
    }
}

impl FileTask for AstExtractor {
    fn name(&self) -> &str {
        "ast"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Bytes
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Ast
    }

    fn applies(&self, path: &Path) -> bool {
        spec_for(path).is_some()
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Bytes(bytes) = input else {
            anyhow::bail!("ast: expected Bytes input");
        };
        let Some(spec) = spec_for(path) else {
            return Ok(Artifact::Ast(Ast::default()));
        };
        Ok(Artifact::Ast(Self::extract(spec, bytes)))
    }
}

/// A dangerous sink: the classification carried onto a finding when a call to
/// it is seen.
struct Sink {
    rule: &'static str,
    severity: Severity,
    cwe: &'static str,
    what: &'static str,
}

/// Match a callee name to a dangerous sink, by full name or last component
/// (so both `system` and `os.system` resolve).
fn sink_for(name: &str) -> Option<Sink> {
    let last = name.rsplit('.').next().unwrap_or(name);
    let sink = |rule, severity, cwe, what| Sink {
        rule,
        severity,
        cwe,
        what,
    };
    // Full-name-specific sinks are matched before the generic last-component
    // ones, so `child_process.exec` is a child-process sink, not a bare `exec`.
    match (name, last) {
        ("child_process.exec" | "child_process.execSync", _) | (_, "execSync") => Some(sink(
            "ast-child-process",
            Severity::High,
            "CWE-78",
            "child_process shell execution",
        )),
        ("os.system", _) => Some(sink(
            "ast-os-command",
            Severity::High,
            "CWE-78",
            "shell command execution",
        )),
        ("yaml.load", _) => Some(sink(
            "ast-yaml-load",
            Severity::Medium,
            "CWE-502",
            "yaml.load without SafeLoader",
        )),
        (_, "loads") if name.starts_with("pickle") => Some(sink(
            "ast-pickle",
            Severity::High,
            "CWE-502",
            "pickle deserialization of untrusted data",
        )),
        // Generic sinks matched by the call's last component.
        (_, "eval") => Some(sink(
            "ast-eval",
            Severity::High,
            "CWE-95",
            "code evaluation",
        )),
        (_, "exec") => Some(sink(
            "ast-exec",
            Severity::High,
            "CWE-95",
            "dynamic code execution",
        )),
        (_, "system") => Some(sink(
            "ast-os-command",
            Severity::High,
            "CWE-78",
            "shell command execution",
        )),
        (_, "popen" | "Popen" | "check_output" | "check_call") => Some(sink(
            "ast-subprocess",
            Severity::Medium,
            "CWE-78",
            "subprocess execution (audit for shell=True / untrusted input)",
        )),
        _ => None,
    }
}

/// Flags calls to dangerous sinks found in the [`Ast`].
pub struct DangerousCallScanner;

impl FileTask for DangerousCallScanner {
    fn name(&self) -> &str {
        "ast-danger"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Ast
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Matches
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Ast(ast) = input else {
            anyhow::bail!("ast-danger: expected Ast input");
        };
        let path_str = path.to_string_lossy().into_owned();
        let mut matches = Vec::new();
        for sym in &ast.symbols {
            if sym.kind != "call" {
                continue;
            }
            if let Some(sink) = sink_for(&sym.name) {
                matches.push(Match {
                    rule: sink.rule.into(),
                    path: path_str.clone(),
                    line: sym.line,
                    col: 1,
                    snippet: format!("call to {} ({})", sym.name, sink.what),
                    severity: Some(sink.severity),
                    cwe: Some(sink.cwe.into()),
                    cve: None,
                });
            }
        }
        Ok(Artifact::Matches(matches))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ast_of(path: &str, src: &str) -> Ast {
        let spec = spec_for(Path::new(path)).expect("supported language");
        AstExtractor::extract(spec, src.as_bytes())
    }

    fn findings(path: &str, src: &str) -> Vec<Match> {
        let ast = ast_of(path, src);
        let Artifact::Matches(m) = DangerousCallScanner
            .run(Path::new(path), &Artifact::Ast(ast))
            .unwrap()
        else {
            unreachable!()
        };
        m
    }

    #[test]
    fn python_extracts_calls_and_functions() {
        let ast = ast_of("m.py", "def handler(req):\n    return os.system(req)\n");
        assert_eq!(ast.lang, "python");
        assert!(ast
            .symbols
            .iter()
            .any(|s| s.kind == "function" && s.name == "handler"));
        assert!(ast
            .symbols
            .iter()
            .any(|s| s.kind == "call" && s.name == "os.system"));
    }

    #[test]
    fn python_flags_os_system_and_eval() {
        let m = findings(
            "m.py",
            "x = eval(data)\nos.system('rm -rf ' + arg)\nsafe = len(items)\n",
        );
        let rules: Vec<&str> = m.iter().map(|x| x.rule.as_str()).collect();
        assert!(rules.contains(&"ast-eval"), "{rules:?}");
        assert!(rules.contains(&"ast-os-command"), "{rules:?}");
        assert_eq!(m.len(), 2, "len() is not a sink: {m:?}");
        // Line numbers come from the parse tree.
        let eval = m.iter().find(|x| x.rule == "ast-eval").unwrap();
        assert_eq!(eval.line, 1);
    }

    #[test]
    fn comments_and_strings_are_not_flagged() {
        // The word "eval" in a comment/string must NOT match — the whole point
        // of parsing over regex.
        let m = findings("m.py", "# call eval here later\nmsg = 'do not eval this'\n");
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn javascript_flags_child_process_exec() {
        let m = findings(
            "s.js",
            "function run(cmd) {\n  child_process.exec(cmd);\n}\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "ast-child-process");
        assert_eq!(m[0].severity, Some(Severity::High));
    }

    #[test]
    fn pickle_loads_is_deserialization() {
        let m = findings("m.py", "obj = pickle.loads(blob)\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "ast-pickle");
        assert_eq!(m[0].cwe.as_deref(), Some("CWE-502"));
    }

    #[test]
    fn extractor_applies_by_extension_only() {
        assert!(AstExtractor.applies(Path::new("a/b.py")));
        assert!(AstExtractor.applies(Path::new("x.mjs")));
        assert!(!AstExtractor.applies(Path::new("x.txt")));
        assert!(!AstExtractor.applies(Path::new("Cargo.toml")));
    }

    #[test]
    fn unparsable_input_yields_empty_ast_not_error() {
        // Even gibberish parses (tree-sitter is error-tolerant); no sinks.
        let m = findings("m.py", ")(*&^%$ not python @@@");
        assert!(m.is_empty());
    }

    #[test]
    fn subprocess_and_bare_exec_and_system() {
        let m = findings(
            "m.py",
            "subprocess.Popen(cmd)\nsubprocess.check_output(cmd)\nexec(src)\nsystem(cmd)\n",
        );
        let rules: Vec<&str> = m.iter().map(|x| x.rule.as_str()).collect();
        assert!(rules.contains(&"ast-subprocess"), "{rules:?}");
        assert!(rules.contains(&"ast-exec"), "{rules:?}");
        assert!(rules.contains(&"ast-os-command"), "{rules:?}");
        // Two subprocess calls (Popen + check_output) plus exec + system.
        assert_eq!(m.len(), 4, "{m:?}");
    }

    #[test]
    fn yaml_load_is_flagged() {
        let m = findings("m.py", "cfg = yaml.load(text)\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "ast-yaml-load");
        assert_eq!(m[0].severity, Some(Severity::Medium));
    }

    #[test]
    fn safe_calls_produce_nothing() {
        let m = findings("m.py", "print(x)\nfoo.bar(y)\njson.dumps(z)\n");
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn javascript_extracts_functions() {
        let ast = ast_of("s.js", "function greet(name) { return name; }\n");
        assert_eq!(ast.lang, "javascript");
        assert!(ast
            .symbols
            .iter()
            .any(|s| s.kind == "function" && s.name == "greet"));
    }

    #[test]
    fn extractor_run_on_unsupported_path_is_empty_ast() {
        let Artifact::Ast(ast) = AstExtractor
            .run(
                Path::new("notes.txt"),
                &Artifact::Bytes(b"eval(x)".to_vec()),
            )
            .unwrap()
        else {
            unreachable!()
        };
        assert!(ast.symbols.is_empty());
        assert!(ast.lang.is_empty());
    }

    #[test]
    fn tasks_reject_wrong_artifact_inputs() {
        let e1 = AstExtractor
            .run(Path::new("m.py"), &Artifact::Matches(vec![]))
            .unwrap_err();
        assert!(e1.to_string().contains("expected Bytes"), "{e1}");
        let e2 = DangerousCallScanner
            .run(Path::new("m.py"), &Artifact::Bytes(vec![]))
            .unwrap_err();
        assert!(e2.to_string().contains("expected Ast"), "{e2}");
    }

    #[test]
    fn task_metadata_is_stable() {
        assert_eq!(AstExtractor.name(), "ast");
        assert_eq!(AstExtractor.needs(), ArtifactKind::Bytes);
        assert_eq!(AstExtractor.provides(), ArtifactKind::Ast);
        assert_eq!(DangerousCallScanner.name(), "ast-danger");
        assert_eq!(DangerousCallScanner.needs(), ArtifactKind::Ast);
        assert_eq!(DangerousCallScanner.provides(), ArtifactKind::Matches);
    }
}
