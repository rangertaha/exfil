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
//! Languages today: Python, JavaScript, TypeScript, Rust, Go, C, C++, and Java.
//! Adding one is a single [`LangSpec`] entry (a grammar plus the node-kind and
//! field names its calls, functions, and assignments use). Bash, Lua, and
//! PowerShell need per-language call handling (different node shapes); C#/VB
//! await an ABI-compatible tree-sitter grammar.

use std::path::Path;

use anyhow::Result;
use exfill_core::{Match, Severity, Symbol};
use exfill_task::{Artifact, ArtifactKind, Assign, Ast, Call, FileTask};
use tree_sitter::{Node, Parser};

/// A supported language: how to load its grammar and the node kinds that name
/// its call expressions, function definitions, and assignments.
pub(crate) struct LangSpec {
    /// Language tag stored on the [`Ast`].
    lang: &'static str,
    /// File extensions that select this language.
    extensions: &'static [&'static str],
    /// Load the tree-sitter grammar.
    language: fn() -> tree_sitter::Language,
    /// Grammar node kind for a call expression.
    call_kind: &'static str,
    /// Field on a call node holding the callee (usually `function`; Java's
    /// `method_invocation` uses `name`).
    fn_field: &'static str,
    /// Field on a call node holding its argument list (usually `arguments`).
    args_field: &'static str,
    /// Grammar node kind for a function definition (its `name` field).
    func_kind: &'static str,
    /// Grammar node kinds for assignments (their target/rhs are read by
    /// [`assignment_parts`]).
    assign_kinds: &'static [&'static str],
}

/// The default call-callee field (`function`) and argument-list field
/// (`arguments`) shared by most C-family grammars.
const DEFAULT_FN_FIELD: &str = "function";
const DEFAULT_ARGS_FIELD: &str = "arguments";

/// The languages this build understands. Most are C-family and share the
/// `function`/`arguments` call fields; the exceptions set `fn_field`.
fn specs() -> &'static [LangSpec] {
    &[
        LangSpec {
            lang: "python",
            extensions: &["py", "pyi"],
            language: || tree_sitter_python::LANGUAGE.into(),
            call_kind: "call",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_definition",
            assign_kinds: &["assignment"],
        },
        LangSpec {
            lang: "javascript",
            extensions: &["js", "jsx", "mjs", "cjs"],
            language: || tree_sitter_javascript::LANGUAGE.into(),
            call_kind: "call_expression",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_declaration",
            assign_kinds: &["assignment_expression", "variable_declarator"],
        },
        LangSpec {
            lang: "typescript",
            extensions: &["ts", "tsx", "mts", "cts"],
            language: || tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            call_kind: "call_expression",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_declaration",
            assign_kinds: &["assignment_expression", "variable_declarator"],
        },
        LangSpec {
            lang: "rust",
            extensions: &["rs"],
            language: || tree_sitter_rust::LANGUAGE.into(),
            call_kind: "call_expression",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_item",
            assign_kinds: &["let_declaration", "assignment_expression"],
        },
        LangSpec {
            lang: "go",
            extensions: &["go"],
            language: || tree_sitter_go::LANGUAGE.into(),
            call_kind: "call_expression",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_declaration",
            assign_kinds: &["short_var_declaration", "assignment_statement"],
        },
        LangSpec {
            lang: "c",
            extensions: &["c", "h"],
            language: || tree_sitter_c::LANGUAGE.into(),
            call_kind: "call_expression",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_definition",
            assign_kinds: &["init_declarator", "assignment_expression"],
        },
        LangSpec {
            lang: "cpp",
            extensions: &["cc", "cpp", "cxx", "hpp", "hh"],
            language: || tree_sitter_cpp::LANGUAGE.into(),
            call_kind: "call_expression",
            fn_field: DEFAULT_FN_FIELD,
            args_field: DEFAULT_ARGS_FIELD,
            func_kind: "function_definition",
            assign_kinds: &["init_declarator", "assignment_expression"],
        },
        // Java's `method_invocation` names the callee via the `name` field.
        LangSpec {
            lang: "java",
            extensions: &["java"],
            language: || tree_sitter_java::LANGUAGE.into(),
            call_kind: "method_invocation",
            fn_field: "name",
            args_field: "arguments",
            func_kind: "method_declaration",
            assign_kinds: &["assignment_expression", "variable_declarator"],
        },
    ]
}

/// The language spec for a path's extension, if supported.
pub(crate) fn spec_for(path: &Path) -> Option<&'static LangSpec> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    specs()
        .iter()
        .find(|s| s.extensions.contains(&ext.as_str()))
}

/// Parse `content` in `spec`'s language into an [`Ast`]. Shared by the AST
/// extractor and the taint scanner.
pub(crate) fn parse(spec: &LangSpec, content: &[u8]) -> Ast {
    let mut parser = Parser::new();
    if parser.set_language(&(spec.language)()).is_err() {
        return Ast::default();
    }
    let Some(tree) = parser.parse(content, None) else {
        return Ast::default();
    };
    let mut ast = Ast {
        lang: spec.lang.to_string(),
        ..Ast::default()
    };
    walk(tree.root_node(), content, spec, &mut ast);
    ast
}

/// Parses supported source files into an [`Ast`] of symbols, calls, and
/// assignments.
pub struct AstExtractor;

/// Split an assignment node into `(target, rhs)`, handling the per-grammar
/// field names (`left`/`right` for assignments, `name`/`value` for JS
/// variable declarators).
fn assignment_parts<'a>(node: Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    // Target field: `left` (assignments), `name` (JS declarators), `pattern`
    // (Rust `let`). RHS field: `right` or `value`.
    let target = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))
        .or_else(|| node.child_by_field_name("pattern"))?;
    let rhs = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))?;
    Some((target, rhs))
}

/// Collect, within `node`'s subtree: plain identifier names into `idents`, and
/// into `calls` both nested-call callees and attribute/member accesses (e.g.
/// `process.argv`, `request.args`). Member accesses matter because most taint
/// sources are member reads, not calls, so treating them as source-check
/// candidates lets `process.argv[2]` be recognized as untrusted.
fn collect_facts(
    node: Node,
    src: &[u8],
    call_kind: &str,
    fn_field: &str,
    idents: &mut Vec<String>,
    calls: &mut Vec<String>,
) {
    match node.kind() {
        "identifier" => {
            if let Ok(t) = node.utf8_text(src) {
                idents.push(t.to_string());
            }
        }
        // Member/path access — `a.b.c` (Python `attribute`, JS
        // `member_expression`, Go `selector_expression`) and `a::b::c` (Rust
        // `scoped_identifier`/`field_expression`). Treated as source-check
        // candidates so member-read sources (os.Args, r.FormValue, env::var)
        // are recognized.
        "attribute"
        | "member_expression"
        | "selector_expression"
        | "scoped_identifier"
        | "field_expression"
        | "member_access_expression"
        | "qualified_name" => {
            if let Ok(t) = node.utf8_text(src) {
                calls.push(t.to_string());
            }
        }
        _ => {}
    }
    if node.kind() == call_kind {
        if let Some(f) = node.child_by_field_name(fn_field) {
            if let Ok(t) = f.utf8_text(src) {
                calls.push(t.to_string());
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_facts(child, src, call_kind, fn_field, idents, calls);
    }
}

/// The name of `node` if it is an identifier, else the first identifier in its
/// subtree — so a wrapped assignment target (Go `expression_list`, a pattern)
/// still yields a variable name.
fn first_identifier(node: Node, src: &[u8]) -> Option<String> {
    if node.kind() == "identifier" {
        return node.utf8_text(src).ok().map(String::from);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = first_identifier(child, src) {
            return Some(name);
        }
    }
    None
}

/// Depth-first walk collecting symbols, call facts, and assignment facts. A
/// call's name is the full callee text (`os.system`, `child_process.exec`), so
/// dotted sinks are recognizable downstream.
fn walk(node: Node, src: &[u8], spec: &LangSpec, ast: &mut Ast) {
    let kind = node.kind();
    if kind == spec.call_kind {
        if let Some(callee) = node.child_by_field_name(spec.fn_field) {
            if let Ok(name) = callee.utf8_text(src) {
                let line = callee.start_position().row as u32 + 1;
                ast.symbols.push(Symbol {
                    kind: "call".into(),
                    name: name.to_string(),
                    line,
                });
                let (mut arg_idents, mut arg_calls) = (Vec::new(), Vec::new());
                if let Some(args) = node.child_by_field_name(spec.args_field) {
                    collect_facts(
                        args,
                        src,
                        spec.call_kind,
                        spec.fn_field,
                        &mut arg_idents,
                        &mut arg_calls,
                    );
                }
                ast.calls.push(Call {
                    callee: name.to_string(),
                    line,
                    arg_idents,
                    arg_calls,
                });
            }
        }
    } else if kind == spec.func_kind {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(src) {
                ast.symbols.push(Symbol {
                    kind: "function".into(),
                    name: name.to_string(),
                    line: name_node.start_position().row as u32 + 1,
                });
            }
        }
    } else if spec.assign_kinds.contains(&kind) {
        if let Some((target, rhs)) = assignment_parts(node) {
            // The target may be a bare identifier or wrap one (Go's
            // `expression_list`, a Rust pattern); take the first identifier.
            if let Some(name) = first_identifier(target, src) {
                let (mut rhs_idents, mut rhs_calls) = (Vec::new(), Vec::new());
                collect_facts(
                    rhs,
                    src,
                    spec.call_kind,
                    spec.fn_field,
                    &mut rhs_idents,
                    &mut rhs_calls,
                );
                ast.assigns.push(Assign {
                    target: name,
                    line: target.start_position().row as u32 + 1,
                    rhs_idents,
                    rhs_calls,
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, src, spec, ast);
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
        Ok(Artifact::Ast(parse(spec, bytes)))
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
    // Cross-language command-execution sinks (Rust/Go/C#), matched on the full
    // callee text before the generic last-component arms below.
    if name.contains("Command::new") || name.contains("process::Command") {
        return Some(sink(
            "ast-process-command",
            Severity::High,
            "CWE-78",
            "process execution",
        ));
    }
    if name.contains("exec.Command") || name.contains("exec.CommandContext") {
        return Some(sink(
            "ast-exec-command",
            Severity::High,
            "CWE-78",
            "os/exec command",
        ));
    }
    if name.contains("Process.Start") {
        return Some(sink(
            "ast-process-start",
            Severity::High,
            "CWE-78",
            "Process.Start execution",
        ));
    }
    // C/C++ process execution: popen and the exec* family.
    if last == "popen" || last.starts_with("execl") || last.starts_with("execv") {
        return Some(sink(
            "ast-c-exec",
            Severity::High,
            "CWE-78",
            "C process execution",
        ));
    }

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
        parse(spec, src.as_bytes())
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
    fn go_flags_exec_command() {
        let m = findings(
            "m.go",
            "func run(c string) {\n  exec.Command(\"sh\", \"-c\", c)\n}\n",
        );
        assert!(m.iter().any(|x| x.rule == "ast-exec-command"), "{m:?}");
    }

    #[test]
    fn rust_flags_process_command() {
        let m = findings(
            "m.rs",
            "fn run(c: &str) {\n  std::process::Command::new(c);\n}\n",
        );
        assert!(m.iter().any(|x| x.rule == "ast-process-command"), "{m:?}");
    }

    #[test]
    fn java_flags_runtime_exec() {
        let m = findings(
            "M.java",
            "class M { void r(String c) { Runtime.getRuntime().exec(c); } }",
        );
        assert!(m.iter().any(|x| x.rule == "ast-exec"), "{m:?}");
    }

    #[test]
    fn c_flags_system_and_popen() {
        let m = findings("m.c", "void r(char* c){ system(c); popen(c, \"r\"); }");
        let rules: Vec<&str> = m.iter().map(|x| x.rule.as_str()).collect();
        assert!(rules.contains(&"ast-os-command"), "{rules:?}");
        assert!(rules.contains(&"ast-c-exec"), "{rules:?}");
    }

    #[test]
    fn typescript_flags_child_process() {
        let m = findings("s.ts", "function r(c: string) { child_process.exec(c); }");
        assert!(m.iter().any(|x| x.rule == "ast-child-process"), "{m:?}");
    }

    #[test]
    fn go_taint_from_form_value() {
        // Go: r.FormValue is a source; passing it to exec.Command is injection.
        let ast = ast_of(
            "h.go",
            "func h(r int) {\n  c := r.FormValue(\"cmd\")\n  exec.Command(c)\n}\n",
        );
        let Artifact::Matches(m) = crate::taint::TaintScanner
            .run(Path::new("h.go"), &Artifact::Ast(ast))
            .unwrap()
        else {
            unreachable!()
        };
        assert!(
            m.iter().any(|x| x.rule == "taint-command-injection"),
            "{m:?}"
        );
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
