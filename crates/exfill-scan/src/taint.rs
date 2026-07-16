//! Taint analysis: flag when *untrusted input* reaches a *dangerous sink*.
//!
//! Where [`DangerousCallScanner`](crate::ast::DangerousCallScanner) flags any
//! call to a sink, taint tracking asks the sharper question — does attacker-
//! controlled data actually flow into it? That is a higher-confidence finding
//! and the classic command/code-injection bug.
//!
//! This is an `Ast → Matches` task: it consumes the call and assignment facts
//! the [`AstExtractor`](crate::ast::AstExtractor) already extracted, so it adds
//! no extra parse. The analysis is intra-file and flow-insensitive to keep it
//! cheap and predictable:
//!
//! 1. **Sources** — calls like `input()`, `os.getenv(...)`, `request.args.get`,
//!    `process.argv`/`process.env` accessors produce tainted data.
//! 2. **Propagation** — a variable assigned from a source, or from another
//!    tainted variable, becomes tainted (a single forward pass over
//!    assignments in source order).
//! 3. **Sinks** — a call to `os.system`, `eval`, `exec`, `subprocess.*`, or
//!    `child_process.exec` is flagged when a tainted variable is passed to it,
//!    or when a source call is nested directly in its arguments
//!    (`os.system(input())`).
//!
//! Limitations (documented, not bugs): no cross-function or cross-file flow,
//! and subscript sources like `sys.argv[1]` are not yet modeled — only call
//! expressions are. False negatives are preferred over noise.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use exfill_core::{Match, Severity};
use exfill_task::{Artifact, ArtifactKind, Ast, FileTask};

/// Whether a callee name denotes an untrusted-input source. Covers Python, JS,
/// Go, Rust, and C# input surfaces.
fn is_source(callee: &str) -> bool {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    matches!(last, "input" | "raw_input" | "getenv")
        || callee.contains("request.")
        || callee.contains("os.environ")
        || callee.contains("process.argv")
        || callee.contains("process.env")
        || callee.contains("req.body")
        || callee.contains("req.query")
        || callee.contains("req.params")
        // Go: os.Args, os.Getenv, r.FormValue, r.URL.Query, r.PostFormValue
        || callee.contains("os.Args")
        || callee.contains("os.Getenv")
        || callee.contains("FormValue")
        || callee.contains("URL.Query")
        // Rust: std::env::var, std::env::args
        || callee.contains("env::var")
        || callee.contains("env::args")
        // C#: Console.ReadLine, Request.Query, Request.Form, .QueryString
        || callee.contains("Console.ReadLine")
        || callee.contains("Request.Query")
        || callee.contains("Request.Form")
        || callee.contains("QueryString")
}

/// A taint sink: the rule and classification if untrusted data reaches it.
struct TaintSink {
    rule: &'static str,
    cwe: &'static str,
    what: &'static str,
}

/// Classify a callee as a command/code-injection sink, if it is one.
fn taint_sink(callee: &str) -> Option<TaintSink> {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    let sink = |rule, cwe, what| TaintSink { rule, cwe, what };
    // Cross-language command-execution sinks (Go/Rust/C#/C), whose last
    // component isn't `exec`/`system`, matched on the full callee first.
    if callee.contains("exec.Command")
        || callee.contains("Command::new")
        || callee.contains("process::Command")
        || callee.contains("Process.Start")
        || last == "popen"
        || last.starts_with("execl")
        || last.starts_with("execv")
    {
        return Some(sink(
            "taint-command-injection",
            "CWE-78",
            "process execution",
        ));
    }
    match (callee, last) {
        ("child_process.exec" | "child_process.execSync", _) | (_, "execSync") => Some(sink(
            "taint-command-injection",
            "CWE-78",
            "child_process shell execution",
        )),
        ("os.system", _) | (_, "system") => Some(sink(
            "taint-command-injection",
            "CWE-78",
            "shell command execution",
        )),
        (_, "popen" | "Popen" | "check_output" | "check_call") => Some(sink(
            "taint-command-injection",
            "CWE-78",
            "subprocess execution",
        )),
        (_, "eval") => Some(sink("taint-code-injection", "CWE-95", "code evaluation")),
        (_, "exec") => Some(sink(
            "taint-code-injection",
            "CWE-95",
            "dynamic code execution",
        )),
        _ => None,
    }
}

/// Tracks untrusted input flowing into dangerous sinks.
pub struct TaintScanner;

impl TaintScanner {
    /// Run the taint analysis over an already-parsed [`Ast`].
    fn analyze(ast: &Ast, path: &str) -> Vec<Match> {
        // 1–2. Forward pass: a target is tainted if its RHS calls a source or
        // references an already-tainted variable.
        let mut tainted: HashSet<&str> = HashSet::new();
        for a in &ast.assigns {
            let from_source = a.rhs_calls.iter().any(|c| is_source(c));
            let from_tainted = a.rhs_idents.iter().any(|i| tainted.contains(i.as_str()));
            if from_source || from_tainted {
                tainted.insert(a.target.as_str());
            }
        }

        // 3. Sinks fed a tainted variable, or a source nested in their args.
        let mut matches = Vec::new();
        for c in &ast.calls {
            let Some(sink) = taint_sink(&c.callee) else {
                continue;
            };
            let via_var = c.arg_idents.iter().any(|i| tainted.contains(i.as_str()));
            let direct = c.arg_calls.iter().any(|x| is_source(x));
            if via_var || direct {
                let how = if direct {
                    "untrusted input passed directly"
                } else {
                    "tainted variable reaches"
                };
                matches.push(Match {
                    rule: sink.rule.into(),
                    path: path.to_string(),
                    line: c.line,
                    col: 1,
                    snippet: format!("{how} {} ({})", c.callee, sink.what),
                    severity: Some(Severity::Critical),
                    cwe: Some(sink.cwe.into()),
                    cve: None,
                });
            }
        }
        matches
    }
}

impl FileTask for TaintScanner {
    fn name(&self) -> &str {
        "taint"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Ast
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Matches
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Ast(ast) = input else {
            anyhow::bail!("taint: expected Ast input");
        };
        Ok(Artifact::Matches(Self::analyze(
            ast,
            &path.to_string_lossy(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AstExtractor;

    fn taint(path: &str, src: &str) -> Vec<Match> {
        let spec = crate::ast::spec_for(Path::new(path)).expect("supported language");
        let ast = crate::ast::parse(spec, src.as_bytes());
        TaintScanner::analyze(&ast, path)
    }

    #[test]
    fn one_hop_variable_flow_python() {
        // cmd is tainted by input(); passing it to os.system is injection.
        let m = taint("m.py", "cmd = input()\nos.system(cmd)\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "taint-command-injection");
        assert_eq!(m[0].line, 2);
        assert!(m[0].snippet.contains("tainted variable"));
    }

    #[test]
    fn direct_nesting_is_flagged() {
        let m = taint("m.py", "os.system(input())\n");
        assert_eq!(m.len(), 1);
        assert!(m[0].snippet.contains("directly"));
    }

    #[test]
    fn transitive_taint_across_two_vars() {
        let m = taint("m.py", "a = request.args.get('x')\nb = a\neval(b)\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "taint-code-injection");
    }

    #[test]
    fn untainted_constant_is_not_flagged() {
        // A constant argument is not attacker-controlled.
        let m = taint("m.py", "cmd = 'ls -la'\nos.system(cmd)\n");
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn source_without_sink_is_silent() {
        let m = taint("m.py", "name = input()\nprint(name)\n");
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn javascript_process_argv_into_exec() {
        let m = taint(
            "s.js",
            "const cmd = process.argv[2];\nchild_process.exec(cmd);\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].rule, "taint-command-injection");
    }

    #[test]
    fn wrong_artifact_input_errors() {
        let err = TaintScanner
            .run(Path::new("m.py"), &Artifact::Bytes(vec![]))
            .unwrap_err();
        assert!(err.to_string().contains("expected Ast"), "{err}");
    }

    #[test]
    fn task_metadata() {
        assert_eq!(TaintScanner.name(), "taint");
        assert_eq!(TaintScanner.needs(), ArtifactKind::Ast);
        assert_eq!(TaintScanner.provides(), ArtifactKind::Matches);
        // The extractor supplies the AST this task consumes.
        assert_eq!(AstExtractor.provides(), ArtifactKind::Ast);
    }
}
