//! Task orchestration: the plugin DAG that turns one file's bytes into
//! findings, AST, expanded archive entries, and whatever future plugins add.
//!
//! Instead of a fixed "read then scan" sequence, plugins are [`FileTask`]s that
//! declare the [`ArtifactKind`] they consume and the one they produce. A
//! [`Pipeline`] topologically sorts them so every task runs after its inputs
//! exist — the dependency edges are the orchestration, and no task ever calls
//! another directly. Adding the tree-sitter AST scanner later is then just
//! registering a `Bytes → Ast` task and a `Ast → Matches` task; the scheduler
//! wires them in automatically.
//!
//! # Rust notes
//!
//! - [`Artifact`] is an `enum`: one value that is *exactly one* of several
//!   shapes (bytes, an AST, a list of matches…). Pattern-matching on it is
//!   exhaustive, so a new variant forces every handler to consider it.
//! - Tasks are trait objects (`Box<dyn FileTask>`) for the same reason
//!   scanners were — a heterogeneous, runtime-built plugin list.
//! - The topological sort is Kahn's algorithm: repeatedly emit a task whose
//!   inputs are all already available, until none remain. If some never
//!   become available, that's a cycle or a missing producer — caught once at
//!   build time, never mid-scan.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Result};
use exfil_core::{Match, Symbol, VirtualFile};
use serde::{Deserialize, Serialize};

/// The kind of data an artifact carries. Tasks declare their input and output
/// in terms of these, and the scheduler matches producers to consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// Raw file bytes (the pipeline's seed input).
    Bytes,
    /// Files expanded from a container (archive entries).
    Files,
    /// A parsed abstract syntax tree.
    Ast,
    /// Observables extracted from content (emails, domains, IPs, URLs, hashes).
    Indicators,
    /// Security findings (a terminal output; may have many producers).
    Matches,
}

/// A call site: the callee plus the flat facts a taint pass needs — the
/// identifier arguments and the callees of any calls nested in the arguments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Call {
    /// Full callee text, e.g. `os.system` or `child_process.exec`.
    pub callee: String,
    /// 1-based line of the call.
    pub line: u32,
    /// Identifier arguments (variable names passed to the call).
    pub arg_idents: Vec<String>,
    /// Callees of any calls nested inside the arguments (for direct-nesting,
    /// e.g. `os.system(input())`).
    pub arg_calls: Vec<String>,
}

/// An assignment `target = <rhs>`, flattened to what a taint pass needs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Assign {
    /// The assigned variable name.
    pub target: String,
    /// 1-based line of the assignment.
    pub line: u32,
    /// Identifiers referenced on the right-hand side.
    pub rhs_idents: Vec<String>,
    /// Callees of any calls on the right-hand side.
    pub rhs_calls: Vec<String>,
}

/// A parsed abstract syntax tree: the symbols a language scanner extracted,
/// plus call and assignment facts for data-flow (taint) analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ast {
    /// Detected language, e.g. `rust` or `python`.
    pub lang: String,
    /// Declarations, imports, and call sites found in the file.
    pub symbols: Vec<Symbol>,
    /// Call sites with argument facts (for taint analysis).
    #[serde(default)]
    pub calls: Vec<Call>,
    /// Assignments with right-hand-side facts (for taint analysis).
    #[serde(default)]
    pub assigns: Vec<Assign>,
}

/// Observables extracted from a file's content, for the graph and for checker
/// plugins (DNS, whois, IOC, leak). Each list holds unique, normalized values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Indicators {
    /// Email addresses.
    #[serde(default)]
    pub emails: Vec<String>,
    /// Domain names.
    #[serde(default)]
    pub domains: Vec<String>,
    /// IPv4/IPv6 addresses.
    #[serde(default)]
    pub ips: Vec<String>,
    /// URLs.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Hex file hashes (md5/sha1/sha256, by length).
    #[serde(default)]
    pub hashes: Vec<String>,
}

impl Indicators {
    /// Whether nothing was extracted (so the engine can skip persisting).
    pub fn is_empty(&self) -> bool {
        self.emails.is_empty()
            && self.domains.is_empty()
            && self.ips.is_empty()
            && self.urls.is_empty()
            && self.hashes.is_empty()
    }
}

/// A typed value flowing between tasks. Each variant corresponds to one
/// [`ArtifactKind`].
#[derive(Debug, Clone)]
pub enum Artifact {
    /// Raw file bytes.
    Bytes(Vec<u8>),
    /// Files expanded from a container.
    Files(Vec<VirtualFile>),
    /// A parsed AST.
    Ast(Ast),
    /// Observables extracted from content.
    Indicators(Indicators),
    /// Security findings.
    Matches(Vec<Match>),
}

impl Artifact {
    /// The kind tag for this value.
    pub fn kind(&self) -> ArtifactKind {
        match self {
            Artifact::Bytes(_) => ArtifactKind::Bytes,
            Artifact::Files(_) => ArtifactKind::Files,
            Artifact::Ast(_) => ArtifactKind::Ast,
            Artifact::Indicators(_) => ArtifactKind::Indicators,
            Artifact::Matches(_) => ArtifactKind::Matches,
        }
    }
}

/// A plugin in the per-file DAG: consumes one artifact kind, produces another.
///
/// The engine reads each file once, seeds the pipeline with [`Artifact::Bytes`],
/// and runs applicable tasks in dependency order, threading each task's output
/// back in as a potential input for later tasks.
pub trait FileTask: Send + Sync {
    /// Stable identifier used in config, errors, and reports.
    fn name(&self) -> &str;

    /// The artifact kind this task consumes.
    fn needs(&self) -> ArtifactKind;

    /// The artifact kind this task produces.
    fn provides(&self) -> ArtifactKind;

    /// Whether this task should run for `path`. Defaults to always; scanners
    /// override to skip files they don't handle by name/extension. The engine
    /// only ever offers actual files (real or expanded from an archive), so
    /// tasks never need to re-check that.
    fn applies(&self, _path: &Path) -> bool {
        true
    }

    /// Transform the input artifact into an output artifact.
    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact>;
}

/// A dependency-ordered collection of [`FileTask`]s.
///
/// Build it with [`Pipeline::new`], which topologically sorts the tasks and
/// fails fast on cycles or artifacts nothing produces. [`Pipeline::run_file`]
/// then executes them for one file.
pub struct Pipeline {
    tasks: Vec<Box<dyn FileTask>>,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.tasks.iter().map(|t| t.name()).collect();
        f.debug_struct("Pipeline").field("tasks", &names).finish()
    }
}

/// Everything one file's pipeline run produced that the engine persists.
#[derive(Debug, Default)]
pub struct FileArtifacts {
    /// All matches, concatenated across every scanning task.
    pub matches: Vec<Match>,
    /// Files expanded from this one (archive entries) to be processed in turn.
    pub expanded: Vec<VirtualFile>,
    /// The parsed AST, if a language task produced one (for the `has_ast` edge).
    pub ast: Option<Ast>,
    /// Observables extracted from this file, if an extractor produced any.
    pub indicators: Option<Indicators>,
}

impl Pipeline {
    /// Order `tasks` so each runs after the task(s) producing what it needs.
    ///
    /// `Bytes` is always available (the engine seeds it). A task whose input is
    /// never produced, or a set of tasks that depend on each other cyclically,
    /// is a configuration error and returns `Err` here — before any scanning.
    pub fn new(tasks: Vec<Box<dyn FileTask>>) -> Result<Self> {
        let ordered = toposort(tasks)?;
        Ok(Self { tasks: ordered })
    }

    /// The tasks in execution order.
    pub fn tasks(&self) -> &[Box<dyn FileTask>] {
        &self.tasks
    }

    /// Run the pipeline for one file, returning its matches and any expanded
    /// entries. `Bytes` seeds the run; each task's output becomes available to
    /// later tasks. Matches accumulate; other kinds keep the latest value.
    pub fn run_file(&self, path: &Path, bytes: Vec<u8>) -> Result<FileArtifacts> {
        let mut available: HashMap<ArtifactKind, Artifact> = HashMap::new();
        available.insert(ArtifactKind::Bytes, Artifact::Bytes(bytes));

        let mut out = FileArtifacts::default();
        for task in &self.tasks {
            if !task.applies(path) {
                continue;
            }
            let Some(input) = available.get(&task.needs()) else {
                continue; // an upstream task didn't apply; nothing to feed this
            };
            let produced = task
                .run(path, input)
                .map_err(|e| e.context(format!("task {:?} on {}", task.name(), path.display())))?;
            match produced {
                Artifact::Matches(mut m) => out.matches.append(&mut m),
                Artifact::Files(mut f) => {
                    out.expanded.append(&mut f);
                    // Keep it available too, in case a later task consumes Files.
                    available.insert(ArtifactKind::Files, Artifact::Files(Vec::new()));
                }
                Artifact::Ast(ast) => {
                    // Surface the AST for persistence, and keep it available for
                    // downstream Ast → Matches tasks.
                    out.ast = Some(ast.clone());
                    available.insert(ArtifactKind::Ast, Artifact::Ast(ast));
                }
                Artifact::Indicators(ind) => {
                    // Surface for persistence, and keep available for downstream
                    // Indicators → Matches checkers (DNS/whois/IOC/leak).
                    out.indicators = Some(ind.clone());
                    available.insert(ArtifactKind::Indicators, Artifact::Indicators(ind));
                }
                other => {
                    available.insert(other.kind(), other);
                }
            }
        }
        Ok(out)
    }
}

/// Kahn's-algorithm topological sort of tasks by their `needs → provides`
/// edges. Returns tasks in an order where every task's input kind is either
/// `Bytes` or produced by an earlier task.
fn toposort(mut tasks: Vec<Box<dyn FileTask>>) -> Result<Vec<Box<dyn FileTask>>> {
    // Kinds available to consume: Bytes is seeded; others appear as tasks emit.
    let mut available = vec![ArtifactKind::Bytes];
    let mut ordered: Vec<Box<dyn FileTask>> = Vec::with_capacity(tasks.len());

    while !tasks.is_empty() {
        // Find a task whose input is already available.
        let ready = tasks.iter().position(|t| available.contains(&t.needs()));
        let Some(idx) = ready else {
            let stuck: Vec<&str> = tasks.iter().map(|t| t.name()).collect();
            bail!(
                "pipeline has a cycle or a missing producer; cannot schedule: {stuck:?} \
                 (available inputs: {available:?})"
            );
        };
        let task = tasks.remove(idx);
        if !available.contains(&task.provides()) {
            available.push(task.provides());
        }
        ordered.push(task);
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A task with declared needs/provides and a recording of whether it ran.
    struct Fake {
        name: &'static str,
        needs: ArtifactKind,
        provides: ArtifactKind,
    }

    impl FileTask for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn needs(&self) -> ArtifactKind {
            self.needs
        }
        fn provides(&self) -> ArtifactKind {
            self.provides
        }
        fn run(&self, _p: &Path, _i: &Artifact) -> Result<Artifact> {
            match self.provides {
                ArtifactKind::Ast => Ok(Artifact::Ast(Ast {
                    lang: "test".into(),
                    ..Ast::default()
                })),
                ArtifactKind::Matches => Ok(Artifact::Matches(vec![Match {
                    rule: self.name.into(),
                    path: String::new(),
                    line: 1,
                    col: 1,
                    snippet: String::new(),
                    severity: None,
                    cwe: None,
                    cve: None,
                }])),
                _ => Ok(Artifact::Bytes(vec![])),
            }
        }
    }

    fn task(name: &'static str, needs: ArtifactKind, provides: ArtifactKind) -> Box<dyn FileTask> {
        Box::new(Fake {
            name,
            needs,
            provides,
        })
    }

    #[test]
    fn orders_ast_before_its_consumer() {
        // taint (Ast→Matches) registered BEFORE ast (Bytes→Ast); the sort must
        // still schedule ast first.
        let pipeline = Pipeline::new(vec![
            task("taint", ArtifactKind::Ast, ArtifactKind::Matches),
            task("ast", ArtifactKind::Bytes, ArtifactKind::Ast),
            task("regex", ArtifactKind::Bytes, ArtifactKind::Matches),
        ])
        .unwrap();
        let names: Vec<&str> = pipeline.tasks().iter().map(|t| t.name()).collect();
        let ast_pos = names.iter().position(|n| *n == "ast").unwrap();
        let taint_pos = names.iter().position(|n| *n == "taint").unwrap();
        assert!(ast_pos < taint_pos, "ast must precede taint: {names:?}");
    }

    #[test]
    fn missing_producer_is_rejected() {
        // taint needs Ast, but nothing produces Ast.
        let err = Pipeline::new(vec![task(
            "taint",
            ArtifactKind::Ast,
            ArtifactKind::Matches,
        )])
        .unwrap_err();
        assert!(err.to_string().contains("missing producer"), "{err}");
    }

    #[test]
    fn cycle_is_rejected() {
        // Ast→Matches and Matches→Ast depend on each other; neither can start.
        let err = Pipeline::new(vec![
            task("a", ArtifactKind::Ast, ArtifactKind::Matches),
            task("b", ArtifactKind::Matches, ArtifactKind::Ast),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("cycle"), "{err}");
    }

    #[test]
    fn run_file_accumulates_matches_from_multiple_producers() {
        let pipeline = Pipeline::new(vec![
            task("regex", ArtifactKind::Bytes, ArtifactKind::Matches),
            task("ast", ArtifactKind::Bytes, ArtifactKind::Ast),
            task("taint", ArtifactKind::Ast, ArtifactKind::Matches),
        ])
        .unwrap();
        let out = pipeline.run_file(Path::new("f"), b"data".to_vec()).unwrap();
        // Two match-producing tasks (regex + taint) → two matches.
        assert_eq!(out.matches.len(), 2);
        let rules: Vec<&str> = out.matches.iter().map(|m| m.rule.as_str()).collect();
        assert!(
            rules.contains(&"regex") && rules.contains(&"taint"),
            "{rules:?}"
        );
        // The captured AST is surfaced for persistence.
        assert!(out.ast.is_some());
        assert_eq!(out.ast.unwrap().lang, "test");
    }

    /// A task that always produces a fixed artifact, optionally not applying.
    struct Producer {
        name: &'static str,
        needs: ArtifactKind,
        output: fn() -> Artifact,
        applies: bool,
    }

    impl FileTask for Producer {
        fn name(&self) -> &str {
            self.name
        }
        fn needs(&self) -> ArtifactKind {
            self.needs
        }
        fn provides(&self) -> ArtifactKind {
            (self.output)().kind()
        }
        fn applies(&self, _p: &Path) -> bool {
            self.applies
        }
        fn run(&self, _p: &Path, _i: &Artifact) -> Result<Artifact> {
            Ok((self.output)())
        }
    }

    #[test]
    fn artifact_kind_tags_match_variants() {
        assert_eq!(Artifact::Bytes(vec![]).kind(), ArtifactKind::Bytes);
        assert_eq!(Artifact::Files(vec![]).kind(), ArtifactKind::Files);
        assert_eq!(Artifact::Ast(Ast::default()).kind(), ArtifactKind::Ast);
        assert_eq!(Artifact::Matches(vec![]).kind(), ArtifactKind::Matches);
    }

    #[test]
    fn run_file_collects_expanded_files() {
        let pipeline = Pipeline::new(vec![Box::new(Producer {
            name: "expand",
            needs: ArtifactKind::Bytes,
            output: || {
                Artifact::Files(vec![VirtualFile {
                    path: "a.zip!inner".into(),
                    content: b"x".to_vec(),
                }])
            },
            applies: true,
        })])
        .unwrap();
        let out = pipeline
            .run_file(Path::new("a.zip"), b"pk".to_vec())
            .unwrap();
        assert_eq!(out.expanded.len(), 1);
        assert_eq!(out.expanded[0].path, "a.zip!inner");
    }

    #[test]
    fn run_file_skips_tasks_that_do_not_apply() {
        let pipeline = Pipeline::new(vec![Box::new(Producer {
            name: "regex",
            needs: ArtifactKind::Bytes,
            output: || Artifact::Matches(vec![]),
            applies: false, // never runs
        })])
        .unwrap();
        let out = pipeline.run_file(Path::new("f"), b"data".to_vec()).unwrap();
        assert!(out.matches.is_empty());
    }

    #[test]
    fn pipeline_debug_lists_task_names() {
        let pipeline = Pipeline::new(vec![task(
            "regex",
            ArtifactKind::Bytes,
            ArtifactKind::Matches,
        )])
        .unwrap();
        let dbg = format!("{pipeline:?}");
        assert!(dbg.contains("regex"), "{dbg}");
    }
}
