//! Run-level orchestration: the coarse pipeline that sequences a whole
//! invocation — **fetch → scan → report** — above the per-file task DAG.
//!
//! Where a [`Pipeline`](exfill_task::Pipeline) wires per-file plugins by their
//! artifact types, a [`RunStage`] is a whole phase of a run. Stages share the
//! graph through [`RunCtx`] and communicate *through* it: the scan stage writes
//! findings, the report stage reads them back. That is the "plugins get a graph
//! interface" model — no stage calls another directly.
//!
//! # Rust notes
//!
//! `RunStage` uses `#[async_trait]` because a plain `async fn` in a trait
//! isn't yet usable behind `dyn` (the object-safety rules don't cover the
//! hidden future type). The macro rewrites each `async fn` to return a boxed
//! future, which *is* object-safe, so `Box<dyn RunStage>` works.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use exfill_report::{reporter_for, Analysis};
use exfill_store::Store;
use exfill_task::Pipeline;

use crate::{scan, ScanEvent};

/// Shared context handed to every stage: the graph and an optional progress
/// sink. The `Store` handle is cheap to clone and thread-safe.
pub struct RunCtx {
    /// The findings graph, shared across stages.
    pub store: Arc<Store>,
    /// Progress events, forwarded to whatever UI is attached.
    pub events: Option<Sender<ScanEvent>>,
}

/// One phase of a run. Stages execute in sequence and coordinate through the
/// shared graph in [`RunCtx`].
#[async_trait]
pub trait RunStage: Send + Sync {
    /// Stage name, shown in logs and errors.
    fn name(&self) -> &str;

    /// Execute the stage against the shared context.
    async fn run(&self, ctx: &RunCtx) -> Result<()>;
}

/// Run every stage in order, stopping at the first failure (which is annotated
/// with the failing stage's name).
pub async fn run_stages(stages: &[Box<dyn RunStage>], ctx: &RunCtx) -> Result<()> {
    for stage in stages {
        stage
            .run(ctx)
            .await
            .with_context(|| format!("run stage {:?}", stage.name()))?;
    }
    Ok(())
}

/// **Fetch** stage: refresh datasets/rules from configured sources.
///
/// Sources and the `update` pipeline are a later milestone, so today this is a
/// declared-but-empty stage: it logs that nothing is configured and returns,
/// keeping the fetch → scan → report shape in place for when sources land.
pub struct FetchStage;

#[async_trait]
impl RunStage for FetchStage {
    fn name(&self) -> &str {
        "fetch"
    }

    async fn run(&self, _ctx: &RunCtx) -> Result<()> {
        // No sources yet (M2). The stage exists so the orchestration graph is
        // complete and fetching slots in without reshaping the run.
        Ok(())
    }
}

/// **Scan** stage: walk `root` with the task `pipeline`, writing files and
/// findings into the shared graph.
pub struct ScanStage {
    /// Directory tree to scan.
    pub root: PathBuf,
    /// The per-file task pipeline.
    pub pipeline: Pipeline,
    /// Directory to exclude (the store itself).
    pub skip_dir: Option<PathBuf>,
}

#[async_trait]
impl RunStage for ScanStage {
    fn name(&self) -> &str {
        "scan"
    }

    async fn run(&self, ctx: &RunCtx) -> Result<()> {
        scan(
            &self.root,
            &self.pipeline,
            &ctx.store,
            self.skip_dir.as_deref(),
            ctx.events.clone(),
        )
        .await
        .map(|_| ())
    }
}

/// **Report** stage: read findings back from the graph and render them with
/// the chosen reporter into the shared sink.
pub struct ReportStage {
    /// Reporter format name (`text`/`json`/`markdown`).
    pub format: String,
    /// Optional finding filter (same syntax as `search`).
    pub query: String,
    /// Where the rendered report is written. Wrapped so the stage is `Send`
    /// and so tests can capture output into a buffer.
    pub sink: Arc<Mutex<dyn Write + Send>>,
}

#[async_trait]
impl RunStage for ReportStage {
    fn name(&self) -> &str {
        "report"
    }

    async fn run(&self, ctx: &RunCtx) -> Result<()> {
        let analysis = gather_analysis(&ctx.store, &self.query).await?;
        let reporter = reporter_for(&self.format)
            .with_context(|| format!("unknown report format {:?}", self.format))?;
        let mut sink = self.sink.lock().expect("report sink poisoned");
        reporter.report(&mut *sink, &analysis)
    }
}

/// Gather an [`Analysis`] from the graph: findings matching `query` plus the
/// whole-store file and scan counts.
pub async fn gather_analysis(store: &Store, query: &str) -> Result<Analysis> {
    let findings = store.search_findings(query).await?;
    let (files, scans) = store.counts().await?;
    Ok(Analysis {
        findings,
        files,
        scans,
    })
}

/// Convenience: render a report for `query` in `format` to `sink`, opening the
/// findings store at `store_dir`. Used by the `analyze` CLI command.
pub async fn analyze(
    store_dir: &Path,
    query: &str,
    format: &str,
    sink: &mut dyn Write,
) -> Result<()> {
    let store = Store::open_findings(store_dir).await?;
    let analysis = gather_analysis(&store, query).await?;
    let reporter =
        reporter_for(format).with_context(|| format!("unknown report format {format:?}"))?;
    reporter.report(sink, &analysis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_scan_report_runs_in_order_through_the_graph() {
        let base = std::env::temp_dir().join(format!("exfill-run-test-{}", std::process::id()));
        let tree = base.join("tree");
        let store_dir = tree.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

        let store = Arc::new(Store::open_findings(&store_dir).await.unwrap());
        let sink = Arc::new(Mutex::new(Vec::<u8>::new()));

        let stages: Vec<Box<dyn RunStage>> = vec![
            Box::new(FetchStage),
            Box::new(ScanStage {
                root: tree.clone(),
                pipeline: exfill_scan::default_pipeline().unwrap(),
                skip_dir: Some(store_dir.clone()),
            }),
            Box::new(ReportStage {
                format: "json".into(),
                query: String::new(),
                sink: sink.clone(),
            }),
        ];

        let ctx = RunCtx {
            store: store.clone(),
            events: None,
        };
        run_stages(&stages, &ctx).await.unwrap();

        // The report stage saw findings the scan stage wrote to the graph.
        let out = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["summary"]["findings"], 1);
        assert_eq!(v["findings"][0]["rule"], "aws-access-key-id");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fetch_stage_and_analyze_convenience() {
        let base = std::env::temp_dir().join(format!("exfill-run-conv-{}", std::process::id()));
        let tree = base.join("tree");
        let store_dir = base.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

        // Fetch stage is a declared no-op today.
        let store = Arc::new(Store::open_findings(&store_dir).await.unwrap());
        let ctx = RunCtx {
            store: store.clone(),
            events: None,
        };
        assert_eq!(FetchStage.name(), "fetch");
        FetchStage.run(&ctx).await.unwrap();

        // Seed then use the analyze() convenience over a text sink.
        exfill_engine_scan(&tree, &store, &store_dir).await;
        let mut buf: Vec<u8> = Vec::new();
        analyze(&store_dir, "", "text", &mut buf).await.unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("finding(s) across"), "{out}");

        // Unknown format errors through the convenience path too.
        let mut sink = Vec::new();
        let err = analyze(&store_dir, "", "xml", &mut sink).await.unwrap_err();
        assert!(err.to_string().contains("unknown report format"), "{err}");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Scan `tree` into `store` with the default pipeline (test helper).
    async fn exfill_engine_scan(tree: &Path, store: &Store, store_dir: &Path) {
        let pipeline = exfill_scan::default_pipeline().unwrap();
        crate::scan(tree, &pipeline, store, Some(store_dir), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn report_stage_rejects_unknown_format() {
        let base = std::env::temp_dir().join(format!("exfill-run-badfmt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let store = Arc::new(Store::open_findings(&base).await.unwrap());
        let ctx = RunCtx {
            store,
            events: None,
        };
        let stage = ReportStage {
            format: "xml".into(),
            query: String::new(),
            sink: Arc::new(Mutex::new(Vec::<u8>::new())),
        };
        let err = stage.run(&ctx).await.unwrap_err();
        assert!(err.to_string().contains("unknown report format"), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }
}
