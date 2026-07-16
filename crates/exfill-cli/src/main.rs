//! exfill — Extra File Lang Lookup.
//!
//! Offline, cross-platform, plugin-based filesystem analysis and SAST engine.
//! This is the CLI entry point; commands are wired to the workspace crates as
//! they are implemented.
//!
//! # Rust notes
//!
//! - The `Cli`/`Command` types below are *declarative* argument parsing: the
//!   clap crate's `#[derive(Parser)]` reads the struct and doc-comments and
//!   generates the whole parser, `--help` text, and error messages from them.
//!   The `///` comment on each variant becomes that subcommand's help line.
//! - `#[tokio::main]` wraps `main` in an async runtime so command handlers
//!   can `.await` the database. `main` returning `Result` means an `Err`
//!   prints the error (with its context chain) and exits nonzero — that's the
//!   whole error-reporting strategy of the binary.

mod progress;
mod tui;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "exfill",
    version,
    about = "Extra File Lang Lookup — offline SAST & filesystem graph"
)]
struct Cli {
    /// Path to the local findings store.
    #[arg(short, long, default_value = ".exfill", global = true)]
    store: String,

    /// Path to a TOML config (default: user config dir, auto-created).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the available dataset source plugins.
    Sources,
    /// Download a pattern dataset into the store.
    Pull { reference: String },
    /// Download configured dataset/model updates.
    Update,
    /// List datasets stored in the catalog.
    Datasets,
    /// Show the rules a scan would apply.
    Rules,
    /// Scan a directory tree for patterns and security issues.
    Scan { path: Option<String> },
    /// Query stored findings.
    Search { query: Option<String> },
    /// Emit the findings graph.
    Graph { query: Option<String> },
    /// Analyze the whole findings graph and render a report.
    Analyze { query: Option<String> },
    /// Run the offline LLM enrichment pass over the stored graph.
    Enrich,
    /// Show the resolved config path and contents.
    Config,
    /// Delete the findings store (keeps downloaded datasets).
    Clean,
    /// Garbage-collect unreachable records.
    Gc,
    /// Run an MCP server on stdio for AI agents.
    Mcp,
    /// Open the mutt-style TUI: scan, browse, and query the graph live.
    Tui,
    /// Print a stored record by id.
    Get { id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let store_dir = PathBuf::from(&cli.store);
    match cli.command {
        Command::Config => cmd_config(cli.config.as_deref())?,
        Command::Scan { path } => cmd_scan(&store_dir, path).await?,
        Command::Search { query } => cmd_search(&store_dir, query).await?,
        Command::Get { id } => cmd_get(&store_dir, &id).await?,
        Command::Rules => cmd_rules()?,
        Command::Clean => cmd_clean(&store_dir)?,
        Command::Tui => {
            // The TUI loop blocks on terminal input, so it runs on a blocking
            // thread with a runtime handle for its database calls.
            let handle = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || tui::run(handle, &store_dir)).await??;
        }
        _ => println!("not yet implemented — scaffolding in progress (see PLAN.md)"),
    }
    Ok(())
}

fn cmd_config(explicit: Option<&std::path::Path>) -> Result<()> {
    let cfg = exfill_config::load(explicit)?;
    println!("# config: {}", cfg.path.display());
    println!("store = {:?}", cfg.store);
    for name in cfg.plugins.keys() {
        println!("plugin {name:?}");
    }
    for u in &cfg.update {
        println!("update {:?} -> {}", u.name, u.reference);
    }
    Ok(())
}

/// Walk the target tree, scan it with the registered scanners, and persist
/// files + findings into the local store. Progress renders live: a ratatui
/// gauge on a terminal, plain match lines when piped.
async fn cmd_scan(store_dir: &std::path::Path, path: Option<String>) -> Result<()> {
    let target = PathBuf::from(path.unwrap_or_else(|| ".".to_string()));
    let registry = exfill_scan::default_registry()?;
    let store = exfill_store::Store::open_findings(store_dir).await?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfill_engine::scan(&target, &registry, &store, Some(store_dir), Some(tx)).await;
    // The engine dropped its sender, so the renderer is finishing; wait for it
    // before printing the summary under the (now final) progress bar.
    let _ = renderer.join();
    let summary = result?;
    println!(
        "scanned {} files ({} unchanged): {} new matches, {} unreadable",
        summary.files, summary.unchanged, summary.matches, summary.errors
    );
    Ok(())
}

/// Query stored findings: no arg lists all, `field=value` filters on
/// rule/cwe/severity/path, anything else matches against rule names.
async fn cmd_search(store_dir: &std::path::Path, query: Option<String>) -> Result<()> {
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let findings = store
        .search_findings(query.as_deref().unwrap_or(""))
        .await?;
    for m in &findings {
        println!("{}", progress::match_line(m));
    }
    println!("{} finding(s)", findings.len());
    Ok(())
}

/// Print one stored record (`table:key`) as JSON.
async fn cmd_get(store_dir: &std::path::Path, id: &str) -> Result<()> {
    let store = exfill_store::Store::open_findings(store_dir).await?;
    match store.get_record(id).await? {
        Some(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        None => println!("no record {id:?}"),
    }
    Ok(())
}

/// Show the rules a scan would apply (currently the built-in set).
fn cmd_rules() -> Result<()> {
    for r in exfill_scan::builtin_rules() {
        let sev = r
            .severity
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_else(|| "-".into());
        println!(
            "{:<22} {:<8} {:<8} {}",
            r.name,
            sev,
            r.cwe.as_deref().unwrap_or("-"),
            r.description
        );
    }
    Ok(())
}

/// Remove the local findings store. Downloaded datasets live in the user config
/// dir and are untouched.
fn cmd_clean(store_dir: &std::path::Path) -> Result<()> {
    if store_dir.exists() {
        std::fs::remove_dir_all(store_dir)
            .with_context(|| format!("remove store {}", store_dir.display()))?;
        println!("removed store {}", store_dir.display());
    } else {
        println!("no store at {}", store_dir.display());
    }
    Ok(())
}
