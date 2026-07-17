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

mod keymap;
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
    /// Download datasets: a specific `reference`, or every configured
    /// `[[update]]` (datasets + LLM model) when no reference is given.
    Pull { reference: Option<String> },
    /// Manage catalog datasets (list by default; add/show/rm subcommands).
    Datasets {
        #[command(subcommand)]
        action: Option<DatasetCmd>,
    },
    /// Show the rules a scan would apply.
    Rules,
    /// Scan a directory tree for patterns and security issues.
    Scan { path: Option<String> },
    /// Scan a remote host over SSH/SFTP (`[user@]host:/path`).
    ScanRemote {
        /// Remote target, e.g. `deploy@web1:/srv`.
        target: String,
        /// SSH port.
        #[arg(short, long, default_value_t = 22)]
        port: u16,
        /// Private key file (default: password auth via $EXFILL_SSH_PASSWORD).
        #[arg(short, long)]
        key: Option<PathBuf>,
    },
    /// Scan the local host's running processes (command lines, exe paths).
    Processes,
    /// Grab and scan TCP service banners from `host:port` targets (authorized
    /// testing only).
    ScanTcp {
        /// One or more `host:port` targets, e.g. `example.com:22`.
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Sweep an IP/CIDR across ports, grab banners of open ones, and scan them
    /// (authorized testing only).
    PortScan {
        /// Host or IPv4 CIDR, e.g. `10.0.0.0/28`.
        hosts: String,
        /// Ports: list/ranges (`22,80,8000-8010`) or `common`.
        #[arg(short, long, default_value = "common")]
        ports: String,
    },
    /// Crawl a website from a seed URL and scan the pages (authorized testing
    /// only).
    ScanWeb {
        /// Seed URL, e.g. `https://example.com`.
        url: String,
        /// Maximum pages to fetch.
        #[arg(long, default_value_t = 64)]
        max_pages: usize,
        /// Maximum link depth from the seed.
        #[arg(long, default_value_t = 2)]
        max_depth: usize,
    },
    /// Query stored findings.
    Search { query: Option<String> },
    /// Emit the findings graph (finding → file / rule) as JSON or DOT.
    Graph {
        /// Optional finding filter (same syntax as `search`).
        query: Option<String>,
        /// Output format: json or dot.
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    /// Analyze the whole findings graph and render a report.
    Analyze {
        /// Optional finding filter (same syntax as `search`).
        query: Option<String>,
        /// Report format: text, json, markdown, or junit.
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Run the offline LLM enrichment pass over the stored graph.
    Enrich,
    /// Show the resolved config path and contents.
    Config,
    /// Delete the findings store (keeps downloaded datasets).
    Clean,
    /// Garbage-collect unreachable records.
    Gc,
    /// Export the whole graph as a portable snapshot (CBOR or JSON).
    Export {
        /// Output file (default: stdout for json, required for cbor).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Format: cbor (DAG-CBOR-style binary) or json.
        #[arg(short, long, default_value = "cbor")]
        format: String,
    },
    /// Run an MCP server on stdio for AI agents.
    Mcp,
    /// Open the mutt-style TUI: scan, browse, and query the graph live.
    Tui,
    /// Print a stored record by id.
    Get { id: String },
}

/// Catalog dataset management actions.
#[derive(Subcommand)]
enum DatasetCmd {
    /// List stored datasets and their rule counts (the default).
    List,
    /// Show a dataset's rules.
    Show { name: String },
    /// Add (or replace) a named dataset from a source reference.
    Add { name: String, reference: String },
    /// Remove a dataset from the catalog.
    Rm { name: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let store_dir = PathBuf::from(&cli.store);
    match cli.command {
        Command::Config => cmd_config(cli.config.as_deref())?,
        Command::Sources => cmd_sources(),
        Command::Pull { reference } => cmd_pull(cli.config.as_deref(), reference).await?,
        Command::Datasets { action } => cmd_datasets(action).await?,
        Command::Scan { path } => cmd_scan(&store_dir, cli.config.as_deref(), path).await?,
        Command::ScanRemote { target, port, key } => {
            cmd_scan_remote(&store_dir, cli.config.as_deref(), &target, port, key).await?
        }
        Command::Processes => cmd_processes(&store_dir, cli.config.as_deref()).await?,
        Command::ScanTcp { targets } => {
            cmd_scan_tcp(&store_dir, cli.config.as_deref(), targets).await?
        }
        Command::PortScan { hosts, ports } => {
            let targets = exfill_remote::netscan::expand_targets(&hosts, &ports)?;
            eprintln!("sweeping {} host:port targets…", targets.len());
            cmd_scan_tcp(&store_dir, cli.config.as_deref(), targets).await?
        }
        Command::ScanWeb {
            url,
            max_pages,
            max_depth,
        } => {
            cmd_scan_web(
                &store_dir,
                cli.config.as_deref(),
                &url,
                max_pages,
                max_depth,
            )
            .await?
        }
        Command::Search { query } => cmd_search(&store_dir, query).await?,
        Command::Analyze { query, format } => cmd_analyze(&store_dir, query, &format).await?,
        Command::Get { id } => cmd_get(&store_dir, &id).await?,
        Command::Graph { query, format } => cmd_graph(&store_dir, query, &format).await?,
        Command::Gc => cmd_gc(&store_dir).await?,
        Command::Enrich => cmd_enrich(&store_dir, cli.config.as_deref()).await?,
        Command::Export { out, format } => cmd_export(&store_dir, out, &format).await?,
        Command::Mcp => {
            let store = exfill_store::Store::open_findings(&store_dir).await?;
            exfill_mcp::serve(store).await?;
        }
        Command::Rules => cmd_rules()?,
        Command::Clean => cmd_clean(&store_dir)?,
        Command::Tui => {
            // The TUI loop blocks on terminal input, so it runs on a blocking
            // thread with a runtime handle for its database calls.
            let keymap = load_keymap(cli.config.as_deref());
            let handle = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || tui::run(handle, &store_dir, keymap)).await??;
        }
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
async fn cmd_scan(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    path: Option<String>,
) -> Result<()> {
    let target = PathBuf::from(path.unwrap_or_else(|| ".".to_string()));
    let pipeline = build_pipeline(config).await?;
    let store = exfill_store::Store::open_findings(store_dir).await?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfill_engine::scan(&target, &pipeline, &store, Some(store_dir), Some(tx)).await;
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

/// Scan a remote host over SSH/SFTP: connect, walk its files, and run the same
/// pipeline as a local scan, tagging findings with the remote host.
async fn cmd_scan_remote(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    target: &str,
    port: u16,
    key: Option<PathBuf>,
) -> Result<()> {
    let target = exfill_remote::RemoteTarget::parse(target, port)?;
    let auth = match key {
        Some(path) => exfill_remote::SshAuth::Key(path, None),
        None => exfill_remote::SshAuth::Password(
            std::env::var("EXFILL_SSH_PASSWORD")
                .context("no --key given and $EXFILL_SSH_PASSWORD is not set for password auth")?,
        ),
    };

    let pipeline = build_pipeline(config).await?;
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let fs = exfill_remote::SshFs::connect(&target, &auth)
        .await
        .with_context(|| format!("connect to {}@{}", target.user, target.host))?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfill_engine::scan_remote(&fs, &target.path, &pipeline, &store, Some(tx)).await;
    let _ = renderer.join();
    let summary = result?;
    println!(
        "scanned {}:{} — {} files: {} matches, {} unreadable",
        target.host, target.path, summary.files, summary.matches, summary.errors
    );
    Ok(())
}

/// Scan the local host's running processes: each process's name, exe path, and
/// command line is scanned by the full pipeline (secrets on a command line, PII,
/// bad domains/IPs in arguments). Reuses `scan_remote` with a process source.
async fn cmd_processes(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
) -> Result<()> {
    let pipeline = build_pipeline(config).await?;
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let fs = exfill_remote::ProcessFs::new();

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfill_engine::scan_remote(&fs, "proc://", &pipeline, &store, Some(tx)).await;
    let _ = renderer.join();
    let summary = result?;
    println!(
        "scanned {} processes: {} matches, {} unreadable",
        summary.files, summary.matches, summary.errors
    );
    Ok(())
}

/// Grab TCP service banners from `targets` and scan them with the full
/// pipeline (version strings, exposed secrets, bad indicators in banners).
async fn cmd_scan_tcp(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    targets: Vec<String>,
) -> Result<()> {
    let pipeline = build_pipeline(config).await?;
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let fs = exfill_remote::TcpFs::new(targets);

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfill_engine::scan_remote(&fs, "tcp://", &pipeline, &store, Some(tx)).await;
    let _ = renderer.join();
    let summary = result?;
    println!(
        "grabbed {} banner(s): {} matches, {} unreachable",
        summary.files, summary.matches, summary.errors
    );
    Ok(())
}

/// Crawl a website and scan the fetched pages with the full pipeline (leaked
/// secrets/keys in HTML/JS, PII, bad indicators).
async fn cmd_scan_web(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    url: &str,
    max_pages: usize,
    max_depth: usize,
) -> Result<()> {
    let pipeline = build_pipeline(config).await?;
    let store = exfill_store::Store::open_findings(store_dir).await?;
    eprintln!("crawling {url}…");
    let fs = exfill_remote::WebFs::crawl(url, max_pages, max_depth)
        .await
        .with_context(|| format!("crawl {url}"))?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfill_engine::scan_remote(&fs, "/", &pipeline, &store, Some(tx)).await;
    let _ = renderer.join();
    let summary = result?;
    println!(
        "crawled {} page(s): {} matches, {} unreadable",
        summary.files, summary.matches, summary.errors
    );
    Ok(())
}

/// Build the scan pipeline: built-in rules plus any catalog datasets, plus
/// ClamAV signatures from files listed under `[plugins.clamav]` in config.
/// Non-compiling external regex patterns are reported and skipped.
async fn build_pipeline(config: Option<&std::path::Path>) -> Result<exfill_task::Pipeline> {
    let mut rules = exfill_scan::builtin_rules();
    if let Ok(dir) = exfill_config::catalog_dir() {
        if dir.exists() {
            if let Ok(catalog) = exfill_store::Store::open_catalog(&dir).await {
                rules.extend(catalog.all_rules().await.unwrap_or_default());
            }
        }
    }
    let clamav_signatures = load_plugin_files(config, "clamav", "signatures");
    let yara_rules = load_plugin_files(config, "yara", "rules");
    let (pipeline, skipped) =
        exfill_scan::pipeline_with_rules(rules, &clamav_signatures, &yara_rules)?;
    if !skipped.is_empty() {
        eprintln!(
            "skipped {} rule(s) with unsupported patterns",
            skipped.len()
        );
    }
    Ok(pipeline)
}

/// Build the navigator keymap from config: vim defaults overlaid with any
/// `[keymap.nav]` remappings. A missing/unreadable config yields the defaults.
fn load_keymap(config: Option<&std::path::Path>) -> keymap::Keymap {
    let nav = exfill_config::load(config)
        .ok()
        .and_then(|c| c.keymap)
        .and_then(|k| k.get("nav").cloned())
        .and_then(|v| v.as_table().cloned());
    keymap::Keymap::from_config(nav.as_ref())
}

/// Read and concatenate the files listed in a plugin's string-array field
/// (e.g. `[plugins.clamav] signatures = [...]` or `[plugins.yara] rules =
/// [...]`). Missing files are skipped silently; a missing/unreadable config or
/// absent field yields an empty string.
fn load_plugin_files(config: Option<&std::path::Path>, plugin: &str, field: &str) -> String {
    let Ok(cfg) = exfill_config::load(config) else {
        return String::new();
    };
    let Ok(Some(table)) = cfg.plugin::<toml::Value>(plugin) else {
        return String::new();
    };
    let Some(paths) = table.get(field).and_then(|v| v.as_array()) else {
        return String::new();
    };
    let mut text = String::new();
    for path in paths.iter().filter_map(|v| v.as_str()) {
        if let Ok(contents) = std::fs::read_to_string(path) {
            text.push_str(&contents);
            text.push('\n');
        }
    }
    text
}

/// List the available dataset source plugins.
fn cmd_sources() {
    println!("available sources:");
    for name in exfill_source::Registry::new().names() {
        let schemes = match name {
            "builtin" => "builtin://",
            "file" => "file:// or a path",
            "http" => "http:// https://",
            _ => "",
        };
        println!("  {name:<8} {schemes}");
    }
}

/// Download a dataset into the catalog: a specific reference, or every
/// configured `[[update]]` when none is given.
async fn cmd_pull(config: Option<&std::path::Path>, reference: Option<String>) -> Result<()> {
    let dir = exfill_config::catalog_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let catalog = exfill_store::Store::open_catalog(&dir).await?;
    let registry = exfill_source::Registry::new();

    let refs: Vec<(String, String)> = match reference {
        Some(r) => vec![(r.clone(), r)],
        None => exfill_config::load(config)?
            .update
            .into_iter()
            .map(|u| (u.name, u.reference))
            .collect(),
    };
    if refs.is_empty() {
        println!("nothing to pull (no reference and no [[update]] entries configured)");
        return Ok(());
    }
    for (name, reference) in refs {
        match registry.fetch(&reference).await {
            Ok(dataset) => {
                let n = catalog.upsert_dataset(&dataset).await?;
                println!("pulled {:?} ({} rules) from {reference}", dataset.name, n);
            }
            Err(e) => eprintln!("failed to pull {name:?} from {reference}: {e:#}"),
        }
    }
    Ok(())
}

/// Manage catalog datasets: list (default), show, add, or remove.
async fn cmd_datasets(action: Option<DatasetCmd>) -> Result<()> {
    let dir = exfill_config::catalog_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let catalog = exfill_store::Store::open_catalog(&dir).await?;

    match action.unwrap_or(DatasetCmd::List) {
        DatasetCmd::List => {
            let datasets = catalog.list_datasets().await?;
            if datasets.is_empty() {
                println!("no datasets — run `exfill pull` to download some");
                return Ok(());
            }
            for (name, rules) in &datasets {
                println!("{name:<24} {rules} rules");
            }
            println!("{} dataset(s)", datasets.len());
        }
        DatasetCmd::Show { name } => match catalog.get_dataset(&name).await? {
            Some(ds) => {
                println!("# dataset {:?} ({} rules)", ds.name, ds.rules.len());
                for r in &ds.rules {
                    let sev = r
                        .severity
                        .map(|s| format!("{s:?}").to_lowercase())
                        .unwrap_or_else(|| "-".into());
                    println!(
                        "{:<28} {:<8} {:<10} {}",
                        r.name,
                        sev,
                        r.cwe.as_deref().unwrap_or("-"),
                        r.pattern
                    );
                }
            }
            None => println!("no dataset {name:?}"),
        },
        DatasetCmd::Add { name, reference } => {
            let mut dataset = exfill_source::Registry::new().fetch(&reference).await?;
            dataset.name = name; // store under the user-chosen name
            let n = catalog.upsert_dataset(&dataset).await?;
            println!(
                "added dataset {:?} ({} rules) from {reference}",
                dataset.name, n
            );
        }
        DatasetCmd::Rm { name } => {
            if catalog.remove_dataset(&name).await? {
                println!("removed dataset {name:?}");
            } else {
                println!("no dataset {name:?}");
            }
        }
    }
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

/// Render a report over the stored findings graph in the chosen format.
async fn cmd_analyze(
    store_dir: &std::path::Path,
    query: Option<String>,
    format: &str,
) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    exfill_engine::run::analyze(
        store_dir,
        query.as_deref().unwrap_or(""),
        format,
        &mut stdout,
    )
    .await
}

/// Emit the findings graph as JSON or Graphviz DOT.
async fn cmd_graph(store_dir: &std::path::Path, query: Option<String>, format: &str) -> Result<()> {
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let graph = store.graph(query.as_deref().unwrap_or("")).await?;
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&graph)?),
        "dot" => {
            println!("digraph exfill {{");
            println!("  rankdir=LR;");
            for n in &graph.nodes {
                let shape = match n.kind.as_str() {
                    "finding" => "box",
                    "file" => "folder",
                    _ => "ellipse",
                };
                println!("  {:?} [label={:?}, shape={shape}];", n.id, n.label);
            }
            for e in &graph.edges {
                println!("  {:?} -> {:?} [label={:?}];", e.from, e.to, e.rel);
            }
            println!("}}");
        }
        other => anyhow::bail!("unknown graph format {other:?} (use json or dot)"),
    }
    Ok(())
}

/// Enrich stored findings with triage notes. A Rhai script configured under
/// `[plugins.script] enrich = "…"` supersedes the built-in rule-based enricher;
/// a downloaded offline model could too, via the same trait.
async fn cmd_enrich(store_dir: &std::path::Path, config: Option<&std::path::Path>) -> Result<()> {
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let enricher: Box<dyn exfill_llm::Enricher> = match enrich_script_path(config) {
        Some(path) => Box::new(exfill_script::ScriptEnricher::from_file(&path)?),
        None => exfill_llm::default_enricher(),
    };
    let n = exfill_llm::run(&store, enricher.as_ref()).await?;
    println!("enriched {n} finding(s) via {}", enricher.name());
    Ok(())
}

/// The `[plugins.script] enrich = "path"` script path, if configured.
fn enrich_script_path(config: Option<&std::path::Path>) -> Option<String> {
    let cfg = exfill_config::load(config).ok()?;
    let table = cfg.plugin::<toml::Value>("script").ok()??;
    table
        .get("enrich")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Export the whole graph as a portable snapshot in CBOR or JSON.
async fn cmd_export(store_dir: &std::path::Path, out: Option<PathBuf>, format: &str) -> Result<()> {
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let snapshot = store.export_snapshot().await?;
    match format {
        "json" => {
            let text = serde_json::to_string_pretty(&snapshot)?;
            match out {
                Some(path) => std::fs::write(&path, text)
                    .with_context(|| format!("write {}", path.display()))?,
                None => println!("{text}"),
            }
        }
        "cbor" => {
            let mut bytes = Vec::new();
            ciborium::into_writer(&snapshot, &mut bytes).context("encode CBOR")?;
            match out {
                Some(path) => {
                    std::fs::write(&path, &bytes)
                        .with_context(|| format!("write {}", path.display()))?;
                    eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
                }
                None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&bytes)?;
                }
            }
        }
        other => anyhow::bail!("unknown export format {other:?} (use cbor or json)"),
    }
    Ok(())
}

/// Garbage-collect the findings store: prune superseded scans and records.
async fn cmd_gc(store_dir: &std::path::Path) -> Result<()> {
    let store = exfill_store::Store::open_findings(store_dir).await?;
    let stats = store.gc().await?;
    println!(
        "gc: removed {} old scan(s), {} stale file(s), {} finding(s)",
        stats.scans, stats.files, stats.findings
    );
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
