//! exfil — offline filesystem analysis & SAST engine.
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
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

/// Worked examples shown at the bottom of `exfil --help`. Grouped so a new user
/// can see the common paths (scan → search → triage) at a glance.
const EXAMPLES: &str = "\
Examples:
  exfil scan                       Scan the current directory
  exfil scan ~/project             Scan a specific path
  exfil search severity=critical   Show only the critical findings
  exfil analyze --format markdown  Render a report of the findings graph
  exfil tui                        Open the interactive workbench
  exfil scan-remote deploy@web1:/srv   Scan a remote host over SSH

Docs: https://rangertaha.github.io/exfil/";

/// Parse a `--fail-on` severity name into a [`Severity`]. Used as a clap
/// `value_parser`, so an unknown name is reported with the valid choices.
fn parse_severity(s: &str) -> std::result::Result<exfil_core::Severity, String> {
    use exfil_core::Severity::*;
    match s.to_ascii_lowercase().as_str() {
        "info" => Ok(Info),
        "low" => Ok(Low),
        "medium" | "med" => Ok(Medium),
        "high" => Ok(High),
        "critical" | "crit" => Ok(Critical),
        other => Err(format!(
            "unknown severity {other:?} (info|low|medium|high|critical)"
        )),
    }
}

/// Print a discoverability hint to stderr, but only on an interactive terminal
/// so piped or redirected output stays clean and scriptable.
fn hint(msg: &str) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        eprintln!("{msg}");
    }
}

#[derive(Parser)]
#[command(
    name = "exfil",
    version,
    about = "exfil — an offline DevSecOps engine for static analysis of code, infrastructure & systems",
    after_help = EXAMPLES,
    // A bare `exfil` shows the help/examples instead of a terse usage error.
    arg_required_else_help = true,
)]
struct Cli {
    /// Path to the local findings store.
    #[arg(short, long, default_value = ".exfil", global = true)]
    store: String,

    /// Path to a TOML config (default: user config dir, auto-created).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// When to colorize output: auto (default), always, or never.
    #[arg(long, value_enum, default_value_t = ColorWhen::Auto, global = true)]
    color: ColorWhen,

    #[command(subcommand)]
    command: Command,
}

/// `--color` choices, mapped onto [`progress::ColorChoice`].
#[derive(Clone, Copy, clap::ValueEnum)]
enum ColorWhen {
    Auto,
    Always,
    Never,
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
    /// Show the rules a scan would apply, optionally filtered by a substring
    /// of the name, description, CWE, or severity.
    Rules { filter: Option<String> },
    /// Scan a directory tree for patterns and security issues.
    Scan {
        path: Option<String>,
        /// Exit non-zero if any finding is at or above this severity
        /// (info|low|medium|high|critical). Useful as a CI gate.
        #[arg(long, value_name = "SEVERITY", value_parser = parse_severity)]
        fail_on: Option<exfil_core::Severity>,
    },
    /// Scan a remote host over SSH/SFTP (`[user@]host:/path`).
    ScanRemote {
        /// Remote target, e.g. `deploy@web1:/srv`.
        target: String,
        /// SSH port.
        #[arg(short, long, default_value_t = 22)]
        port: u16,
        /// Private key file (default: password auth via $EXFIL_SSH_PASSWORD).
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
    /// Resolve domains observed during scans and flag reserved/private
    /// resolutions (online; authorized use).
    CheckDns,
    /// Normalize findings into CIM events (shared category/action fields) for
    /// cross-source correlation.
    Normalize,
    /// WHOIS-check observed domains and flag newly-registered ones (online;
    /// authorized use).
    CheckWhois {
        /// Flag domains registered within this many days.
        #[arg(long, default_value_t = exfil_scan::whois::DEFAULT_RECENT_DAYS)]
        recent_days: i64,
    },
    /// Query stored findings.
    ///
    /// With no query, lists every finding. A `field=value` term filters on one
    /// of `rule`, `cwe`, `severity`, or `path`; any other text matches against
    /// rule names. Examples: `severity=critical`, `cwe=CWE-798`, `path=src/`,
    /// or just `aws`.
    Search {
        /// `field=value` (rule/cwe/severity/path) or free text; empty lists all.
        query: Option<String>,
    },
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
    Clean {
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
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
    ///
    /// The id is `table:key`, e.g. `file:<blake3-hash>` or `finding:<id>`, as
    /// shown by `search` and the graph. Prints the record as pretty JSON.
    Get {
        /// Record id as `table:key`, e.g. `file:<blake3-hash>`.
        id: String,
    },
    /// Print a shell completion script (bash, zsh, fish, powershell, elvish).
    Completions {
        /// Target shell, e.g. `bash`. Source or install the output; for bash:
        /// `exfil completions bash > /etc/bash_completion.d/exfil`.
        shell: Shell,
    },
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
    progress::set_color_choice(match cli.color {
        ColorWhen::Auto => progress::ColorChoice::Auto,
        ColorWhen::Always => progress::ColorChoice::Always,
        ColorWhen::Never => progress::ColorChoice::Never,
    });
    let store_dir = PathBuf::from(&cli.store);
    match cli.command {
        Command::Config => cmd_config(cli.config.as_deref())?,
        Command::Sources => cmd_sources(),
        Command::Pull { reference } => cmd_pull(cli.config.as_deref(), reference).await?,
        Command::Datasets { action } => cmd_datasets(action).await?,
        Command::Scan { path, fail_on } => {
            cmd_scan(&store_dir, cli.config.as_deref(), path, fail_on).await?
        }
        Command::ScanRemote { target, port, key } => {
            cmd_scan_remote(&store_dir, cli.config.as_deref(), &target, port, key).await?
        }
        Command::Processes => cmd_processes(&store_dir, cli.config.as_deref()).await?,
        Command::ScanTcp { targets } => {
            cmd_scan_tcp(&store_dir, cli.config.as_deref(), targets).await?
        }
        Command::PortScan { hosts, ports } => {
            let targets = exfil_remote::netscan::expand_targets(&hosts, &ports)?;
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
        Command::CheckDns => cmd_check_dns(&store_dir).await?,
        Command::Normalize => cmd_normalize(&store_dir).await?,
        Command::CheckWhois { recent_days } => cmd_check_whois(&store_dir, recent_days).await?,
        Command::Search { query } => cmd_search(&store_dir, query).await?,
        Command::Analyze { query, format } => cmd_analyze(&store_dir, query, &format).await?,
        Command::Get { id } => cmd_get(&store_dir, &id).await?,
        Command::Graph { query, format } => cmd_graph(&store_dir, query, &format).await?,
        Command::Gc => cmd_gc(&store_dir).await?,
        Command::Enrich => cmd_enrich(&store_dir, cli.config.as_deref()).await?,
        Command::Export { out, format } => cmd_export(&store_dir, out, &format).await?,
        Command::Mcp => {
            let store = exfil_store::Store::open_findings(&store_dir).await?;
            exfil_mcp::serve(store).await?;
        }
        Command::Rules { filter } => cmd_rules(filter)?,
        Command::Completions { shell } => cmd_completions(shell),
        Command::Clean { yes } => cmd_clean(&store_dir, yes)?,
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
    let cfg = exfil_config::load(explicit)?;
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
    fail_on: Option<exfil_core::Severity>,
) -> Result<()> {
    let target = PathBuf::from(path.unwrap_or_else(|| ".".to_string()));
    let pipeline = build_pipeline(config).await?;
    let store = exfil_store::Store::open_findings(store_dir).await?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan(&target, &pipeline, &store, Some(store_dir), Some(tx)).await;
    // The engine dropped its sender, so the renderer is finishing; wait for it
    // before printing the summary under the (now final) progress bar.
    let _ = renderer.join();
    let summary = result?;
    println!(
        "scanned {} files ({} unchanged): {} new matches, {} unreadable",
        summary.files, summary.unchanged, summary.matches, summary.errors
    );
    if summary.matches > 0 {
        hint("\nNext: `exfil tui` to triage · `exfil analyze` for a report · `exfil search severity=critical` to filter");
    } else if summary.files > 0 {
        hint(
            "\nNo findings. `exfil rules` shows what was checked; `exfil pull` adds more rulesets.",
        );
    }

    // CI gate: exit non-zero when the store holds a finding at or above the
    // threshold. Checked against the whole store, so a fresh scan gates on its
    // own results and an incremental scan gates on the cumulative state.
    if let Some(threshold) = fail_on {
        let findings = store.search_findings("").await?;
        let breaching = findings
            .iter()
            .filter(|m| m.severity.is_some_and(|s| s.weight() >= threshold.weight()))
            .count();
        if breaching > 0 {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            eprintln!("✗ {breaching} finding(s) at or above {threshold:?}");
            std::process::exit(1);
        }
    }
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
    let target = exfil_remote::RemoteTarget::parse(target, port)?;
    let auth = match key {
        Some(path) => exfil_remote::SshAuth::Key(path, None),
        None => exfil_remote::SshAuth::Password(
            std::env::var("EXFIL_SSH_PASSWORD")
                .context("no --key given and $EXFIL_SSH_PASSWORD is not set for password auth")?,
        ),
    };

    let pipeline = build_pipeline(config).await?;
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let fs = exfil_remote::SshFs::connect(&target, &auth)
        .await
        .with_context(|| format!("connect to {}@{}", target.user, target.host))?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(&fs, &target.path, &pipeline, &store, Some(tx)).await;
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
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let fs = exfil_remote::ProcessFs::new();

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(&fs, "proc://", &pipeline, &store, Some(tx)).await;
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
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let fs = exfil_remote::TcpFs::new(targets);

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(&fs, "tcp://", &pipeline, &store, Some(tx)).await;
    let _ = renderer.join();
    let summary = result?;
    println!(
        "grabbed {} banner(s): {} matches, {} unreachable",
        summary.files, summary.matches, summary.errors
    );
    Ok(())
}

/// WHOIS-check every observed domain and flag newly-registered ones (a common
/// phishing signal). Online: the port-43 lookups run off the async thread.
async fn cmd_check_whois(store_dir: &std::path::Path, recent_days: i64) -> Result<()> {
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let domains = store.indicator_domains().await?;
    let today = exfil_scan::whois::today_epoch_days();
    let total: usize = domains.iter().map(|(_, d)| d.len()).sum();
    eprintln!("WHOIS-checking {total} domain(s)…");

    let mut flagged = 0u64;
    for (hash, list) in domains {
        for domain in list {
            let d = domain.clone();
            let finding = tokio::task::spawn_blocking(move || {
                let whois = exfil_scan::whois::lookup(&d).ok()?;
                exfil_scan::whois::check(&whois, &d, today, recent_days, "whois")
            })
            .await
            .ok()
            .flatten();
            if let Some(m) = finding {
                println!("{}", progress::styled_line(&m));
                store.add_finding(&m, &hash).await?;
                flagged += 1;
            }
        }
    }
    println!("{flagged} newly-registered domain(s)");
    Ok(())
}

/// Normalize every stored finding into a CIM event (shared category/action
/// fields) so heterogeneous findings can be correlated. Prints a per-category
/// summary.
async fn cmd_normalize(store_dir: &std::path::Path) -> Result<()> {
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let findings = store.findings_with_ids("").await?;
    for (fid, m) in &findings {
        let event = exfil_scan::cim::normalize(m);
        let value = serde_json::to_value(&event).unwrap_or_default();
        store.upsert_event(fid, &value).await?;
    }
    println!("normalized {} finding(s) into CIM events", findings.len());
    for (category, n) in store.event_summary().await? {
        println!("  {category:<16} {n}");
    }
    Ok(())
}

/// Resolve every domain observed during scans and flag those resolving to a
/// reserved/private address. Online: runs the blocking resolver off the async
/// thread, then attaches findings to the file each domain came from.
async fn cmd_check_dns(store_dir: &std::path::Path) -> Result<()> {
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let domains = store.indicator_domains().await?;
    let total: usize = domains.iter().map(|(_, d)| d.len()).sum();
    eprintln!("resolving {total} domain(s)…");

    let mut flagged = 0u64;
    for (hash, list) in domains {
        for domain in list {
            // DNS resolution blocks; keep it off the async runtime thread.
            let d = domain.clone();
            let finding =
                tokio::task::spawn_blocking(move || exfil_scan::dns::check_domain(&d, "dns"))
                    .await
                    .ok()
                    .flatten();
            if let Some(m) = finding {
                println!("{}", progress::styled_line(&m));
                store.add_finding(&m, &hash).await?;
                flagged += 1;
            }
        }
    }
    println!("{flagged} domain(s) resolve to reserved addresses");
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
    let store = exfil_store::Store::open_findings(store_dir).await?;
    eprintln!("crawling {url}…");
    let fs = exfil_remote::WebFs::crawl(url, max_pages, max_depth)
        .await
        .with_context(|| format!("crawl {url}"))?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(&fs, "/", &pipeline, &store, Some(tx)).await;
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
async fn build_pipeline(config: Option<&std::path::Path>) -> Result<exfil_task::Pipeline> {
    let mut rules = exfil_scan::builtin_rules();
    if let Ok(dir) = exfil_config::catalog_dir() {
        if dir.exists() {
            if let Ok(catalog) = exfil_store::Store::open_catalog(&dir).await {
                rules.extend(catalog.all_rules().await.unwrap_or_default());
            }
        }
    }
    let clamav_signatures = load_plugin_files(config, "clamav", "signatures");
    let yara_rules = load_plugin_files(config, "yara", "rules");
    let (pipeline, skipped) =
        exfil_scan::pipeline_with_rules(rules, &clamav_signatures, &yara_rules)?;
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
    let nav = exfil_config::load(config)
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
    let Ok(cfg) = exfil_config::load(config) else {
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
    for name in exfil_source::Registry::new().names() {
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
    let dir = exfil_config::catalog_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let catalog = exfil_store::Store::open_catalog(&dir).await?;
    let registry = exfil_source::Registry::new();

    let refs: Vec<(String, String)> = match reference {
        Some(r) => vec![(r.clone(), r)],
        None => exfil_config::load(config)?
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
    let dir = exfil_config::catalog_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let catalog = exfil_store::Store::open_catalog(&dir).await?;

    match action.unwrap_or(DatasetCmd::List) {
        DatasetCmd::List => {
            let datasets = catalog.list_datasets().await?;
            if datasets.is_empty() {
                println!("no datasets — run `exfil pull` to download some");
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
            let mut dataset = exfil_source::Registry::new().fetch(&reference).await?;
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
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let findings = store
        .search_findings(query.as_deref().unwrap_or(""))
        .await?;
    for m in &findings {
        println!("{}", progress::styled_line(m));
    }
    println!("{} finding(s)", findings.len());
    if let Some(summary) = progress::severity_summary(&findings) {
        println!("{summary}");
    }
    if findings.is_empty() {
        hint("No findings. Run `exfil scan` to populate the store, or broaden your query (`exfil search` with no args lists everything).");
    }
    Ok(())
}

/// Render a report over the stored findings graph in the chosen format.
async fn cmd_analyze(
    store_dir: &std::path::Path,
    query: Option<String>,
    format: &str,
) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    exfil_engine::run::analyze(
        store_dir,
        query.as_deref().unwrap_or(""),
        format,
        &mut stdout,
    )
    .await
}

/// Emit the findings graph as JSON or Graphviz DOT.
async fn cmd_graph(store_dir: &std::path::Path, query: Option<String>, format: &str) -> Result<()> {
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let graph = store.graph(query.as_deref().unwrap_or("")).await?;
    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&graph)?),
        "dot" => {
            println!("digraph exfil {{");
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
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let enricher: Box<dyn exfil_llm::Enricher> = match enrich_script_path(config) {
        Some(path) => Box::new(exfil_script::ScriptEnricher::from_file(&path)?),
        None => exfil_llm::default_enricher(),
    };
    let n = exfil_llm::run(&store, enricher.as_ref()).await?;
    println!("enriched {n} finding(s) via {}", enricher.name());
    Ok(())
}

/// The `[plugins.script] enrich = "path"` script path, if configured.
fn enrich_script_path(config: Option<&std::path::Path>) -> Option<String> {
    let cfg = exfil_config::load(config).ok()?;
    let table = cfg.plugin::<toml::Value>("script").ok()??;
    table
        .get("enrich")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Export the whole graph as a portable snapshot in CBOR or JSON.
async fn cmd_export(store_dir: &std::path::Path, out: Option<PathBuf>, format: &str) -> Result<()> {
    let store = exfil_store::Store::open_findings(store_dir).await?;
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
    let store = exfil_store::Store::open_findings(store_dir).await?;
    let stats = store.gc().await?;
    println!(
        "gc: removed {} old scan(s), {} stale file(s), {} finding(s)",
        stats.scans, stats.files, stats.findings
    );
    Ok(())
}

/// Print one stored record (`table:key`) as JSON.
async fn cmd_get(store_dir: &std::path::Path, id: &str) -> Result<()> {
    let store = exfil_store::Store::open_findings(store_dir).await?;
    match store.get_record(id).await? {
        Some(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        None => println!("no record {id:?}"),
    }
    Ok(())
}

/// Print a shell completion script for `shell` to stdout. Generated from the
/// clap command tree, so it always covers the current subcommands and flags.
fn cmd_completions(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "exfil", &mut std::io::stdout());
}

/// Show the rules a scan would apply (currently the built-in set), optionally
/// filtered by a case-insensitive substring of the name, description, CWE, or
/// severity. Prints a trailing count.
fn cmd_rules(filter: Option<String>) -> Result<()> {
    let needle = filter.unwrap_or_default().to_lowercase();
    let matches = |r: &exfil_core::Rule| {
        if needle.is_empty() {
            return true;
        }
        let sev = r.severity.map(|s| format!("{s:?}").to_lowercase());
        r.name.to_lowercase().contains(&needle)
            || r.description.to_lowercase().contains(&needle)
            || r.cwe
                .as_deref()
                .is_some_and(|c| c.to_lowercase().contains(&needle))
            || sev.as_deref() == Some(needle.as_str())
    };

    let mut shown = 0;
    for r in exfil_scan::builtin_rules().iter().filter(|r| matches(r)) {
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
        shown += 1;
    }
    if needle.is_empty() {
        println!("{shown} rule(s)");
    } else {
        println!("{shown} rule(s) matching {needle:?}");
    }
    Ok(())
}

/// Remove the local findings store. Downloaded datasets live in the user config
/// dir and are untouched. On an interactive terminal this asks first (unless
/// `--yes`); when piped/redirected it proceeds, so scripts are unaffected.
fn cmd_clean(store_dir: &std::path::Path, yes: bool) -> Result<()> {
    if !store_dir.exists() {
        println!("no store at {}", store_dir.display());
        return Ok(());
    }
    if !yes && !confirm(&format!("Delete findings store {}?", store_dir.display())) {
        println!("aborted");
        return Ok(());
    }
    std::fs::remove_dir_all(store_dir)
        .with_context(|| format!("remove store {}", store_dir.display()))?;
    println!("removed store {}", store_dir.display());
    Ok(())
}

/// Ask a yes/no question on an interactive terminal, defaulting to no. When
/// stdin is not a terminal (a pipe, a script), there's no one to ask, so this
/// returns `true` and lets the action proceed unattended.
fn confirm(question: &str) -> bool {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return true;
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
