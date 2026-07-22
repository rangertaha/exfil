//! exfil — an offline DevSecOps engine for static analysis.
//!
//! Offline, cross-platform, plugin-based static analysis of source code,
//! infrastructure code, systems, and container artifacts. This is the CLI
//! entry point; commands are wired to the workspace crates as they are
//! implemented.
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

mod graphql;
mod progress;
mod server;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

/// Worked examples shown at the bottom of `exfil --help`. Grouped so a new user
/// can see the common paths (scan → search → triage) at a glance.
const EXAMPLES: &str = "\
Examples:
  exfil scan                       Scan the current directory (passive)
  exfil scan ~/project             Scan a specific path
  exfil scan processes             Scan local running processes (passive)
  exfil scan example.com:22        Grab & scan a service banner (active)
  exfil search severity=critical   Show only the critical findings
  exfil analyze --format markdown  Render a report of the findings graph

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

/// Print the per-severity tally line after a scan summary, when any match was
/// rated. Shared by the local and remote scan commands.
fn print_tally(counts: &progress::SevCounts) {
    if let Some(tally) = progress::tally_line(counts) {
        println!("{tally}");
    }
}

/// The `[database]` override from config, or `None` for the embedded default.
/// An empty (or absent) endpoint keeps the built-in per-path embedded stores.
fn database_override(config: Option<&std::path::Path>) -> Option<exfil_store::DbConfig> {
    let db = exfil_config::load(config).ok()?.database?;
    if db.endpoint.trim().is_empty() {
        return None;
    }
    Some(exfil_store::DbConfig {
        endpoint: db.endpoint,
        username: db.username,
        password: db.password,
    })
}

/// Open the findings database: the configured `[database]` endpoint, or the
/// embedded on-disk store at `store_dir`.
async fn open_findings(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
) -> Result<exfil_store::Store> {
    match database_override(config) {
        Some(db) => exfil_store::Store::connect(&db, exfil_store::DB_FINDINGS).await,
        None => exfil_store::Store::open_findings(store_dir).await,
    }
}

/// Open the catalog database (datasets, rules, CWE): the configured
/// `[database]` endpoint, or the embedded catalog in the config directory.
async fn open_catalog(config: Option<&std::path::Path>) -> Result<exfil_store::Store> {
    if let Some(db) = database_override(config) {
        return exfil_store::Store::connect(&db, exfil_store::DB_CATALOG).await;
    }
    let dir = exfil_config::catalog_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    exfil_store::Store::open_catalog(&dir).await
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
    /// Path to the local findings store (default: `.exfil`, or the system
    /// data dir when running with elevated privileges — see `exfil config`).
    #[arg(short, long, global = true)]
    store: Option<String>,

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
    /// Manage the URL feed catalog and fetch feeds into rule datasets (list by
    /// default; add/rm/pull subcommands).
    Feeds {
        #[command(subcommand)]
        action: Option<FeedCmd>,
    },
    /// Show the rules a scan would apply, optionally filtered by a substring
    /// of the name, description, CWE, or severity.
    Rules { filter: Option<String> },
    /// Scan a target for secrets and security issues. With no target, scans
    /// the current directory. Passive targets stay on the local system: a
    /// path (default), or the literal `processes`. Active targets reach out
    /// over the network (authorized testing only): one or more
    /// comma-separated `host:port` banner targets, a host/CIDR swept across
    /// `--ports`, or an `http(s)://` URL to crawl.
    Scan {
        /// Target to scan: a local path, `processes`, `host:port`
        /// (comma-separated for several), a host/CIDR (with `--ports`), or
        /// an `http(s)://` URL. Default: the current directory.
        target: Option<String>,
        /// Sweep `target` (a host or IPv4 CIDR, e.g. `10.0.0.0/28`) across
        /// these ports instead of treating it as a path: list/ranges
        /// (`22,80,8000-8010`) or `common`.
        #[arg(long, value_name = "PORTS", requires = "target")]
        ports: Option<String>,
        /// Maximum pages to fetch when `target` is a URL.
        #[arg(long, default_value_t = 64)]
        max_pages: usize,
        /// Maximum link depth from the seed when `target` is a URL.
        #[arg(long, default_value_t = 2)]
        max_depth: usize,
        /// Render pages through a WebDriver server (e.g.
        /// `http://localhost:4444`) when `target` is a URL, to crawl
        /// JavaScript-heavy, dynamic sites.
        #[arg(long, value_name = "URL")]
        driver: Option<String>,
        /// Tag this as an active scan (it reached a remote system) in the
        /// summary. Inferred from the target when neither this nor
        /// `--passive` is given.
        #[arg(short = 'a', long, conflicts_with = "passive")]
        active: bool,
        /// Tag this as a passive scan (local system only) in the summary.
        /// Inferred from the target when neither this nor `--active` is
        /// given.
        #[arg(short = 'p', long, conflicts_with = "active")]
        passive: bool,
        /// Exit non-zero if any finding is at or above this severity
        /// (info|low|medium|high|critical). Useful as a CI gate.
        #[arg(long, value_name = "SEVERITY", value_parser = parse_severity)]
        fail_on: Option<exfil_core::Severity>,
    },
    /// Check observed indicators against live network sources (online;
    /// authorized use). `check dns` resolves domains; `check whois` ages them.
    Check {
        #[command(subcommand)]
        action: CheckCmd,
    },
    /// Normalize findings into CIM events (shared category/action fields) for
    /// cross-source correlation.
    Normalize,
    /// Query stored findings.
    ///
    /// With no query, lists every finding. A `field=value` term filters on one
    /// of `rule`, `cwe`, `severity`, or `path`; any other text matches against
    /// rule names. Examples: `severity=critical`, `cwe=CWE-798`, `path=src/`,
    /// or just `aws`.
    Search {
        /// `field=value` (rule/cwe/severity/path) or free text; empty lists all.
        query: Option<String>,
        /// Show at most N findings (the most severe first).
        #[arg(short = 'n', long)]
        limit: Option<usize>,
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
        /// Report format: text, json, markdown, junit, or sarif.
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Run the offline LLM enrichment pass over the stored graph.
    Enrich,
    /// Look up a weakness in the local MITRE CWE catalog (`exfil pull
    /// mitre://cwe` downloads it).
    Cwe {
        /// CWE id, e.g. `CWE-798` or `798`.
        id: String,
    },
    /// Show the resolved config path and contents.
    Config,
    /// Maintain the findings store: export a snapshot, garbage-collect, or
    /// delete it (`store export`/`gc`/`clean`).
    Store {
        #[command(subcommand)]
        action: StoreCmd,
    },
    /// Run an MCP server on stdio for AI agents.
    Mcp,
    /// Run a long-lived service exposing a read-only HTTP API over the findings
    /// graph (`/health`, `/findings`, `/rules`, `/stats`) until interrupted.
    Server {
        /// Address to bind, e.g. `127.0.0.1:8080` or `0.0.0.0:8080`.
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
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
    /// Manage per-plugin settings (overrides live in the catalog, taking
    /// precedence over `[plugins.<name>]` in the config file).
    Plugin {
        #[command(subcommand)]
        action: PluginCmd,
    },
}

/// Plugin setting actions.
#[derive(Subcommand)]
enum PluginCmd {
    /// Interactively walk every setting on a plugin — a select menu for
    /// fixed choices, a validated prompt for free-form input — pre-filled
    /// with each setting's current effective value.
    Config {
        /// Plugin name, e.g. `scan`.
        plugin: String,
    },
}

/// Network reachability checks over observed indicators (online).
#[derive(Subcommand)]
enum CheckCmd {
    /// Resolve domains observed during scans and flag reserved/private
    /// resolutions.
    Dns,
    /// WHOIS-check observed domains and flag newly-registered ones.
    Whois {
        /// Flag domains registered within this many days.
        #[arg(long, default_value_t = exfil_scan::whois::DEFAULT_RECENT_DAYS)]
        recent_days: i64,
    },
}

/// Findings-store maintenance actions.
#[derive(Subcommand)]
enum StoreCmd {
    /// Export the whole graph as a portable snapshot (CBOR or JSON).
    Export {
        /// Output file (default: stdout for json, required for cbor).
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Format: cbor (DAG-CBOR-style binary) or json.
        #[arg(short, long, default_value = "cbor")]
        format: String,
    },
    /// Garbage-collect unreachable records.
    Gc,
    /// Delete the findings store (keeps downloaded datasets).
    Clean {
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
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

/// URL feed catalog actions.
#[derive(Subcommand)]
enum FeedCmd {
    /// List stored feeds and their URLs (the default).
    List,
    /// Add (or update) a feed URL under a name.
    Add { name: String, url: String },
    /// Remove a feed from the catalog.
    Rm { name: String },
    /// Show a feed's URL and a breakdown of the rules it last pulled.
    Show { name: String },
    /// Fetch feeds into rule datasets: a specific `name`, or all when omitted.
    Pull { name: Option<String> },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    progress::set_color_choice(match cli.color {
        ColorWhen::Auto => progress::ColorChoice::Auto,
        ColorWhen::Always => progress::ColorChoice::Always,
        ColorWhen::Never => progress::ColorChoice::Never,
    });
    let store_dir = match &cli.store {
        Some(s) => PathBuf::from(s),
        None => exfil_config::default_store_dir(),
    };
    let cfg = cli.config.as_deref();
    match cli.command {
        Command::Config => cmd_config(cli.config.as_deref())?,
        Command::Sources => cmd_sources(),
        Command::Pull { reference } => cmd_pull(cli.config.as_deref(), reference).await?,
        Command::Datasets { action } => cmd_datasets(cfg, action).await?,
        Command::Feeds { action } => cmd_feeds(cfg, action).await?,
        Command::Scan {
            target,
            ports,
            max_pages,
            max_depth,
            driver,
            active,
            passive,
            fail_on,
        } => {
            cmd_scan(
                &store_dir,
                cfg,
                target,
                ports,
                max_pages,
                max_depth,
                driver.as_deref(),
                explicit_scan_mode(active, passive),
                fail_on,
            )
            .await?
        }
        Command::Check { action } => match action {
            CheckCmd::Dns => cmd_check_dns(&store_dir, cfg).await?,
            CheckCmd::Whois { recent_days } => {
                cmd_check_whois(&store_dir, cfg, recent_days).await?
            }
        },
        Command::Normalize => cmd_normalize(&store_dir, cfg).await?,
        Command::Search { query, limit } => cmd_search(&store_dir, cfg, query, limit).await?,
        Command::Analyze { query, format } => cmd_analyze(&store_dir, cfg, query, &format).await?,
        Command::Get { id } => cmd_get(&store_dir, cfg, &id).await?,
        Command::Graph { query, format } => cmd_graph(&store_dir, cfg, query, &format).await?,
        Command::Store { action } => match action {
            StoreCmd::Export { out, format } => cmd_export(&store_dir, cfg, out, &format).await?,
            StoreCmd::Gc => cmd_gc(&store_dir, cfg).await?,
            StoreCmd::Clean { yes } => cmd_clean(&store_dir, yes)?,
        },
        Command::Enrich => cmd_enrich(&store_dir, cfg).await?,
        Command::Cwe { id } => cmd_cwe(cfg, &id).await?,
        Command::Mcp => {
            let store = open_findings(&store_dir, cfg).await?;
            exfil_mcp::serve(store).await?;
        }
        Command::Server { addr } => cmd_server(&store_dir, cfg, &addr).await?,
        Command::Rules { filter } => cmd_rules(filter)?,
        Command::Completions { shell } => cmd_completions(shell),
        Command::Plugin { action } => match action {
            PluginCmd::Config { plugin } => cmd_plugin_config(cfg, &plugin).await?,
        },
    }
    Ok(())
}

/// Show the resolved config path and its contents, so the user can see exactly
/// what a scan will use and where to edit it. Prints the actual TOML file when
/// it exists (the default is written on first run); if it can't be read, falls
/// back to a summary of the loaded values.
fn cmd_config(explicit: Option<&std::path::Path>) -> Result<()> {
    let cfg = exfil_config::load(explicit)?;
    println!("# config: {}", cfg.path.display());
    match std::fs::read_to_string(&cfg.path) {
        Ok(contents) => print!("{contents}"),
        Err(_) => {
            println!("store = {:?}", cfg.store);
            for name in cfg.plugins.keys() {
                println!("plugin {name:?}");
            }
            for u in &cfg.update {
                println!("update {:?} -> {}", u.name, u.reference);
            }
        }
    }
    Ok(())
}

/// Whether a scan reached out to a remote system (active) or stayed on the
/// local one (passive). Shown with the scan summary; `-a`/`-p` override the
/// default inferred from the target's shape.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Active,
    Passive,
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ScanMode::Active => "active",
            ScanMode::Passive => "passive",
        })
    }
}

/// Resolve the `-a`/`-p` flags (mutually exclusive per clap) to an explicit
/// mode override, or `None` to infer one from the target.
fn explicit_scan_mode(active: bool, passive: bool) -> Option<ScanMode> {
    if active {
        Some(ScanMode::Active)
    } else if passive {
        Some(ScanMode::Passive)
    } else {
        None
    }
}

/// Parse `spec` as one or more comma-separated `host:port` banner-grab
/// targets. `None` if any piece lacks a trailing `:<port>`, so callers fall
/// back to treating `spec` as a local path.
fn parse_tcp_targets(spec: &str) -> Option<Vec<String>> {
    let pieces: Vec<&str> = spec.split(',').collect();
    let all_host_port = pieces.iter().all(|p| {
        p.rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    });
    all_host_port.then(|| pieces.into_iter().map(String::from).collect())
}

/// Every plugin's published config schema (see `exfil_config::PluginSchema`),
/// gathered from the plugin crates that each define their own — the same
/// "define it, register it" seam as `Source`/`Reporter`/`RemoteFs`.
const PLUGIN_SCHEMAS: &[exfil_config::PluginSchema] = &[exfil_remote::netscan::PLUGIN_SCHEMA];

/// Find a plugin's schema and one of its fields by name.
fn find_plugin_field(
    plugin: &str,
    key: &str,
) -> Option<(
    &'static exfil_config::PluginSchema,
    &'static exfil_config::FieldSchema,
)> {
    let schema = PLUGIN_SCHEMAS.iter().find(|p| p.name == plugin)?;
    let field = schema.fields.iter().find(|f| f.key == key)?;
    Some((schema, field))
}

/// Resolve a setting's effective value: a catalog override, else the config
/// file's `[plugins.<plugin>]` table, else the field's own schema default.
/// Best-effort — a store/config read failure, or a value that fails the
/// field's own validation (e.g. a hand-edited config out of range), just
/// falls through to the next layer rather than erroring, with a warning so
/// an ignored value isn't silently mistaken for one that took effect.
async fn resolve_plugin_setting(
    config: Option<&std::path::Path>,
    plugin: &str,
    field: &exfil_config::FieldSchema,
) -> String {
    if let Ok(catalog) = open_catalog(config).await {
        if let Ok(Some(v)) = catalog.get_plugin_setting(plugin, field.key).await {
            match field.validate(&v) {
                Ok(normalized) => return normalized,
                Err(e) => eprintln!(
                    "warning: stored {plugin}.{} override {v:?} is invalid ({e}); ignoring",
                    field.key
                ),
            }
        }
    }
    if let Ok(cfg) = exfil_config::load(config) {
        if let Some(v) = cfg.plugin_field(plugin, field.key) {
            match field.validate(&v) {
                Ok(normalized) => return normalized,
                Err(e) => eprintln!(
                    "warning: config [plugins.{plugin}] {}={v:?} is invalid ({e}); ignoring",
                    field.key
                ),
            }
        }
    }
    field.default.to_string()
}

/// Interactively walk every setting on a plugin: a select menu for fixed
/// choices (`Select`/`Bool`), a validated text prompt for a number — each
/// pre-filled with the setting's current effective value — saving each
/// answer as a catalog override as soon as it's confirmed.
async fn cmd_plugin_config(config: Option<&std::path::Path>, plugin: &str) -> Result<()> {
    let schema = PLUGIN_SCHEMAS
        .iter()
        .find(|p| p.name == plugin)
        .with_context(|| format!("no such plugin {plugin:?}"))?;
    let catalog = open_catalog(config).await?;
    println!("Configuring {plugin:?} ({} setting(s)):\n", schema.fields.len());
    for field in schema.fields {
        let current = resolve_plugin_setting(config, plugin, field).await;
        let answer = prompt_field(field, &current)?;
        let normalized = field.validate(&answer).map_err(|e| anyhow::anyhow!(e))?;
        catalog.set_plugin_setting(plugin, field.key, &normalized).await?;
        println!("{plugin}.{} = {normalized}\n", field.key);
    }
    Ok(())
}

/// Prompt for one field's new value: a select menu for `Select`/`Bool`
/// (cursor starting on the current value), or a validated text input for
/// `Number`, defaulting to the current value.
fn prompt_field(field: &'static exfil_config::FieldSchema, current: &str) -> Result<String> {
    use inquire::validator::Validation;
    use inquire::{Select, Text};

    let message = format!("{} — {}", field.key, field.description);
    match field.kind {
        exfil_config::FieldKind::Select(options) => {
            let idx = options.iter().position(|o| *o == current).unwrap_or(0);
            let choice = Select::new(&message, options.to_vec())
                .with_starting_cursor(idx)
                .prompt()?;
            Ok(choice.to_string())
        }
        exfil_config::FieldKind::Bool => {
            let options = vec!["true", "false"];
            let idx = usize::from(current != "true");
            let choice = Select::new(&message, options)
                .with_starting_cursor(idx)
                .prompt()?;
            Ok(choice.to_string())
        }
        exfil_config::FieldKind::Number { .. } => Text::new(&message)
            .with_default(current)
            .with_validator(move |input: &str| match field.validate(input) {
                Ok(_) => Ok(Validation::Valid),
                Err(e) => Ok(Validation::Invalid(e.into())),
            })
            .prompt()
            .map_err(Into::into),
    }
}

/// Dispatch a scan by the shape of `target`: an `http(s)://` URL crawls a
/// site; the literal `processes` scans local running processes; `--ports`
/// sweeps `target` as a host/CIDR; comma-separated `host:port` grabs banners;
/// anything else (or no target) scans a local directory tree.
#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    target: Option<String>,
    ports: Option<String>,
    max_pages: usize,
    max_depth: usize,
    driver: Option<&str>,
    mode: Option<ScanMode>,
    fail_on: Option<exfil_core::Severity>,
) -> Result<()> {
    if let Some(spec) = &target {
        if let Some(ports) = &ports {
            let top_n = match find_plugin_field("scan", "top-ports") {
                Some((_, field)) => resolve_plugin_setting(config, "scan", field)
                    .await
                    .parse()
                    .unwrap_or(100),
                None => 100,
            };
            let targets = exfil_remote::netscan::expand_targets(spec, ports, top_n)?;
            eprintln!("sweeping {} host:port targets…", targets.len());
            cmd_scan_tcp(store_dir, config, targets, mode.unwrap_or(ScanMode::Active)).await?
        } else if let Some(url) = spec
            .strip_prefix("https://")
            .map(|_| spec.as_str())
            .or_else(|| spec.strip_prefix("http://").map(|_| spec.as_str()))
        {
            cmd_scan_web(
                store_dir,
                config,
                url,
                max_pages,
                max_depth,
                driver,
                mode.unwrap_or(ScanMode::Active),
            )
            .await?
        } else if spec == "processes" {
            cmd_processes(store_dir, config, mode.unwrap_or(ScanMode::Passive)).await?
        } else if let Some(targets) = parse_tcp_targets(spec) {
            cmd_scan_tcp(store_dir, config, targets, mode.unwrap_or(ScanMode::Active)).await?
        } else {
            cmd_scan_files(
                store_dir,
                config,
                Some(spec.clone()),
                mode.unwrap_or(ScanMode::Passive),
            )
            .await?
        }
    } else {
        cmd_scan_files(store_dir, config, None, mode.unwrap_or(ScanMode::Passive)).await?
    }

    // CI gate: exit non-zero when the store holds a finding at or above the
    // threshold. Checked against the whole store, so a fresh scan gates on its
    // own results and an incremental scan gates on the cumulative state.
    if let Some(threshold) = fail_on {
        let store = open_findings(store_dir, config).await?;
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

/// Walk a local directory tree, scan it with the registered scanners, and
/// persist files + findings into the local store. Progress renders live: a
/// ratatui gauge on a terminal, plain match lines when piped.
async fn cmd_scan_files(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    path: Option<String>,
    mode: ScanMode,
) -> Result<()> {
    let target = PathBuf::from(match path {
        Some(p) if !p.is_empty() => p,
        _ => ".".to_string(),
    });
    let pipeline = build_pipeline(config).await?;
    let store = open_findings(store_dir, config).await?;

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan(&target, &pipeline, &store, Some(store_dir), Some(tx)).await;
    // The engine dropped its sender, so the renderer is finishing; wait for it
    // before printing the summary under the (now final) progress bar. Joining
    // yields the per-severity counts of the matches it just streamed.
    let counts = renderer.join().unwrap_or_default();
    let summary = result?;
    println!(
        "scanned {} files ({} unchanged): {} new matches, {} unreadable ({mode})",
        summary.files, summary.unchanged, summary.matches, summary.errors
    );
    print_tally(&counts);
    if summary.matches > 0 {
        hint("\nNext: `exfil analyze` for a report · `exfil search severity=critical` to filter");
    } else if summary.files > 0 {
        hint(
            "\nNo findings. `exfil rules` shows what was checked; `exfil pull` adds more rulesets.",
        );
    }
    Ok(())
}

/// Scan the local host's running processes: each process's name, exe path,
/// and command line is scanned by the full pipeline (secrets on a command
/// line, PII, bad domains/IPs in arguments). Reuses `scan_remote` with a
/// process source.
async fn cmd_processes(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    mode: ScanMode,
) -> Result<()> {
    let pipeline = build_pipeline(config).await?;
    let store = open_findings(store_dir, config).await?;
    let fs = exfil_remote::ProcessFs::new();

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(&fs, "proc://", &pipeline, &store, Some(tx)).await;
    let counts = renderer.join().unwrap_or_default();
    let summary = result?;
    println!(
        "scanned {} processes: {} matches, {} unreadable ({mode})",
        summary.files, summary.matches, summary.errors
    );
    print_tally(&counts);
    Ok(())
}

/// Grab TCP service banners from `targets` and scan them with the full
/// pipeline (version strings, exposed secrets, bad indicators in banners).
async fn cmd_scan_tcp(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    targets: Vec<String>,
    mode: ScanMode,
) -> Result<()> {
    let pipeline = build_pipeline(config).await?;
    let store = open_findings(store_dir, config).await?;
    let fs = exfil_remote::TcpFs::new(targets);

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(&fs, "tcp://", &pipeline, &store, Some(tx)).await;
    let counts = renderer.join().unwrap_or_default();
    let summary = result?;
    println!(
        "grabbed {} banner(s): {} matches, {} unreachable ({mode})",
        summary.files, summary.matches, summary.errors
    );
    print_tally(&counts);
    Ok(())
}

/// Crawl a website and scan the fetched pages with the full pipeline (leaked
/// secrets/keys in HTML/JS, PII, bad indicators).
#[allow(clippy::too_many_arguments)]
async fn cmd_scan_web(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    url: &str,
    max_pages: usize,
    max_depth: usize,
    driver: Option<&str>,
    mode: ScanMode,
) -> Result<()> {
    let pipeline = build_pipeline(config).await?;
    let store = open_findings(store_dir, config).await?;

    // A WebDriver server renders JavaScript (dynamic sites); otherwise a plain
    // HTTP crawl. Both present the pages as a `RemoteFs` to the same scan.
    let (counts, summary) = match driver {
        Some(driver) => {
            eprintln!("rendering {url} via WebDriver {driver}…");
            let fs = exfil_remote::webdriver::WebDriverFs::crawl(driver, url, max_pages, max_depth)
                .await
                .with_context(|| format!("render {url} via WebDriver"))?;
            run_web_scan(&fs, &pipeline, &store).await
        }
        None => {
            eprintln!("crawling {url}…");
            let fs = exfil_remote::WebFs::crawl(url, max_pages, max_depth)
                .await
                .with_context(|| format!("crawl {url}"))?;
            run_web_scan(&fs, &pipeline, &store).await
        }
    };
    let summary = summary?;
    println!(
        "crawled {} page(s): {} matches, {} unreadable ({mode})",
        summary.files, summary.matches, summary.errors
    );
    print_tally(&counts);
    Ok(())
}

/// Scan an already-crawled/rendered site (a `RemoteFs`) through the pipeline,
/// draining progress. Returns the severity counts and the scan result.
async fn run_web_scan(
    fs: &impl exfil_engine::RemoteFs,
    pipeline: &exfil_task::Pipeline,
    store: &exfil_store::Store,
) -> (progress::SevCounts, Result<exfil_engine::Summary>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = exfil_engine::scan_remote(fs, "/", pipeline, store, Some(tx)).await;
    let counts = renderer.join().unwrap_or_default();
    (counts, result)
}

/// WHOIS-check every observed domain and flag newly-registered ones (a common
/// phishing signal). Online: the port-43 lookups run off the async thread.
async fn cmd_check_whois(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    recent_days: i64,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
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
async fn cmd_normalize(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
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
async fn cmd_check_dns(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
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

/// Build the scan pipeline: built-in rules plus any catalog datasets, plus
/// ClamAV signatures from files listed under `[plugins.clamav]` in config.
/// Non-compiling external regex patterns are reported and skipped.
async fn build_pipeline(config: Option<&std::path::Path>) -> Result<exfil_task::Pipeline> {
    let mut rules = exfil_scan::builtin_rules();
    // YARA rules from feeds are stored as `yara:<source>` in the catalog;
    // split them out and compile them into the YARA scanner.
    let mut yara_from_feeds = String::new();
    if let Ok(catalog) = open_catalog(config).await {
        for rule in catalog.all_rules().await.unwrap_or_default() {
            if let Some(src) = exfil_scan::yara::is_yara_source(&rule.pattern) {
                yara_from_feeds.push_str(src);
                yara_from_feeds.push('\n');
            } else {
                rules.push(rule);
            }
        }
    }
    let clamav_signatures = load_plugin_files(config, "clamav", "signatures");
    let yara_rules = format!(
        "{}\n{yara_from_feeds}",
        load_plugin_files(config, "yara", "rules")
    );
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
    let catalog = open_catalog(config).await?;
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
        // MITRE reference catalogs (CWE today) are enrichment data, not rules,
        // so they take a separate path into their own tables.
        if let Some(kind) = reference.strip_prefix("mitre://") {
            if let Err(e) = pull_mitre(&catalog, kind).await {
                eprintln!("failed to pull mitre://{kind}: {e:#}");
            }
            continue;
        }
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

/// Download a MITRE reference catalog into the local catalog store. Currently
/// `cwe` (CVE/CPE are planned). These enrich findings; they are not rules.
async fn pull_mitre(catalog: &exfil_store::Store, kind: &str) -> Result<()> {
    match kind {
        "cwe" => {
            eprintln!(
                "downloading CWE catalog from {}…",
                exfil_source::mitre::CWE_URL
            );
            let entries = exfil_source::mitre::fetch_cwe(exfil_source::mitre::CWE_URL).await?;
            let n = catalog.upsert_cwe(&entries).await?;
            println!("pulled MITRE CWE catalog ({n} weaknesses)");
            Ok(())
        }
        other => anyhow::bail!("unknown MITRE catalog {other:?} (known: cwe)"),
    }
}

/// Manage catalog datasets: list (default), show, add, or remove.
async fn cmd_datasets(config: Option<&std::path::Path>, action: Option<DatasetCmd>) -> Result<()> {
    let catalog = open_catalog(config).await?;

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

/// Manage the URL feed catalog: list (default), add, remove, or pull. `pull`
/// runs the ingestion pipeline (fetch → decompress → detect → parse) over a
/// feed and stores the extracted rules as a dataset named after the feed.
async fn cmd_feeds(config: Option<&std::path::Path>, action: Option<FeedCmd>) -> Result<()> {
    let catalog = open_catalog(config).await?;
    match action.unwrap_or(FeedCmd::List) {
        FeedCmd::List => {
            let feeds = catalog.list_feeds().await?;
            if feeds.is_empty() {
                println!("no feeds — add one with `exfil feeds add <name> <url>`");
                return Ok(());
            }
            for (name, url) in &feeds {
                println!("{name:<24} {url}");
            }
            println!("{} feed(s)", feeds.len());
        }
        FeedCmd::Add { name, url } => {
            catalog.upsert_feed(&name, &url).await?;
            println!("added feed {name:?} → {url}");
        }
        FeedCmd::Rm { name } => {
            if catalog.remove_feed(&name).await? {
                println!("removed feed {name:?}");
            } else {
                println!("no feed {name:?}");
            }
        }
        FeedCmd::Show { name } => {
            let feeds = catalog.list_feeds().await?;
            let Some((_, url)) = feeds.iter().find(|(n, _)| *n == name) else {
                println!("no feed {name:?}");
                return Ok(());
            };
            println!("feed {name:?}\n  url: {url}");
            match catalog.get_dataset(&name).await? {
                Some(ds) if !ds.rules.is_empty() => {
                    // Group the pulled rules by indicator / rule type.
                    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
                    for r in &ds.rules {
                        *counts.entry(feed_rule_kind(&r.pattern)).or_default() += 1;
                    }
                    println!("  rules: {}", ds.rules.len());
                    for (kind, n) in &counts {
                        println!("    {kind:<8} {n}");
                    }
                }
                _ => println!("  rules: none pulled yet — run `exfil feeds pull {name}`"),
            }
        }
        FeedCmd::Pull { name } => {
            let mut targets = catalog.list_feeds().await?;
            if let Some(want) = &name {
                targets.retain(|(n, _)| n == want);
            }
            if targets.is_empty() {
                println!("nothing to pull (add a feed with `exfil feeds add`)");
                return Ok(());
            }
            let total = targets.len();
            let (mut ok, mut failed, mut rules) = (0usize, 0usize, 0usize);
            for (name, url) in targets {
                eprintln!("pulling feed {name:?} from {url}…");
                match exfil_source::feed::fetch_feed(&name, &url).await {
                    Ok(dataset) => {
                        let n = catalog.upsert_dataset(&dataset).await?;
                        println!("pulled feed {name:?}: {n} rule(s) from {url}");
                        ok += 1;
                        rules += n;
                    }
                    Err(e) => {
                        eprintln!("failed to pull feed {name:?}: {e:#}");
                        failed += 1;
                    }
                }
            }
            // Rollup, but only when it adds information (more than one feed).
            if total > 1 {
                let failed_note = if failed > 0 {
                    format!(", {failed} failed")
                } else {
                    String::new()
                };
                println!("pulled {ok}/{total} feed(s), {rules} rule(s){failed_note}");
            }
            if failed > 0 {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Classify a rule pattern into a coarse type label for the `feeds show`
/// breakdown, by its scheme prefix (a plain pattern is a regex rule).
fn feed_rule_kind(pattern: &str) -> &'static str {
    match pattern.split_once(':').map(|(s, _)| s) {
        Some("domain") => "domain",
        Some("ip") => "ip",
        Some("url") => "url",
        Some("md5" | "sha1" | "sha256") => "hash",
        Some("breach-email") => "email",
        Some("yara") => "yara",
        _ => "regex",
    }
}

/// Query stored findings: no arg lists all, `field=value` filters on
/// rule/cwe/severity/path, anything else matches against rule names.
async fn cmd_search(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    query: Option<String>,
    limit: Option<usize>,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    // Results arrive worst-first; the severity tally covers the full match set,
    // while `--limit` only caps how many are printed (the most severe ones).
    let findings = store
        .search_findings(query.as_deref().unwrap_or(""))
        .await?;
    let total = findings.len();
    let shown = limit.map_or(total, |n| n.min(total));
    for m in &findings[..shown] {
        println!("{}", progress::styled_line(m));
    }
    if shown < total {
        println!("showing {shown} of {total} finding(s)");
    } else {
        println!("{total} finding(s)");
    }
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
    config: Option<&std::path::Path>,
    query: Option<String>,
    format: &str,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    let mut stdout = std::io::stdout().lock();
    exfil_engine::run::analyze(&store, query.as_deref().unwrap_or(""), format, &mut stdout).await
}

/// Emit the findings graph as JSON or Graphviz DOT.
async fn cmd_graph(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    query: Option<String>,
    format: &str,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
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
    let store = open_findings(store_dir, config).await?;
    let enricher: Box<dyn exfil_llm::Enricher> = match enrich_script_path(config) {
        Some(path) => Box::new(exfil_script::ScriptEnricher::from_file(&path)?),
        None => exfil_llm::default_enricher(),
    };
    let n = exfil_llm::run(&store, enricher.as_ref()).await?;
    println!("enriched {n} finding(s) via {}", enricher.name());

    // Annotate findings with the authoritative CWE name from the local MITRE
    // catalog, when one has been pulled (`exfil pull mitre://cwe`).
    match annotate_cwe(&store, config).await {
        Ok(0) => {}
        Ok(a) => println!("annotated {a} finding(s) with CWE names from the MITRE catalog"),
        Err(e) => eprintln!("cwe annotation skipped: {e:#}"),
    }
    Ok(())
}

/// Attach the authoritative CWE name (from a pulled MITRE catalog) to every
/// finding that carries a matching `cwe`. Returns how many were annotated; a
/// no-op (0) when no catalog has been pulled.
async fn annotate_cwe(
    findings: &exfil_store::Store,
    config: Option<&std::path::Path>,
) -> Result<usize> {
    let catalog = open_catalog(config).await?;
    let cwe = catalog.cwe_catalog().await?;
    if cwe.is_empty() {
        return Ok(0);
    }
    let mut annotated = 0;
    for (fid, m) in findings.findings_with_ids("").await? {
        if let Some(entry) = m.cwe.as_deref().and_then(|id| cwe.get(id)) {
            findings
                .set_field(&fid, "cwe_name", serde_json::json!(entry.name))
                .await?;
            annotated += 1;
        }
    }
    Ok(annotated)
}

/// Look up one CWE in the local MITRE catalog and print its name/description.
async fn cmd_cwe(config: Option<&std::path::Path>, id: &str) -> Result<()> {
    let catalog = open_catalog(config).await?;
    match catalog.cwe_get(id).await? {
        Some(e) => {
            println!("{} — {}", e.id, e.name);
            if !e.abstraction.is_empty() || !e.status.is_empty() {
                println!("  {} · {}", e.abstraction, e.status);
            }
            if !e.description.is_empty() {
                println!("\n{}", e.description);
            }
        }
        None => println!("no {id} in the local CWE catalog (run `exfil pull mitre://cwe`)"),
    }
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
async fn cmd_export(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    out: Option<PathBuf>,
    format: &str,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
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
async fn cmd_gc(store_dir: &std::path::Path, config: Option<&std::path::Path>) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    let stats = store.gc().await?;
    println!(
        "gc: removed {} old scan(s), {} stale file(s), {} finding(s)",
        stats.scans, stats.files, stats.findings
    );
    Ok(())
}

/// Print one stored record (`table:key`) as JSON.
async fn cmd_get(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    id: &str,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    match store.get_record(id).await? {
        Some(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        None => println!("no record {id:?}"),
    }
    Ok(())
}

/// Run the long-lived HTTP API service until interrupted. Binds `addr`, opens
/// the findings store, and serves read-only JSON endpoints; a graceful
/// shutdown (Ctrl-C / SIGTERM) stops accepting connections and returns.
async fn cmd_server(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    addr: &str,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    eprintln!(
        "[server] serving findings from {} — Ctrl-C to stop",
        store_dir.display()
    );
    eprintln!("[server]   REST: GET /health /findings[?q=…] /rules /stats");
    eprintln!("[server]   GraphQL: POST /graphql · IDE at GET /graphql");
    server::serve(listener, store, server::shutdown_signal()).await
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

#[cfg(test)]
mod tests {
    use super::{feed_rule_kind, find_plugin_field, parse_tcp_targets, resolve_plugin_setting};

    #[test]
    fn feed_rule_kind_classifies_by_scheme() {
        assert_eq!(feed_rule_kind("domain:evil.test"), "domain");
        assert_eq!(feed_rule_kind("ip:203.0.113.9"), "ip");
        assert_eq!(feed_rule_kind("url:https://evil.test/x"), "url");
        assert_eq!(feed_rule_kind("sha256:deadbeef"), "hash");
        assert_eq!(feed_rule_kind("md5:abc"), "hash");
        assert_eq!(feed_rule_kind("breach-email:a@b.test"), "email");
        assert_eq!(feed_rule_kind("yara:src"), "yara");
        // A plain regex (even one containing a colon) is not a scheme.
        assert_eq!(feed_rule_kind("AKIA[0-9A-Z]{16}"), "regex");
        assert_eq!(feed_rule_kind("https://not-a-scheme"), "regex");
    }

    #[test]
    fn parse_tcp_targets_rejects_paths_and_windows_drive_letters() {
        assert_eq!(
            parse_tcp_targets("example.com:22"),
            Some(vec!["example.com:22".to_string()])
        );
        assert_eq!(
            parse_tcp_targets("a.test:22,b.test:80"),
            Some(vec!["a.test:22".to_string(), "b.test:80".to_string()])
        );
        // A local path (even an absolute one) has no trailing `:<port>`.
        assert_eq!(parse_tcp_targets("/etc/passwd"), None);
        // A Windows drive letter looks like `host:port` but the "port" half
        // isn't numeric, so it must not be misread as a scan target.
        assert_eq!(parse_tcp_targets(r"C:\Users\x"), None);
    }

    #[tokio::test]
    async fn resolve_plugin_setting_falls_back_when_config_value_is_out_of_range() {
        let dir = std::env::temp_dir().join(format!(
            "exfil-cli-resolve-setting-{}",
            std::process::id()
        ));
        let path = dir.join("config.toml");
        std::fs::create_dir_all(&dir).unwrap();
        // mem:// isolates this from the developer's real catalog; top-ports
        // is out of the schema's 1..=2000 range, so it must not be used as-is.
        std::fs::write(
            &path,
            "[database]\nendpoint = \"mem://\"\n[plugins.scan]\ntop-ports = 99999\n",
        )
        .unwrap();

        let (_, field) = find_plugin_field("scan", "top-ports").expect("scan.top-ports exists");
        let resolved = resolve_plugin_setting(Some(&path), "scan", field).await;
        assert_eq!(resolved, field.default, "out-of-range config value must fall back to default");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
