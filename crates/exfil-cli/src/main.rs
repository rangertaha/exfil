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

mod progress;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

// Store opening and pipeline building live in the engine so the CLI and the MCP
// server (which exposes the same operations to agents) cannot drift apart.
use exfil_engine::setup::{build_pipeline, open_catalog, open_findings};
use exfil_model::PathScorer;
use exfil_remote::target::{self, Mode as ScanMode, Target};

/// Worked examples shown at the bottom of `exfil --help`. Grouped so a new user
/// can see the common paths (scan → search → triage) at a glance.
const EXAMPLES: &str = "\
Examples:
  exfil scan                       Scan the current directory (passive)
  exfil scan ~/project             Scan a specific path
  exfil scan processes             Scan local running processes (passive)
  exfil scan example.com:22        Grab & scan a service banner (active)
  exfil scan --budget 20%          Scan the most promising fifth, worst first
  exfil search severity=critical   Show only the critical findings
  exfil analyze --format markdown  Render a report of the findings graph

Docs: https://rangertaha.github.io/exfil/";

/// Whether `path` lies inside the directory `root`.
///
/// A plain `starts_with` on the string matches a *sibling* whose name extends
/// the root's — `/repo/app` would claim `/repo/app-legacy/.env` — so a
/// `--fail-on` gate failed builds over findings from a tree it never scanned.
/// The comparison has to land on a separator boundary.
fn path_is_under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches(['/', '\\']);
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('\\'))
}

/// Exit quietly when the reader of our stdout goes away.
///
/// Rust ignores `SIGPIPE`, so `exfil search | head -5` does not stop at the
/// fifth line — it keeps writing until the closed pipe surfaces as an I/O
/// error, and `println!` turns that into a panic and a backtrace. Every command
/// piped into `head`, `less` or `grep -m` did this.
///
/// The usual fix is restoring the default `SIGPIPE` handler, which needs
/// `unsafe`; this workspace denies it. A panic hook is the safe equivalent:
/// recognise the one panic that means "nobody is listening any more" and exit
/// 0, because that is a normal end to a pipeline rather than a failure. Every
/// other panic keeps the default hook's message and backtrace.
fn quiet_on_broken_pipe() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if msg.contains("Broken pipe") {
            std::process::exit(0);
        }
        default(info);
    }));
}

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

/// The model name used when `--model` is not given, on both `train` and
/// `scan` — so "the default model" is one string, not two that agree by luck.
const DEFAULT_MODEL: &str = "default";

/// Parse a `--model` kind for `train`, so an unknown name is reported with
/// what is available rather than a bare parse failure.
fn parse_scorer_kind(s: &str) -> std::result::Result<exfil_model::ScorerKind, String> {
    s.parse()
}

/// Print the per-severity tally line after a scan summary, when any match was
/// rated. Shared by the local and remote scan commands.
fn print_tally(counts: &progress::SevCounts) {
    if let Some(tally) = progress::tally_line(counts) {
        println!("{tally}");
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
    about = "exfil — an offline DevSecOps engine for static analysis",
    long_about = "exfil — an offline DevSecOps engine for static analysis of \
                  code, infrastructure & systems.",
    after_help = EXAMPLES,
    // A bare `exfil` shows the help/examples instead of a terse usage error.
    arg_required_else_help = true,
    // Wrap help at the terminal width, but never wider than 80 columns, so the
    // output reads the same in a standard 80-column window as in a wide one.
    max_term_width = 80,
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
    /// Manage catalog datasets (list by default; add/get/remove/update
    /// subcommands).
    Dataset {
        #[command(subcommand)]
        action: Option<DatasetCmd>,
    },
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
        /// Render pages through a WebDriver server (e.g.
        /// `http://localhost:4444`) when `target` is a URL, to crawl
        /// JavaScript-heavy, dynamic sites.
        #[arg(long, value_name = "URL")]
        driver: Option<String>,
        /// Permit reaching remote systems (authorized testing only). Targets
        /// that leave this machine — `host:port` banners, a host/CIDR sweep,
        /// an `http(s)://` crawl — are refused without it, so a scan never
        /// touches the network merely because a target string parsed that way.
        #[arg(short = 'a', long, conflicts_with = "passive")]
        active: bool,
        /// Assert that this scan stays local, failing if the target would
        /// reach out. The default is already local; this makes it a guarantee
        /// a CI job can rely on rather than an assumption.
        #[arg(long, conflicts_with = "active")]
        passive: bool,
        /// Exit non-zero if any finding is at or above this severity
        /// (info|low|medium|high|critical). Useful as a CI gate.
        #[arg(long, value_name = "SEVERITY", value_parser = parse_severity,
              conflicts_with = "budget")]
        fail_on: Option<exfil_core::Severity>,
        /// Stop once this much work is done, scanning the most promising files
        /// first: `30s`/`5m` time, `20%` of files, `500mb` read, a bare file
        /// count, or `90c` for 90% of the *expected findings* (which adapts to
        /// the tree instead of assuming a shape, and needs a calibrated model).
        /// Ranking uses the trained path model when one exists
        /// (`exfil train`). Cannot be combined with `--fail-on`: a partial
        /// scan cannot certify that a tree is clean.
        #[arg(long, value_name = "BUDGET")]
        budget: Option<exfil_engine::Budget>,
        /// Show matched credentials in the clear instead of masking them.
        /// Findings are masked by default so the store, the JSON/SARIF reports
        /// and CI logs do not themselves become copies of the secrets — pass
        /// this when you need the value in order to go and revoke it.
        #[arg(long)]
        show_secrets: bool,
        /// Skip files excluded by `.gitignore` (and `.ignore`) rules in the
        /// tree. Off by default: what a project keeps out of version control
        /// and what a security scanner should ignore are different questions,
        /// and `.env`, `*.pem` and friends are usually both gitignored and
        /// exactly what you are looking for.
        #[arg(long)]
        respect_gitignore: bool,
        /// Scan worst-first using the trained path model, without stopping
        /// early. Same results as an ordinary scan, reached sooner.
        #[arg(long)]
        ranked: bool,
        /// Which stored model to rank with, by the name `exfil train --name`
        /// saved it under. (On `train`, `--model` names a *kind* to fit; here
        /// it names one you already have.)
        #[arg(long, value_name = "NAME", default_value = DEFAULT_MODEL)]
        model: String,
        /// Name this run, so `exfil analyze -n <name>` and `exfil search
        /// run=<name>` can address it later. Defaults to the start time, so
        /// every run stays addressable either way.
        #[arg(short, long, value_name = "NAME")]
        name: Option<String>,
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
        /// Show at most N findings (the most severe first).
        #[arg(short = 'l', long)]
        limit: Option<usize>,
    },
    /// Summarize the findings graph: how many, how bad, and where they cluster.
    ///
    /// No finding list — that is what `search` and `report` are for. This is
    /// the glance you take between scans.
    Analyze {
        /// Optional finding filter (same syntax as `search`).
        query: Option<String>,
        /// Report on one run's findings only. Sugar for the `run=<name>`
        /// filter, so it composes with a query rather than replacing it.
        #[arg(short, long, value_name = "RUN")]
        name: Option<String>,
    },
    /// Write a report over the findings graph to a file.
    ///
    /// The same rendering `analyze` prints, aimed at a file you keep or send.
    /// With no `--out` it writes to stdout, which makes it a superset of
    /// `analyze`; `analyze` stays because it is the one you type constantly.
    Report {
        /// Optional finding filter (same syntax as `search`).
        query: Option<String>,
        /// Report format: text, json, markdown, junit, or sarif.
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Report on one run's findings only. Sugar for the `run=<name>`
        /// filter, so it composes with a query rather than replacing it.
        #[arg(short, long, value_name = "RUN")]
        name: Option<String>,
        /// Write here instead of stdout. The parent directory must exist.
        #[arg(short, long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Train the path model on the scans already in the store and save it to
    /// the catalog. Every file recorded is a training sample; whether a finding
    /// was attached to it is the label, so there is nothing to hand-label.
    Train {
        /// Which model to fit: `path-hmm` (default) conditions on the whole
        /// path sequence; `dir-prior` is a finding rate per parent directory
        /// — no states, calibrated by construction. Run `exfil model eval`
        /// first: when it reports that the baseline ties, `dir-prior` is the
        /// one to keep.
        #[arg(long, value_name = "KIND", default_value = "path-hmm",
              value_parser = parse_scorer_kind)]
        model: exfil_model::ScorerKind,
        /// Number of latent states to fit (`path-hmm` only).
        #[arg(long, default_value_t = 12)]
        states: usize,
        /// Maximum Baum-Welch iterations (`path-hmm` only).
        #[arg(long, default_value_t = 30)]
        iterations: usize,
        /// Keep at most this many distinct path tokens (`path-hmm` only).
        #[arg(long, default_value_t = 4096)]
        vocab: usize,
        /// Name to save the model under.
        #[arg(short, long, default_value = DEFAULT_MODEL)]
        name: String,
    },
    /// Inspect the path models that `exfil train` produced.
    Model {
        #[command(subcommand)]
        action: Option<ModelCmd>,
    },
    /// Look up a weakness in the local MITRE CWE catalog (`exfil dataset
    /// update mitre://cwe` downloads it).
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
        action: Option<PluginCmd>,
    },
}

/// Plugin setting actions.
#[derive(Subcommand)]
enum PluginCmd {
    /// List the configurable plugins (the default).
    List,
    /// Show a plugin's settings: each one's effective value and where that
    /// value came from.
    Get {
        /// Plugin name, e.g. `scan`.
        plugin: String,
    },
    /// Set one setting, stored as a catalog override.
    Set {
        /// Plugin name, e.g. `scan`.
        plugin: String,
        /// Setting key, e.g. `top-ports`.
        key: String,
        /// New value, validated against the setting's own schema.
        value: String,
    },
    /// Drop a stored override, restoring the config file's value or the
    /// built-in default. With no key, drops every override on the plugin.
    Remove {
        /// Plugin name, e.g. `scan`.
        plugin: String,
        /// Setting key. Omit to clear them all.
        key: Option<String>,
    },
    /// Interactively walk every setting on a plugin — a select menu for
    /// fixed choices, a validated prompt for free-form input — pre-filled
    /// with each setting's current effective value.
    Config {
        /// Plugin name, e.g. `scan`.
        plugin: String,
    },
}

/// Path-model actions.
#[derive(Subcommand)]
enum ModelCmd {
    /// List the trained models in the catalog (the default).
    List,
    /// Summarize a model: states, vocabulary, base rate, and the ruleset it
    /// was trained under.
    Get {
        /// Model name.
        #[arg(default_value = "default")]
        name: String,
    },
    /// Forget a trained model.
    Remove {
        /// Model name.
        name: String,
    },
    /// Show what the trained model would give a path, and why.
    Score {
        /// Path to score (need not exist).
        path: String,
        /// Model name.
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Measure whether the model actually helps: fit on part of the stored
    /// scans, then report how much of the findings a budgeted scan would
    /// recover on the rest — against a directory-frequency baseline and
    /// against blind selection.
    Eval {
        /// Fraction of paths held out for measurement.
        #[arg(long, default_value_t = 0.3)]
        holdout: f64,
        /// Number of latent states to fit.
        #[arg(long, default_value_t = 8)]
        states: usize,
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
    Get { name: String },
    /// Add (or replace) a named dataset from a source reference.
    Add { name: String, reference: String },
    /// Remove a dataset from the catalog.
    Remove { name: String },
    /// Re-fetch datasets: every `[[update]]` entry in the config when no
    /// target is given, or one entry by name. A target that is not a
    /// configured name is fetched as a source reference directly
    /// (`builtin://…`, a path, an `https://` URL, or `mitre://cwe` for the
    /// MITRE CWE catalog).
    Update {
        /// An `[[update]]` entry's name, or a source reference. Omit for all.
        target: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    quiet_on_broken_pipe();
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
        Command::Dataset { action } => cmd_datasets(cfg, action).await?,
        Command::Scan {
            target,
            ports,
            driver,
            active,
            passive,
            fail_on,
            budget,
            respect_gitignore,
            show_secrets,
            ranked,
            model,
            name,
        } => {
            cmd_scan(
                &store_dir,
                cfg,
                target,
                ports,
                driver.as_deref(),
                explicit_scan_mode(active, passive),
                fail_on,
                budget,
                respect_gitignore,
                show_secrets,
                ranked,
                &model,
                name,
            )
            .await?
        }
        Command::Search { query, limit } => cmd_search(&store_dir, cfg, query, limit).await?,
        Command::Analyze { query, name } => {
            cmd_analyze(&store_dir, cfg, run_query(query, name)?).await?
        }
        Command::Report {
            query,
            format,
            name,
            out,
        } => {
            cmd_report(
                &store_dir,
                cfg,
                run_query(query, name)?,
                &format,
                out.as_deref(),
            )
            .await?
        }
        Command::Get { id } => cmd_get(&store_dir, cfg, &id).await?,
        Command::Store { action } => match action {
            StoreCmd::Export { out, format } => cmd_export(&store_dir, cfg, out, &format).await?,
            StoreCmd::Gc => cmd_gc(&store_dir, cfg).await?,
            StoreCmd::Clean { yes } => cmd_clean(&store_dir, yes)?,
        },
        Command::Train {
            model,
            states,
            iterations,
            vocab,
            name,
        } => cmd_model_train(&store_dir, cfg, model, states, iterations, vocab, &name).await?,
        Command::Model { action } => match action.unwrap_or(ModelCmd::List) {
            ModelCmd::List => cmd_model_list(cfg).await?,
            ModelCmd::Get { name } => cmd_model_status(cfg, &name).await?,
            ModelCmd::Remove { name } => cmd_model_remove(cfg, &name).await?,
            ModelCmd::Score { path, name } => cmd_model_score(cfg, &path, &name).await?,
            ModelCmd::Eval { holdout, states } => {
                cmd_model_eval(&store_dir, cfg, holdout, states).await?
            }
        },
        Command::Cwe { id } => cmd_cwe(cfg, &id).await?,
        Command::Mcp => {
            exfil_mcp::serve(exfil_mcp::Ctx {
                store_dir: store_dir.clone(),
                config: cli.config.clone(),
            })
            .await?
        }
        Command::Completions { shell } => cmd_completions(shell),
        Command::Plugin { action } => match action.unwrap_or(PluginCmd::List) {
            PluginCmd::List => cmd_plugin_list(),
            PluginCmd::Get { plugin } => cmd_plugin_get(cfg, &plugin).await?,
            PluginCmd::Set { plugin, key, value } => {
                cmd_plugin_set(cfg, &plugin, &key, &value).await?
            }
            PluginCmd::Remove { plugin, key } => {
                cmd_plugin_remove(cfg, &plugin, key.as_deref()).await?
            }
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

/// Resolve the `-a`/`-p` flags (mutually exclusive per clap) to an explicit
/// mode override, or `None` to infer one from the target's shape.
fn explicit_scan_mode(active: bool, passive: bool) -> Option<ScanMode> {
    if active {
        Some(ScanMode::Active)
    } else if passive {
        Some(ScanMode::Passive)
    } else {
        None
    }
}

/// The plugin registry and field lookup live in `exfil-remote`, beside the
/// plugins that publish them, so the MCP server can validate against the same
/// schemas this binary does.
use exfil_remote::{find_plugin_field, PLUGIN_SCHEMAS};

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

/// List the plugins that publish a config schema.
fn cmd_plugin_list() {
    for schema in PLUGIN_SCHEMAS {
        println!("{:<12} {} setting(s)", schema.name, schema.fields.len());
    }
    println!("{} plugin(s)", PLUGIN_SCHEMAS.len());
}

/// Show a plugin's settings with each value's provenance.
///
/// The provenance is the point: a value has up to three possible sources
/// (a stored override, the config file, the built-in default) and being told
/// only the number leaves you guessing which one you are looking at — and
/// which file to edit to change it.
async fn cmd_plugin_get(config: Option<&std::path::Path>, plugin: &str) -> Result<()> {
    let Some(schema) = PLUGIN_SCHEMAS.iter().find(|p| p.name == plugin) else {
        anyhow::bail!("unknown plugin {plugin:?} (see `exfil plugin list`)");
    };
    let overrides = match open_catalog(config).await {
        Ok(catalog) => catalog
            .list_plugin_settings(plugin)
            .await
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let cfg = exfil_config::load(config).ok();
    println!("# plugin {:?}", schema.name);
    for field in schema.fields {
        let value = resolve_plugin_setting(config, plugin, field).await;
        let source = if overrides.iter().any(|(k, _)| k == field.key) {
            "override"
        } else if cfg
            .as_ref()
            .and_then(|c| c.plugin_field(plugin, field.key))
            .is_some()
        {
            "config"
        } else {
            "default"
        };
        println!("{:<14} {:<20} [{source}]", field.key, value);
        println!("               {}", field.description);
    }
    Ok(())
}

/// Store one setting as a catalog override, after validating it.
async fn cmd_plugin_set(
    config: Option<&std::path::Path>,
    plugin: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let Some((_, field)) = find_plugin_field(plugin, key) else {
        anyhow::bail!("unknown setting {plugin}.{key} (see `exfil plugin get {plugin}`)");
    };
    // Validate before storing: an override that fails its own schema would be
    // silently ignored at read time, which looks exactly like the setting
    // having no effect.
    let normalized = field
        .validate(value)
        .map_err(|e| anyhow::anyhow!("invalid value for {plugin}.{key}: {e}"))?;
    open_catalog(config)
        .await?
        .set_plugin_setting(plugin, key, &normalized)
        .await?;
    println!("set {plugin}.{key} = {normalized}");
    Ok(())
}

/// Drop one override, or all of a plugin's.
async fn cmd_plugin_remove(
    config: Option<&std::path::Path>,
    plugin: &str,
    key: Option<&str>,
) -> Result<()> {
    if PLUGIN_SCHEMAS.iter().all(|p| p.name != plugin) {
        anyhow::bail!("unknown plugin {plugin:?} (see `exfil plugin list`)");
    }
    let n = open_catalog(config)
        .await?
        .remove_plugin_setting(plugin, key)
        .await?;
    match (n, key) {
        (0, Some(k)) => println!("no override on {plugin}.{k}"),
        (0, None) => println!("no overrides on {plugin}"),
        // Say what it fell back to, so "removed" is not mistaken for "unset".
        (n, _) => println!("removed {n} override(s); {plugin} now uses its config/default values"),
    }
    Ok(())
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
    println!(
        "Configuring {plugin:?} ({} setting(s)):\n",
        schema.fields.len()
    );
    for field in schema.fields {
        let current = resolve_plugin_setting(config, plugin, field).await;
        let answer = prompt_field(field, &current)?;
        let normalized = field.validate(&answer).map_err(|e| anyhow::anyhow!(e))?;
        catalog
            .set_plugin_setting(plugin, field.key, &normalized)
            .await?;
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

/// The walk policy for this run: the `--respect-gitignore` flag, plus any
/// `skip-dirs` the config file replaces the built-in list with.
///
/// Which directories are worth skipping is a property of a project, not of
/// exfil — a monorepo's `vendor/` may be the most interesting tree in it — so
/// the list is one editable value rather than a constant baked into the walk.
/// An unreadable config falls back to the defaults instead of failing the scan.
fn walk_policy(
    config: Option<&std::path::Path>,
    respect_gitignore: bool,
) -> exfil_engine::WalkPolicy {
    let configured = exfil_config::load(config)
        .ok()
        .map(|cfg| cfg.plugin_strings("scan", "skip-dirs"))
        .filter(|dirs| !dirs.is_empty());
    exfil_engine::WalkPolicy {
        respect_gitignore,
        skip_dirs: configured.unwrap_or_else(|| {
            exfil_engine::DEFAULT_SKIP_DIRS
                .iter()
                .map(|s| s.to_string())
                .collect()
        }),
    }
}

/// Dispatch a scan by the shape of `target` — resolved by
/// [`exfil_remote::target`], which the MCP server uses too, so a spec means the
/// same thing however it arrives. Progress renders live: a ratatui gauge on a
/// terminal, plain match lines when piped.
#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    spec: Option<String>,
    ports: Option<String>,
    driver: Option<&str>,
    mode: Option<ScanMode>,
    fail_on: Option<exfil_core::Severity>,
    budget: Option<exfil_engine::Budget>,
    respect_gitignore: bool,
    show_secrets: bool,
    ranked: bool,
    model_name: &str,
    name: Option<String>,
) -> Result<()> {
    // Bounds come from the plugins that own them, not from flags on `scan`.
    // `setting` resolves override → config → schema default, so the fallback
    // here only fires if a plugin stops publishing the field at all.
    async fn setting(
        config: Option<&std::path::Path>,
        plugin: &str,
        key: &str,
        fallback: usize,
    ) -> usize {
        match find_plugin_field(plugin, key) {
            Some((_, field)) => resolve_plugin_setting(config, plugin, field)
                .await
                .parse()
                .unwrap_or(fallback),
            None => fallback,
        }
    }
    let opts = target::Options {
        ports,
        max_pages: Some(setting(config, "web", "max-pages", 64).await),
        max_depth: Some(setting(config, "web", "max-depth", 2).await),
        driver: driver.map(String::from),
        top_ports: setting(config, "scan", "top-ports", 100).await as u16,
    };
    let target = target::parse(spec.as_deref(), &opts)?;

    // A path that is not there is a typo, not an empty tree. Without this,
    // `exfil scan ./sr --fail-on critical` (for `./src`) scanned nothing,
    // printed a summary, and exited 0 — a gate certifying a tree never read.
    if let Target::Path(p) = &target {
        if !p.exists() {
            anyhow::bail!("{} does not exist", p.display());
        }
    }

    // Reaching a remote system is a permission, not a parse result. Before
    // this, a colon in the target string was enough to put exfil on the
    // network — `exfil scan example.com:22` looked like a typo for a path and
    // behaved like a port scan. `--active` has to be asked for, and
    // `--passive` is how a CI job asserts it will never happen.
    let reaches_out = !matches!(target, Target::Path(_) | Target::Processes);
    if reaches_out {
        let what = spec.as_deref().unwrap_or("this target");
        // Checked before the general case so an explicit `--passive` gets the
        // answer to the question it actually asked.
        if mode == Some(ScanMode::Passive) {
            anyhow::bail!("--passive was given, but {what} is not local");
        }
        if mode != Some(ScanMode::Active) {
            anyhow::bail!(
                "{what} would reach a remote system; pass --active to permit \
                 it (authorized testing only)"
            );
        }
    }

    announce(&target, opts.ports.is_some());
    // Ranking and budgets only apply to a local tree walk. Say so rather than
    // accepting the flag and quietly ignoring it.
    if (budget.is_some() || ranked) && !target.honors_plan() {
        eprintln!(
            "warning: --budget/--ranked apply only to a local path scan; \
             ignored for this target (bound it with `exfil plugin set web \
             max-pages` or --ports)"
        );
    }

    // Masked unless asked otherwise: a finding outlives the run that made it,
    // and the store, the reports and the CI log are all worse places for a live
    // credential than the file it was already in.
    let snippet_policy = if show_secrets {
        exfil_core::SnippetPolicy::ShowSecrets
    } else {
        exfil_core::SnippetPolicy::Redact
    };
    let built = build_pipeline(config, snippet_policy).await?;
    if !built.skipped.is_empty() {
        eprintln!(
            "skipped {} rule(s) with unsupported patterns",
            built.skipped.len()
        );
    }
    let store = open_findings(store_dir, config).await?;
    let fingerprint = exfil_engine::setup::ruleset_fingerprint(config).await;
    // A local walk must exclude the store itself; remote targets have no
    // directory to skip.
    let skip = matches!(target, Target::Path(_)).then_some(store_dir);
    // Captured before the run consumes `target`: the tree a `--fail-on` gate
    // is allowed to consider. `None` for targets with no directory to bound.
    let gate_scope = match &target {
        Target::Path(p) => Some(
            std::fs::canonicalize(p)
                .unwrap_or_else(|_| p.clone())
                .display()
                .to_string(),
        ),
        _ => None,
    };

    // Load the path model when ranking or budgeting was asked for. A budget
    // without a model still works — it just cuts in walk order rather than
    // value order — so a missing model is a note, not an error.
    let model = if budget.is_some() || ranked {
        let m = load_model(config, model_name).await.unwrap_or(None);
        // …unless a particular model was *asked for*. Falling back to walk
        // order then would answer a question nobody put: the caller named a
        // ranking, and a typo would silently produce a differently-shaped scan
        // under a reassuring summary.
        if m.is_none() && model_name != DEFAULT_MODEL {
            let known = open_catalog(config)
                .await?
                .list_path_models()
                .await
                .unwrap_or_default();
            anyhow::bail!(
                "no model {model_name:?}{}",
                if known.is_empty() {
                    " — none are trained yet (`exfil train`)".to_string()
                } else {
                    format!(" — stored models: {}", known.join(", "))
                }
            );
        }
        match &m {
            None => eprintln!(
                "no trained path model; scanning in walk order \
                 (run `exfil train` to rank by probability)"
            ),
            // Both of these can be true at once, so they are separate checks
            // rather than match arms: a stale model can also be an
            // uncalibrated one, and hearing about only the first would leave
            // the more consequential problem unsaid.
            Some(stored) => {
                let m = stored.as_scorer();
                if !m.ruleset().is_empty() && m.ruleset() != fingerprint {
                    eprintln!(
                        "warning: the path model was trained under ruleset {} but this \
                         scan applies {fingerprint}; its ranking may be stale — re-run \
                         `exfil train`",
                        m.ruleset()
                    );
                }
                // A confidence budget is the only one that reads the score as a
                // probability rather than a rank: it stops once the scanned
                // files account for a share of the *expected* findings, which
                // means summing them. An uncalibrated model's scores are raw
                // likelihood ratios piled up at 0 and 1, so that sum is not an
                // expectation and the target is not the one asked for. Every
                // other budget caps cost and is indifferent to this.
                if matches!(budget, Some(exfil_engine::Budget::Confidence(_)))
                    && !m.has_calibration()
                {
                    eprintln!(
                        "warning: this model has no calibration (too little held-out data \
                         when it was trained), so its scores rank but are not probabilities \
                         — a `c` budget sums them as if they were, and will not stop where \
                         you asked. Train on a wider corpus, or bound the scan with a \
                         `%`/time/size budget instead."
                    );
                }
            }
        }
        m
    } else {
        None
    };
    // The fingerprint rides on every scan, ranked or not: it is what lets the
    // next scan notice the ruleset moved and stop trusting "unchanged".
    let plan = exfil_engine::ScanPlan {
        // The concrete model is what the warnings above inspect — its ruleset,
        // its calibration. The engine only needs something that scores a path,
        // so it goes in behind the trait.
        model: model.map(|m| m.into_scorer()),
        budget,
        ruleset: fingerprint,
        name: name.unwrap_or_default(),
        walk: walk_policy(config, respect_gitignore),
    };

    let (tx, rx) = std::sync::mpsc::channel();
    let renderer = progress::spawn(rx);
    let result = target::run(target, &built.pipeline, &store, skip, Some(tx), mode, &plan).await;
    // The scan dropped its sender, so the renderer is finishing; wait for it
    // before printing the summary under the (now final) progress bar. Joining
    // yields the per-severity counts of the matches it just streamed.
    let counts = renderer.join().unwrap_or_default();
    let outcome = result?;
    println!("{}", summary_line(&outcome));
    print_tally(&counts);
    // A budgeted scan looked at part of the tree. Say so on its own line, in
    // the same breath as the result — a partial run that reads like a clean
    // one is the whole risk of this feature.
    if outcome.summary.is_partial() {
        println!(
            "coverage: {} of {} files ({:.0}%, {}) — {} not examined",
            outcome.summary.candidates - outcome.summary.skipped,
            outcome.summary.candidates,
            outcome.summary.coverage() * 100.0,
            if plan.model.is_some() {
                "probability-ranked"
            } else {
                "walk order"
            },
            outcome.summary.skipped,
        );
        hint("Run without `--budget` for full coverage.");
    }
    scan_hints(&outcome);

    // CI gate. Deliberately checked against the stored state rather than only
    // what this run re-read: an incremental scan re-reads just the changed
    // files, and a critical sitting in a file that did not change is still a
    // critical. Gating on "what this run saw" would let a tree pass because
    // nothing moved.
    //
    // Scoped to the tree that was scanned, though. One store can hold several
    // roots, and gating a scan of `./b` on findings from `./a` fails a build
    // for something it did not look at.
    if let Some(threshold) = fail_on {
        let findings = store.search_findings("").await?;
        let breaching = findings
            .iter()
            .filter(|m| {
                gate_scope
                    .as_ref()
                    .is_none_or(|root| path_is_under(&m.path, root))
            })
            .filter(|m| m.severity.is_some_and(|s| s.weight() >= threshold.weight()))
            .count();
        // A gate that passes is a claim the tree is clean, so it has to say
        // when that claim is narrower than it sounds. Not fatal — unreadable
        // and oversize files are facts about the tree, not failures — but never
        // silent, because "0 findings" over content nothing searched reads
        // exactly like a clean result.
        if breaching == 0 && !outcome.summary.is_complete() {
            let s = &outcome.summary;
            let mut why = Vec::new();
            if s.unexamined.any() {
                why.push(s.unexamined.describe());
            }
            if s.errors > 0 {
                why.push(format!("{} unreadable", s.errors));
            }
            if s.is_partial() {
                why.push(format!("{} not reached", s.skipped));
            }
            eprintln!(
                "! gate passed, but {} file(s) went unsearched ({})",
                s.unexamined.total() + s.errors + s.skipped,
                why.join(", ")
            );
        }
        if breaching > 0 {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            eprintln!("\u{2717} {breaching} finding(s) at or above {threshold:?}");
            // 2, not 1: a tripped gate is a result, not a failure to run. CI
            // can then tell "findings exceeded the threshold" from "exfil
            // broke" and treat them differently.
            std::process::exit(2);
        }
    }
    Ok(())
}

/// Tell the user what a long-running remote target is about to do, before it
/// starts — a sweep, a crawl, or a rendered crawl can take a while with nothing
/// to show until the first result arrives.
fn announce(target: &Target, swept: bool) {
    match target {
        Target::Tcp(targets) if swept => {
            eprintln!("sweeping {} host:port targets\u{2026}", targets.len())
        }
        Target::Web {
            url,
            driver: Some(driver),
            ..
        } => eprintln!("rendering {url} via WebDriver {driver}\u{2026}"),
        Target::Web { url, .. } => eprintln!("crawling {url}\u{2026}"),
        _ => {}
    }
}

/// The summary line for a finished scan, phrased for the target that ran.
fn summary_line(outcome: &target::Outcome) -> String {
    let s = &outcome.summary;
    let mode = outcome.mode;
    match &outcome.target {
        Target::Path(_) => format!(
            "scanned {} files ({} unchanged): {} new matches, {} unreadable{} ({mode})",
            s.files,
            s.unchanged,
            s.matches,
            s.errors,
            // Content that was filed but never searched belongs on the line
            // that says what the scan did, not only in a hint below it.
            if s.unexamined.any() {
                format!(", {} unexamined", s.unexamined.describe())
            } else {
                String::new()
            }
        ),
        Target::Processes => format!(
            "scanned {} processes: {} matches, {} unreadable ({mode})",
            s.files, s.matches, s.errors
        ),
        Target::Tcp(_) => format!(
            "grabbed {} banner(s): {} matches, {} unreachable ({mode})",
            s.files, s.matches, s.errors
        ),
        Target::Web { .. } => format!(
            "crawled {} page(s): {} matches, {} unreadable ({mode})",
            s.files, s.matches, s.errors
        ),
    }
}

/// Point at the obvious next command after a scan (terminal only).
fn scan_hints(outcome: &target::Outcome) {
    if outcome.summary.matches > 0 {
        hint("\nNext: `exfil analyze` for a report \u{b7} `exfil search severity=critical` to filter");
    } else if outcome.summary.files > 0 {
        hint(
            "\nNo findings. `exfil dataset` lists the rulesets in play; \
             `exfil dataset add <name> <ref>` adds more.",
        );
    }
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

/// Manage catalog datasets: list (default), show, add, or remove.
async fn cmd_datasets(config: Option<&std::path::Path>, action: Option<DatasetCmd>) -> Result<()> {
    let catalog = open_catalog(config).await?;

    match action.unwrap_or(DatasetCmd::List) {
        DatasetCmd::List => {
            let datasets = catalog.list_datasets().await?;
            if datasets.is_empty() {
                println!("no datasets — add one with `exfil dataset add <name> <reference>`");
                return Ok(());
            }
            for (name, rules) in &datasets {
                println!("{name:<24} {rules} rules");
            }
            println!("{} dataset(s)", datasets.len());
        }
        DatasetCmd::Get { name } => match catalog.get_dataset(&name).await? {
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
        DatasetCmd::Remove { name } => {
            if catalog.remove_dataset(&name).await? {
                println!("removed dataset {name:?}");
            } else {
                println!("no dataset {name:?}");
            }
        }
        DatasetCmd::Update { target } => cmd_datasets_update(config, &catalog, target).await?,
    }
    Ok(())
}

/// Re-fetch the configured `[[update]]` entries, or one target.
///
/// A bare target is resolved against the config first: `datasets update
/// security` means the entry named `security`, not a source called that. Only
/// when no entry matches is it treated as a reference, so a name and a URL can
/// share one argument without either shadowing the other.
///
/// One failed fetch does not abandon the rest — a feed being down should cost
/// you that dataset, not the whole update — so failures are reported per entry
/// and the command still exits zero. The exception is a target that named
/// nothing at all, which is a mistake in the command rather than a fact about
/// the network.
async fn cmd_datasets_update(
    config: Option<&std::path::Path>,
    catalog: &exfil_store::Store,
    target: Option<String>,
) -> Result<()> {
    let configured = exfil_config::load(config)?.update;
    let entries: Vec<(String, String)> = match target {
        Some(t) => match configured.into_iter().find(|u| u.name == t) {
            Some(u) => vec![(u.name, u.reference)],
            // Not a configured name: fetch it as a reference, stored under the
            // name its source reports.
            None => vec![(String::new(), t)],
        },
        None => configured
            .into_iter()
            .map(|u| (u.name, u.reference))
            .collect(),
    };
    if entries.is_empty() {
        println!("nothing to update (no [[update]] entries in the config — see `exfil config`)");
        return Ok(());
    }

    let registry = exfil_source::Registry::new();
    for (name, reference) in entries {
        // MITRE reference catalogs (CWE today) are enrichment data, not rules,
        // so they take a separate path into their own tables.
        if let Some(kind) = reference.strip_prefix("mitre://") {
            if let Err(e) = update_mitre(catalog, kind).await {
                eprintln!("failed to update mitre://{kind}: {e:#}");
            }
            continue;
        }
        match registry.fetch(&reference).await {
            Ok(mut dataset) => {
                // A configured entry's name is what it is stored under, so the
                // config decides what a dataset is called rather than the
                // source deciding for it — the same rule `datasets add` follows.
                if !name.is_empty() {
                    dataset.name = name;
                }
                let n = catalog.upsert_dataset(&dataset).await?;
                println!("updated {:?} ({} rules) from {reference}", dataset.name, n);
            }
            Err(e) => eprintln!("failed to update {reference}: {e:#}"),
        }
    }
    Ok(())
}

/// Download a MITRE reference catalog into the local catalog store. Currently
/// `cwe` (CVE/CPE are planned). These enrich findings; they are not rules.
async fn update_mitre(catalog: &exfil_store::Store, kind: &str) -> Result<()> {
    match kind {
        "cwe" => {
            eprintln!(
                "downloading CWE catalog from {}…",
                exfil_source::mitre::CWE_URL
            );
            let entries = exfil_source::mitre::fetch_cwe(exfil_source::mitre::CWE_URL).await?;
            let n = catalog.upsert_cwe(&entries).await?;
            println!("updated MITRE CWE catalog ({n} weaknesses)");
            Ok(())
        }
        other => anyhow::bail!("unknown MITRE catalog {other:?} (known: cwe)"),
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
) -> Result<()> {
    use exfil_report::Reporter;
    let store = open_findings(store_dir, config).await?;
    let analysis =
        exfil_engine::run::gather_analysis(&store, query.as_deref().unwrap_or("")).await?;
    let mut stdout = std::io::stdout().lock();
    exfil_report::SummaryReporter {
        width: progress::display_width(),
    }
    .report(&mut stdout, &analysis)
}

/// Train the path model on everything the store already knows and save it to
/// the catalog.
///
/// No new scanning and no hand-labelling: every recorded file is a sample, and
/// whether a finding hangs off it is the label. That also means the model is
/// only as good as the ruleset that produced those findings, which is why the
/// ruleset fingerprint is recorded alongside it.
async fn cmd_model_train(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    kind: exfil_model::ScorerKind,
    states: usize,
    iterations: usize,
    vocab: usize,
    name: &str,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    let samples = store.training_paths().await?;
    if samples.is_empty() {
        println!("nothing to train on — run `exfil scan` first");
        return Ok(());
    }
    // A classifier needs both classes. All-positive is exactly as unlearnable as
    // all-negative: with one chain fitted on nothing, every path scores the same
    // and the ranking is arbitrary.
    let positives = samples.iter().filter(|(_, found)| *found).count();
    let negatives = samples.len() - positives;
    if positives == 0 || negatives == 0 {
        let which = if positives == 0 {
            "none carry a finding"
        } else {
            "every one carries a finding"
        };
        println!(
            "{} file(s) recorded but {which} — a model needs examples of both to \
             tell them apart. Scan a wider tree, then train.",
            samples.len()
        );
        return Ok(());
    }

    let cfg = exfil_model::TrainConfig {
        states,
        iterations,
        vocab_cap: vocab,
        ruleset: exfil_engine::setup::ruleset_fingerprint(config).await,
        ..exfil_model::TrainConfig::default()
    };
    println!(
        "training {kind} on {} path(s), {positives} with findings ({:.1}% base rate)…",
        samples.len(),
        100.0 * positives as f64 / samples.len() as f64
    );
    let fitted = exfil_model::StoredScorer::fit(kind, &samples, &cfg);

    let catalog = open_catalog(config).await?;
    catalog
        .upsert_path_model(name, &serde_json::to_value(&fitted)?)
        .await?;
    match &fitted {
        exfil_model::StoredScorer::PathHmm(m) => println!(
            "trained {name:?} ({kind}): {} states/chain, {} tokens, mean log-likelihood {:.3}",
            m.states(),
            m.vocab.len(),
            m.log_likelihood
        ),
        exfil_model::StoredScorer::DirPrior(p) => println!(
            "trained {name:?} ({kind}): {} director{} observed, base rate {:.4}",
            p.rate.len(),
            if p.rate.len() == 1 { "y" } else { "ies" },
            p.base
        ),
    }
    hint("\nNext: `exfil scan --ranked` to scan worst-first, or `--budget 20%` to cap the work");
    Ok(())
}

/// Score one path and show which components drove the number.
async fn cmd_model_score(config: Option<&std::path::Path>, path: &str, name: &str) -> Result<()> {
    let Some(stored) = load_model(config, name).await? else {
        println!("no model {name:?} — run `exfil train`");
        return Ok(());
    };
    let model = stored.as_scorer();
    println!("{path}   [{}]", model.name());
    println!(
        "  P(finding) = {:.4}   (base rate {:.4})",
        model.score(path),
        model.base_rate()
    );
    // Per-component log-odds: what each part of the path contributed, so the
    // number is inspectable rather than oracular. Only the sequence model has a
    // vocabulary, so only it can say a component was never seen in training.
    let obs = match &stored {
        exfil_model::StoredScorer::PathHmm(m) => m.observe(path),
        _ => Vec::new(),
    };
    println!("\n  {:<28} {:>9}", "component", "log-odds");
    for (i, (token, delta)) in model.explain(path).into_iter().enumerate() {
        let unseen = if obs.get(i) == Some(&exfil_model::UNK) {
            "  (unseen)"
        } else {
            ""
        };
        println!("  {token:<28} {delta:>+9.3}{unseen}");
    }
    Ok(())
}

/// Render a report to a file, or to stdout when `out` is `None`.
///
/// Writing to a file is not the same as writing to a terminal, so the text
/// report is fitted to a window only in the stdout-to-a-terminal case. A saved
/// report is a document: truncating its paths would corrupt the artifact the
/// caller asked for.
async fn cmd_report(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    query: Option<String>,
    format: &str,
    out: Option<&std::path::Path>,
) -> Result<()> {
    // Check the format before touching the filesystem. `File::create`
    // truncates, so validating afterwards would leave an empty file behind —
    // and would clobber a good report from a previous run on a typo.
    if exfil_report::reporter_for(format).is_none() {
        anyhow::bail!(
            "unknown report format {format:?} (try {})",
            exfil_report::FORMATS.join(", ")
        );
    }
    let store = open_findings(store_dir, config).await?;
    let query = query.unwrap_or_default();
    match out {
        Some(path) => {
            let mut file = std::fs::File::create(path)
                .with_context(|| format!("create {}", path.display()))?;
            exfil_engine::run::analyze(&store, &query, format, None, &mut file).await?;
            // Say where it went: a command whose whole purpose is producing a
            // file should not be silent about having produced one.
            hint(&format!("wrote {} report to {}", format, path.display()));
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            exfil_engine::run::analyze(
                &store,
                &query,
                format,
                progress::display_width(),
                &mut stdout,
            )
            .await?;
        }
    }
    Ok(())
}

/// List the trained models in the catalog.
async fn cmd_model_list(config: Option<&std::path::Path>) -> Result<()> {
    let catalog = open_catalog(config).await?;
    let names = catalog.list_path_models().await?;
    if names.is_empty() {
        println!("no models — `exfil train` fits one on the scans you have");
        return Ok(());
    }
    for name in &names {
        println!("{name}");
    }
    println!("{} model(s)", names.len());
    Ok(())
}

/// Forget a trained model.
async fn cmd_model_remove(config: Option<&std::path::Path>, name: &str) -> Result<()> {
    let catalog = open_catalog(config).await?;
    if catalog.remove_path_model(name).await? {
        println!("removed model {name:?}");
    } else {
        println!("no model {name:?}");
    }
    Ok(())
}

/// Summarize a trained model.
async fn cmd_model_status(config: Option<&std::path::Path>, name: &str) -> Result<()> {
    let catalog = open_catalog(config).await?;
    let names = catalog.list_path_models().await.unwrap_or_default();
    let Some(model) = load_model(config, name).await? else {
        println!("no model {name:?} — run `exfil train`");
        if !names.is_empty() {
            println!("stored models: {}", names.join(", "));
        }
        return Ok(());
    };
    let scorer = model.as_scorer();
    println!("model         {name}");
    println!("kind          {}", model.kind());
    println!("              {}", model.kind().about());
    println!("trained on    {} path(s)", model.observations());
    println!("base rate     {:.4}", scorer.base_rate());
    // Everything below is what one kind can say and the other cannot, so it is
    // reported per kind rather than flattened into fields that would be blank.
    match &model {
        exfil_model::StoredScorer::PathHmm(m) => {
            println!(
                "states        {} per chain (positive + negative)",
                m.states()
            );
            println!("vocabulary    {} token(s)", m.vocab.len());
            println!("log-likelihood {:.4} per path", m.log_likelihood);
            println!(
                "calibration   {}",
                if m.has_calibration() {
                    format!("Platt slope {:.4}, intercept {:+.3}", m.platt.0, m.platt.1)
                } else {
                    "identity (uncalibrated — too little held-out data to fit)".to_string()
                }
            );
        }
        exfil_model::StoredScorer::DirPrior(p) => {
            println!("directories   {} observed", p.rate.len());
            println!("calibration   a smoothed frequency is already a probability");
        }
    }
    println!(
        "ruleset       {}",
        if scorer.ruleset().is_empty() {
            "(unrecorded)"
        } else {
            scorer.ruleset()
        }
    );
    Ok(())
}

/// Measure the model out of sample: recall-at-budget against a
/// directory-frequency baseline and against blind selection.
///
/// This is the number that decides whether ranked scanning earns its
/// complexity. Scoring the paths a model was fitted on would flatter it, so the
/// corpus is split and the model only ever sees the training half.
async fn cmd_model_eval(
    store_dir: &std::path::Path,
    config: Option<&std::path::Path>,
    holdout: f64,
    states: usize,
) -> Result<()> {
    let store = open_findings(store_dir, config).await?;
    let samples = store.training_paths().await?;
    if samples.is_empty() {
        println!("nothing to evaluate — run `exfil scan` first");
        return Ok(());
    }
    let cfg = exfil_model::TrainConfig {
        states: states.max(1),
        ruleset: exfil_engine::setup::ruleset_fingerprint(config).await,
        ..exfil_model::TrainConfig::default()
    };
    let Some(report) = exfil_model::eval::evaluate(&samples, &cfg, holdout) else {
        println!(
            "{} path(s), but the split leaves nothing to measure — a corpus needs \
             findings on both sides of it. Scan a wider tree.",
            samples.len()
        );
        return Ok(());
    };

    println!(
        "trained on {} path(s), measured on {} held out ({} with findings)\n",
        report.train, report.test, report.test_positives
    );
    println!(
        "  {:>7}  {:>7}  {:>8}  {:>6}  {:>5}",
        "budget", "model", "baseline", "random", "lift"
    );
    for p in &report.points {
        println!(
            "  {:>6.0}%  {:>6.0}%  {:>7.0}%  {:>5.0}%  {:>4.1}x",
            p.budget * 100.0,
            p.model * 100.0,
            p.baseline * 100.0,
            p.random * 100.0,
            p.lift()
        );
    }
    println!();
    println!("mean lift over blind selection: {:.1}x", report.mean_lift());
    println!(
        "calibration: Brier {:.3}, expected error {:.3}{}",
        report.brier,
        report.ece,
        if report.is_calibrated() {
            ""
        } else {
            "  (too high — treat the scores as a ranking, not probabilities)"
        }
    );
    // The honest verdict, stated rather than left for the reader to infer.
    if report.mean_lift() <= 1.1 {
        println!("VERDICT: the model is not beating blind selection — do not rely on --budget.");
    } else if !report.beats_baseline() {
        println!(
            "VERDICT: a plain directory-frequency prior does as well. The sequence \
             model is not earning its complexity on this corpus."
        );
    } else {
        println!("VERDICT: the model beats both blind selection and the directory baseline.");
    }
    Ok(())
}

/// Load a trained model from the catalog, if one exists under `name`.
async fn load_model(
    config: Option<&std::path::Path>,
    name: &str,
) -> Result<Option<exfil_model::StoredScorer>> {
    let catalog = open_catalog(config).await?;
    match catalog.load_path_model(name).await? {
        Some(value) => Ok(Some(
            serde_json::from_value(value).context("decode stored path model")?,
        )),
        None => Ok(None),
    }
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
        None => {
            println!("no {id} in the local CWE catalog (run `exfil dataset update mitre://cwe`)")
        }
    }
    Ok(())
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

/// Combine an optional `--name <run>` with an optional free-form query into the
/// single filter string the store understands.
///
/// `--name` is sugar for the `run=<name>` filter rather than a separate code
/// path, so there is one query grammar to learn and one place it is parsed.
/// The store takes a single filter, so asking for both a run and a query is
/// rejected out loud instead of silently dropping one of them.
fn run_query(query: Option<String>, name: Option<String>) -> Result<Option<String>> {
    match (query, name) {
        (Some(q), Some(n)) => anyhow::bail!(
            "--name {n:?} and the query {q:?} cannot be combined \
             (the store filters on one field at a time)"
        ),
        (None, Some(n)) => Ok(Some(format!("run={n}"))),
        (q, None) => Ok(q),
    }
}

/// Print a shell completion script for `shell` to stdout. Generated from the
/// clap command tree, so it always covers the current subcommands and flags.
fn cmd_completions(shell: Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "exfil", &mut std::io::stdout());
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
    use super::{find_plugin_field, resolve_plugin_setting};

    #[tokio::test]
    async fn resolve_plugin_setting_falls_back_when_config_value_is_out_of_range() {
        let dir =
            std::env::temp_dir().join(format!("exfil-cli-resolve-setting-{}", std::process::id()));
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
        assert_eq!(
            resolved, field.default,
            "out-of-range config value must fall back to default"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
