//! The operations behind the MCP tools.
//!
//! Each function here is one thing an agent can ask exfil to do, returning the
//! text the agent sees. They are deliberately the *same* library calls the CLI
//! makes — shared store opening and pipeline building come from
//! [`exfil_engine::setup`], and scan-target dispatch from
//! [`exfil_remote::target`] — so an agent-run scan applies exactly the ruleset
//! a shell-run scan would.
//!
//! # Rust notes
//!
//! Every operation opens the store it needs and drops it on return, rather than
//! holding one handle for the life of the server. That costs a little per call
//! and buys two things: `clean` can delete the store directory without a live
//! handle writing into unlinked files, and a `pull` is visible to the very next
//! `scan` without any cache invalidation.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use exfil_engine::setup::{build_pipeline, open_catalog, open_findings};
use exfil_model::PathScorer;
use exfil_remote::target::{self, Options, Target};
use exfil_report::{reporter_for, Analysis};
use exfil_store::Store;

/// Where the server's stores live: everything an operation needs to find the
/// findings store, the catalog, and the config that shapes both.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// The findings store directory (the `--store` path).
    pub store_dir: PathBuf,
    /// An explicit config path, or `None` for the user default.
    pub config: Option<PathBuf>,
}

impl Ctx {
    /// The config path as the setup helpers want it.
    fn config(&self) -> Option<&Path> {
        self.config.as_deref()
    }

    /// Open the findings store.
    pub async fn findings(&self) -> Result<Store> {
        open_findings(&self.store_dir, self.config()).await
    }

    /// Open the catalog store (datasets, rules, CWE, feeds, plugin settings).
    pub async fn catalog(&self) -> Result<Store> {
        open_catalog(self.config()).await
    }
}

// ── Reading the findings graph ───────────────────────────────────────────────

/// Search findings and format them as location lines plus a count.
pub async fn search(ctx: &Ctx, query: &str) -> Result<String> {
    let findings = ctx.findings().await?.search_findings(query).await?;
    let mut out = String::new();
    for m in &findings {
        out.push_str(&format!(
            "{}:{}:{} [{}] {}\n",
            m.path, m.line, m.col, m.rule, m.snippet
        ));
    }
    out.push_str(&format!("{} finding(s)", findings.len()));
    Ok(out)
}

/// The findings graph (nodes and edges) for an optional filter.
pub async fn graph(ctx: &Ctx, query: &str) -> Result<String> {
    json(ctx.findings().await?.graph(query).await?)
}

/// Everything connected to a node by any edge.
pub async fn neighbors(ctx: &Ctx, id: &str) -> Result<String> {
    json(ctx.findings().await?.neighbors(id).await?)
}

/// One record by `table:key`.
pub async fn get(ctx: &Ctx, id: &str) -> Result<String> {
    json(ctx.findings().await?.get_record(id).await?)
}

/// Render a report over the findings graph in any supported format.
pub async fn analyze(ctx: &Ctx, query: &str, format: &str) -> Result<String> {
    let format = if format.is_empty() { "text" } else { format };
    let store = ctx.findings().await?;
    let findings = store.search_findings(query).await?;
    let (files, scans) = store.counts().await?;
    let analysis = Analysis {
        findings,
        files,
        scans,
    };
    let reporter =
        reporter_for(format).with_context(|| format!("unknown report format {format:?}"))?;
    let mut buf = Vec::new();
    reporter.report(&mut buf, &analysis)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Store counts plus the CIM event tally, as a compact status block.
pub async fn stats(ctx: &Ctx) -> Result<String> {
    let store = ctx.findings().await?;
    let (files, scans) = store.counts().await?;
    let findings = store.search_findings("").await?.len();
    let mut out = format!("files: {files}\nscans: {scans}\nfindings: {findings}\n");
    let events = store.event_summary().await.unwrap_or_default();
    if !events.is_empty() {
        out.push_str("events by category:\n");
        for (category, n) in events {
            out.push_str(&format!("  {category:<16} {n}\n"));
        }
    }
    Ok(out)
}

/// The whole graph as a portable JSON snapshot.
pub async fn export(ctx: &Ctx) -> Result<String> {
    json(ctx.findings().await?.export_snapshot().await?)
}

// ── Reading the catalog and config ───────────────────────────────────────────

/// The rules a scan would apply — built-ins plus catalog datasets — optionally
/// filtered by a substring of the name, description, CWE, or severity.
pub async fn rules(ctx: &Ctx, filter: &str) -> Result<String> {
    let needle = filter.to_lowercase();
    let mut all = exfil_scan::builtin_rules();
    if let Ok(catalog) = ctx.catalog().await {
        all.extend(catalog.all_rules().await.unwrap_or_default());
    }
    let mut out = String::new();
    let mut shown = 0;
    for r in &all {
        let sev = r
            .severity
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_else(|| "-".into());
        let hit = needle.is_empty()
            || r.name.to_lowercase().contains(&needle)
            || r.description.to_lowercase().contains(&needle)
            || r.cwe
                .as_deref()
                .is_some_and(|c| c.to_lowercase().contains(&needle))
            || sev == needle;
        if !hit {
            continue;
        }
        out.push_str(&format!(
            "{:<22} {:<8} {:<8} {}\n",
            r.name,
            sev,
            r.cwe.as_deref().unwrap_or("-"),
            r.description
        ));
        shown += 1;
    }
    out.push_str(&format!("{shown} rule(s)"));
    Ok(out)
}

/// Look up one weakness in the local MITRE CWE catalog.
pub async fn cwe(ctx: &Ctx, id: &str) -> Result<String> {
    let id = if id.starts_with("CWE-") || id.is_empty() {
        id.to_string()
    } else {
        format!("CWE-{id}")
    };
    match ctx.catalog().await?.cwe_get(&id).await? {
        Some(e) => {
            let mut out = format!("{} — {}\n", e.id, e.name);
            if !e.abstraction.is_empty() || !e.status.is_empty() {
                out.push_str(&format!("{} · {}\n", e.abstraction, e.status));
            }
            if !e.description.is_empty() {
                out.push_str(&format!("\n{}", e.description));
            }
            Ok(out)
        }
        None => Ok(format!(
            "no {id} in the local CWE catalog (pull mitre://cwe first)"
        )),
    }
}

/// Catalog datasets and their rule counts.
pub async fn datasets(ctx: &Ctx) -> Result<String> {
    let datasets = ctx.catalog().await?.list_datasets().await?;
    if datasets.is_empty() {
        return Ok("no datasets — pull one first".into());
    }
    let mut out = String::new();
    for (name, rules) in &datasets {
        out.push_str(&format!("{name:<24} {rules} rules\n"));
    }
    out.push_str(&format!("{} dataset(s)", datasets.len()));
    Ok(out)
}

/// Configured URL feeds.
pub async fn feeds(ctx: &Ctx) -> Result<String> {
    let feeds = ctx.catalog().await?.list_feeds().await?;
    if feeds.is_empty() {
        return Ok("no feeds configured".into());
    }
    let mut out = String::new();
    for (name, url) in &feeds {
        out.push_str(&format!("{name:<20} {url}\n"));
    }
    out.push_str(&format!("{} feed(s)", feeds.len()));
    Ok(out)
}

/// The dataset source plugins and the references they handle.
pub fn sources() -> String {
    let mut out = String::from("available sources:\n");
    for name in exfil_source::Registry::new().names() {
        let schemes = match name {
            "builtin" => "builtin://",
            "file" => "file:// or a path",
            "http" => "http:// https://",
            _ => "",
        };
        out.push_str(&format!("  {name:<8} {schemes}\n"));
    }
    out
}

/// The resolved config path and contents.
pub fn config(ctx: &Ctx) -> Result<String> {
    let cfg = exfil_config::load(ctx.config())?;
    let contents = std::fs::read_to_string(&cfg.path).unwrap_or_default();
    Ok(format!("# config: {}\n{contents}", cfg.path.display()))
}

/// A plugin's stored setting overrides.
pub async fn plugin_settings(ctx: &Ctx, plugin: &str) -> Result<String> {
    let settings = ctx.catalog().await?.list_plugin_settings(plugin).await?;
    if settings.is_empty() {
        return Ok(format!("no stored overrides for plugin {plugin:?}"));
    }
    let mut out = String::new();
    for (key, value) in &settings {
        out.push_str(&format!("{plugin}.{key} = {value}\n"));
    }
    Ok(out)
}

// ── Scanning ─────────────────────────────────────────────────────────────────

/// Scan a target: a local path, `processes`, `host:port` banners, a host/CIDR
/// swept across ports, or an `http(s)://` URL to crawl.
///
/// `budget` caps the work, scanning the most promising files first when a
/// trained path model exists. A budgeted result always states its coverage —
/// an agent must not be able to mistake a partial scan for a clean tree.
pub async fn scan(
    ctx: &Ctx,
    spec: &str,
    opts: &Options,
    budget: Option<exfil_engine::Budget>,
    name: &str,
) -> Result<String> {
    let target = target::parse(Some(spec), opts)?;
    let built = build_pipeline(ctx.config()).await?;
    let store = ctx.findings().await?;
    // A local walk must exclude the store itself; remote targets have no
    // directory to skip.
    let skip = matches!(target, Target::Path(_)).then_some(ctx.store_dir.as_path());

    // The fingerprint rides on every scan, budgeted or not: it is what lets the
    // next scan notice the ruleset moved and stop trusting "unchanged".
    let plan = exfil_engine::ScanPlan {
        model: if budget.is_some() {
            load_model(ctx)
                .await
                .map(|m| Box::new(m) as Box<dyn PathScorer>)
        } else {
            None
        },
        budget,
        ruleset: exfil_engine::setup::ruleset_fingerprint(ctx.config()).await,
        name: name.to_string(),
    };

    let ignored_budget = budget.is_some() && !target.honors_plan();
    let outcome = target::run(target, &built.pipeline, &store, skip, None, None, &plan).await?;
    let s = &outcome.summary;
    let mut out = format!(
        "scanned {} {} ({} unchanged): {} matches, {} unreadable ({})",
        s.files,
        outcome.target.unit(),
        s.unchanged,
        s.matches,
        s.errors,
        outcome.mode
    );
    if s.is_partial() {
        out.push_str(&format!(
            "\nCOVERAGE: {} of {} files ({:.0}%, {}) — {} NOT examined. \
             This scan did not look at the whole target; absence of findings \
             does not mean the target is clean.",
            s.candidates - s.skipped,
            s.candidates,
            s.coverage() * 100.0,
            if plan.model.is_some() {
                "probability-ranked"
            } else {
                "walk order"
            },
            s.skipped,
        ));
    }
    if ignored_budget {
        out.push_str(
            "\nNOTE: budget ignored — it applies only to a local path scan. \
             This target was scanned in full.",
        );
    }
    if !built.skipped.is_empty() {
        out.push_str(&format!(
            "\nskipped {} rule(s) with unsupported patterns",
            built.skipped.len()
        ));
    }
    Ok(out)
}

/// The trained path model from the catalog, if any. A missing or undecodable
/// model is not an error: ranking degrades to walk order.
async fn load_model(ctx: &Ctx) -> Option<exfil_model::PathModel> {
    let catalog = ctx.catalog().await.ok()?;
    let value = catalog.load_path_model("default").await.ok()??;
    serde_json::from_value(value).ok()
}

// ── The path model ───────────────────────────────────────────────────────────

/// Train the path model on the scans already in the store.
pub async fn model_train(ctx: &Ctx, states: usize, iterations: usize) -> Result<String> {
    let samples = ctx.findings().await?.training_paths().await?;
    if samples.is_empty() {
        return Ok("nothing to train on — run a scan first".into());
    }
    // A classifier needs both classes: all-positive is as unlearnable as
    // all-negative, since one chain would be fitted on nothing.
    let positives = samples.iter().filter(|(_, found)| *found).count();
    let negatives = samples.len() - positives;
    if positives == 0 || negatives == 0 {
        let which = if positives == 0 {
            "none carry a finding"
        } else {
            "every one carries a finding"
        };
        return Ok(format!(
            "{} file(s) recorded but {which} — a model needs examples of both to \
             tell them apart",
            samples.len()
        ));
    }
    let cfg = exfil_model::TrainConfig {
        states: states.max(1),
        iterations: iterations.max(1),
        ruleset: exfil_engine::setup::ruleset_fingerprint(ctx.config()).await,
        ..exfil_model::TrainConfig::default()
    };
    let model = exfil_model::train(&samples, &cfg);
    ctx.catalog()
        .await?
        .upsert_path_model("default", &serde_json::to_value(&model)?)
        .await?;
    Ok(format!(
        "trained on {} path(s), {positives} with findings ({:.1}% base rate): \
         {} states/chain, {} tokens",
        samples.len(),
        100.0 * positives as f64 / samples.len() as f64,
        model.states(),
        model.vocab.len(),
    ))
}

/// Score one path under the trained model, with the per-component evidence.
pub async fn model_score(ctx: &Ctx, path: &str) -> Result<String> {
    let Some(model) = load_model(ctx).await else {
        return Ok("no trained model — run the `train` tool first".into());
    };
    let mut out = format!(
        "{path}\nP(finding) = {:.4}   (base rate {:.4})\n\ncomponent contributions (log-odds):\n",
        model.score(path),
        model.base_rate()
    );
    let obs = model.observe(path);
    for (i, (token, delta)) in model.explain(path).into_iter().enumerate() {
        let unseen = if obs.get(i) == Some(&exfil_model::UNK) {
            "  (unseen)"
        } else {
            ""
        };
        out.push_str(&format!("  {token:<28} {delta:>+9.3}{unseen}\n"));
    }
    Ok(out)
}

/// Measure the model out of sample: recall-at-budget against a
/// directory-frequency baseline and against blind selection.
pub async fn model_eval(ctx: &Ctx, holdout: f64, states: usize) -> Result<String> {
    let samples = ctx.findings().await?.training_paths().await?;
    if samples.is_empty() {
        return Ok("nothing to evaluate — run a scan first".into());
    }
    let cfg = exfil_model::TrainConfig {
        states: states.max(1),
        ruleset: exfil_engine::setup::ruleset_fingerprint(ctx.config()).await,
        ..exfil_model::TrainConfig::default()
    };
    let Some(report) = exfil_model::eval::evaluate(&samples, &cfg, holdout) else {
        return Ok(format!(
            "{} path(s), but the split leaves nothing to measure — a corpus needs \
             findings on both sides of it",
            samples.len()
        ));
    };
    let mut out = format!(
        "trained on {} path(s), measured on {} held out ({} with findings)\n\n\
         budget  model  baseline  random  lift\n",
        report.train, report.test, report.test_positives
    );
    for p in &report.points {
        out.push_str(&format!(
            "{:>5.0}%  {:>4.0}%  {:>7.0}%  {:>5.0}%  {:>4.1}x\n",
            p.budget * 100.0,
            p.model * 100.0,
            p.baseline * 100.0,
            p.random * 100.0,
            p.lift()
        ));
    }
    out.push_str(&format!(
        "\nmean lift over blind selection: {:.1}x\ncalibration: Brier {:.3}, expected error {:.3}{}\n{}",
        report.mean_lift(),
        report.brier,
        report.ece,
        if report.is_calibrated() { "" } else { "  (uncalibrated — treat as a ranking)" },
        if report.mean_lift() <= 1.1 {
            "VERDICT: not beating blind selection — do not rely on budgeted scans here."
        } else if !report.beats_baseline() {
            "VERDICT: a plain directory-frequency prior does as well; the sequence model \
             is not earning its complexity on this corpus."
        } else {
            "VERDICT: beats both blind selection and the directory baseline."
        }
    ));
    Ok(out)
}

/// The recorded scan runs, newest first.
pub async fn run_list(ctx: &Ctx) -> Result<String> {
    let runs = ctx.findings().await?.list_runs().await?;
    if runs.is_empty() {
        return Ok("no runs — the `scan` tool records one\n".into());
    }
    let mut out = String::new();
    for r in &runs {
        out.push_str(&format!(
            "{}\t{} files\t{} matches\t{}\n",
            r.name, r.files, r.matches, r.root
        ));
    }
    out.push_str(&format!("{} run(s)\n", runs.len()));
    Ok(out)
}

/// One run's details, by name.
pub async fn run_get(ctx: &Ctx, name: &str) -> Result<String> {
    match ctx.findings().await?.get_run(name).await? {
        Some(r) => Ok(format!(
            "name     {}\nroot     {}\nhost     {}\nstarted  {}\n\
             files    {}\nmatches  {}\nruleset  {}\n",
            r.name, r.root, r.host, r.started_at, r.files, r.matches, r.ruleset
        )),
        None => Ok(format!("no run {name:?}\n")),
    }
}

/// Forget a run record. Its files and findings stay — another run may still
/// stand behind them — so `gc` is what reclaims anything left unreferenced.
pub async fn run_remove(ctx: &Ctx, name: &str) -> Result<String> {
    let n = ctx.findings().await?.remove_run(name).await?;
    Ok(if n == 0 {
        format!("no run {name:?}\n")
    } else {
        format!(
            "removed {n} run(s) named {name:?}; findings kept, `gc` reclaims unreferenced ones\n"
        )
    })
}

/// The names of every trained model in the catalog.
pub async fn model_list(ctx: &Ctx) -> Result<String> {
    let names = ctx.catalog().await?.list_path_models().await?;
    if names.is_empty() {
        return Ok("no models — run the `train` tool to fit one".into());
    }
    Ok(format!("{}\n{} model(s)\n", names.join("\n"), names.len()))
}

/// Forget a trained model.
pub async fn model_remove(ctx: &Ctx, name: &str) -> Result<String> {
    let removed = ctx.catalog().await?.remove_path_model(name).await?;
    Ok(if removed {
        format!("removed model {name:?}\n")
    } else {
        format!("no model {name:?}\n")
    })
}

/// Summarize the trained path model.
pub async fn model_status(ctx: &Ctx) -> Result<String> {
    let Some(model) = load_model(ctx).await else {
        return Ok("no trained model — run model_train first".into());
    };
    let current = exfil_engine::setup::ruleset_fingerprint(ctx.config()).await;
    let stale = !model.ruleset.is_empty() && model.ruleset != current;
    Ok(format!(
        "states        {} per chain (positive + negative)\n\
         vocabulary    {} token(s)\n\
         trained on    {} path(s)\n\
         base rate     {:.4}\n\
         ruleset       {}{}\n",
        model.states(),
        model.vocab.len(),
        model.observations,
        model.base_rate(),
        if model.ruleset.is_empty() {
            "(unrecorded)"
        } else {
            &model.ruleset
        },
        if stale {
            format!(" — STALE, this store now applies {current}; retrain")
        } else {
            String::new()
        },
    ))
}

// ── Catalog maintenance ──────────────────────────────────────────────────────

/// Download a dataset into the catalog: a specific reference, or every
/// configured `[[update]]` entry when none is given.
pub async fn pull(ctx: &Ctx, reference: &str) -> Result<String> {
    let catalog = ctx.catalog().await?;
    let registry = exfil_source::Registry::new();

    let refs: Vec<(String, String)> = if reference.is_empty() {
        exfil_config::load(ctx.config())?
            .update
            .into_iter()
            .map(|u| (u.name, u.reference))
            .collect()
    } else {
        vec![(reference.to_string(), reference.to_string())]
    };
    if refs.is_empty() {
        return Ok("nothing to pull (no reference and no [[update]] entries configured)".into());
    }

    let mut out = String::new();
    for (name, reference) in refs {
        if let Some(kind) = reference.strip_prefix("mitre://") {
            match pull_mitre(&catalog, kind).await {
                Ok(line) => out.push_str(&line),
                Err(e) => out.push_str(&format!("failed to pull mitre://{kind}: {e:#}\n")),
            }
            continue;
        }
        match registry.fetch(&reference).await {
            Ok(dataset) => {
                let n = catalog.upsert_dataset(&dataset).await?;
                out.push_str(&format!(
                    "pulled {:?} ({n} rules) from {reference}\n",
                    dataset.name
                ));
            }
            Err(e) => out.push_str(&format!(
                "failed to pull {name:?} from {reference}: {e:#}\n"
            )),
        }
    }
    Ok(out)
}

/// Download a MITRE reference catalog (CWE today) into the catalog store.
async fn pull_mitre(catalog: &Store, kind: &str) -> Result<String> {
    match kind {
        "cwe" => {
            let entries = exfil_source::mitre::fetch_cwe(exfil_source::mitre::CWE_URL).await?;
            let n = catalog.upsert_cwe(&entries).await?;
            Ok(format!("pulled MITRE CWE catalog ({n} weaknesses)\n"))
        }
        other => anyhow::bail!("unknown MITRE catalog {other:?} (known: cwe)"),
    }
}

/// Add or update a URL feed.
pub async fn feed_add(ctx: &Ctx, name: &str, url: &str) -> Result<String> {
    ctx.catalog().await?.upsert_feed(name, url).await?;
    Ok(format!("feed {name:?} -> {url}"))
}

/// Remove a URL feed.
pub async fn feed_rm(ctx: &Ctx, name: &str) -> Result<String> {
    let removed = ctx.catalog().await?.remove_feed(name).await?;
    Ok(if removed {
        format!("removed feed {name:?}")
    } else {
        format!("no feed {name:?}")
    })
}

/// Remove a dataset and its rules from the catalog.
pub async fn dataset_rm(ctx: &Ctx, name: &str) -> Result<String> {
    let removed = ctx.catalog().await?.remove_dataset(name).await?;
    Ok(if removed {
        format!("removed dataset {name:?}")
    } else {
        format!("no dataset {name:?}")
    })
}

/// Store a per-plugin setting override in the catalog.
pub async fn plugin_set(ctx: &Ctx, plugin: &str, key: &str, value: &str) -> Result<String> {
    ctx.catalog()
        .await?
        .set_plugin_setting(plugin, key, value)
        .await?;
    Ok(format!("{plugin}.{key} = {value}"))
}

// ── Post-scan passes ─────────────────────────────────────────────────────────

/// Normalize stored findings into CIM events for cross-source correlation.
pub async fn normalize(ctx: &Ctx) -> Result<String> {
    let store = ctx.findings().await?;
    let findings = store.findings_with_ids("").await?;
    for (fid, m) in &findings {
        let event = exfil_scan::cim::normalize(m);
        let value = serde_json::to_value(&event).unwrap_or_default();
        store.upsert_event(fid, &value).await?;
    }
    let mut out = format!("normalized {} finding(s) into CIM events\n", findings.len());
    for (category, n) in store.event_summary().await? {
        out.push_str(&format!("  {category:<16} {n}\n"));
    }
    Ok(out)
}

/// Annotate findings with authoritative CWE names from a pulled MITRE catalog.
pub async fn annotate_cwe(ctx: &Ctx) -> Result<String> {
    let findings = ctx.findings().await?;
    let catalog = ctx.catalog().await?.cwe_catalog().await?;
    if catalog.is_empty() {
        return Ok("no CWE catalog pulled (pull mitre://cwe first)".into());
    }
    let mut annotated = 0;
    for (fid, m) in findings.findings_with_ids("").await? {
        if let Some(entry) = m.cwe.as_deref().and_then(|id| catalog.get(id)) {
            findings
                .set_field(&fid, "cwe_name", serde_json::json!(entry.name))
                .await?;
            annotated += 1;
        }
    }
    Ok(format!(
        "annotated {annotated} finding(s) with CWE names from the MITRE catalog"
    ))
}

/// Resolve every observed domain and flag those pointing at reserved addresses.
/// Online: makes DNS queries.
pub async fn check_dns(ctx: &Ctx) -> Result<String> {
    let store = ctx.findings().await?;
    let domains = store.indicator_domains().await?;
    let mut flagged = 0u64;
    for (hash, list) in domains {
        for domain in list {
            let d = domain.clone();
            let finding =
                tokio::task::spawn_blocking(move || exfil_scan::dns::check_domain(&d, "dns"))
                    .await
                    .ok()
                    .flatten();
            if let Some(m) = finding {
                store.add_finding(&m, &hash).await?;
                flagged += 1;
            }
        }
    }
    Ok(format!("{flagged} domain(s) resolve to reserved addresses"))
}

/// WHOIS-check every observed domain and flag newly-registered ones. Online:
/// makes port-43 queries.
pub async fn check_whois(ctx: &Ctx, recent_days: i64) -> Result<String> {
    let store = ctx.findings().await?;
    let domains = store.indicator_domains().await?;
    let today = exfil_scan::whois::today_epoch_days();
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
                store.add_finding(&m, &hash).await?;
                flagged += 1;
            }
        }
    }
    Ok(format!("{flagged} newly-registered domain(s)"))
}

// ── Store maintenance ────────────────────────────────────────────────────────

/// Garbage-collect records unreachable from the newest scan.
pub async fn gc(ctx: &Ctx) -> Result<String> {
    let stats = ctx.findings().await?.gc().await?;
    Ok(format!(
        "gc: removed {} old scan(s), {} stale file(s), {} finding(s)",
        stats.scans, stats.files, stats.findings
    ))
}

/// Delete the findings store directory. Destructive, and irreversible — the
/// catalog (datasets, rules, CWE) lives elsewhere and is untouched.
pub fn clean(ctx: &Ctx) -> Result<String> {
    if !ctx.store_dir.exists() {
        return Ok(format!("no store at {}", ctx.store_dir.display()));
    }
    std::fs::remove_dir_all(&ctx.store_dir)
        .with_context(|| format!("remove store {}", ctx.store_dir.display()))?;
    Ok(format!("removed store {}", ctx.store_dir.display()))
}

/// Pretty-print any serializable result as JSON text.
fn json<T: serde::Serialize>(value: T) -> Result<String> {
    Ok(serde_json::to_string_pretty(&value)?)
}
