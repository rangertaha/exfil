//! Scan-target dispatch: turn a target *spec* — the one string a user or an
//! agent types — into the right scan.
//!
//! `exfil scan <spec>` and the MCP `scan` tool accept the same shapes, and they
//! must resolve them identically: a spec that crawls a site from the shell has
//! to crawl the same site for an agent. That shared resolution lives here,
//! above the individual [`RemoteFs`](exfil_engine::RemoteFs) implementations
//! and below both front ends.
//!
//! Front ends keep their own presentation: [`run`] returns an [`Outcome`]
//! carrying the engine [`Summary`](exfil_engine::Summary) and which kind of
//! target produced it, so the CLI can print "crawled 12 page(s)" where the MCP
//! server returns the same facts as tool text.
//!
//! # Rust notes
//!
//! [`Target`] is an enum with data in its variants — Rust's way of saying "one
//! of these shapes, and the compiler will make you handle each". Parsing
//! returns one, and [`run`] matches on it exhaustively; adding a new target
//! kind stops both from compiling until they're updated.

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use anyhow::{Context, Result};
use exfil_engine::{ScanEvent, Summary};
use exfil_store::Store;
use exfil_task::Pipeline;

/// A resolved scan target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A local directory tree.
    Path(PathBuf),
    /// The local host's running processes.
    Processes,
    /// One or more `host:port` banner-grab targets.
    Tcp(Vec<String>),
    /// A website to crawl.
    Web {
        /// Seed URL.
        url: String,
        /// Maximum pages to fetch.
        max_pages: usize,
        /// Maximum link depth from the seed.
        max_depth: usize,
        /// WebDriver server URL, to render JavaScript-heavy pages.
        driver: Option<String>,
    },
}

/// Whether a target reaches a remote system (active) or stays local (passive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The scan reached out over the network.
    Active,
    /// The scan stayed on the local system.
    Passive,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Mode::Active => "active",
            Mode::Passive => "passive",
        })
    }
}

impl Target {
    /// The mode this target implies, before any explicit `--active`/`--passive`
    /// override: anything that opens a socket is active.
    pub fn default_mode(&self) -> Mode {
        match self {
            Target::Path(_) | Target::Processes => Mode::Passive,
            Target::Tcp(_) | Target::Web { .. } => Mode::Active,
        }
    }

    /// A short noun for what this target yields, for summary lines: `files`,
    /// `processes`, `banner(s)`, `page(s)`.
    pub fn unit(&self) -> &'static str {
        match self {
            Target::Path(_) => "files",
            Target::Processes => "processes",
            Target::Tcp(_) => "banner(s)",
            Target::Web { .. } => "page(s)",
        }
    }
}

/// Web crawl defaults, used when a caller doesn't specify.
pub const DEFAULT_MAX_PAGES: usize = 25;
/// Default maximum link depth from the crawl seed.
pub const DEFAULT_MAX_DEPTH: usize = 2;

/// Options that only apply to some target shapes; ignored by the others.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Port spec (`22,80,8000-8010` or `common`). Its presence is what makes
    /// `spec` a host/CIDR sweep rather than a path.
    pub ports: Option<String>,
    /// Maximum pages to fetch when the target is a URL.
    pub max_pages: Option<usize>,
    /// Maximum link depth when the target is a URL.
    pub max_depth: Option<usize>,
    /// WebDriver server to render pages through when the target is a URL.
    pub driver: Option<String>,
    /// How many ports `ports = "common"` expands to.
    pub top_ports: u16,
}

/// Parse `spec` as one or more comma-separated `host:port` banner-grab
/// targets. `None` if any piece lacks a trailing `:<port>`, so callers fall
/// back to treating `spec` as a local path.
pub fn parse_tcp_targets(spec: &str) -> Option<Vec<String>> {
    let pieces: Vec<&str> = spec.split(',').collect();
    let all_host_port = pieces.iter().all(|p| {
        p.rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    });
    all_host_port.then(|| pieces.into_iter().map(String::from).collect())
}

/// Resolve a target spec by its shape: an `http(s)://` URL crawls a site; the
/// literal `processes` scans local running processes; a `ports` option sweeps
/// `spec` as a host/CIDR; comma-separated `host:port` grabs banners; anything
/// else (or no spec) is a local directory tree.
pub fn parse(spec: Option<&str>, opts: &Options) -> Result<Target> {
    let Some(spec) = spec.filter(|s| !s.is_empty()) else {
        return Ok(Target::Path(PathBuf::from(".")));
    };

    if let Some(ports) = &opts.ports {
        let top_n = if opts.top_ports == 0 {
            100
        } else {
            opts.top_ports
        };
        return Ok(Target::Tcp(crate::netscan::expand_targets(
            spec,
            ports,
            usize::from(top_n),
        )?));
    }
    if spec.starts_with("http://") || spec.starts_with("https://") {
        return Ok(Target::Web {
            url: spec.to_string(),
            max_pages: opts.max_pages.unwrap_or(DEFAULT_MAX_PAGES),
            max_depth: opts.max_depth.unwrap_or(DEFAULT_MAX_DEPTH),
            driver: opts.driver.clone(),
        });
    }
    if spec == "processes" {
        return Ok(Target::Processes);
    }
    if let Some(targets) = parse_tcp_targets(spec) {
        return Ok(Target::Tcp(targets));
    }
    Ok(Target::Path(PathBuf::from(spec)))
}

/// What a scan produced, plus the target that produced it (so callers can
/// phrase a summary without re-deriving the shape).
pub struct Outcome {
    /// Engine counts for the run.
    pub summary: Summary,
    /// The target that was scanned.
    pub target: Target,
    /// Active or passive, after any caller override.
    pub mode: Mode,
}

/// Run `target` through `pipeline`, persisting into `store`. `store_dir` is
/// excluded from a local walk (so the store never scans itself) and is unused
/// for remote targets. Progress streams over `events` when provided.
///
/// `plan` (ranking model + budget) applies only to a local tree walk. The
/// remote sources enumerate a bounded set they have already fetched — a crawl's
/// pages, a sweep's banners — so there is nothing to rank or cut short; their
/// equivalent knobs are `--max-pages` and `--ports`.
pub async fn run(
    target: Target,
    pipeline: &Pipeline,
    store: &Store,
    store_dir: Option<&Path>,
    events: Option<Sender<ScanEvent>>,
    mode: Option<Mode>,
    plan: &exfil_engine::ScanPlan,
) -> Result<Outcome> {
    let mode = mode.unwrap_or_else(|| target.default_mode());
    let summary = match &target {
        Target::Path(path) => {
            exfil_engine::scan_with_plan(path, pipeline, store, store_dir, events, plan).await?
        }
        Target::Processes => {
            let fs = crate::ProcessFs::new();
            exfil_engine::scan_remote(&fs, "proc://", pipeline, store, events).await?
        }
        Target::Tcp(targets) => {
            let fs = crate::TcpFs::new(targets.clone());
            exfil_engine::scan_remote(&fs, "tcp://", pipeline, store, events).await?
        }
        Target::Web {
            url,
            max_pages,
            max_depth,
            driver,
        } => match driver {
            Some(driver) => {
                let fs = crate::webdriver::WebDriverFs::crawl(driver, url, *max_pages, *max_depth)
                    .await
                    .with_context(|| format!("render {url} via WebDriver"))?;
                exfil_engine::scan_remote(&fs, "/", pipeline, store, events).await?
            }
            None => {
                let fs = crate::WebFs::crawl(url, *max_pages, *max_depth)
                    .await
                    .with_context(|| format!("crawl {url}"))?;
                exfil_engine::scan_remote(&fs, "/", pipeline, store, events).await?
            }
        },
    };
    Ok(Outcome {
        summary,
        target,
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_spec_is_the_current_directory() {
        let t = parse(None, &Options::default()).unwrap();
        assert_eq!(t, Target::Path(PathBuf::from(".")));
        // An empty string means the same thing as no argument.
        assert_eq!(
            parse(Some(""), &Options::default()).unwrap(),
            Target::Path(PathBuf::from("."))
        );
    }

    #[test]
    fn shapes_resolve_to_their_targets() {
        let o = Options::default();
        assert_eq!(parse(Some("processes"), &o).unwrap(), Target::Processes);
        assert_eq!(
            parse(Some("example.com:22"), &o).unwrap(),
            Target::Tcp(vec!["example.com:22".into()])
        );
        assert_eq!(
            parse(Some("a.com:22,b.com:80"), &o).unwrap(),
            Target::Tcp(vec!["a.com:22".into(), "b.com:80".into()])
        );
        assert_eq!(
            parse(Some("./src"), &o).unwrap(),
            Target::Path(PathBuf::from("./src"))
        );
        // A path that merely contains a colon is not a host:port.
        assert_eq!(
            parse(Some("C:/code"), &o).unwrap(),
            Target::Path(PathBuf::from("C:/code"))
        );
        // A Windows drive letter splits like `host:port`, but the "port" half
        // isn't numeric, so it must not be misread as a scan target.
        assert_eq!(
            parse(Some(r"C:\Users\x"), &o).unwrap(),
            Target::Path(PathBuf::from(r"C:\Users\x"))
        );
        // An absolute Unix path has no trailing `:<port>` at all.
        assert_eq!(parse_tcp_targets("/etc/passwd"), None);
    }

    #[test]
    fn urls_crawl_with_defaults_and_overrides() {
        let o = Options::default();
        assert_eq!(
            parse(Some("https://example.com"), &o).unwrap(),
            Target::Web {
                url: "https://example.com".into(),
                max_pages: DEFAULT_MAX_PAGES,
                max_depth: DEFAULT_MAX_DEPTH,
                driver: None,
            }
        );
        let o = Options {
            max_pages: Some(3),
            max_depth: Some(1),
            driver: Some("http://localhost:4444".into()),
            ..Options::default()
        };
        let Target::Web {
            max_pages,
            max_depth,
            driver,
            ..
        } = parse(Some("http://example.com"), &o).unwrap()
        else {
            panic!("expected a web target");
        };
        assert_eq!((max_pages, max_depth), (3, 1));
        assert_eq!(driver.as_deref(), Some("http://localhost:4444"));
    }

    #[test]
    fn ports_make_the_spec_a_sweep() {
        let o = Options {
            ports: Some("22,80".into()),
            ..Options::default()
        };
        let Target::Tcp(targets) = parse(Some("10.0.0.1"), &o).unwrap() else {
            panic!("expected a tcp sweep");
        };
        assert_eq!(targets, vec!["10.0.0.1:22", "10.0.0.1:80"]);
    }

    #[test]
    fn modes_follow_the_target_shape() {
        assert_eq!(Target::Processes.default_mode(), Mode::Passive);
        assert_eq!(Target::Path(".".into()).default_mode(), Mode::Passive);
        assert_eq!(Target::Tcp(vec![]).default_mode(), Mode::Active);
        assert_eq!(Mode::Active.to_string(), "active");
        assert_eq!(Target::Processes.unit(), "processes");
    }
}
