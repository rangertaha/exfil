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

pub mod run;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use exfill_core::{platform::ownership, FileMeta, Match};
use exfill_store::{FileStat, ScanRecord, Store};
use exfill_task::Pipeline;
use ignore::{WalkBuilder, WalkState};

/// How much of a file's head to inspect for NUL bytes when deciding whether
/// it is binary (binary files are recorded but not scanned).
const BINARY_SNIFF_LEN: usize = 8192;

/// How deep archive-within-archive expansion recurses before stopping. Bounds
/// work on hostile nested archives (a zip inside a zip inside a zip…).
const MAX_EXPAND_DEPTH: u32 = 8;

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
}

/// One processed file: its metadata, any matches, an optional parsed AST, and —
/// for files expanded from an archive — the content hash of the container.
struct FileResult {
    meta: FileMeta,
    matches: Vec<Match>,
    /// The parsed AST, when a language task produced one (for `has_ast`).
    ast: Option<exfill_task::Ast>,
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
/// includes dotfiles, and skips `.git`, `.exfill`, and the store directory
/// itself (`skip`, compared by canonical path so any `--store` location is
/// excluded even when it sits inside the scanned tree).
fn walk_builder(root: &Path, skip: Option<&Path>) -> WalkBuilder {
    let skip = skip.and_then(|p| std::fs::canonicalize(p).ok());
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // scan dotfiles; .gitignore is still honored
        .filter_entry(move |e| {
            if e.file_name() == ".exfill" || e.file_name() == ".git" {
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
    if let Some(ev) = &events {
        let _ = ev.send(ScanEvent::Total(count_files(root, skip_dir)));
    }
    // Stat cache from previous scans: files whose size+mtime still match are
    // skipped without reading. Wrapped in Arc so every walker thread can
    // share one read-only copy instead of cloning the whole map.
    let index = std::sync::Arc::new(store.file_index().await.unwrap_or_default());
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
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
    let mut summary = Summary::default();
    let mut hashes = Vec::new();
    while let Ok(res) = rx.recv() {
        match res {
            WalkOutcome::Scanned(results) => {
                for fr in results {
                    summary.files += 1;
                    summary.matches += fr.matches.len() as u64;
                    store.upsert_file(&fr.meta).await?;
                    // Replace, don't append: stale findings from earlier scans
                    // of this content are removed before the fresh ones go in.
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
    }

    store
        .commit_scan(
            &ScanRecord {
                root: root.display().to_string(),
                host,
                started_at,
                files: summary.files,
                matches: summary.matches,
            },
            &hashes,
        )
        .await?;
    Ok(summary)
}

/// A remote filesystem the engine can scan: enumerate files under a root and
/// read their bytes. Implemented over SSH/SFTP (see the `exfill-remote` crate)
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
        .map(|d| d.as_secs())
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
        let processed = run_pipeline(Path::new(&path), content, pipeline);
        results.push(FileResult {
            meta,
            matches: processed.matches,
            ast: processed.ast,
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
            },
            &hashes,
        )
        .await?;
    Ok(summary)
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

    let content = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let hash = blake3::hash(&content).to_hex().to_string();
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
    let processed = run_pipeline(path, content, pipeline);
    results.push(FileResult {
        meta,
        matches: processed.matches,
        ast: processed.ast,
        contained_in: None,
    });
    expand_into(&hash, processed.expanded, host, pipeline, 1, &mut results);

    Ok(WalkOutcome::Scanned(results))
}

/// What running the pipeline over one file's bytes yielded.
#[derive(Default)]
struct Processed {
    matches: Vec<Match>,
    expanded: Vec<exfill_core::VirtualFile>,
    ast: Option<exfill_task::Ast>,
}

/// Run the pipeline over one file's bytes, skipping binary content (but still
/// expanding archives — their inner files feed re-processing).
fn run_pipeline(path: &Path, content: Vec<u8>, pipeline: &Pipeline) -> Processed {
    // An archive is a container: expand it, but never content-scan its raw
    // bytes (that would match on compression artifacts and produce garbage
    // findings). Its inner files are scanned individually after expansion.
    let is_archive = pipeline
        .tasks()
        .iter()
        .any(|t| t.provides() == exfill_task::ArtifactKind::Files && t.applies(path));
    if is_archive {
        let expanded = match pipeline.run_file(path, content) {
            Ok(out) => out.expanded,
            Err(_) => Vec::new(),
        };
        return Processed {
            expanded,
            ..Default::default()
        };
    }

    // Binary files get a record (full VFS coverage) but are not scanned.
    let head = &content[..content.len().min(BINARY_SNIFF_LEN)];
    if head.contains(&0) {
        return Processed::default();
    }
    match pipeline.run_file(path, content) {
        Ok(out) => Processed {
            matches: out.matches,
            expanded: out.expanded,
            ast: out.ast,
        },
        Err(_) => Processed::default(),
    }
}

/// Turn expanded virtual files into [`FileResult`]s, recursing into nested
/// archives up to [`MAX_EXPAND_DEPTH`]. Each result links to its container.
fn expand_into(
    container_hash: &str,
    expanded: Vec<exfill_core::VirtualFile>,
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
            contained_in: Some(container_hash.to_string()),
        });
        expand_into(&hash, processed.expanded, host, pipeline, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfill_scan::default_pipeline;

    #[tokio::test(flavor = "multi_thread")]
    async fn scans_a_tree_and_persists_findings() {
        let base = std::env::temp_dir().join(format!("exfill-engine-test-{}", std::process::id()));
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
            "exfill-engine-test-unreadable-{}",
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
        let base = std::env::temp_dir().join(format!("exfill-remote-test-{}", std::process::id()));
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
        let base = std::env::temp_dir().join(format!("exfill-remote-err-{}", std::process::id()));
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
            std::env::temp_dir().join(format!("exfill-engine-test-ast-{}", std::process::id()));
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
            .bind(("h", hash))
            .await
            .unwrap();
        let rows: Vec<serde_json::Value> = res.take(0).unwrap();
        assert_eq!(rows[0]["n"], 1, "file linked to its ast");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scans_inside_archives_and_links_container() {
        use std::io::Write;

        let base =
            std::env::temp_dir().join(format!("exfill-engine-test-zip-{}", std::process::id()));
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
}
