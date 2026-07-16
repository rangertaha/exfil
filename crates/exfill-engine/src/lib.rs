//! The scan engine: walk a tree in parallel, read each regular file once,
//! hash it (blake3), run the scanner registry over its bytes, stream matches
//! as they are found, then upsert the results into the store and commit a
//! scan record.
//!
//! Incremental rescans (stat fast-path against the previous scan) are the next
//! step; today every file is read.
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

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use exfill_core::{platform::ownership, FileMeta, Match};
use exfill_scan::Registry;
use exfill_store::{ScanRecord, Store};
use ignore::{WalkBuilder, WalkState};

/// How much of a file's head to inspect for NUL bytes when deciding whether
/// it is binary (binary files are recorded but not scanned).
const BINARY_SNIFF_LEN: usize = 8192;

/// Result of one scan run.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    /// Regular files recorded.
    pub files: u64,
    /// Total matches found.
    pub matches: u64,
    /// Files that could not be read (permission, races); they are skipped.
    pub errors: u64,
}

/// One walked file: its metadata plus any matches.
struct FileResult {
    meta: FileMeta,
    matches: Vec<Match>,
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

/// Walk `root` in parallel, scan every regular file with `registry`, and
/// persist files, findings, and the scan record into `store`. Progress and
/// matches stream over `events` when a sender is provided. `skip_dir` names
/// a directory to exclude from the walk (the store itself).
pub async fn scan(
    root: &Path,
    registry: &Registry,
    store: &Store,
    skip_dir: Option<&Path>,
    events: Option<mpsc::Sender<ScanEvent>>,
) -> Result<Summary> {
    if let Some(ev) = &events {
        let _ = ev.send(ScanEvent::Total(count_files(root, skip_dir)));
    }
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Parallel walk: worker threads read/hash/scan and send results over a
    // channel; progress events stream immediately from the workers.
    let (tx, rx) = mpsc::channel::<std::result::Result<FileResult, ()>>();
    let walker = walk_builder(root, skip_dir).build_parallel();

    walker.run(|| {
        let tx = tx.clone();
        let host = host.clone();
        let registry = &registry;
        let events = events.clone();
        Box::new(move |entry| {
            // `let-else`: unwrap the happy case or bail out of this closure.
            // `let _ =` deliberately ignores a Result we can't act on (if the
            // receiver hung up, this thread has nothing better to do anyway).
            let Ok(entry) = entry else {
                let _ = tx.send(Err(()));
                return WalkState::Continue;
            };
            let Some(ft) = entry.file_type() else {
                return WalkState::Continue;
            };
            if !ft.is_file() {
                return WalkState::Continue;
            }
            match process_file(entry.path(), &host, registry) {
                Ok(res) => {
                    if let Some(ev) = &events {
                        for m in &res.matches {
                            let _ = ev.send(ScanEvent::Match(m.clone()));
                        }
                        let _ = ev.send(ScanEvent::FileDone);
                    }
                    let _ = tx.send(Ok(res));
                }
                Err(_) => {
                    let _ = tx.send(Err(()));
                }
            }
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
            Ok(fr) => {
                summary.files += 1;
                summary.matches += fr.matches.len() as u64;
                store.upsert_file(&fr.meta).await?;
                for m in &fr.matches {
                    store.add_finding(m, &fr.meta.hash).await?;
                }
                hashes.push(fr.meta.hash);
            }
            Err(()) => summary.errors += 1,
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

/// Read, hash, and scan one regular file.
fn process_file(path: &Path, host: &str, registry: &Registry) -> Result<FileResult> {
    let md = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let content = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let hash = blake3::hash(&content).to_hex().to_string();

    let own = ownership(&md);
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    let abs: PathBuf = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

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
        hash,
    };

    // Binary files get a record (full VFS coverage) but are not scanned.
    let head = &content[..content.len().min(BINARY_SNIFF_LEN)];
    let matches = if head.contains(&0) {
        Vec::new()
    } else {
        registry.scan_file(path, &md, &content)?
    };

    Ok(FileResult { meta, matches })
}

#[cfg(test)]
mod tests {
    use super::*;
    use exfill_scan::{builtin_rules, RegexScanner};

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

        let registry = Registry::new().with(Box::new(RegexScanner::new(builtin_rules()).unwrap()));
        let store = Store::open_findings(&store_dir).await.unwrap();

        // With an event channel attached, the scan reports its progress live.
        let (ev_tx, ev_rx) = mpsc::channel();
        let summary = scan(&tree, &registry, &store, Some(&store_dir), Some(ev_tx))
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

        let registry = Registry::new().with(Box::new(RegexScanner::new(builtin_rules()).unwrap()));
        let store = Store::open_findings(&base.join("store")).await.unwrap();
        let summary = scan(&tree, &registry, &store, None, None).await.unwrap();

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

    #[cfg(unix)]
    fn nix_is_root() -> bool {
        std::fs::metadata("/proc/self")
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid() == 0
            })
            .unwrap_or(false)
    }
}
