//! Archive expansion: a [`FileTask`] that turns a container's bytes into the
//! [`VirtualFile`]s inside it, so every other scanner sees archived files
//! without knowing anything about archives.
//!
//! This is the `Bytes → Files` edge of the pipeline. The engine feeds the
//! produced files back through the whole pipeline (with a recursion-depth cap),
//! so an AWS key inside `dist.zip → app/.env` is found exactly as if `.env`
//! sat on disk, and the file record gains a `contained_in` edge to the archive.
//!
//! Supported: zip (`.zip`, `.jar`, `.war`), tar (`.tar`), gzipped tar
//! (`.tar.gz`, `.tgz`), and single-member gzip (`.gz`).
//!
//! # Safety
//!
//! Untrusted archives are hostile input, so expansion is bounded: a per-entry
//! size cap, a total-output cap, and an entry-count cap defuse decompression
//! bombs. Anything over a limit is skipped, and unreadable archives yield no
//! files rather than failing the scan.

use std::io::Read;
use std::path::Path;

use anyhow::Result;
use exfil_core::VirtualFile;
use exfil_task::{Artifact, ArtifactKind, FileTask};

/// Caps that bound the work an archive can cause.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest single decompressed entry to keep (bytes).
    pub per_entry: usize,
    /// Largest total decompressed output across all entries (bytes).
    pub total: usize,
    /// Maximum number of entries to expand.
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_entry: 32 * 1024 * 1024, // 32 MiB
            total: 256 * 1024 * 1024,    // 256 MiB
            max_entries: 10_000,
        }
    }
}

/// Expands supported archives into their contained files.
#[derive(Debug, Default)]
pub struct ArchiveExpander {
    limits: Limits,
}

impl ArchiveExpander {
    /// An expander with custom limits.
    pub fn with_limits(limits: Limits) -> Self {
        Self { limits }
    }

    /// The archive flavor a filename implies, if any.
    fn kind_of(path: &Path) -> Option<Kind> {
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if name.ends_with(".zip") || name.ends_with(".jar") || name.ends_with(".war") {
            Some(Kind::Zip)
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Some(Kind::TarGz)
        } else if name.ends_with(".tar") {
            Some(Kind::Tar)
        } else if name.ends_with(".gz") {
            Some(Kind::Gz)
        } else {
            None
        }
    }
}

/// The recognized archive flavors.
enum Kind {
    Zip,
    Tar,
    TarGz,
    Gz,
}

impl FileTask for ArchiveExpander {
    fn name(&self) -> &str {
        "archive-expand"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Bytes
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Files
    }

    fn applies(&self, path: &Path) -> bool {
        Self::kind_of(path).is_some()
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Bytes(bytes) = input else {
            anyhow::bail!("archive-expand: expected Bytes input");
        };
        let container = path.to_string_lossy();
        let files = match Self::kind_of(path) {
            Some(Kind::Zip) => expand_zip(&container, bytes, &self.limits),
            Some(Kind::Tar) => expand_tar(&container, bytes, &self.limits),
            Some(Kind::TarGz) => {
                let decoded = gunzip(bytes, self.limits.total);
                expand_tar(&container, &decoded, &self.limits)
            }
            Some(Kind::Gz) => expand_gz(path, &container, bytes, &self.limits),
            None => Vec::new(),
        };
        Ok(Artifact::Files(files))
    }
}

/// Build the `container!inner` display path used for expanded entries.
fn vpath(container: &str, inner: &str) -> String {
    format!("{container}!{inner}")
}

/// Decompress a single gzip stream, bounded by `cap` bytes.
fn gunzip(bytes: &[u8], cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let decoder = flate2::read::GzDecoder::new(bytes);
    let _ = decoder.take(cap as u64).read_to_end(&mut out);
    out
}

/// Expand a zip archive, skipping directories and oversize entries.
fn expand_zip(container: &str, bytes: &[u8], limits: &Limits) -> Vec<VirtualFile> {
    let reader = std::io::Cursor::new(bytes);
    let Ok(mut archive) = zip::ZipArchive::new(reader) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut total = 0usize;
    let count = archive.len().min(limits.max_entries);
    for i in 0..count {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.is_file() {
            continue;
        }
        // Skip entries whose declared size alone blows the per-entry cap.
        if entry.size() as usize > limits.per_entry {
            continue;
        }
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        if entry
            .take(limits.per_entry as u64)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }
        total += buf.len();
        if total > limits.total {
            break;
        }
        out.push(VirtualFile {
            path: vpath(container, &name),
            content: buf,
        });
    }
    out
}

/// Expand a (already-decompressed) tar archive.
fn expand_tar(container: &str, bytes: &[u8], limits: &Limits) -> Vec<VirtualFile> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(bytes));
    let Ok(entries) = archive.entries() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut total = 0usize;
    for entry in entries.flatten() {
        if out.len() >= limits.max_entries {
            break;
        }
        let is_file = entry.header().entry_type().is_file();
        if !is_file {
            continue;
        }
        let name = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "?".into());
        let mut buf = Vec::new();
        if entry
            .take(limits.per_entry as u64)
            .read_to_end(&mut buf)
            .is_err()
        {
            continue;
        }
        total += buf.len();
        if total > limits.total {
            break;
        }
        out.push(VirtualFile {
            path: vpath(container, &name),
            content: buf,
        });
    }
    out
}

/// Expand a single-member gzip file (`foo.txt.gz` → `foo.txt`).
fn expand_gz(path: &Path, container: &str, bytes: &[u8], limits: &Limits) -> Vec<VirtualFile> {
    let decoded = gunzip(bytes, limits.per_entry);
    if decoded.is_empty() {
        return Vec::new();
    }
    // Drop the trailing `.gz` for the inner name.
    let inner = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".gz").to_string())
        .unwrap_or_else(|| "content".into());
    vec![VirtualFile {
        path: vpath(container, &inner),
        content: decoded,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    fn run(path: &str, bytes: Vec<u8>) -> Vec<VirtualFile> {
        let exp = ArchiveExpander::default();
        assert!(exp.applies(Path::new(path)), "should apply to {path}");
        let Artifact::Files(files) = exp.run(Path::new(path), &Artifact::Bytes(bytes)).unwrap()
        else {
            panic!("expander must produce Files");
        };
        files
    }

    #[test]
    fn expands_zip_entries_with_container_paths() {
        let bytes = zip_of(&[
            ("app/.env", b"AWS=AKIA0123456789ABCDEF"),
            ("readme.md", b"hello"),
        ]);
        let files = run("dist.zip", bytes);
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.path == "dist.zip!app/.env"));
        assert!(files
            .iter()
            .find(|f| f.path.ends_with(".env"))
            .is_some_and(|f| f.content.starts_with(b"AWS=")));
    }

    #[test]
    fn jar_is_treated_as_zip() {
        let files = run("lib.jar", zip_of(&[("META-INF/x", b"data")]));
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "lib.jar!META-INF/x");
    }

    #[test]
    fn single_gzip_yields_one_file_without_gz_suffix() {
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(b"key = AKIA0123456789ABCDEF\n").unwrap();
            enc.finish().unwrap();
        }
        let files = run("secrets.txt.gz", gz);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "secrets.txt.gz!secrets.txt");
        assert!(files[0].content.starts_with(b"key = "));
    }

    #[test]
    fn per_entry_cap_skips_oversize_entries() {
        let big = vec![b'a'; 2048];
        let bytes = zip_of(&[("big.txt", &big), ("small.txt", b"ok")]);
        let exp = ArchiveExpander::with_limits(Limits {
            per_entry: 1024,
            total: 1 << 20,
            max_entries: 100,
        });
        let Artifact::Files(files) = exp
            .run(Path::new("a.zip"), &Artifact::Bytes(bytes))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(files.len(), 1, "oversize entry dropped");
        assert_eq!(files[0].path, "a.zip!small.txt");
    }

    #[test]
    fn does_not_apply_to_plain_files() {
        let exp = ArchiveExpander::default();
        assert!(!exp.applies(Path::new("main.rs")));
        assert!(!exp.applies(Path::new("archive.txt")));
    }

    #[test]
    fn corrupt_archive_yields_no_files() {
        let files = run("broken.zip", b"not a real zip".to_vec());
        assert!(files.is_empty());
    }

    /// Build a tar archive of `(name, bytes)` entries.
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn expands_tar_entries() {
        let files = run(
            "bundle.tar",
            tar_of(&[("etc/app.conf", b"secret=1"), ("readme", b"hi")]),
        );
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.path == "bundle.tar!etc/app.conf"));
    }

    #[test]
    fn expands_tar_gz_and_tgz() {
        let tar = tar_of(&[("inner.txt", b"AKIA0123456789ABCDEF")]);
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(&tar).unwrap();
            enc.finish().unwrap();
        }
        for name in ["release.tar.gz", "release.tgz"] {
            let files = run(name, gz.clone());
            assert_eq!(files.len(), 1, "{name}");
            assert_eq!(files[0].path, format!("{name}!inner.txt"));
            assert!(files[0].content.starts_with(b"AKIA"));
        }
    }

    #[test]
    fn total_cap_stops_expansion() {
        // Three 400-byte entries with a 900-byte total budget: the third
        // pushes past the cap and is dropped.
        let e = vec![b'x'; 400];
        let bytes = zip_of(&[("a", &e), ("b", &e), ("c", &e)]);
        let exp = ArchiveExpander::with_limits(Limits {
            per_entry: 1 << 20,
            total: 900,
            max_entries: 100,
        });
        let Artifact::Files(files) = exp
            .run(Path::new("z.zip"), &Artifact::Bytes(bytes))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(files.len(), 2, "third entry exceeds total cap");
    }

    #[test]
    fn max_entries_cap_limits_count() {
        let e = b"x".as_slice();
        let bytes = tar_of(&[("a", e), ("b", e), ("c", e)]);
        let exp = ArchiveExpander::with_limits(Limits {
            per_entry: 1 << 20,
            total: 1 << 20,
            max_entries: 2,
        });
        let Artifact::Files(files) = exp
            .run(Path::new("z.tar"), &Artifact::Bytes(bytes))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(files.len(), 2, "capped at max_entries");
    }

    #[test]
    fn empty_gzip_yields_nothing() {
        let mut gz = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(b"").unwrap();
            enc.finish().unwrap();
        }
        assert!(run("empty.gz", gz).is_empty());
    }

    #[test]
    fn non_archive_run_returns_no_files() {
        // A path the expander doesn't recognize produces an empty Files set.
        let exp = ArchiveExpander::default();
        let Artifact::Files(files) = exp
            .run(Path::new("plain.txt"), &Artifact::Bytes(b"data".to_vec()))
            .unwrap()
        else {
            unreachable!()
        };
        assert!(files.is_empty());
    }

    #[test]
    fn wrong_artifact_input_errors() {
        let exp = ArchiveExpander::default();
        let err = exp
            .run(Path::new("a.zip"), &Artifact::Matches(vec![]))
            .unwrap_err();
        assert!(err.to_string().contains("expected Bytes"), "{err}");
    }
}
