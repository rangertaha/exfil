//! ISO 9660 disc-image expansion: a [`FileTask`] that turns a `.iso`'s
//! directory tree into [`VirtualFile`]s, so every other scanner sees what is
//! *on* the disc without knowing anything about disc images — the same
//! `Bytes → Files` seam [`ArchiveExpander`](crate::ArchiveExpander) uses for
//! zip/tar and [`SqliteExpander`](crate::SqliteExpander) uses for databases.
//!
//! Disc images are exactly the kind of thing a secret hides in and a scanner
//! walks straight past: installer media, appliance images, forensic captures,
//! "here is the whole environment" hand-offs. Expanding one means an
//! `AKIA…` in `/boot/grub/grub.cfg` inside `appliance.iso` is found by the
//! ordinary regex scanner, and `contained_in` records which image it came from.
//!
//! The reader is written here rather than pulled in: ISO 9660 is a small,
//! stable, 1988 format, and the alternative crates are either C bindings
//! (against this project's pure-Rust rule) or carry licences that would have to
//! be reconciled with GPL-3.0. Roughly:
//!
//! ```text
//!   byte 0x8000 ── volume descriptors, one per 2048-byte sector
//!     │  type 1 = primary, "CD001" magic
//!     │  offset 156: the root directory record (34 bytes)
//!     ▼
//!   root directory extent ── a run of directory records
//!     │  each: length, extent LBA, data length, flags, identifier
//!     │  flags bit 1 set ⇒ it is a directory, so recurse
//!     ▼
//!   files ── emitted as `image.iso!path/within/disc`
//! ```
//!
//! # Safety
//!
//! An arbitrary `.iso` is untrusted input. It is sniffed by magic rather than
//! trusted by extension, every offset is bounds-checked against the image
//! before use, directory recursion is depth- and visit-capped, and a directory
//! extent that points back at itself (or at an ancestor) cannot loop forever.
//! [`Limits`] bounds the output the same way the archive and database
//! expanders do. A malformed image yields the files that could be read, not an
//! error that fails the scan.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use exfil_core::VirtualFile;
use exfil_task::{Artifact, ArtifactKind, FileTask};

/// ISO 9660 logical sector size. Fixed by the standard.
const SECTOR: usize = 2048;

/// Volume descriptors begin here — sector 16.
const VOLUME_DESCRIPTOR_START: usize = 16 * SECTOR;

/// The magic every volume descriptor carries at offset 1.
const MAGIC: &[u8; 5] = b"CD001";

/// Offset of the root directory record within a primary volume descriptor.
const ROOT_RECORD_OFFSET: usize = 156;

/// Directory-record flag bit marking an entry as a directory.
const FLAG_DIRECTORY: u8 = 0x02;

/// Offset of the escape sequences in a supplementary volume descriptor, which
/// is how a Joliet directory tree announces itself.
const ESCAPE_SEQUENCE_OFFSET: usize = 88;

/// The three UCS-2 escape sequences Joliet may use (levels 1, 2 and 3).
const JOLIET_ESCAPES: [&[u8]; 3] = [b"%/@", b"%/C", b"%/E"];

/// Caps that bound the work one image can cause.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest image this task will look at.
    pub max_input_bytes: usize,
    /// Most files emitted from one image.
    pub max_files: usize,
    /// Largest single file emitted; longer ones are truncated.
    pub max_file_bytes: usize,
    /// Total bytes emitted across all files.
    pub max_total_bytes: usize,
    /// Deepest directory nesting followed.
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 2 << 30, // 2 GiB
            max_files: 10_000,
            max_file_bytes: 8 << 20, // 8 MiB
            max_total_bytes: 256 << 20,
            max_depth: 16,
        }
    }
}

impl Limits {
    /// The bounds an image shares with every other container, for the
    /// [`Emitter`](crate::container::Emitter) that enforces them. Only
    /// [`max_depth`](Self::max_depth) is specific to a directory tree.
    fn shared(&self) -> crate::container::Limits {
        crate::container::Limits {
            max_input_bytes: self.max_input_bytes,
            max_files: self.max_files,
            max_file_bytes: self.max_file_bytes,
            max_total_bytes: self.max_total_bytes,
        }
    }
}

/// Expands ISO 9660 disc images into the files they contain.
#[derive(Debug, Clone, Default)]
pub struct IsoExpander {
    /// Bounds on the work one image may cause.
    pub limits: Limits,
}

impl IsoExpander {
    /// Whether the path looks like a disc image by name. Extension gating only
    /// decides whether to *look*; [`is_iso`] decides whether to believe it.
    fn has_iso_extension(path: &Path) -> bool {
        matches!(
            path.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .as_deref(),
            Some("iso" | "img" | "udf")
        )
    }
}

/// Whether `bytes` really is an ISO 9660 image, by the `CD001` magic on a
/// volume descriptor rather than by its name.
///
/// Disc images are routinely misnamed, and `.img` especially is used for half a
/// dozen unrelated formats, so the extension is never trusted on its own.
pub fn is_iso(bytes: &[u8]) -> bool {
    volume_descriptors(bytes).any(|(kind, _)| kind == 1)
}

/// Iterate the volume descriptors as `(type, sector)` pairs, stopping at the
/// terminator (type 255) or the first sector that isn't one.
fn volume_descriptors(bytes: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    (0..).map_while(move |i| {
        let start = VOLUME_DESCRIPTOR_START + i * SECTOR;
        let sector = bytes.get(start..start + SECTOR)?;
        if &sector[1..6] != MAGIC || sector[0] == 255 {
            return None;
        }
        Some((sector[0], sector))
    })
}

/// One parsed directory record.
struct Record {
    /// Bytes this record occupies, for advancing to the next one.
    len: usize,
    /// Starting sector of the entry's data.
    extent: u32,
    /// Size of the entry's data in bytes.
    size: u32,
    /// Whether the entry is a directory.
    is_dir: bool,
    /// The entry's name, cleaned of the `;1` version suffix.
    name: String,
}

/// Read a little-endian u32 at `off`, or `None` past the end.
fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Parse one directory record from the front of `b`.
///
/// Returns `None` for a zero-length record, which marks the end of the records
/// in a sector.
fn parse_record(b: &[u8], ucs2: bool) -> Option<Record> {
    let len = *b.first()? as usize;
    if len < 33 || len > b.len() {
        return None;
    }
    // Both-endian fields: the little-endian half comes first.
    let extent = le_u32(b, 2)?;
    let size = le_u32(b, 10)?;
    let flags = *b.get(25)?;
    let name_len = *b.get(32)? as usize;
    let raw = b.get(33..33 + name_len)?;

    // Identifiers 0x00 and 0x01 are "." and ".." — never emitted, never
    // followed, which is also what stops the walk climbing out of the tree.
    if raw == [0x00] || raw == [0x01] {
        return Some(Record {
            len,
            extent,
            size,
            is_dir: true,
            name: String::new(),
        });
    }
    let decoded = if ucs2 {
        decode_ucs2(raw)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    // Strip the `;1` version suffix ISO 9660 appends to file identifiers, and
    // the bare trailing dot it gives extensionless names.
    let name = decoded
        .split(';')
        .next()
        .unwrap_or(&decoded)
        .trim_end_matches('.')
        .to_string();

    Some(Record {
        len,
        extent,
        size,
        is_dir: flags & FLAG_DIRECTORY != 0,
        name,
    })
}

/// Decode a Joliet identifier: UCS-2, big-endian, as the standard specifies.
///
/// Unpaired surrogates are replaced rather than rejected — a malformed name on
/// an untrusted disc should not cost us the file's contents.
fn decode_ucs2(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// The bytes of an extent, bounds-checked against the image.
fn extent_bytes(image: &[u8], extent: u32, size: u32) -> Option<&[u8]> {
    let start = (extent as usize).checked_mul(SECTOR)?;
    let end = start.checked_add(size as usize)?;
    image.get(start..end)
}

/// Accumulator threaded through the recursive walk.
struct Walk<'a> {
    image: &'a [u8],
    /// Output accounting, shared with every other container expander.
    out: crate::container::Emitter,
    /// Deepest directory nesting to follow — the one bound specific to a tree.
    max_depth: usize,
    /// Whether identifiers in this tree are Joliet UCS-2 rather than ASCII.
    ucs2: bool,
    /// Extents already descended into, so a self-referential or cyclic image
    /// cannot loop forever.
    seen: HashSet<u32>,
}

impl Walk<'_> {
    fn descend(&mut self, extent: u32, size: u32, prefix: &str, depth: usize) {
        if depth > self.max_depth || self.out.is_full() || !self.seen.insert(extent) {
            return;
        }
        let Some(dir) = extent_bytes(self.image, extent, size) else {
            return;
        };

        // Records never straddle a sector boundary: a sector is padded out with
        // zeros once the next record won't fit, so each sector is walked from
        // its own start.
        for sector in dir.chunks(SECTOR) {
            let mut off = 0usize;
            while off < sector.len() {
                let Some(rec) = parse_record(&sector[off..], self.ucs2) else {
                    break; // zero length: rest of this sector is padding
                };
                off += rec.len;
                if rec.name.is_empty() {
                    continue; // "." or ".."
                }
                if self.out.is_full() {
                    return;
                }
                let child = if prefix.is_empty() {
                    rec.name.clone()
                } else {
                    format!("{prefix}/{}", rec.name)
                };
                if rec.is_dir {
                    self.descend(rec.extent, rec.size, &child, depth + 1);
                } else if let Some(data) = extent_bytes(self.image, rec.extent, rec.size) {
                    // Clamped, not skipped: an ISO member is stored uncompressed,
                    // so a prefix of an oversize one is still readable content.
                    if self.out.push_clamped(&child, data.to_vec()).is_stop() {
                        return;
                    }
                }
            }
        }
    }
}

/// Whether a supplementary volume descriptor is a Joliet tree.
fn is_joliet(svd: &[u8]) -> bool {
    svd.get(ESCAPE_SEQUENCE_OFFSET..ESCAPE_SEQUENCE_OFFSET + 3)
        .is_some_and(|esc| JOLIET_ESCAPES.contains(&esc))
}

/// Expand every file in an ISO 9660 image, as `container!path/within/disc`.
///
/// Prefers the **Joliet** tree when the image has one. Plain ISO 9660 folds
/// names to uppercase 8.3, which is not merely ugly — it changes what the other
/// scanners see. `package.json` becomes `PACKAGE.JSO`, and the supply-chain
/// scanner, which matches on the manifest's name, walks straight past it.
/// Joliet carries the real names, so reading it is what makes the rest of the
/// pipeline behave the same on a disc as on a directory.
pub fn expand(image: &[u8], container: &str, limits: Limits) -> Vec<VirtualFile> {
    if image.len() > limits.max_input_bytes {
        return Vec::new();
    }
    // Joliet (a supplementary descriptor) if present, else the primary.
    let joliet = volume_descriptors(image).find(|(kind, d)| *kind == 2 && is_joliet(d));
    let (ucs2, descriptor) = match joliet {
        Some((_, d)) => (true, d),
        None => match volume_descriptors(image).find(|(k, _)| *k == 1) {
            Some((_, d)) => (false, d),
            None => return Vec::new(),
        },
    };
    let Some(root) = descriptor
        .get(ROOT_RECORD_OFFSET..ROOT_RECORD_OFFSET + 34)
        .and_then(|r| parse_record(r, false))
    else {
        return Vec::new();
    };

    let mut walk = Walk {
        image,
        out: crate::container::Emitter::new(container, limits.shared()),
        max_depth: limits.max_depth,
        ucs2,
        seen: HashSet::new(),
    };
    walk.descend(root.extent, root.size, "", 0);
    walk.out.finish()
}

impl FileTask for IsoExpander {
    fn name(&self) -> &str {
        "iso-expand"
    }

    fn needs(&self) -> ArtifactKind {
        ArtifactKind::Bytes
    }

    fn provides(&self) -> ArtifactKind {
        ArtifactKind::Files
    }

    fn applies(&self, path: &Path) -> bool {
        Self::has_iso_extension(path)
    }

    /// A disc image is binary by nature — reading it is exactly this task's
    /// job, so it must not be held back from binary content.
    fn binary_safe(&self) -> bool {
        true
    }

    fn run(&self, path: &Path, input: &Artifact) -> Result<Artifact> {
        let Artifact::Bytes(bytes) = input else {
            anyhow::bail!("iso-expand: expected Bytes input");
        };
        // `.img` in particular names half a dozen unrelated formats, so a
        // name match is only permission to look at the magic.
        if !is_iso(bytes) {
            return Ok(Artifact::Files(Vec::new()));
        }
        Ok(Artifact::Files(expand(
            bytes,
            &path.display().to_string(),
            self.limits,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but valid ISO 9660 image: a primary volume descriptor,
    /// a root directory holding one file and one subdirectory, and that
    /// subdirectory holding a second file.
    ///
    /// Hand-built rather than shelled out to `genisoimage`, so the test runs
    /// anywhere and pins the parser against a known byte layout.
    fn build_iso() -> Vec<u8> {
        const ROOT_LBA: u32 = 20;
        const SUB_LBA: u32 = 21;
        const FILE_A_LBA: u32 = 22;
        const FILE_B_LBA: u32 = 23;
        let file_a = b"AWS_ACCESS_KEY_ID=AKIA0123456789ABCDEF\n";
        let file_b = b"nothing interesting here\n";

        let mut img = vec![0u8; 24 * SECTOR];

        // ── primary volume descriptor at sector 16 ──
        let pvd = VOLUME_DESCRIPTOR_START;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(MAGIC);
        img[pvd + 6] = 1;
        let root = record(ROOT_LBA, SECTOR as u32, true, &[0x00]);
        img[pvd + ROOT_RECORD_OFFSET..pvd + ROOT_RECORD_OFFSET + root.len()].copy_from_slice(&root);

        // ── terminator so the descriptor scan stops ──
        let term = VOLUME_DESCRIPTOR_START + SECTOR;
        img[term] = 255;
        img[term + 1..term + 6].copy_from_slice(MAGIC);

        // ── root directory ──
        let mut dir = Vec::new();
        dir.extend(record(ROOT_LBA, SECTOR as u32, true, &[0x00]));
        dir.extend(record(ROOT_LBA, SECTOR as u32, true, &[0x01]));
        dir.extend(record(FILE_A_LBA, file_a.len() as u32, false, b"KEY.ENV;1"));
        dir.extend(record(SUB_LBA, SECTOR as u32, true, b"SUB"));
        img[ROOT_LBA as usize * SECTOR..ROOT_LBA as usize * SECTOR + dir.len()]
            .copy_from_slice(&dir);

        // ── subdirectory ──
        let mut sub = Vec::new();
        sub.extend(record(SUB_LBA, SECTOR as u32, true, &[0x00]));
        sub.extend(record(ROOT_LBA, SECTOR as u32, true, &[0x01]));
        sub.extend(record(
            FILE_B_LBA,
            file_b.len() as u32,
            false,
            b"NOTES.TXT;1",
        ));
        img[SUB_LBA as usize * SECTOR..SUB_LBA as usize * SECTOR + sub.len()].copy_from_slice(&sub);

        // ── file contents ──
        img[FILE_A_LBA as usize * SECTOR..FILE_A_LBA as usize * SECTOR + file_a.len()]
            .copy_from_slice(file_a);
        img[FILE_B_LBA as usize * SECTOR..FILE_B_LBA as usize * SECTOR + file_b.len()]
            .copy_from_slice(file_b);
        img
    }

    /// One directory record with the both-endian fields the format requires.
    fn record(extent: u32, size: u32, is_dir: bool, name: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 33 + name.len()];
        r[0] = r.len() as u8;
        r[2..6].copy_from_slice(&extent.to_le_bytes());
        r[6..10].copy_from_slice(&extent.to_be_bytes());
        r[10..14].copy_from_slice(&size.to_le_bytes());
        r[14..18].copy_from_slice(&size.to_be_bytes());
        r[25] = if is_dir { FLAG_DIRECTORY } else { 0 };
        r[32] = name.len() as u8;
        r[33..].copy_from_slice(name);
        // Records are padded to an even length.
        if r.len() % 2 == 1 {
            r.push(0);
            let n = r.len() as u8;
            r[0] = n;
        }
        r
    }

    #[test]
    fn expands_files_and_recurses_into_directories() {
        let files = expand(&build_iso(), "disc.iso", Limits::default());
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"disc.iso!KEY.ENV"), "{paths:?}");
        assert!(paths.contains(&"disc.iso!SUB/NOTES.TXT"), "{paths:?}");
        assert_eq!(files.len(), 2, "only real files, no . or .. entries");

        let key = files.iter().find(|f| f.path.ends_with("KEY.ENV")).unwrap();
        assert!(String::from_utf8_lossy(&key.content).contains("AKIA0123456789ABCDEF"));
    }

    #[test]
    fn a_non_iso_is_rejected_by_magic_not_trusted_by_name() {
        // `.img` names half a dozen formats; content decides.
        assert!(!is_iso(b"not a disc image at all"));
        assert!(!is_iso(&vec![0u8; 64 * SECTOR]));
        assert!(is_iso(&build_iso()));
        assert!(expand(b"junk", "x.iso", Limits::default()).is_empty());
    }

    #[test]
    fn truncated_and_malformed_images_yield_what_they_can() {
        let full = build_iso();
        // Cut the image short: parsing must not panic or read out of bounds.
        for cut in [SECTOR, 17 * SECTOR, 21 * SECTOR, full.len() - 1] {
            let files = expand(&full[..cut], "disc.iso", Limits::default());
            assert!(files.len() <= 2, "cut at {cut} produced {}", files.len());
        }
        // A record claiming an extent past the end is skipped, not fatal.
        let mut bad = full.clone();
        let off = ROOT_LBA_OFFSET + 2;
        bad[off..off + 4].copy_from_slice(&9_999_999u32.to_le_bytes());
        let _ = expand(&bad, "disc.iso", Limits::default());
    }

    /// Sector 20 (the root directory), third record, is the KEY.ENV entry.
    const ROOT_LBA_OFFSET: usize = 20 * SECTOR;

    #[test]
    fn a_cyclic_image_cannot_loop_forever() {
        let mut img = build_iso();
        // Point the SUB directory's extent back at the root: a naive walker
        // would recurse until the stack ran out.
        let sub_rec = ROOT_LBA_OFFSET + 34 + 34 + (33 + 9 + 1); // ., .., KEY.ENV
        img[sub_rec + 2..sub_rec + 6].copy_from_slice(&20u32.to_le_bytes());
        let files = expand(&img, "disc.iso", Limits::default());
        assert!(files.len() < 100, "cycle produced {} files", files.len());
    }

    #[test]
    fn limits_bound_the_output() {
        let iso = build_iso();
        let capped = Limits {
            max_files: 1,
            ..Limits::default()
        };
        assert_eq!(expand(&iso, "disc.iso", capped).len(), 1);

        let tiny = Limits {
            max_file_bytes: 4,
            ..Limits::default()
        };
        assert!(expand(&iso, "disc.iso", tiny)
            .iter()
            .all(|f| f.content.len() <= 4));

        // An image larger than the input cap is not read at all.
        let strict = Limits {
            max_input_bytes: 10,
            ..Limits::default()
        };
        assert!(expand(&iso, "disc.iso", strict).is_empty());

        let shallow = Limits {
            max_depth: 0,
            ..Limits::default()
        };
        // Depth 0 still reads the root, but does not descend into SUB.
        let files = expand(&iso, "disc.iso", shallow);
        assert!(files.iter().all(|f| !f.path.contains("SUB/")), "{files:?}");
    }

    #[test]
    fn the_task_gates_on_extension_and_is_binary_safe() {
        let t = IsoExpander::default();
        assert!(t.applies(Path::new("a.iso")));
        assert!(t.applies(Path::new("A.ISO")));
        assert!(t.applies(Path::new("b.img")));
        assert!(!t.applies(Path::new("c.txt")));
        assert!(t.binary_safe(), "a disc image is binary by nature");
        assert_eq!(t.needs(), ArtifactKind::Bytes);
        assert_eq!(t.provides(), ArtifactKind::Files);

        // A non-ISO with an ISO name yields no files rather than an error.
        let out = t
            .run(Path::new("x.iso"), &Artifact::Bytes(b"nope".to_vec()))
            .unwrap();
        assert!(matches!(out, Artifact::Files(f) if f.is_empty()));
    }
}

#[cfg(test)]
mod real_image_tests {
    use super::*;

    /// A hand-built fixture only proves the parser agrees with itself. This
    /// runs against an image produced by `genisoimage`, when it is available,
    /// so the parser is pinned against a real-world writer rather than my own
    /// understanding of the spec.
    #[test]
    fn parses_an_image_written_by_genisoimage() {
        let Ok(out) = std::process::Command::new("genisoimage")
            .args(["-quiet", "-o", "-", "-r"])
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/src"))
            .output()
        else {
            eprintln!("genisoimage unavailable; skipping real-image check");
            return;
        };
        if !out.status.success() || out.stdout.len() < 32 * SECTOR {
            eprintln!("genisoimage produced nothing usable; skipping");
            return;
        }
        assert!(is_iso(&out.stdout), "genisoimage output not recognised");

        let files = expand(&out.stdout, "src.iso", Limits::default());
        assert!(!files.is_empty(), "no files extracted from a real image");

        // The crate's own sources are on that disc; find one and check the
        // bytes survived the round trip intact.
        let iso_rs = files
            .iter()
            .find(|f| f.path.to_ascii_lowercase().contains("iso.rs"))
            .expect("iso.rs should be on the image");
        let text = String::from_utf8_lossy(&iso_rs.content);
        assert!(
            text.contains("ISO 9660"),
            "extracted content does not look like iso.rs"
        );
    }
}
