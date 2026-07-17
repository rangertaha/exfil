//! Cross-platform file-ownership metadata. One `ownership` function, resolved
//! per target: unix reads uid/gid; windows and other targets degrade to zeros.
//! The portable fields (size, mtime, mode-ish, hash) are captured by the caller
//! from the standard `Metadata`; this module fills in the OS-specific bits.
//!
//! # Rust notes
//!
//! `#[cfg(unix)]` is *conditional compilation*: the annotated item only exists
//! when compiling for that target. Three versions of `ownership` are written
//! below, but any given build contains exactly one — so callers never need an
//! `if windows` at runtime, and code for other platforms isn't even compiled.

use std::fs::Metadata;

/// OS-level ownership fields that vary by platform.
#[derive(Debug, Clone, Default)]
pub struct Ownership {
    /// Unix permission/mode bits.
    pub mode: u32,
    /// Owning user id.
    pub uid: u32,
    /// Owning group id.
    pub gid: u32,
    /// Resolved user name, when available.
    pub user: String,
    /// Resolved group name, when available.
    pub group: String,
}

/// Capture ownership metadata on unix systems (uid/gid/mode).
#[cfg(unix)]
pub fn ownership(md: &Metadata) -> Ownership {
    use std::os::unix::fs::MetadataExt;
    // User/group name resolution is added later (via a users crate); the
    // numeric ids are captured now.
    Ownership {
        mode: md.mode(),
        uid: md.uid(),
        gid: md.gid(),
        user: String::new(),
        group: String::new(),
    }
}

/// Capture ownership metadata on Windows (best-effort; SIDs come later).
#[cfg(windows)]
pub fn ownership(_md: &Metadata) -> Ownership {
    // Windows has no uid/gid; owner SID resolution is added later.
    Ownership::default()
}

/// Fallback for platforms with neither unix nor windows metadata.
#[cfg(not(any(unix, windows)))]
pub fn ownership(_md: &Metadata) -> Ownership {
    Ownership::default()
}
