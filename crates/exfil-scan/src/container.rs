//! What every container expander shares: the bounds on what one container may
//! yield, and the accounting that enforces them.
//!
//! An expander's own job is format-specific — walking a zip's central
//! directory, an ISO's directory records, a database's tables. What follows
//! that walk is not: each one emits `container!inner` virtual files, and each
//! one has to stop before a hostile container turns into unbounded work. That
//! second half lived three times over, and the three copies did not agree.
//!
//! # Why one implementation matters here
//!
//! The zip expander used to cap by *central-directory index* — it looked at the
//! first `max_entries` records, whatever they were. The tar expander capped by
//! *files emitted*. Same limit, same name, two meanings, and the zip reading was
//! a detection hole: 10,000 empty directory entries cost nothing to author, and
//! everything after them was never expanded. A payload placed at entry 10,001
//! of a 600 KB archive was simply invisible to the scanner.
//!
//! So [`Emitter`] defines the meaning once, and every expander drives it:
//!
//! - [`Limits::max_files`] counts **files emitted**, never entries inspected.
//!   Directories, skipped entries, and unreadable ones cost nothing, so no
//!   amount of padding can push real content out of the budget.
//! - [`Limits::max_file_bytes`] bounds a single emitted file. A container's
//!   own policy decides whether an oversize entry is skipped ([`Emitter::push`])
//!   or clamped ([`Emitter::push_clamped`]) — a truncated table is still
//!   readable text, a truncated compressed member usually is not — but both
//!   spend the budget through the same accounting.
//! - [`Limits::max_total_bytes`] bounds the whole container's output, and is
//!   the one cap that ends the walk rather than skipping an entry.

use exfil_core::VirtualFile;

/// Whether an expander should keep walking its container.
///
/// Returned by every [`Emitter`] push so the caller's loop reads as
/// `if emitter.push(..).is_stop() { break }` regardless of format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Budget remains; keep going.
    Continue,
    /// A total-output cap is spent; stop walking this container.
    Stop,
}

impl Flow {
    /// Whether the caller's walk should end here.
    pub fn is_stop(self) -> bool {
        self == Flow::Stop
    }
}

/// Bounds on the work one container may cause.
///
/// Every expander embeds this for the caps they have in common and keeps only
/// its genuinely format-specific knobs (an ISO's directory depth, a database's
/// rows per table) beside it.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Largest container this task will look at at all.
    ///
    /// Unlike the others this bounds the *input*. Some formats cannot be read
    /// without first staging the whole thing (SQLite cannot open a memory
    /// buffer), so refusing early is the only bound that helps.
    pub max_input_bytes: usize,
    /// Most files emitted from one container.
    pub max_files: usize,
    /// Largest single emitted file.
    pub max_file_bytes: usize,
    /// Total bytes emitted across all files.
    pub max_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 2 << 30,   // 2 GiB
            max_files: 10_000,          //
            max_file_bytes: 32 << 20,   // 32 MiB
            max_total_bytes: 256 << 20, // 256 MiB
        }
    }
}

/// Accumulates the virtual files one container yields, enforcing [`Limits`].
///
/// Owns the `container!inner` path convention too, so the display path an
/// expanded file carries is built in one place rather than per format.
#[derive(Debug)]
pub struct Emitter {
    container: String,
    limits: Limits,
    files: Vec<VirtualFile>,
    bytes: usize,
}

impl Emitter {
    /// An emitter for files found inside `container`, bounded by `limits`.
    pub fn new(container: &str, limits: Limits) -> Self {
        Self {
            container: container.to_string(),
            limits,
            files: Vec::new(),
            bytes: 0,
        }
    }

    /// The bounds in force, for the format-specific checks an expander makes
    /// before it has the bytes to offer (reading only `max_file_bytes` from a
    /// stream, say, rather than reading everything and discarding it).
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Whether no further file can be accepted, so a caller mid-walk can stop
    /// without building content it is about to throw away.
    pub fn is_full(&self) -> bool {
        self.files.len() >= self.limits.max_files || self.bytes >= self.limits.max_total_bytes
    }

    /// Offer one entry, skipping it whole if it exceeds [`Limits::max_file_bytes`].
    ///
    /// For formats where a partial entry is not meaningful — half a deflate
    /// stream is not half a file.
    pub fn push(&mut self, inner: &str, content: Vec<u8>) -> Flow {
        if content.len() > self.limits.max_file_bytes {
            // Skipped, not stopped: one fat entry must not hide its siblings.
            return self.flow();
        }
        self.accept(inner, content)
    }

    /// Offer one entry, clamping it to [`Limits::max_file_bytes`] rather than
    /// dropping it.
    ///
    /// For formats where a prefix is still worth scanning — a flattened table
    /// or an ISO member is readable text either way, and the secret is as likely
    /// to be in the first megabyte as anywhere.
    pub fn push_clamped(&mut self, inner: &str, mut content: Vec<u8>) -> Flow {
        content.truncate(self.limits.max_file_bytes);
        self.accept(inner, content)
    }

    /// Record one accepted entry against the file and byte budgets.
    fn accept(&mut self, inner: &str, content: Vec<u8>) -> Flow {
        if self.files.len() >= self.limits.max_files {
            return Flow::Stop;
        }
        // Checked before pushing, so the total is a ceiling on what is kept
        // rather than something the last entry is allowed to overshoot.
        if self.bytes + content.len() > self.limits.max_total_bytes {
            return Flow::Stop;
        }
        self.bytes += content.len();
        self.files.push(VirtualFile {
            path: format!("{}!{inner}", self.container),
            content,
        });
        self.flow()
    }

    /// Whether anything more can be accepted after the current state.
    fn flow(&self) -> Flow {
        if self.is_full() {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    /// The files collected, in the order the container yielded them.
    pub fn finish(self) -> Vec<VirtualFile> {
        self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_input_bytes: 1 << 20,
            max_files: 3,
            max_file_bytes: 10,
            max_total_bytes: 20,
        }
    }

    #[test]
    fn emitted_files_carry_the_container_path() {
        let mut e = Emitter::new("dist.zip", limits());
        assert_eq!(e.push("app/.env", b"k=1".to_vec()), Flow::Continue);
        let files = e.finish();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "dist.zip!app/.env");
        assert_eq!(files[0].content, b"k=1");
    }

    /// The evasion this type exists to prevent: entries that emit nothing must
    /// not consume the file budget, or padding hides the payload behind it.
    #[test]
    fn skipped_entries_do_not_spend_the_file_budget() {
        let mut e = Emitter::new("c", limits());
        // Ten oversize entries, all skipped, none of them costing a file slot.
        for i in 0..10 {
            assert_eq!(e.push(&format!("big{i}"), vec![b'x'; 50]), Flow::Continue);
        }
        assert!(!e.is_full(), "nothing was emitted, so nothing was spent");
        assert_eq!(e.push("payload", b"secret".to_vec()), Flow::Continue);
        let files = e.finish();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "c!payload");
    }

    #[test]
    fn the_file_cap_counts_emitted_files() {
        let mut e = Emitter::new("c", limits());
        for i in 0..3 {
            e.push(&format!("f{i}"), b"x".to_vec());
        }
        assert!(e.is_full());
        assert_eq!(e.push("f3", b"x".to_vec()), Flow::Stop);
        assert_eq!(e.finish().len(), 3, "capped at max_files");
    }

    #[test]
    fn the_total_cap_stops_the_walk_without_overshooting() {
        let mut e = Emitter::new("c", limits());
        assert_eq!(e.push("a", vec![b'x'; 9]), Flow::Continue);
        assert_eq!(e.push("b", vec![b'x'; 9]), Flow::Continue);
        // 9 + 9 + 9 would exceed the 20-byte total, so the third is refused
        // rather than admitted and counted afterwards.
        assert_eq!(e.push("c", vec![b'x'; 9]), Flow::Stop);
        let files = e.finish();
        assert_eq!(files.len(), 2);
        assert_eq!(files.iter().map(|f| f.content.len()).sum::<usize>(), 18);
    }

    #[test]
    fn push_clamped_keeps_a_prefix_instead_of_dropping_the_entry() {
        let mut e = Emitter::new("disc.iso", limits());
        e.push_clamped("big.txt", vec![b'x'; 50]);
        let files = e.finish();
        assert_eq!(files.len(), 1, "clamped, not skipped");
        assert_eq!(files[0].content.len(), 10, "cut to max_file_bytes");
    }

    #[test]
    fn flow_reports_whether_to_stop() {
        assert!(Flow::Stop.is_stop());
        assert!(!Flow::Continue.is_stop());
    }
}
