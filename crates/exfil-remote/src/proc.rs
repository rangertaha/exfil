//! Live process inspection as a [`RemoteFs`] source.
//!
//! [`ProcessFs`] presents the running processes of the local host as
//! "files" — one per process, whose bytes are the process's metadata (name,
//! executable path, and command line). Feeding those through the normal engine
//! pipeline means *every* scanner runs over live processes for free: the regex
//! secret scanner catches passwords/tokens passed on a command line, the PII
//! scanner catches exposed data, and the indicator/IOC checkers catch bad
//! domains or IPs in arguments.
//!
//! It reuses [`exfil_engine::scan_remote`] rather than adding a new code path —
//! a process is just another place bytes come from. On Linux it reads `/proc`;
//! other platforms return an empty listing (documented, not an error).

use anyhow::Result;
use async_trait::async_trait;
use exfil_engine::RemoteFs;

/// The running processes of the local host, exposed as a [`RemoteFs`].
pub struct ProcessFs {
    host: String,
}

impl Default for ProcessFs {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessFs {
    /// Build a process source tagged with this host's name.
    pub fn new() -> Self {
        Self {
            host: gethostname::gethostname().to_string_lossy().into_owned(),
        }
    }

    /// Parse a `proc://<pid>` path back to its PID string.
    fn pid_of(path: &str) -> Option<&str> {
        path.strip_prefix("proc://")
    }
}

#[async_trait]
impl RemoteFs for ProcessFs {
    fn host(&self) -> &str {
        &self.host
    }

    async fn list(&self, _root: &str) -> Result<Vec<String>> {
        Ok(list_pids()
            .into_iter()
            .map(|pid| format!("proc://{pid}"))
            .collect())
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let pid =
            Self::pid_of(path).ok_or_else(|| anyhow::anyhow!("not a process path: {path}"))?;
        Ok(read_process(pid).into_bytes())
    }
}

/// The PIDs of running processes (Linux: numeric `/proc` entries).
#[cfg(target_os = "linux")]
fn list_pids() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.chars().all(|c| c.is_ascii_digit()).then_some(name)
        })
        .collect()
}

/// A process's inspectable text: name, exe path, and command line.
#[cfg(target_os = "linux")]
fn read_process(pid: &str) -> String {
    let base = format!("/proc/{pid}");
    // comm: the process name. cmdline: NUL-separated argv. exe: symlink target.
    let name = std::fs::read_to_string(format!("{base}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let cmdline = std::fs::read(format!("{base}/cmdline"))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    let exe = std::fs::read_link(format!("{base}/exe"))
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    format!("pid={pid}\nname={name}\nexe={exe}\ncmdline={cmdline}\n")
}

/// Non-Linux fallback: no procfs, so nothing is enumerated.
#[cfg(not(target_os = "linux"))]
fn list_pids() -> Vec<String> {
    Vec::new()
}

#[cfg(not(target_os = "linux"))]
fn read_process(pid: &str) -> String {
    format!("pid={pid}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_parsing() {
        assert_eq!(ProcessFs::pid_of("proc://1234"), Some("1234"));
        assert_eq!(ProcessFs::pid_of("/etc/passwd"), None);
    }

    #[tokio::test]
    async fn host_is_set_and_paths_are_proc_urls() {
        let fs = ProcessFs::new();
        assert!(!fs.host().is_empty());
        let paths = fs.list("/").await.unwrap();
        // On Linux there is always at least this test process; elsewhere empty.
        for p in &paths {
            assert!(p.starts_with("proc://"), "{p}");
        }
        #[cfg(target_os = "linux")]
        {
            assert!(!paths.is_empty(), "linux lists at least one process");
            // Our own process is readable and reports a cmdline.
            let me = format!("proc://{}", std::process::id());
            let bytes = fs.read(&me).await.unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(text.contains("pid="), "{text}");
            assert!(text.contains("cmdline="), "{text}");
        }
    }

    #[tokio::test]
    async fn read_rejects_non_process_path() {
        let fs = ProcessFs::new();
        assert!(fs.read("/etc/passwd").await.is_err());
    }
}
