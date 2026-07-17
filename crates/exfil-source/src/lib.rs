//! Dataset sources: where rule/IOC datasets come from. A [`Source`] fetches a
//! [`Dataset`] for a reference (`builtin://security`, a file path, or an
//! `https://…` URL); [`fetch`] dispatches to the source that handles the
//! reference's scheme.
//!
//! Datasets are JSON in the native [`Dataset`] shape (`{ "name", "rules": [...]
//! }`) — the same format `datasets/*.json` and gitleaks exports already use.
//!
//! # Rust notes
//!
//! `Source::fetch` is `async` behind `#[async_trait]` (network I/O), so the
//! trait is object-safe as `Box<dyn Source>`. The registry tries each source's
//! [`handles`](Source::handles) in turn — the first match wins.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use exfil_core::Dataset;

/// A place datasets are fetched from.
#[async_trait]
pub trait Source: Send + Sync {
    /// Stable identifier, shown by `exfil sources`.
    fn name(&self) -> &str;

    /// Whether this source handles a reference's `scheme` (the part before
    /// `://`, or `"file"` for a bare path).
    fn handles(&self, scheme: &str) -> bool;

    /// Fetch and parse the dataset named by `reference`.
    async fn fetch(&self, reference: &str) -> Result<Dataset>;
}

/// The scheme of a reference: the part before `://`, or `file` for a path.
fn scheme_of(reference: &str) -> &str {
    match reference.split_once("://") {
        Some((s, _)) => s,
        None => "file",
    }
}

/// Parse the native dataset JSON, tagging the error with the reference.
fn parse_dataset(bytes: &[u8], reference: &str) -> Result<Dataset> {
    serde_json::from_slice(bytes).with_context(|| format!("parse dataset {reference}"))
}

/// Built-in datasets embedded in the binary. `builtin://security` is the
/// curated secrets ruleset the scanner falls back to.
pub struct BuiltinSource;

#[async_trait]
impl Source for BuiltinSource {
    fn name(&self) -> &str {
        "builtin"
    }

    fn handles(&self, scheme: &str) -> bool {
        scheme == "builtin"
    }

    async fn fetch(&self, reference: &str) -> Result<Dataset> {
        let name = reference.strip_prefix("builtin://").unwrap_or(reference);
        match name {
            "security" => Ok(Dataset {
                name: "security".into(),
                rules: exfil_scan::builtin_rules(),
            }),
            other => bail!("unknown builtin dataset {other:?} (known: security)"),
        }
    }
}

/// Reads a dataset from a local JSON file.
pub struct FileSource;

#[async_trait]
impl Source for FileSource {
    fn name(&self) -> &str {
        "file"
    }

    fn handles(&self, scheme: &str) -> bool {
        scheme == "file"
    }

    async fn fetch(&self, reference: &str) -> Result<Dataset> {
        let path = reference.strip_prefix("file://").unwrap_or(reference);
        // Datasets are small; a synchronous read inside this async fn is fine.
        let bytes = std::fs::read(path).with_context(|| format!("read dataset file {path}"))?;
        parse_dataset(&bytes, reference)
    }
}

/// Downloads a dataset over HTTP(S).
pub struct HttpSource {
    client: reqwest::Client,
}

impl Default for HttpSource {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Source for HttpSource {
    fn name(&self) -> &str {
        "http"
    }

    fn handles(&self, scheme: &str) -> bool {
        scheme == "http" || scheme == "https"
    }

    async fn fetch(&self, reference: &str) -> Result<Dataset> {
        let resp = self
            .client
            .get(reference)
            .send()
            .await
            .with_context(|| format!("GET {reference}"))?
            .error_for_status()
            .with_context(|| format!("fetch {reference}"))?;
        let bytes = resp.bytes().await.context("read response body")?;
        parse_dataset(&bytes, reference)
    }
}

/// An ordered set of sources, tried by scheme.
pub struct Registry {
    sources: Vec<Box<dyn Source>>,
}

impl Registry {
    /// The default lineup: builtin, file, and http(s).
    pub fn new() -> Self {
        Self {
            sources: vec![
                Box::new(BuiltinSource),
                Box::new(FileSource),
                Box::new(HttpSource::default()),
            ],
        }
    }

    /// The registered source names.
    pub fn names(&self) -> Vec<&str> {
        self.sources.iter().map(|s| s.name()).collect()
    }

    /// Fetch a dataset for `reference` via the first source handling its scheme.
    pub async fn fetch(&self, reference: &str) -> Result<Dataset> {
        let scheme = scheme_of(reference);
        for source in &self.sources {
            if source.handles(scheme) {
                return source.fetch(reference).await;
            }
        }
        bail!("no source handles scheme {scheme:?} for reference {reference:?}")
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// Fetch a dataset for `reference` using the default source registry.
pub async fn fetch(reference: &str) -> Result<Dataset> {
    Registry::new().fetch(reference).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_detection() {
        assert_eq!(scheme_of("builtin://security"), "builtin");
        assert_eq!(scheme_of("https://x/y.json"), "https");
        assert_eq!(scheme_of("http://x"), "http");
        assert_eq!(scheme_of("/tmp/a.json"), "file");
        assert_eq!(scheme_of("rel/path.json"), "file");
    }

    #[tokio::test]
    async fn builtin_security_dataset() {
        let ds = fetch("builtin://security").await.unwrap();
        assert_eq!(ds.name, "security");
        assert!(ds.rules.iter().any(|r| r.name == "aws-access-key-id"));
        let err = fetch("builtin://nope").await.unwrap_err();
        assert!(err.to_string().contains("unknown builtin"), "{err}");
    }

    #[tokio::test]
    async fn file_source_reads_native_json() {
        let dir = std::env::temp_dir().join(format!("exfil-src-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.json");
        std::fs::write(
            &path,
            r#"{"name":"custom","rules":[{"name":"r","pattern":"AKIA","severity":"high"}]}"#,
        )
        .unwrap();
        let ds = fetch(path.to_str().unwrap()).await.unwrap();
        assert_eq!(ds.name, "custom");
        assert_eq!(ds.rules.len(), 1);
        // A file:// prefix works too.
        let ds2 = fetch(&format!("file://{}", path.display())).await.unwrap();
        assert_eq!(ds2.name, "custom");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn file_source_errors_on_missing() {
        let err = fetch("/no/such/dataset.json").await.unwrap_err();
        assert!(err.to_string().contains("read dataset file"), "{err}");
    }

    #[tokio::test]
    async fn unknown_scheme_is_rejected() {
        let err = fetch("ftp://x/y").await.unwrap_err();
        assert!(err.to_string().contains("no source handles"), "{err}");
    }

    #[test]
    fn registry_lists_sources() {
        assert_eq!(Registry::new().names(), vec!["builtin", "file", "http"]);
    }

    #[tokio::test]
    async fn http_source_fetches_from_a_local_server() {
        use std::io::{Read, Write};
        // A one-shot HTTP/1.1 server on an ephemeral port serving a dataset.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = r#"{"name":"remote","rules":[{"name":"r","pattern":"AKIA"}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let ds = fetch(&format!("http://{addr}/d.json")).await.unwrap();
        assert_eq!(ds.name, "remote");
        assert_eq!(ds.rules.len(), 1);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn http_source_reports_status_errors() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        });
        let err = fetch(&format!("http://{addr}/missing")).await.unwrap_err();
        assert!(err.to_string().contains("fetch"), "{err}");
        server.join().unwrap();
    }
}
