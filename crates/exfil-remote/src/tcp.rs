//! TCP banner grabbing as a [`RemoteFs`] source.
//!
//! [`TcpFs`] connects to one or more `host:port` targets, reads the service
//! banner (and, if the service stays silent, sends a minimal HTTP probe to
//! elicit one), and returns those bytes — so the normal pipeline scans service
//! banners for secrets, version strings, bad indicators, and the like.
//!
//! This is active network reconnaissance; use it only against hosts you are
//! authorized to test. It reuses [`exfil_engine::scan_remote`]: a socket is
//! just another place bytes come from. It is the building block the port/range
//! scanner extends.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use exfil_engine::RemoteFs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// How long to wait for the TCP connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long to wait for the service to speak before probing / giving up.
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Cap on banner bytes read from a service.
const MAX_BANNER: usize = 8192;

/// Grabs TCP service banners from a fixed list of `host:port` targets.
pub struct TcpFs {
    targets: Vec<String>,
}

impl TcpFs {
    /// Build from `host:port` targets (e.g. `example.com:22`).
    pub fn new(targets: Vec<String>) -> Self {
        Self { targets }
    }
}

#[async_trait]
impl RemoteFs for TcpFs {
    fn host(&self) -> &str {
        "tcp"
    }

    async fn list(&self, _root: &str) -> Result<Vec<String>> {
        Ok(self.targets.iter().map(|t| format!("tcp://{t}")).collect())
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let target = path.strip_prefix("tcp://").unwrap_or(path);
        let banner = grab_banner(target).await?;
        // Tag the bytes with the target so findings are attributable.
        Ok(format!("target={target}\n{banner}").into_bytes())
    }
}

/// Connect to `host:port`, read a banner, and — if the service is silent —
/// send a minimal HTTP probe and read again. Returns the banner text.
pub async fn grab_banner(target: &str) -> Result<String> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .with_context(|| format!("connect timeout to {target}"))?
        .with_context(|| format!("connect to {target}"))?;

    // Many services (SSH/FTP/SMTP) speak first.
    if let Some(banner) = read_available(&mut stream).await {
        return Ok(banner);
    }
    // Otherwise nudge an HTTP-like service into responding.
    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
    Ok(read_available(&mut stream).await.unwrap_or_default())
}

/// Read up to [`MAX_BANNER`] bytes within [`READ_TIMEOUT`], as lossy UTF-8.
/// Returns `None` if the service sent nothing in time.
async fn read_available(stream: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0u8; MAX_BANNER];
    match timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn grabs_a_banner_from_a_speaking_service() {
        // A localhost service that speaks first, like SSH/FTP.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
            }
        });

        let fs = TcpFs::new(vec![addr.to_string()]);
        let paths = fs.list("/").await.unwrap();
        assert_eq!(paths, vec![format!("tcp://{addr}")]);
        let bytes = fs.read(&paths[0]).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("SSH-2.0-OpenSSH_9.6"), "{text}");
        assert!(text.contains("target="), "{text}");
    }

    #[tokio::test]
    async fn connection_refused_is_an_error() {
        // Port 1 on localhost is (almost certainly) closed.
        let fs = TcpFs::new(vec!["127.0.0.1:1".into()]);
        assert!(fs.read("tcp://127.0.0.1:1").await.is_err());
    }

    #[tokio::test]
    async fn host_tag_is_stable() {
        assert_eq!(TcpFs::new(vec![]).host(), "tcp");
    }
}
