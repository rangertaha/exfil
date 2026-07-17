//! Web crawling as a [`RemoteFs`] source.
//!
//! [`WebFs`] crawls a website starting from a seed URL — following same-origin
//! links breadth-first up to a page and depth cap — and caches each page body.
//! Presented as a [`RemoteFs`], the crawled pages flow through the normal
//! pipeline: the secret scanner finds leaked keys in HTML/JS, the PII scanner
//! finds exposed data, and the indicator/IOC checkers find bad domains and IPs.
//!
//! Crawling is bounded (page count, depth, same host only) and best-effort:
//! fetch failures skip a page rather than abort. It is online; only crawl sites
//! you are authorized to. `robots.txt` is not yet honored (a documented gap).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use exfil_engine::RemoteFs;
use regex::Regex;

/// Default cap on pages fetched in one crawl.
const DEFAULT_MAX_PAGES: usize = 64;

/// A crawled site: a map of URL → page body, plus the origin host tag.
pub struct WebFs {
    host: String,
    pages: HashMap<String, Vec<u8>>,
}

impl WebFs {
    /// Crawl `seed` breadth-first (same host), following links up to `max_pages`
    /// pages and `max_depth` link hops, caching each page body.
    pub async fn crawl(seed: &str, max_pages: usize, max_depth: usize) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("exfil-crawler")
            .build()
            .context("build HTTP client")?;
        let origin = host_of(seed).context("seed URL has no host")?;
        let cap = if max_pages == 0 {
            DEFAULT_MAX_PAGES
        } else {
            max_pages
        };

        let mut pages = HashMap::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((seed.to_string(), 0));
        seen.insert(seed.to_string());

        while let Some((url, depth)) = queue.pop_front() {
            if pages.len() >= cap {
                break;
            }
            let Ok(body) = fetch(&client, &url).await else {
                continue; // skip unreachable pages
            };
            // Enqueue same-origin links from this page (unless at max depth).
            if depth < max_depth {
                for link in extract_links(&url, &body) {
                    if host_of(&link).as_deref() == Some(origin.as_str())
                        && seen.insert(link.clone())
                    {
                        queue.push_back((link, depth + 1));
                    }
                }
            }
            pages.insert(url, body.into_bytes());
        }

        Ok(Self {
            host: origin,
            pages,
        })
    }
}

#[async_trait]
impl RemoteFs for WebFs {
    fn host(&self) -> &str {
        &self.host
    }

    async fn list(&self, _root: &str) -> Result<Vec<String>> {
        Ok(self.pages.keys().cloned().collect())
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.pages
            .get(path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("page not crawled: {path}"))
    }
}

/// Fetch a URL's body as text.
async fn fetch(client: &reqwest::Client, url: &str) -> Result<String> {
    let resp = client.get(url).send().await?.error_for_status()?;
    Ok(resp.text().await?)
}

/// The host portion of a URL (scheme://host/…), lowercased.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.split('@').next_back()?; // strip userinfo
    let host = host.split(':').next()?; // strip port
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Extract absolute links from an HTML page's `href`/`src` attributes,
/// resolving root-relative and same-page relative URLs against `base`.
fn extract_links(base: &str, html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"']+)["']"#).unwrap());
    let mut out = Vec::new();
    for cap in re.captures_iter(html) {
        if let Some(link) = resolve(base, &cap[1]) {
            out.push(link);
        }
    }
    out
}

/// Resolve a possibly-relative `link` against `base` into an absolute http(s)
/// URL. Skips fragments, mailto:, javascript:, and other schemes.
fn resolve(base: &str, link: &str) -> Option<String> {
    let link = link.trim();
    if link.is_empty() || link.starts_with('#') {
        return None;
    }
    if link.starts_with("http://") || link.starts_with("https://") {
        return Some(link.to_string());
    }
    // Reject non-http schemes (mailto:, javascript:, data:, tel:…).
    if let Some((scheme, _)) = link.split_once(':') {
        if !scheme.contains('/') && !link.starts_with("//") {
            return None;
        }
    }
    let (scheme, rest) = base.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if let Some(abs) = link.strip_prefix('/') {
        Some(format!("{scheme}://{host}/{abs}"))
    } else {
        // Same-directory relative: drop the base's last path segment.
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        Some(format!("{dir}/{link}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("https://Example.com/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("http://u@h:8080/p").as_deref(), Some("h"));
        assert_eq!(host_of("notaurl"), None);
    }

    #[test]
    fn link_resolution() {
        let base = "http://site.test/dir/page.html";
        assert_eq!(
            resolve(base, "/abs").as_deref(),
            Some("http://site.test/abs")
        );
        assert_eq!(
            resolve(base, "next.html").as_deref(),
            Some("http://site.test/dir/next.html")
        );
        assert_eq!(
            resolve(base, "https://other/x").as_deref(),
            Some("https://other/x")
        );
        assert!(resolve(base, "#frag").is_none());
        assert!(resolve(base, "mailto:a@b.co").is_none());
        assert!(resolve(base, "javascript:void(0)").is_none());
    }

    #[test]
    fn extracts_href_and_src() {
        let html = r#"<a href="/a">A</a> <script src="app.js"></script> <a href="mailto:x">m</a>"#;
        let links = extract_links("http://h.test/", html);
        assert!(links.iter().any(|l| l == "http://h.test/a"), "{links:?}");
        assert!(
            links.iter().any(|l| l == "http://h.test/app.js"),
            "{links:?}"
        );
    }

    /// A tiny hermetic HTTP/1.0 server serving two linked pages, so the crawl is
    /// tested without touching the network.
    #[tokio::test]
    async fn crawls_linked_pages_same_origin() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 1024];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/");
                let body = if path == "/second.html" {
                    "<html>token AKIA0123456789ABCDEF here</html>".to_string()
                } else {
                    "<html><a href=\"/second.html\">next</a></html>".to_string()
                };
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let seed = format!("http://{addr}/");
        let web = WebFs::crawl(&seed, 10, 2).await.unwrap();
        let pages = web.list("/").await.unwrap();
        // Both the seed and the linked page were crawled.
        assert_eq!(pages.len(), 2, "{pages:?}");
        let second = format!("http://{addr}/second.html");
        let body = web.read(&second).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("AKIA0123456789ABCDEF"));
    }
}
