//! WebDriver-rendered crawling as a [`RemoteFs`] source — for dynamic sites.
//!
//! Where [`WebFs`](crate::web::WebFs) fetches raw HTTP, [`WebDriverFs`] drives a
//! real headless browser over the WebDriver protocol (geckodriver/chromedriver),
//! so JavaScript-rendered, single-page, and dynamically-loaded sites are
//! traversed as a browser sees them — content a plain HTTP crawl never observes.
//! Each rendered page's post-JavaScript HTML flows through the normal pipeline.
//!
//! exfil connects to an already-running WebDriver server (its URL is a
//! parameter); it does not launch or manage the browser process. Crawling is
//! bounded (page/depth caps, same host) and best-effort, like `WebFs`. Online —
//! only crawl sites you are authorized to.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};
use async_trait::async_trait;
use exfil_engine::RemoteFs;
use fantoccini::{Client, ClientBuilder};
use serde_json::{json, Map, Value};

use crate::web::{extract_links, host_of};

/// Default cap on pages rendered in one crawl (browsers are heavier than HTTP).
const DEFAULT_MAX_PAGES: usize = 32;

/// A crawl of a dynamic site, rendered through a headless browser.
#[derive(Debug)]
pub struct WebDriverFs {
    host: String,
    pages: HashMap<String, Vec<u8>>,
}

impl WebDriverFs {
    /// Crawl `seed` breadth-first (same host) through the WebDriver server at
    /// `driver` (e.g. `http://localhost:4444`), rendering each page in a
    /// headless browser and caching its post-JavaScript HTML.
    pub async fn crawl(
        driver: &str,
        seed: &str,
        max_pages: usize,
        max_depth: usize,
    ) -> Result<Self> {
        let origin = host_of(seed).context("seed URL has no host")?;
        let cap = if max_pages == 0 {
            DEFAULT_MAX_PAGES
        } else {
            max_pages
        };

        install_crypto_provider();
        let client = ClientBuilder::rustls()
            .context("build WebDriver client")?
            .capabilities(headless_caps())
            .connect(driver)
            .await
            .with_context(|| format!("connect to WebDriver at {driver}"))?;

        // Render pages; close the browser session cleanly whatever happens.
        let rendered = Self::render_all(&client, seed, &origin, cap, max_depth).await;
        let _ = client.close().await;

        Ok(Self {
            host: origin,
            pages: rendered?,
        })
    }

    /// Breadth-first render loop, factored out so the session is always closed.
    async fn render_all(
        client: &Client,
        seed: &str,
        origin: &str,
        cap: usize,
        max_depth: usize,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let mut pages = HashMap::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((seed.to_string(), 0));
        seen.insert(seed.to_string());

        while let Some((url, depth)) = queue.pop_front() {
            if pages.len() >= cap {
                break;
            }
            if client.goto(&url).await.is_err() {
                continue; // skip pages the browser can't load
            }
            let Ok(html) = client.source().await else {
                continue;
            };
            // Enqueue same-origin links from the rendered DOM.
            if depth < max_depth {
                for link in extract_links(&url, &html) {
                    if host_of(&link).as_deref() == Some(origin) && seen.insert(link.clone()) {
                        queue.push_back((link, depth + 1));
                    }
                }
            }
            pages.insert(url, html.into_bytes());
        }
        Ok(pages)
    }
}

/// Install the `ring` rustls crypto provider once. The dependency tree carries
/// both `ring` and `aws-lc-rs`, so rustls can't pick a default on its own;
/// choosing one explicitly avoids a runtime panic when the TLS stack starts.
fn install_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Capabilities requesting headless Firefox *and* Chrome; a driver ignores the
/// options block for the browser it doesn't run.
fn headless_caps() -> Map<String, Value> {
    let mut caps = Map::new();
    caps.insert(
        "moz:firefoxOptions".to_string(),
        json!({ "args": ["-headless"] }),
    );
    caps.insert(
        "goog:chromeOptions".to_string(),
        json!({ "args": ["--headless=new", "--no-sandbox", "--disable-gpu"] }),
    );
    caps
}

#[async_trait]
impl RemoteFs for WebDriverFs {
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
            .ok_or_else(|| anyhow::anyhow!("page not rendered: {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_caps_offer_firefox_and_chrome() {
        let caps = headless_caps();
        assert!(caps.contains_key("moz:firefoxOptions"));
        assert!(caps.contains_key("goog:chromeOptions"));
        // Firefox headless flag is present.
        let ff = caps["moz:firefoxOptions"]["args"].as_array().unwrap();
        assert!(ff.iter().any(|a| a == "-headless"));
    }

    #[tokio::test]
    async fn connect_error_when_no_driver() {
        // No WebDriver server on this port → a clear connection error, not a hang.
        let err = WebDriverFs::crawl("http://127.0.0.1:5999", "http://x.test/", 1, 0)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("WebDriver"), "{err:#}");
    }
}
