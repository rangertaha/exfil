//! `exfil server` — a small, read-only HTTP API over the findings graph.
//!
//! A long-lived service that keeps the findings store open and answers HTTP
//! GET requests with JSON. It is intentionally hand-rolled over `tokio::net`
//! (no web framework), mirroring how [`exfil-mcp`](exfil_mcp) speaks JSON-RPC
//! over stdio — the whole binary stays a single portable, pure-Rust artifact.
//!
//! Routes (all `GET`, all JSON):
//!
//! - `/health` — liveness: `{"status":"ok","service":"exfil"}`
//! - `/findings` — every finding, worst-first; `?q=<filter>` uses the same
//!   filter grammar as `exfil search` (`severity=high`, `path=…`, or free text)
//! - `/rules` — the built-in ruleset
//! - `/stats` — total findings and a per-severity breakdown
//!
//! The service is read-only, so exposing it is safe; bind it to a loopback
//! address unless you intend to serve other hosts. It shuts down gracefully on
//! Ctrl-C (SIGINT) or SIGTERM.

use std::future::Future;

use anyhow::{Context, Result};
use exfil_core::{Match, Severity};
use exfil_store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Serve the HTTP API on `listener` until `shutdown` resolves. Each connection
/// is handled on its own task; the store is cheap to clone (a shared handle).
pub async fn serve(
    listener: TcpListener,
    store: Store,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let local = listener.local_addr().context("listener address")?;
    eprintln!("[server] listening on http://{local}");
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted.context("accept connection")?;
                let store = store.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, store).await {
                        eprintln!("[server] connection error: {e:#}");
                    }
                });
            }
            _ = &mut shutdown => {
                eprintln!("[server] shutting down");
                return Ok(());
            }
        }
    }
}

/// Read one HTTP request from `stream`, route it, and write the JSON response.
/// Only the request line is parsed (this is a GET-only API); headers are read
/// and discarded, capped so a client can't stream headers forever.
async fn handle(mut stream: TcpStream, store: Store) -> Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }

    let head = String::from_utf8_lossy(&buf);
    let request_line = head.lines().next().unwrap_or("");
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or("");
    let target = fields.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    let (status, body) = if method != "GET" {
        (405, json_error("method not allowed"))
    } else {
        route(&store, path, query).await
    };

    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        reason = reason(status),
        len = body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Map a request path to a `(status, json_body)` pair.
async fn route(store: &Store, path: &str, query: &str) -> (u16, String) {
    match path {
        "/" | "/health" => (200, r#"{"status":"ok","service":"exfil"}"#.to_string()),
        "/findings" => {
            let filter = query_get(query, "q").unwrap_or_default();
            match store.search_findings(&filter).await {
                Ok(findings) => (
                    200,
                    serde_json::to_string(&findings).unwrap_or_else(|_| "[]".into()),
                ),
                Err(e) => (400, json_error(&format!("{e:#}"))),
            }
        }
        "/rules" => (
            200,
            serde_json::to_string(&exfil_scan::builtin_rules()).unwrap_or_else(|_| "[]".into()),
        ),
        "/stats" => match store.search_findings("").await {
            Ok(findings) => (200, stats_json(&findings)),
            Err(e) => (500, json_error(&format!("{e:#}"))),
        },
        _ => (404, json_error("not found")),
    }
}

/// A `{"total":N,"by_severity":{…}}` summary of a finding set.
fn stats_json(findings: &[Match]) -> String {
    let count = |sev: Severity| findings.iter().filter(|m| m.severity == Some(sev)).count();
    format!(
        r#"{{"total":{},"by_severity":{{"critical":{},"high":{},"medium":{},"low":{},"info":{}}}}}"#,
        findings.len(),
        count(Severity::Critical),
        count(Severity::High),
        count(Severity::Medium),
        count(Severity::Low),
        count(Severity::Info),
    )
}

/// Reason phrase for the status codes this API emits.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    }
}

/// A `{"error":"…"}` body with the message safely JSON-escaped.
fn json_error(message: &str) -> String {
    format!(
        r#"{{"error":{}}}"#,
        serde_json::Value::String(message.to_string())
    )
}

/// Read one query-string parameter, percent-decoding its value. Returns `None`
/// when the key is absent.
fn query_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Minimal `application/x-www-form-urlencoded` decode: `%XX` byte escapes and
/// `+` for space. Invalid escapes are passed through literally.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolve when the process is asked to stop: Ctrl-C (SIGINT) everywhere, and
/// SIGTERM on Unix (what `systemd`/`docker stop`/`kill` send).
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    /// Issue a GET and return the full raw response (status line, headers, body).
    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_serves_health_findings_rules_and_stats() {
        let base = std::env::temp_dir().join(format!("exfil-server-test-{}", std::process::id()));
        let tree = base.join("tree");
        let store_dir = base.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

        // Seed the store by scanning the tree.
        let store = Store::open_findings(&store_dir).await.unwrap();
        let pipeline = exfil_scan::default_pipeline().unwrap();
        exfil_engine::scan(&tree, &pipeline, &store, Some(&store_dir), None)
            .await
            .unwrap();

        // Serve on an ephemeral port; shut down via a oneshot.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(listener, store, async move {
            let _ = rx.await;
        }));

        let health = http_get(addr, "/health").await;
        assert!(health.contains("200 OK"), "{health}");
        assert!(health.contains(r#""status":"ok""#), "{health}");

        let findings = http_get(addr, "/findings").await;
        assert!(findings.contains("aws-access-key-id"), "{findings}");

        // The `?q=` filter uses the search grammar.
        let critical = http_get(addr, "/findings?q=severity=critical").await;
        assert!(critical.contains("aws-access-key-id"), "{critical}");
        let none = http_get(addr, "/findings?q=severity=low").await;
        assert!(none.contains("200 OK") && none.contains("[]"), "{none}");

        let rules = http_get(addr, "/rules").await;
        assert!(rules.contains("aws-access-key-id"), "{rules}");

        let stats = http_get(addr, "/stats").await;
        assert!(stats.contains(r#""total":1"#), "{stats}");
        assert!(stats.contains(r#""critical":1"#), "{stats}");

        let missing = http_get(addr, "/nope").await;
        assert!(missing.contains("404 Not Found"), "{missing}");

        tx.send(()).unwrap();
        server.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn percent_decode_handles_escapes_and_plus() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("path%3Dsrc%2F"), "path=src/");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
    }

    #[test]
    fn query_get_reads_named_param() {
        assert_eq!(
            query_get("q=severity%3Dhigh&x=1", "q").as_deref(),
            Some("severity=high")
        );
        assert_eq!(query_get("x=1", "q"), None);
    }
}
