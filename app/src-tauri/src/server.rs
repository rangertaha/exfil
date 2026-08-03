//! The desktop app's own HTTP API over the findings graph.
//!
//! The app used to shell out to `exfil server`; that command is gone, so the
//! API now runs *inside* the app process. Same routes, same JSON, one less
//! moving part: no child process to spawn, supervise, or leave orphaned, and
//! no dependency on an `exfil` binary being installed on `PATH`.
//!
//! It is hand-rolled over `tokio::net` (no web framework) so the app stays a
//! single portable artifact. Routes — read-only, bound to loopback:
//!
//! - `GET /health` — liveness: `{"status":"ok","service":"exfil"}`
//! - `GET /findings` — every finding, worst-first; `?q=<filter>` uses the same
//!   grammar as `exfil search` (`severity=high`, `path=…`, or free text)
//! - `GET /stats` — total findings and a per-severity breakdown
//!
//! These are exactly what `../ui/app.js` fetches. The GraphQL endpoint the old
//! `exfil server` also carried is not reproduced: nothing in the UI used it.

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
    eprintln!("[app] serving the findings API on http://{local}");
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted.context("accept connection")?;
                let store = store.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, store).await {
                        eprintln!("[app] connection error: {e:#}");
                    }
                });
            }
            _ = &mut shutdown => {
                eprintln!("[app] stopping the findings API");
                return Ok(());
            }
        }
    }
}

/// Read one HTTP request from `stream` (request line and headers), route it,
/// and write the response.
async fn handle(mut stream: TcpStream, store: Store) -> Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    // Read at least through the end of the header block (or give up at a cap).
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            break buf.len();
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break buf.len();
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_end = header_end.min(buf.len());
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let request_line = header_text.lines().next().unwrap_or("");
    let mut fields = request_line.split_whitespace();
    let method = fields.next().unwrap_or("").to_string();
    let target = fields.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    let (status, content_type, out) = route(&store, &method, path, query).await;
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{out}",
        reason = reason(status),
        len = out.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Route a request to `(status, content_type, body)`.
async fn route(
    store: &Store,
    method: &str,
    path: &str,
    query: &str,
) -> (u16, &'static str, String) {
    const JSON: &str = "application/json";
    match (method, path) {
        ("GET", "/") | ("GET", "/health") => (
            200,
            JSON,
            r#"{"status":"ok","service":"exfil"}"#.to_string(),
        ),
        ("GET", "/findings") => {
            let filter = query_get(query, "q").unwrap_or_default();
            match store.search_findings(&filter).await {
                Ok(findings) => (
                    200,
                    JSON,
                    serde_json::to_string(&findings).unwrap_or_else(|_| "[]".into()),
                ),
                Err(e) => (400, JSON, json_error(&format!("{e:#}"))),
            }
        }
        ("GET", "/stats") => match store.search_findings("").await {
            Ok(findings) => (200, JSON, stats_json(&findings)),
            Err(e) => (500, JSON, json_error(&format!("{e:#}"))),
        },
        ("GET", _) => (404, JSON, json_error("not found")),
        _ => (405, JSON, json_error("method not allowed")),
    }
}

/// First occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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

/// Read one query-string parameter, percent-decoding its value.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_escapes_and_plus() {
        assert_eq!(percent_decode("severity%3Dhigh"), "severity=high");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn query_get_reads_named_parameters() {
        assert_eq!(query_get("q=a&x=1", "q").as_deref(), Some("a"));
        assert_eq!(query_get("x=1", "q"), None);
    }

    #[test]
    fn stats_json_counts_each_severity() {
        let m = |sev| Match {
            rule: "r".into(),
            path: "p".into(),
            line: 1,
            col: 1,
            snippet: String::new(),
            severity: Some(sev),
            cwe: None,
            cve: None,
        };
        let json = stats_json(&[m(Severity::Critical), m(Severity::Low)]);
        assert!(json.contains(r#""total":2"#), "{json}");
        assert!(json.contains(r#""critical":1"#), "{json}");
        assert!(json.contains(r#""low":1"#), "{json}");
        assert!(json.contains(r#""high":0"#), "{json}");
    }
}
