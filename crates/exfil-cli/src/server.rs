//! `exfil server` — a small HTTP API over the findings graph.
//!
//! A long-lived service that keeps the findings store open and answers HTTP
//! requests with JSON. It is intentionally hand-rolled over `tokio::net` (no
//! web framework), mirroring how [`exfil-mcp`](exfil_mcp) speaks JSON-RPC over
//! stdio — the whole binary stays a single portable, pure-Rust artifact.
//!
//! Routes:
//!
//! - `GET /health` — liveness: `{"status":"ok","service":"exfil"}`
//! - `GET /findings` — every finding, worst-first; `?q=<filter>` uses the same
//!   grammar as `exfil search` (`severity=high`, `path=…`, or free text)
//! - `GET /rules` — the built-in ruleset
//! - `GET /stats` — total findings and a per-severity breakdown
//! - `GET /graphql` — an interactive GraphiQL IDE
//! - `POST /graphql` — execute a GraphQL query (see [`crate::graphql`])
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

use crate::graphql::{self, ExfilSchema};

/// Serve the HTTP API on `listener` until `shutdown` resolves. Each connection
/// is handled on its own task; the store and GraphQL schema are cheap to clone
/// (shared handles).
pub async fn serve(
    listener: TcpListener,
    store: Store,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let local = listener.local_addr().context("listener address")?;
    eprintln!("[server] listening on http://{local}");
    let schema = graphql::schema(store.clone());
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _peer) = accepted.context("accept connection")?;
                let store = store.clone();
                let schema = schema.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, store, schema).await {
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

/// Read one HTTP request from `stream` (request line, headers, and — for a
/// POST — the `Content-Length` body), route it, and write the response.
async fn handle(mut stream: TcpStream, store: Store, schema: ExfilSchema) -> Result<()> {
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
    let (path, query) = (path.to_string(), query.to_string());

    // A POST carries a Content-Length body; read whatever wasn't already buffered.
    let content_length = header_content_length(&header_text);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    let body = String::from_utf8_lossy(&body).to_string();

    let (status, content_type, out) = route(&store, &schema, &method, &path, &query, &body).await;
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
    schema: &ExfilSchema,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
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
        ("GET", "/rules") => (
            200,
            JSON,
            serde_json::to_string(&exfil_scan::builtin_rules()).unwrap_or_else(|_| "[]".into()),
        ),
        ("GET", "/stats") => match store.search_findings("").await {
            Ok(findings) => (200, JSON, stats_json(&findings)),
            Err(e) => (500, JSON, json_error(&format!("{e:#}"))),
        },
        ("GET", "/graphql") => (200, "text/html; charset=utf-8", graphiql_html()),
        ("POST", "/graphql") => match serde_json::from_str::<async_graphql::Request>(body) {
            Ok(request) => {
                let response = schema.execute(request).await;
                (
                    200,
                    JSON,
                    serde_json::to_string(&response).unwrap_or_else(|_| json_error("serialize")),
                )
            }
            Err(e) => (
                400,
                JSON,
                json_error(&format!("invalid GraphQL request: {e}")),
            ),
        },
        ("GET", _) => (404, JSON, json_error("not found")),
        _ => (405, JSON, json_error("method not allowed")),
    }
}

/// The GraphiQL IDE page, pointed at this server's `/graphql` endpoint.
fn graphiql_html() -> String {
    async_graphql::http::GraphiQLSource::build()
        .endpoint("/graphql")
        .title("exfil GraphQL")
        .finish()
}

/// First occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse the `Content-Length` header value (0 if absent or unparseable).
fn header_content_length(headers: &str) -> usize {
    headers
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
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

    /// Issue a raw request and return the full response (status line + body).
    async fn http(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    async fn get(addr: std::net::SocketAddr, path: &str) -> String {
        http(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        )
        .await
    }

    async fn post(addr: std::net::SocketAddr, path: &str, body: &str) -> String {
        http(
            addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_serves_rest_and_graphql() {
        let base = std::env::temp_dir().join(format!("exfil-server-test-{}", std::process::id()));
        let tree = base.join("tree");
        let store_dir = base.join("store");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

        let store = Store::open_findings(&store_dir).await.unwrap();
        let pipeline = exfil_scan::default_pipeline().unwrap();
        exfil_engine::scan(&tree, &pipeline, &store, Some(&store_dir), None)
            .await
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve(listener, store, async move {
            let _ = rx.await;
        }));

        // REST.
        let health = get(addr, "/health").await;
        assert!(health.contains("200 OK") && health.contains(r#""status":"ok""#));
        let findings = get(addr, "/findings").await;
        assert!(findings.contains("aws-access-key-id"), "{findings}");
        let critical = get(addr, "/findings?q=severity=critical").await;
        assert!(critical.contains("aws-access-key-id"), "{critical}");
        let stats = get(addr, "/stats").await;
        assert!(stats.contains(r#""total":1"#) && stats.contains(r#""critical":1"#));
        assert!(get(addr, "/nope").await.contains("404 Not Found"));

        // Error branches: an invalid filter is a 400; unsupported methods and
        // non-GraphQL POSTs are 405s.
        assert!(get(addr, "/findings?q=bogus=1")
            .await
            .contains("400 Bad Request"));
        let put = http(
            addr,
            "PUT / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(put.contains("405 Method Not Allowed"), "{put}");
        assert!(post(addr, "/findings", "{}")
            .await
            .contains("405 Method Not Allowed"));

        // GraphiQL IDE.
        let ide = get(addr, "/graphql").await;
        assert!(ide.contains("text/html") && ide.to_lowercase().contains("graphiql"));

        // GraphQL query.
        let q = r#"{"query":"{ stats { total critical } findings(query:\"severity=critical\"){ rule severity } }"}"#;
        let resp = post(addr, "/graphql", q).await;
        assert!(resp.contains(r#""total":1"#), "{resp}");
        assert!(resp.contains("aws-access-key-id"), "{resp}");
        assert!(!resp.contains(r#""errors""#), "{resp}");

        // Malformed GraphQL body.
        let bad = post(addr, "/graphql", "not json").await;
        assert!(bad.contains("400 Bad Request"), "{bad}");

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
    fn content_length_header_is_parsed() {
        let headers = "POST /graphql HTTP/1.1\r\nContent-Length: 42\r\nHost: x\r\n\r\n";
        assert_eq!(header_content_length(headers), 42);
        assert_eq!(header_content_length("GET / HTTP/1.1\r\n\r\n"), 0);
    }
}
