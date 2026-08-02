//! A [Model Context Protocol](https://modelcontextprotocol.io) server exposing
//! exfil to AI agents over stdio.
//!
//! It speaks JSON-RPC 2.0 with newline-delimited messages (MCP's stdio
//! transport): `initialize`, `tools/list`, and `tools/call`. The tools are
//! exfil's whole surface — scanning, catalog management, post-scan passes, and
//! store maintenance as well as read-only queries over the findings graph — so
//! an agent can do anything the CLI can, driving the same library calls. See
//! [`tools`] for the catalog and [`ops`] for what each one runs.
//!
//! The protocol logic is a pure [`handle`] function (testable without any I/O);
//! [`serve`] is the thin stdio loop around it.
//!
//! # Rust notes
//!
//! Tool *failures* come back as `isError` content rather than JSON-RPC errors,
//! per the MCP convention: the agent is meant to read the message and adapt, so
//! it belongs in the result the model sees, not in the transport's error slot.
//! Only malformed protocol (an unknown method) is a JSON-RPC error.

pub mod ops;
pub mod tools;

pub use ops::Ctx;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The MCP protocol version this server implements.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Handle one JSON-RPC request, returning the response value — or `None` for
/// notifications (requests without an `id`), which get no reply.
pub async fn handle(ctx: &Ctx, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    // Notifications (no id) are acknowledged silently.
    id.as_ref()?;
    let id = id.unwrap();

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "exfil", "version": env!("CARGO_PKG_VERSION") },
        })),
        "tools/list" => Ok(json!({ "tools": tools::definitions() })),
        "tools/call" => call_tool(ctx, req.get("params")).await,
        other => Err(format!("unknown method {other:?}")),
    };

    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err(msg) => json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32603, "message": msg },
        }),
    })
}

/// Dispatch a `tools/call` to the named tool, wrapping the output as MCP text
/// content. Tool errors are returned as `isError` content, not JSON-RPC errors,
/// so the agent sees the message.
async fn call_tool(ctx: &Ctx, params: Option<&Value>) -> std::result::Result<Value, String> {
    let params = params.ok_or("missing params")?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("missing tool name")?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    // An unknown tool is a protocol-level mistake, not a failed operation.
    if !tools::exists(name) {
        return Err(format!("unknown tool {name:?}"));
    }

    Ok(match tools::dispatch(ctx, name, &args).await {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": format!("error: {e:#}") }],
            "isError": true,
        }),
    })
}

/// Serve the MCP protocol over stdio until stdin closes.
pub async fn serve(ctx: Ctx) -> Result<()> {
    serve_io(ctx, tokio::io::stdin(), tokio::io::stdout()).await
}

/// The stdio loop, generic over its reader and writer so it can be driven from
/// a test with in-memory pipes. Each input line is one JSON-RPC message; each
/// response is written as one line. Blank and malformed lines are skipped.
async fn serve_io<R, W>(ctx: Ctx, reader: R, mut writer: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // ignore malformed lines
        };
        if let Some(resp) = handle(&ctx, &req).await {
            let mut s = serde_json::to_string(&resp)?;
            s.push('\n');
            writer.write_all(s.as_bytes()).await?;
            writer.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use exfil_core::{FileMeta, Match, Severity};
    use exfil_store::Store;

    fn meta(hash: &str, path: &str) -> FileMeta {
        FileMeta {
            path: path.into(),
            abs: path.into(),
            host: "h".into(),
            mode: 0,
            uid: 0,
            gid: 0,
            user: String::new(),
            group: String::new(),
            size: 1,
            mtime: String::new(),
            hash: hash.into(),
        }
    }

    fn finding(rule: &str, path: &str) -> Match {
        Match {
            rule: rule.into(),
            path: path.into(),
            line: 1,
            col: 1,
            snippet: "hit".into(),
            severity: Some(Severity::High),
            cwe: Some("CWE-798".into()),
            cve: None,
        }
    }

    /// A context over a fresh store seeded with one finding. The config path
    /// points at a written file so no test touches the user's real config.
    async fn ctx_with_finding() -> (Ctx, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let base = std::env::temp_dir().join(format!(
            "exfil-mcp-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let store_dir = base.join("store");

        let store = Store::open_findings(&store_dir).await.unwrap();
        store.upsert_file(&meta("aaa", "a.env")).await.unwrap();
        store
            .add_finding(&finding("aws-key", "a.env"), "aaa")
            .await
            .unwrap();
        drop(store);

        let config = base.join("config.toml");
        std::fs::write(&config, "store = \".exfil\"\n").unwrap();
        let ctx = Ctx {
            store_dir,
            config: Some(config),
        };
        (ctx, base)
    }

    /// Call a tool and return its text content.
    async fn call(ctx: &Ctx, name: &str, args: Value) -> Value {
        handle(
            ctx,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                    "params":{"name":name,"arguments":args}}),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn initialize_and_tools_list() {
        let (ctx, base) = ctx_with_finding().await;

        let init = handle(&ctx, &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
            .await
            .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "exfil");
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);

        let list = handle(&ctx, &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
            .await
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        // The graph queries, and the wider surface beyond them.
        for expected in ["search", "graph", "scan", "rules", "pull", "gc", "clean"] {
            assert!(names.contains(&expected), "missing {expected}: {names:?}");
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn tools_call_search_and_graph() {
        let (ctx, base) = ctx_with_finding().await;

        let search = call(&ctx, "search", json!({"query": ""})).await;
        let text = search["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("aws-key") && text.contains("1 finding(s)"));

        let graph = call(&ctx, "graph", json!({})).await;
        let gtext = graph["result"]["content"][0]["text"].as_str().unwrap();
        assert!(gtext.contains("\"nodes\""));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn unknown_method_and_tool_errors() {
        let (ctx, base) = ctx_with_finding().await;

        let bad = handle(&ctx, &json!({"jsonrpc":"2.0","id":5,"method":"nope"}))
            .await
            .unwrap();
        assert!(bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown method"));

        let bad_tool = call(&ctx, "frobnicate", json!({})).await;
        assert!(bad_tool["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));

        // A notification (no id) gets no response.
        let none = handle(&ctx, &json!({"jsonrpc":"2.0","method":"initialized"})).await;
        assert!(none.is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn tools_call_analyze_renders_report() {
        let (ctx, base) = ctx_with_finding().await;
        let resp = call(&ctx, "analyze", json!({})).await;
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("finding(s)"), "{text}");
        assert!(text.contains("risk score"), "{text}");

        // A named format is honored.
        let sarif = call(&ctx, "analyze", json!({"format": "sarif"})).await;
        let stext = sarif["result"]["content"][0]["text"].as_str().unwrap();
        assert!(stext.contains("\"version\""), "{stext}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn tool_failure_reports_is_error() {
        let (ctx, base) = ctx_with_finding().await;
        // An invalid search field makes the tool return an error result.
        let resp = call(&ctx, "search", json!({"query": "bogus=1"})).await;
        assert_eq!(resp["result"]["isError"], json!(true), "{resp}");
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("error:"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn read_only_tools_over_the_wider_surface() {
        let (ctx, base) = ctx_with_finding().await;

        let rules = call(&ctx, "rules", json!({"filter": "aws"})).await;
        let text = rules["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("aws-access-key-id"), "{text}");

        let stats = call(&ctx, "stats", json!({})).await;
        let text = stats["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("findings: 1"), "{text}");

        let sources = call(&ctx, "sources", json!({})).await;
        let text = sources["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("builtin://"), "{text}");

        let config = call(&ctx, "config", json!({})).await;
        let text = config["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("# config:"), "{text}");

        let export = call(&ctx, "export", json!({})).await;
        let text = export["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"tables\""), "{text}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scan_tool_walks_a_tree_into_the_store() {
        let (ctx, base) = ctx_with_finding().await;
        let tree = base.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("leak.env"), "AWS=AKIA0123456789ABCDEF\n").unwrap();

        let resp = call(&ctx, "scan", json!({"target": tree.to_str().unwrap()})).await;
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("scanned 1 files"), "{text}");
        assert!(text.contains("passive"), "{text}");

        // The finding is queryable straight afterwards.
        let search = call(&ctx, "search", json!({"query": "aws"})).await;
        let stext = search["result"]["content"][0]["text"].as_str().unwrap();
        assert!(stext.contains("aws-access-key-id"), "{stext}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn normalize_then_gc_then_clean() {
        let (ctx, base) = ctx_with_finding().await;

        let norm = call(&ctx, "normalize", json!({})).await;
        let text = norm["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("normalized 1 finding(s)"), "{text}");

        let gc = call(&ctx, "gc", json!({})).await;
        let text = gc["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("gc: removed"), "{text}");

        // clean deletes the store directory outright.
        assert!(ctx.store_dir.exists());
        let clean = call(&ctx, "clean", json!({})).await;
        let text = clean["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("removed store"), "{text}");
        assert!(!ctx.store_dir.exists());

        // A second clean is a no-op, not an error.
        let again = call(&ctx, "clean", json!({})).await;
        let text = again["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("no store at"), "{text}");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn serve_io_processes_lines_and_skips_junk() {
        let (ctx, base) = ctx_with_finding().await;
        // Blank line and malformed line are skipped; the real request answered.
        let input = "\n\
                     not json\n\
                     {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\"}\n";
        let mut output = Vec::new();
        serve_io(ctx, input.as_bytes(), &mut output).await.unwrap();
        let out = String::from_utf8(output).unwrap();
        assert_eq!(
            out.lines().count(),
            1,
            "only the valid request replies: {out}"
        );
        assert!(out.contains("\"tools\""), "{out}");
        let _ = std::fs::remove_dir_all(&base);
    }
}
