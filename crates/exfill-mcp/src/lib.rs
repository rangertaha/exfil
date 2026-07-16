//! A minimal [Model Context Protocol](https://modelcontextprotocol.io) server
//! exposing the findings graph to AI agents over stdio.
//!
//! It speaks JSON-RPC 2.0 with newline-delimited messages (MCP's stdio
//! transport): `initialize`, `tools/list`, and `tools/call`. The tools are
//! read-only queries over the store — `search`, `graph`, `neighbors`, `get`,
//! `analyze` — so an agent can explore what a scan found. The protocol logic is
//! a pure [`handle`] function (testable without any I/O); [`serve`] is the thin
//! stdio loop around it.

use anyhow::Result;
use exfill_report::{reporter_for, Analysis};
use exfill_store::Store;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The MCP protocol version this server implements.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// The tools this server advertises, with their input schemas.
fn tool_definitions() -> Value {
    let str_arg = |name: &str, desc: &str| {
        json!({
            "type": "object",
            "properties": { name: { "type": "string", "description": desc } },
        })
    };
    json!([
        {
            "name": "search",
            "description": "Search stored findings. Empty query returns all; \
                            'field=value' filters on rule/cwe/severity/path; \
                            other text matches rule names.",
            "inputSchema": str_arg("query", "filter expression or free text"),
        },
        {
            "name": "graph",
            "description": "The findings graph (finding→file/rule nodes and edges) \
                            for findings matching an optional filter.",
            "inputSchema": str_arg("query", "optional finding filter"),
        },
        {
            "name": "neighbors",
            "description": "Nodes connected to a graph node (table:key) by any edge.",
            "inputSchema": str_arg("id", "node id, e.g. file:<hash>"),
        },
        {
            "name": "get",
            "description": "Fetch one record (table:key) as JSON.",
            "inputSchema": str_arg("id", "record id, e.g. finding:… or file:<hash>"),
        },
        {
            "name": "analyze",
            "description": "A text report over the findings graph (counts, risk score).",
            "inputSchema": str_arg("query", "optional finding filter"),
        },
    ])
}

/// Handle one JSON-RPC request, returning the response value — or `None` for
/// notifications (requests without an `id`), which get no reply.
pub async fn handle(store: &Store, req: &Value) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    // Notifications (no id) are acknowledged silently.
    id.as_ref()?;
    let id = id.unwrap();

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "exfill", "version": env!("CARGO_PKG_VERSION") },
        })),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(store, req.get("params")).await,
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
/// per the MCP convention (so the agent sees the message).
async fn call_tool(store: &Store, params: Option<&Value>) -> std::result::Result<Value, String> {
    let params = params.ok_or("missing params")?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("missing tool name")?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let arg = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    let output: Result<String> = match name {
        "search" => run_search(store, &arg("query")).await,
        "graph" => run_json(store.graph(&arg("query")).await),
        "neighbors" => run_json(store.neighbors(&arg("id")).await),
        "get" => run_json(store.get_record(&arg("id")).await),
        "analyze" => run_analyze(store, &arg("query")).await,
        other => return Err(format!("unknown tool {other:?}")),
    };

    Ok(match output {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": format!("error: {e:#}") }],
            "isError": true,
        }),
    })
}

/// Search findings and format them as text lines plus a count.
async fn run_search(store: &Store, query: &str) -> Result<String> {
    let findings = store.search_findings(query).await?;
    let mut out = String::new();
    for m in &findings {
        out.push_str(&format!(
            "{}:{}:{} [{}] {}\n",
            m.path, m.line, m.col, m.rule, m.snippet
        ));
    }
    out.push_str(&format!("{} finding(s)", findings.len()));
    Ok(out)
}

/// Pretty-print any serializable store result as JSON text.
fn run_json<T: serde::Serialize>(result: Result<T>) -> Result<String> {
    let value = result?;
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Render the text analysis report.
async fn run_analyze(store: &Store, query: &str) -> Result<String> {
    let findings = store.search_findings(query).await?;
    let (files, scans) = store.counts().await?;
    let analysis = Analysis {
        findings,
        files,
        scans,
    };
    let mut buf = Vec::new();
    reporter_for("text")
        .ok_or_else(|| anyhow::anyhow!("text reporter"))?
        .report(&mut buf, &analysis)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Serve the MCP protocol over stdio until stdin closes. Each line of stdin is
/// one JSON-RPC message; each response is written as one line to stdout.
pub async fn serve(store: Store) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // ignore malformed lines
        };
        if let Some(resp) = handle(&store, &req).await {
            let mut s = serde_json::to_string(&resp)?;
            s.push('\n');
            stdout.write_all(s.as_bytes()).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use exfill_core::{FileMeta, Match, Severity};

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
            cwe: None,
            cve: None,
        }
    }

    async fn store_with_finding() -> (Store, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "exfill-mcp-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir, exfill_store::DB_FINDINGS).await.unwrap();
        store.upsert_file(&meta("aaa", "a.env")).await.unwrap();
        store
            .add_finding(&finding("aws-key", "a.env"), "aaa")
            .await
            .unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn initialize_and_tools_list() {
        let (store, dir) = store_with_finding().await;

        let init = handle(
            &store,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .await
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "exfill");
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);

        let list = handle(
            &store,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .await
        .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"search") && names.contains(&"graph"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tools_call_search_and_graph() {
        let (store, dir) = store_with_finding().await;

        let search = handle(
            &store,
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                    "params":{"name":"search","arguments":{"query":""}}}),
        )
        .await
        .unwrap();
        let text = search["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("aws-key") && text.contains("1 finding(s)"));

        let graph = handle(
            &store,
            &json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                    "params":{"name":"graph","arguments":{}}}),
        )
        .await
        .unwrap();
        let gtext = graph["result"]["content"][0]["text"].as_str().unwrap();
        assert!(gtext.contains("\"nodes\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unknown_method_and_tool_errors() {
        let (store, dir) = store_with_finding().await;

        // Unknown method → JSON-RPC error.
        let bad = handle(&store, &json!({"jsonrpc":"2.0","id":5,"method":"nope"}))
            .await
            .unwrap();
        assert!(bad["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown method"));

        // Unknown tool → JSON-RPC error.
        let bad_tool = handle(
            &store,
            &json!({"jsonrpc":"2.0","id":6,"method":"tools/call",
                    "params":{"name":"frobnicate","arguments":{}}}),
        )
        .await
        .unwrap();
        assert!(bad_tool["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool"));

        // A notification (no id) gets no response.
        let none = handle(&store, &json!({"jsonrpc":"2.0","method":"initialized"})).await;
        assert!(none.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
