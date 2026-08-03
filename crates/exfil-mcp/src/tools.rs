//! The tool catalog: what an agent can call, and what each call runs.
//!
//! Tools cover exfil's whole surface, not just the graph — scanning, catalog
//! management, post-scan passes, and store maintenance alongside the read-only
//! queries. Each entry pairs an advertised JSON schema with the [`ops`] call it
//! dispatches to, so the two cannot drift.
//!
//! Tools are grouped by [`Access`], which is advertised in each description.
//! An agent should be able to tell, before calling, whether a tool reads, writes
//! to the local store, reaches the network, or destroys data.

use serde_json::{json, Value};

use crate::ops::{self, Ctx};
use exfil_remote::target::Options;

/// What a tool does beyond reading — surfaced in its description so an agent
/// (and whoever is reading its transcript) can see the consequence before the
/// call, not after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reads stored state; changes nothing.
    Read,
    /// Writes to the local findings store or catalog.
    Write,
    /// Reaches out over the network.
    Network,
    /// Irreversibly deletes stored data.
    Destructive,
}

impl Access {
    /// The tag prefixed to the tool's advertised description.
    fn tag(self) -> &'static str {
        match self {
            Access::Read => "[read-only]",
            Access::Write => "[writes to the local store]",
            Access::Network => "[network: reaches remote systems]",
            Access::Destructive => "[DESTRUCTIVE: deletes stored data]",
        }
    }
}

/// One advertised tool: its name, access class, description, and parameters.
struct Tool {
    name: &'static str,
    access: Access,
    description: &'static str,
    /// `(name, type, description)` for each accepted argument.
    params: &'static [(&'static str, &'static str, &'static str)],
}

/// Every tool the server advertises.
const TOOLS: &[Tool] = &[
    // ── Reading the findings graph ──
    Tool {
        name: "search",
        access: Access::Read,
        description: "Search stored findings. Empty query returns all; 'field=value' filters on \
                      rule/cwe/severity/path; other text matches rule names.",
        params: &[("query", "string", "filter expression or free text")],
    },
    Tool {
        name: "graph",
        access: Access::Read,
        description: "The findings graph (finding→file/rule nodes and edges) for findings \
                      matching an optional filter.",
        params: &[("query", "string", "optional finding filter")],
    },
    Tool {
        name: "neighbors",
        access: Access::Read,
        description: "Nodes connected to a graph node (table:key) by any edge.",
        params: &[("id", "string", "node id, e.g. file:<hash>")],
    },
    Tool {
        name: "get",
        access: Access::Read,
        description: "Fetch one record (table:key) as JSON.",
        params: &[("id", "string", "record id, e.g. finding:… or file:<hash>")],
    },
    Tool {
        name: "analyze",
        access: Access::Read,
        description: "A report over the findings graph (counts, risk score). Formats: text, \
                      json, markdown, junit, sarif.",
        params: &[
            ("query", "string", "optional finding filter"),
            ("format", "string", "report format (default: text)"),
        ],
    },
    Tool {
        name: "stats",
        access: Access::Read,
        description: "Store counts (files, scans, findings) and the CIM event tally.",
        params: &[],
    },
    Tool {
        name: "export",
        access: Access::Read,
        description: "The whole findings graph as a portable JSON snapshot.",
        params: &[],
    },
    // ── Reading the catalog and config ──
    Tool {
        name: "rules",
        access: Access::Read,
        description: "The rules a scan would apply — built-ins plus catalog datasets — \
                      optionally filtered by name, description, CWE, or severity.",
        params: &[("filter", "string", "optional substring filter")],
    },
    Tool {
        name: "cwe",
        access: Access::Read,
        description: "Look up a weakness in the local MITRE CWE catalog.",
        params: &[("id", "string", "CWE id, e.g. CWE-798 or 798")],
    },
    Tool {
        name: "datasets",
        access: Access::Read,
        description: "Catalog datasets and their rule counts.",
        params: &[],
    },
    Tool {
        name: "feeds",
        access: Access::Read,
        description: "Configured URL feeds.",
        params: &[],
    },
    Tool {
        name: "sources",
        access: Access::Read,
        description: "The dataset source plugins and the reference schemes they handle.",
        params: &[],
    },
    Tool {
        name: "config",
        access: Access::Read,
        description: "The resolved config path and its contents.",
        params: &[],
    },
    Tool {
        name: "plugin_settings",
        access: Access::Read,
        description: "A plugin's stored setting overrides.",
        params: &[("plugin", "string", "plugin name, e.g. scan")],
    },
    // ── Scanning ──
    Tool {
        name: "scan",
        access: Access::Network,
        description: "Scan a target and store the findings. A local path or 'processes' stays \
                      on this machine; 'host:port' (comma-separated), a host/CIDR with ports, \
                      or an http(s):// URL reaches remote systems — authorized testing only.",
        params: &[
            (
                "target",
                "string",
                "path, 'processes', host:port, host/CIDR, or http(s):// URL",
            ),
            (
                "ports",
                "string",
                "port list/ranges (22,80,8000-8010) or 'common'; makes target a sweep",
            ),
            ("max_pages", "integer", "max pages to fetch when crawling"),
            ("max_depth", "integer", "max link depth when crawling"),
            ("driver", "string", "WebDriver URL to render JS-heavy pages"),
            (
                "budget",
                "string",
                "cap the work, most-promising files first: '30s', '20%', '500mb', \
                 or a file count. A budgeted result states its coverage and is NOT \
                 evidence the target is clean.",
            ),
        ],
    },
    // ── Catalog maintenance ──
    Tool {
        name: "pull",
        access: Access::Network,
        description: "Download a dataset into the catalog by reference (builtin://, a path, an \
                      https:// URL, or mitre://cwe). Empty pulls every configured [[update]].",
        params: &[("reference", "string", "dataset reference; empty for all")],
    },
    Tool {
        name: "feed_add",
        access: Access::Write,
        description: "Add or update a URL feed in the catalog.",
        params: &[
            ("name", "string", "feed name"),
            ("url", "string", "feed URL"),
        ],
    },
    Tool {
        name: "feed_rm",
        access: Access::Write,
        description: "Remove a URL feed from the catalog.",
        params: &[("name", "string", "feed name")],
    },
    Tool {
        name: "dataset_rm",
        access: Access::Write,
        description: "Remove a dataset and its rules from the catalog.",
        params: &[("name", "string", "dataset name")],
    },
    Tool {
        name: "plugin_set",
        access: Access::Write,
        description: "Store a per-plugin setting override in the catalog.",
        params: &[
            ("plugin", "string", "plugin name"),
            ("key", "string", "setting key"),
            ("value", "string", "setting value"),
        ],
    },
    // ── Post-scan passes ──
    Tool {
        name: "normalize",
        access: Access::Write,
        description: "Normalize stored findings into CIM events for cross-source correlation.",
        params: &[],
    },
    Tool {
        name: "annotate_cwe",
        access: Access::Write,
        description: "Annotate findings with authoritative CWE names from a pulled MITRE catalog.",
        params: &[],
    },
    Tool {
        name: "check_dns",
        access: Access::Network,
        description: "Resolve every observed domain and flag those pointing at reserved \
                      addresses. Makes DNS queries.",
        params: &[],
    },
    Tool {
        name: "check_whois",
        access: Access::Network,
        description: "WHOIS-check observed domains and flag newly-registered ones. Makes \
                      port-43 queries.",
        params: &[(
            "recent_days",
            "integer",
            "flag domains registered within this many days (default 30)",
        )],
    },
    // ── The path model ──
    Tool {
        name: "model_train",
        access: Access::Write,
        description: "Train the path model that ranks what a scan looks at first, on the \
                      scans already in this store. Every recorded file is a sample; whether \
                      a finding hangs off it is the label.",
        params: &[
            ("states", "integer", "latent states per chain (default 8)"),
            (
                "iterations",
                "integer",
                "max Baum-Welch iterations (default 30)",
            ),
        ],
    },
    Tool {
        name: "model_score",
        access: Access::Read,
        description: "The trained model's P(finding) for a path, with each path component's \
                      contribution in log-odds. The path need not exist.",
        params: &[("path", "string", "path to score")],
    },
    Tool {
        name: "model_eval",
        access: Access::Read,
        description: "Measure whether the path model actually helps: fit on part of the stored \
                      scans and report how much of the findings a budgeted scan recovers on the \
                      rest, against a directory-frequency baseline and blind selection. Use this \
                      before trusting a budgeted scan.",
        params: &[
            (
                "holdout",
                "number",
                "fraction held out for measurement (default 0.3)",
            ),
            ("states", "integer", "latent states per chain (default 8)"),
        ],
    },
    Tool {
        name: "model_status",
        access: Access::Read,
        description: "Summarize the trained path model, and warn when it was trained under a \
                      different ruleset than this store now applies.",
        params: &[],
    },
    // ── Store maintenance ──
    Tool {
        name: "gc",
        access: Access::Write,
        description: "Garbage-collect records unreachable from the newest scan.",
        params: &[],
    },
    Tool {
        name: "clean",
        access: Access::Destructive,
        description: "Delete the entire findings store directory. Irreversible. The catalog \
                      (datasets, rules, CWE) lives elsewhere and is untouched.",
        params: &[],
    },
];

/// The advertised tool list, as MCP `tools/list` expects it.
pub fn definitions() -> Value {
    let tools: Vec<Value> = TOOLS
        .iter()
        .map(|t| {
            let mut properties = serde_json::Map::new();
            for (name, ty, desc) in t.params {
                properties.insert(
                    (*name).to_string(),
                    json!({ "type": ty, "description": desc }),
                );
            }
            json!({
                "name": t.name,
                "description": format!("{} {}", t.access.tag(), t.description),
                "inputSchema": { "type": "object", "properties": properties },
            })
        })
        .collect();
    Value::Array(tools)
}

/// Whether `name` is an advertised tool. Lets the protocol layer tell an
/// unknown tool (a caller mistake, a JSON-RPC error) from a tool that ran and
/// failed (an `isError` result the agent should read).
pub fn exists(name: &str) -> bool {
    TOOLS.iter().any(|t| t.name == name)
}

/// Run one named tool with its arguments.
pub async fn dispatch(ctx: &Ctx, name: &str, args: &Value) -> anyhow::Result<String> {
    let text = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let number = |k: &str| args.get(k).and_then(Value::as_u64).map(|n| n as usize);

    match name {
        // Reading the findings graph.
        "search" => ops::search(ctx, &text("query")).await,
        "graph" => ops::graph(ctx, &text("query")).await,
        "neighbors" => ops::neighbors(ctx, &text("id")).await,
        "get" => ops::get(ctx, &text("id")).await,
        "analyze" => ops::analyze(ctx, &text("query"), &text("format")).await,
        "stats" => ops::stats(ctx).await,
        "export" => ops::export(ctx).await,

        // Reading the catalog and config.
        "rules" => ops::rules(ctx, &text("filter")).await,
        "cwe" => ops::cwe(ctx, &text("id")).await,
        "datasets" => ops::datasets(ctx).await,
        "feeds" => ops::feeds(ctx).await,
        "sources" => Ok(ops::sources()),
        "config" => ops::config(ctx),
        "plugin_settings" => ops::plugin_settings(ctx, &text("plugin")).await,

        // Scanning.
        "scan" => {
            let ports = text("ports");
            let driver = text("driver");
            let opts = Options {
                ports: (!ports.is_empty()).then_some(ports),
                max_pages: number("max_pages"),
                max_depth: number("max_depth"),
                driver: (!driver.is_empty()).then_some(driver),
                top_ports: 100,
            };
            let raw = text("budget");
            let budget = if raw.is_empty() {
                None
            } else {
                Some(raw.parse().map_err(|e| anyhow::anyhow!("{e}"))?)
            };
            ops::scan(ctx, &text("target"), &opts, budget).await
        }

        // Catalog maintenance.
        "pull" => ops::pull(ctx, &text("reference")).await,
        "feed_add" => ops::feed_add(ctx, &text("name"), &text("url")).await,
        "feed_rm" => ops::feed_rm(ctx, &text("name")).await,
        "dataset_rm" => ops::dataset_rm(ctx, &text("name")).await,
        "plugin_set" => ops::plugin_set(ctx, &text("plugin"), &text("key"), &text("value")).await,

        // Post-scan passes.
        "normalize" => ops::normalize(ctx).await,
        "annotate_cwe" => ops::annotate_cwe(ctx).await,
        "check_dns" => ops::check_dns(ctx).await,
        "check_whois" => {
            let days = args
                .get("recent_days")
                .and_then(Value::as_i64)
                .unwrap_or(30);
            ops::check_whois(ctx, days).await
        }

        // The path model.
        "model_train" => {
            ops::model_train(
                ctx,
                number("states").unwrap_or(8),
                number("iterations").unwrap_or(30),
            )
            .await
        }
        "model_score" => ops::model_score(ctx, &text("path")).await,
        "model_eval" => {
            let holdout = args.get("holdout").and_then(Value::as_f64).unwrap_or(0.3);
            ops::model_eval(ctx, holdout, number("states").unwrap_or(8)).await
        }
        "model_status" => ops::model_status(ctx).await,

        // Store maintenance.
        "gc" => ops::gc(ctx).await,
        "clean" => ops::clean(ctx),

        other => anyhow::bail!("unknown tool {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_is_dispatchable_and_tagged() {
        let defs = definitions();
        let list = defs.as_array().unwrap();
        assert_eq!(list.len(), TOOLS.len());
        for tool in list {
            let desc = tool["description"].as_str().unwrap();
            assert!(
                desc.starts_with('['),
                "{} lacks an access tag: {desc}",
                tool["name"]
            );
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn destructive_and_network_tools_are_marked() {
        let by_name = |n: &str| TOOLS.iter().find(|t| t.name == n).unwrap().access;
        assert_eq!(by_name("clean"), Access::Destructive);
        assert_eq!(by_name("scan"), Access::Network);
        assert_eq!(by_name("check_whois"), Access::Network);
        assert_eq!(by_name("search"), Access::Read);
        assert_eq!(by_name("gc"), Access::Write);
    }

    #[test]
    fn tool_names_are_unique() {
        let mut names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate tool name");
    }
}
