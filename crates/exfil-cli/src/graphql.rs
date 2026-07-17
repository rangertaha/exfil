//! GraphQL schema for the `exfil server` API.
//!
//! A read-only schema over the findings graph, served at `POST /graphql` (with
//! an interactive GraphiQL IDE at `GET /graphql`). It mirrors the REST routes —
//! findings, rules, stats — but lets a client ask for exactly the fields it
//! needs and filter findings in one round trip:
//!
//! ```graphql
//! { stats { total critical high }
//!   findings(query: "severity=critical") { rule path line severity } }
//! ```
//!
//! The [`Store`] is injected as schema data, so resolvers query it directly.

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema, SimpleObject};
use exfil_core::{Match, Severity};
use exfil_store::Store;

/// The concrete schema type served by the HTTP layer.
pub type ExfilSchema = Schema<Query, EmptyMutation, EmptySubscription>;

/// Lowercase severity name (`"critical"`, …) for GraphQL output.
fn severity_name(sev: Option<Severity>) -> Option<String> {
    sev.map(|s| format!("{s:?}").to_lowercase())
}

/// A single finding, exposed to GraphQL clients.
#[derive(SimpleObject)]
struct Finding {
    rule: String,
    path: String,
    line: u32,
    col: u32,
    snippet: String,
    severity: Option<String>,
    cwe: Option<String>,
    cve: Option<String>,
}

impl From<&Match> for Finding {
    fn from(m: &Match) -> Self {
        Finding {
            rule: m.rule.clone(),
            path: m.path.clone(),
            line: m.line,
            col: m.col,
            snippet: m.snippet.clone(),
            severity: severity_name(m.severity),
            cwe: m.cwe.clone(),
            cve: m.cve.clone(),
        }
    }
}

/// A detection rule, exposed to GraphQL clients.
#[derive(SimpleObject)]
struct Rule {
    name: String,
    description: String,
    severity: Option<String>,
    cwe: Option<String>,
    pattern: String,
}

/// Finding counts by severity.
#[derive(SimpleObject, Default)]
struct Stats {
    total: i32,
    critical: i32,
    high: i32,
    medium: i32,
    low: i32,
    info: i32,
}

/// The query root.
pub struct Query;

#[Object]
impl Query {
    /// Liveness probe.
    async fn health(&self) -> &'static str {
        "ok"
    }

    /// Findings, worst-first. `query` uses the same grammar as `exfil search`
    /// (`severity=high`, `path=…`, or free text); omit it to list all.
    async fn findings(
        &self,
        ctx: &Context<'_>,
        query: Option<String>,
    ) -> async_graphql::Result<Vec<Finding>> {
        let store = ctx.data::<Store>()?;
        let found = store
            .search_findings(query.as_deref().unwrap_or(""))
            .await?;
        Ok(found.iter().map(Finding::from).collect())
    }

    /// The built-in ruleset.
    async fn rules(&self) -> Vec<Rule> {
        exfil_scan::builtin_rules()
            .into_iter()
            .map(|r| Rule {
                name: r.name,
                description: r.description,
                severity: severity_name(r.severity),
                cwe: r.cwe,
                pattern: r.pattern,
            })
            .collect()
    }

    /// Total findings and a per-severity breakdown.
    async fn stats(&self, ctx: &Context<'_>) -> async_graphql::Result<Stats> {
        let store = ctx.data::<Store>()?;
        let found = store.search_findings("").await?;
        let count = |sev: Severity| found.iter().filter(|m| m.severity == Some(sev)).count() as i32;
        Ok(Stats {
            total: found.len() as i32,
            critical: count(Severity::Critical),
            high: count(Severity::High),
            medium: count(Severity::Medium),
            low: count(Severity::Low),
            info: count(Severity::Info),
        })
    }
}

/// Build the schema with the findings store injected as context data.
pub fn schema(store: Store) -> ExfilSchema {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .data(store)
        .finish()
}
