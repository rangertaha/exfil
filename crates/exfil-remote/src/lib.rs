//! Non-interactive remote/local scan sources beyond a plain directory tree.
//!
//! Each of [`ProcessFs`], [`TcpFs`], [`WebFs`], and
//! [`webdriver::WebDriverFs`] implements the engine's
//! [`RemoteFs`](exfil_engine::RemoteFs) trait, so every scanner (secrets,
//! AST, taint, IOC, ClamAV, …) runs on their bytes exactly as on local files.
//! [`netscan`] expands a host/CIDR + port spec into `host:port` targets for
//! [`TcpFs`], and [`target`] resolves a user-typed spec to whichever of these
//! it names, so every front end dispatches a scan the same way.

pub mod netscan;
pub mod proc;
pub mod target;
pub mod tcp;
pub mod web;
pub mod webdriver;
pub use proc::ProcessFs;
pub use target::Target;
pub use tcp::TcpFs;
pub use web::WebFs;

/// Every plugin that publishes a config schema.
///
/// Lives here, beside the plugins themselves, rather than in the CLI binary:
/// the MCP server writes plugin overrides too, and a registry only the binary
/// could see meant the server had nothing to validate against — it stored
/// whatever it was handed, and an invalid override is silently ignored at read
/// time, which looks exactly like the setting having no effect.
pub const PLUGIN_SCHEMAS: &[exfil_config::PluginSchema] =
    &[netscan::PLUGIN_SCHEMA, web::PLUGIN_SCHEMA];

/// Find a plugin's schema and one of its fields by name.
pub fn find_plugin_field(
    plugin: &str,
    key: &str,
) -> Option<(
    &'static exfil_config::PluginSchema,
    &'static exfil_config::FieldSchema,
)> {
    let schema = PLUGIN_SCHEMAS.iter().find(|p| p.name == plugin)?;
    let field = schema.fields.iter().find(|f| f.key == key)?;
    Some((schema, field))
}
