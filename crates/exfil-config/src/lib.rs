//! exfil's TOML configuration. A default config is embedded in the binary and
//! written to the user config directory on first run. Each plugin is a
//! `[plugins.<name>]` table decoded on demand into the plugin's own struct.
//!
//! # Rust notes
//!
//! - `include_str!("../config.toml")` pastes that file's contents into the
//!   binary *at compile time* as a `&'static str` — the default config ships
//!   inside the executable, no install step needed.
//! - Functions here return `Result<T>` (anyhow's alias for
//!   `Result<T, anyhow::Error>`). The `?` operator after a fallible call means
//!   "if this failed, return the error to my caller now" — it replaces
//!   try/catch pyramids with a single character.
//! - `.with_context(|| ...)` (from anyhow) wraps an error with a description
//!   of what we were *trying* to do, so failures read like a story:
//!   `read config /path: No such file or directory`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

mod schema;
pub use schema::{FieldKind, FieldSchema, PluginSchema};

/// The embedded default configuration, written on first run.
pub const DEFAULT_CONFIG: &str = include_str!("../config.toml");

/// Top-level configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Location of the local findings store (default `.exfil`).
    #[serde(default = "default_store")]
    pub store: String,
    /// Per-plugin tables, decoded on demand via [`Config::plugin`].
    #[serde(default)]
    pub plugins: BTreeMap<String, toml::Value>,
    /// Optional LLM settings.
    #[serde(default)]
    pub llm: Option<toml::Value>,
    /// Datasets/model to (re)download on `exfil update`.
    #[serde(default)]
    pub update: Vec<Update>,
    /// Optional `[database]` connection settings (embedded by default).
    #[serde(default)]
    pub database: Option<Database>,
    /// Where this config was loaded from (not part of the file).
    #[serde(skip)]
    pub path: PathBuf,
}

/// `[database]` connection settings. The `endpoint` selects the SurrealDB
/// engine: embedded on-disk (`surrealkv://<path>`), in-memory (`mem://`), or a
/// remote server / cluster (`ws://`, `wss://`, `http://`, `https://`). An empty
/// endpoint keeps the built-in embedded default (findings under `--store`,
/// catalog in the data dir). `username`/`password` sign in to a remote server.
#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    /// Connection endpoint; empty for the embedded default.
    #[serde(default)]
    pub endpoint: String,
    /// Root username for a remote server (empty = no sign-in).
    #[serde(default)]
    pub username: String,
    /// Root password for a remote server.
    #[serde(default)]
    pub password: String,
}

/// One `[[update]]` entry.
#[derive(Debug, Deserialize)]
pub struct Update {
    /// Name the fetched dataset/model is stored under.
    pub name: String,
    /// Where to fetch it from (`builtin://…`, a file path, or a URL).
    /// (`ref` is a Rust keyword, so the field is renamed for serde.)
    #[serde(rename = "ref")]
    pub reference: String,
}

fn default_store() -> String {
    ".exfil".to_string()
}

/// True when exfil should use system-wide paths instead of the per-user
/// dirs: root (uid 0) on Linux, or an elevated/Administrator process on
/// Windows. Any other platform (e.g. macOS) always keeps per-user dirs, even
/// as root, since it has no equivalent system convention for this.
fn use_system_dirs() -> bool {
    cfg!(any(target_os = "linux", windows)) && is_root::is_root()
}

/// The system-wide config directory: `/etc` on Linux, `%ProgramData%` on
/// Windows (falling back to `C:\ProgramData` if the env var is unset).
fn system_config_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    } else {
        PathBuf::from("/etc")
    }
}

/// The system-wide data directory: `/var/lib` on Linux, or the same
/// `%ProgramData%` used for config on Windows (which has no config/data
/// split analogous to Linux's `/etc` vs `/var/lib`).
fn system_data_dir() -> PathBuf {
    if cfg!(windows) {
        system_config_dir()
    } else {
        PathBuf::from("/var/lib")
    }
}

/// The default config path: the user config directory (e.g.
/// `~/.config/exfil/config.toml`), or `/etc/exfil/config.toml`
/// (`%ProgramData%\exfil\config.toml` on Windows) when running with
/// elevated privileges.
pub fn default_path() -> Result<PathBuf> {
    if use_system_dirs() {
        return Ok(system_config_dir().join("exfil").join("config.toml"));
    }
    let dir = dirs::config_dir().context("could not determine user config directory")?;
    Ok(dir.join("exfil").join("config.toml"))
}

/// The datasets/rules catalog directory: the downloaded rules, sitting
/// alongside their SurrealDB catalog files. `$EXFIL_CATALOG_DIR` overrides
/// the default location in the user data dir (e.g. `~/.local/share/exfil/
/// catalog` on Linux; same as the config dir on macOS/Windows, which don't
/// distinguish the two), or `/var/lib/exfil/catalog`
/// (`%ProgramData%\exfil\catalog` on Windows) when running with elevated
/// privileges. Survives `exfil store clean`, which only removes the local
/// findings store.
pub fn catalog_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("EXFIL_CATALOG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if use_system_dirs() {
        return Ok(system_data_dir().join("exfil").join("catalog"));
    }
    let dir = dirs::data_dir().context("could not determine user data directory")?;
    Ok(dir.join("exfil").join("catalog"))
}

/// The default findings-store directory used when `--store` is not given:
/// the current directory's `.exfil`, or `/var/lib/exfil/store`
/// (`%ProgramData%\exfil\store` on Windows) when running with elevated
/// privileges.
pub fn default_store_dir() -> PathBuf {
    if use_system_dirs() {
        system_data_dir().join("exfil").join("store")
    } else {
        PathBuf::from(default_store())
    }
}

/// Load the config. With no explicit path, use the user config directory,
/// writing the embedded default there if none exists yet.
pub fn load(explicit: Option<&Path>) -> Result<Config> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => default_path()?,
    };
    if explicit.is_none() && !path.exists() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create config dir {}", dir.display()))?;
        }
        std::fs::write(&path, DEFAULT_CONFIG)
            .with_context(|| format!("write default config {}", path.display()))?;
    }
    let src = std::fs::read_to_string(&path)
        .with_context(|| format!("read config {}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&src).with_context(|| format!("parse config {}", path.display()))?;
    cfg.path = path;
    Ok(cfg)
}

impl Config {
    /// Decode a named plugin's table into its own config struct, returning
    /// `None` when the plugin has no block.
    ///
    /// This is a *generic* function: `T` is whatever struct the caller asks
    /// for, e.g. `cfg.plugin::<RegexCfg>("regex")`. The `where` clause
    /// constrains `T` to types serde can deserialize into (the `for<'de>`
    /// syntax just means "from borrowed data of any lifetime" — a standard
    /// incantation for "owns its data after decoding").
    pub fn plugin<T>(&self, name: &str) -> Result<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.plugins.get(name) {
            Some(v) => {
                Ok(Some(v.clone().try_into().with_context(|| {
                    format!("decode config for plugin {name:?}")
                })?))
            }
            None => Ok(None),
        }
    }

    /// Read one field of a `[plugins.<name>]` table as a plain string
    /// (stringifying a TOML string/integer/float/bool), for schema-driven
    /// settings (see `FieldSchema`) that don't warrant their own struct.
    /// `None` only when the plugin or field is genuinely absent — a
    /// present-but-wrong-shape value (e.g. an array or table) still returns
    /// `None`, since there's no sensible string for it, but a float is
    /// stringified rather than treated as absent, so a caller validating the
    /// result (e.g. against `FieldKind::Number`, which is integers only) sees
    /// a clear "not a whole number" rejection instead of silently falling
    /// back to the schema default as if nothing were configured.
    pub fn plugin_field(&self, plugin: &str, key: &str) -> Option<String> {
        let table = self.plugins.get(plugin)?;
        let value = table.get(key)?;
        if let Some(s) = value.as_str() {
            return Some(s.to_string());
        }
        if let Some(i) = value.as_integer() {
            return Some(i.to_string());
        }
        if let Some(f) = value.as_float() {
            return Some(f.to_string());
        }
        value.as_bool().map(|b| b.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("exfil-config-{}-{}", std::process::id(), name))
    }

    #[derive(Debug, Deserialize)]
    struct RegexCfg {
        datasets: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    struct AstCfg {
        languages: Vec<String>,
    }

    #[test]
    fn embedded_default_parses() {
        let cfg: Config = toml::from_str(DEFAULT_CONFIG).expect("embedded default is valid TOML");
        // Every option is documented but commented out, so the defaults apply:
        // `store` falls back to its default and no plugin blocks are active.
        assert_eq!(cfg.store, ".exfil");
        assert!(
            cfg.plugins.is_empty(),
            "options are documented but commented out"
        );
        // The shipped security dataset is the one active entry.
        assert_eq!(cfg.update.len(), 1);
        assert_eq!(cfg.update[0].name, "security");
        assert_eq!(cfg.update[0].reference, "builtin://security");
    }

    #[test]
    fn load_explicit_path() {
        let path = tmp("explicit.toml");
        std::fs::write(
            &path,
            "store = \"/tmp/s\"\n[plugins.regex]\ndatasets = [\"a\"]\n",
        )
        .unwrap();
        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.store, "/tmp/s");
        assert_eq!(cfg.path, path);
        let regex: RegexCfg = cfg.plugin("regex").unwrap().expect("regex block present");
        assert_eq!(regex.datasets, ["a"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_explicit_missing_file_errors() {
        let err = load(Some(&tmp("does-not-exist.toml"))).unwrap_err();
        assert!(err.to_string().contains("read config"), "{err}");
    }

    #[test]
    fn load_explicit_invalid_toml_errors() {
        let path = tmp("invalid.toml");
        std::fs::write(&path, "store = [not toml").unwrap();
        let err = load(Some(&path)).unwrap_err();
        assert!(err.to_string().contains("parse config"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn plugin_decoding() {
        let cfg: Config = toml::from_str(
            "[plugins.ast]\nlanguages = [\"rust\", \"go\"]\n\
             [plugins.regex]\ndatasets = [\"a\"]\n",
        )
        .unwrap();
        // Present block decodes into the plugin's own struct.
        let ast: AstCfg = cfg.plugin("ast").unwrap().expect("ast block present");
        assert!(ast.languages.contains(&"rust".to_string()));
        // Absent block is None, not an error.
        assert!(cfg.plugin::<AstCfg>("no-such-plugin").unwrap().is_none());
        // Present block with mismatched shape is an error naming the plugin.
        let err = cfg.plugin::<AstCfg>("regex").unwrap_err();
        assert!(err.to_string().contains("regex"), "{err}");
    }

    #[test]
    fn first_run_writes_default_into_config_dir() {
        // Point the config dir at a temp location so the real one is untouched.
        // (`dirs` honors XDG_CONFIG_HOME on Linux.)
        let home = tmp("xdg-home");
        let _ = std::fs::remove_dir_all(&home);
        std::env::set_var("XDG_CONFIG_HOME", &home);

        let cfg = load(None).expect("first load writes the default");
        assert_eq!(cfg.store, ".exfil");
        assert!(
            cfg.path.starts_with(&home),
            "config written under temp XDG home"
        );
        assert!(cfg.path.exists());

        // Second load reads the file it wrote.
        let again = load(None).unwrap();
        assert_eq!(again.path, cfg.path);

        std::env::remove_var("XDG_CONFIG_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn store_defaults_when_omitted() {
        // A config file that omits `store` falls back to default_store().
        let path = tmp("no-store.toml");
        std::fs::write(&path, "[plugins.regex]\ndatasets = []\n").unwrap();
        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.store, ".exfil");
        assert_eq!(cfg.path, path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn plugin_field_stringifies_every_scalar_kind() {
        let cfg: Config = toml::from_str(
            "[plugins.scan]\n\
             top-ports = 500\n\
             ratio = 1.5\n\
             label = \"x\"\n\
             enabled = true\n",
        )
        .unwrap();
        assert_eq!(cfg.plugin_field("scan", "top-ports"), Some("500".into()));
        // A float is stringified, not silently treated as absent — a caller
        // validating against an integer-only field sees a clear rejection
        // instead of the value vanishing as if unconfigured.
        assert_eq!(cfg.plugin_field("scan", "ratio"), Some("1.5".into()));
        assert_eq!(cfg.plugin_field("scan", "label"), Some("x".into()));
        assert_eq!(cfg.plugin_field("scan", "enabled"), Some("true".into()));
        assert_eq!(cfg.plugin_field("scan", "no-such-key"), None);
        assert_eq!(cfg.plugin_field("no-such-plugin", "top-ports"), None);
    }
}
