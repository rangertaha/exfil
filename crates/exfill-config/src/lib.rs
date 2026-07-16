//! exfill's TOML configuration. A default config is embedded in the binary and
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

/// The embedded default configuration, written on first run.
pub const DEFAULT_CONFIG: &str = include_str!("../config.toml");

/// Top-level configuration.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Location of the local findings store (default `.exfill`).
    #[serde(default = "default_store")]
    pub store: String,
    /// Per-plugin tables, decoded on demand via [`Config::plugin`].
    #[serde(default)]
    pub plugins: BTreeMap<String, toml::Value>,
    /// Optional LLM settings.
    #[serde(default)]
    pub llm: Option<toml::Value>,
    /// Datasets/model to (re)download on `exfill update`.
    #[serde(default)]
    pub update: Vec<Update>,
    /// Optional `[keymap]` tables (e.g. `[keymap.nav]`) that remap TUI keys.
    #[serde(default)]
    pub keymap: Option<toml::Value>,
    /// Where this config was loaded from (not part of the file).
    #[serde(skip)]
    pub path: PathBuf,
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
    ".exfill".to_string()
}

/// The default config path in the user config directory
/// (e.g. `~/.config/exfill/config.toml`).
pub fn default_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("could not determine user config directory")?;
    Ok(dir.join("exfill").join("config.toml"))
}

/// The datasets/rules catalog directory. `$EXFILL_CATALOG_DIR` overrides the
/// default location in the user config dir (e.g. `~/.config/exfill/catalog`).
/// Survives `exfill clean`, which only removes the local findings store.
pub fn catalog_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("EXFILL_CATALOG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let dir = dirs::config_dir().context("could not determine user config directory")?;
    Ok(dir.join("exfill").join("catalog"))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("exfill-config-{}-{}", std::process::id(), name))
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
        assert_eq!(cfg.store, ".exfill");
        assert!(cfg.plugins.contains_key("regex"));
        assert!(cfg.plugins.contains_key("ast"));
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
        let cfg: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
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
        assert_eq!(cfg.store, ".exfill");
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
}
