//! Plugin setting schemas: the typed, validated settings a plugin exposes
//! beyond its `[plugins.<name>]` config-file table, set via an interactive
//! wizard (`exfil plugin config <name>`) that renders a select menu or a
//! validated input per [`FieldKind`]. Overrides are stored in the catalog
//! database, so they persist independently of the config file and survive
//! `store clean`.
//!
//! This module only defines the shared vocabulary (`FieldKind`, `FieldSchema`,
//! `PluginSchema`) and how a field validates its input — the same
//! "define a trait, implement it, register it" seam as `Source`/`Reporter`/
//! `RemoteFs`. Each plugin crate publishes its own `PluginSchema` (e.g.
//! `exfil_remote::netscan::PLUGIN_SCHEMA`); `exfil-cli` collects the published
//! schemas into its registry, since this crate has no dependency on — and no
//! built-in knowledge of — any specific plugin.

/// The kind of value a setting holds, and how it is presented and validated.
#[derive(Debug, Clone, Copy)]
pub enum FieldKind {
    /// A whole number within `[min, max]`, entered as free-form text.
    Number {
        /// Smallest accepted value, inclusive.
        min: i64,
        /// Largest accepted value, inclusive.
        max: i64,
    },
    /// One of a fixed set of choices, shown as a select menu.
    Select(&'static [&'static str]),
    /// True or false, shown as a two-item select menu.
    Bool,
}

/// One configurable setting on a plugin.
#[derive(Debug, Clone, Copy)]
pub struct FieldSchema {
    /// The setting's name, e.g. `top-ports`.
    pub key: &'static str,
    /// A one-line description shown as the prompt/help text.
    pub description: &'static str,
    /// How the value is validated and presented.
    pub kind: FieldKind,
    /// The value used when no override or config-file entry exists.
    pub default: &'static str,
}

impl FieldSchema {
    /// Validate and normalize a raw input string against this field's kind.
    /// Returns the string to store, or a message explaining why it's invalid.
    pub fn validate(&self, raw: &str) -> Result<String, String> {
        let raw = raw.trim();
        match self.kind {
            FieldKind::Number { min, max } => {
                let n: i64 = raw
                    .parse()
                    .map_err(|_| format!("{raw:?} is not a whole number"))?;
                if n < min || n > max {
                    return Err(format!("{n} is out of range {min}..={max}"));
                }
                Ok(n.to_string())
            }
            FieldKind::Select(options) => {
                if options.contains(&raw) {
                    Ok(raw.to_string())
                } else {
                    Err(format!("{raw:?} is not one of {options:?}"))
                }
            }
            FieldKind::Bool => match raw.to_ascii_lowercase().as_str() {
                "true" | "yes" | "y" | "1" => Ok("true".to_string()),
                "false" | "no" | "n" | "0" => Ok("false".to_string()),
                _ => Err(format!("{raw:?} is not true/false")),
            },
        }
    }
}

/// A plugin's configurable settings.
#[derive(Debug, Clone, Copy)]
pub struct PluginSchema {
    /// The plugin's name, e.g. `scan`.
    pub name: &'static str,
    /// Its configurable settings, in display order.
    pub fields: &'static [FieldSchema],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_validates_range() {
        let f = FieldSchema {
            key: "n",
            description: "",
            kind: FieldKind::Number { min: 1, max: 10 },
            default: "5",
        };
        assert_eq!(f.validate("7").unwrap(), "7");
        assert!(f.validate("0").is_err());
        assert!(f.validate("11").is_err());
        assert!(f.validate("abc").is_err());
    }

    #[test]
    fn bool_accepts_common_spellings() {
        let f = FieldSchema {
            key: "b",
            description: "",
            kind: FieldKind::Bool,
            default: "false",
        };
        assert_eq!(f.validate("yes").unwrap(), "true");
        assert_eq!(f.validate("N").unwrap(), "false");
        assert!(f.validate("maybe").is_err());
    }

    #[test]
    fn select_rejects_unknown_option() {
        let f = FieldSchema {
            key: "s",
            description: "",
            kind: FieldKind::Select(&["a", "b"]),
            default: "a",
        };
        assert_eq!(f.validate("b").unwrap(), "b");
        assert!(f.validate("c").is_err());
    }
}
