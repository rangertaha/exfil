//! Configurable key bindings for the graph navigator.
//!
//! Keys are decoupled from behavior: a [`NavAction`] names *what* a key does,
//! and a [`Keymap`] maps key strings to actions. The defaults are vim-style;
//! a `[keymap.nav]` table in config remaps any key. Motions are interpreted
//! relative to the focused pane, so one small action set covers both panes:
//! `Ascend`/`Descend` mean "toward the node view" / "toward and into edges",
//! and `Up`/`Down` move within the focused pane.

use std::collections::HashMap;

use crossterm::event::KeyCode;

/// A navigator action a key can be bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavAction {
    /// Move up in the focused pane (scroll view / previous edge).
    Up,
    /// Move down in the focused pane (scroll view / next edge).
    Down,
    /// Move toward the node view: focus it, or step back from it.
    Ascend,
    /// Move into edges: focus them, or follow the selected edge.
    Descend,
    /// Jumplist back.
    Back,
    /// Jumplist forward.
    Forward,
    /// Edit a field of the current node.
    Edit,
    /// Delete the selected edge.
    DeleteEdge,
    /// Undo the last edit.
    Undo,
    /// Redo the last undone edit.
    Redo,
    /// Leave the navigator.
    Quit,
}

impl NavAction {
    /// Parse an action name (as written in config).
    fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "Up" => Self::Up,
            "Down" => Self::Down,
            "Ascend" => Self::Ascend,
            "Descend" => Self::Descend,
            "Back" => Self::Back,
            "Forward" => Self::Forward,
            "Edit" => Self::Edit,
            "DeleteEdge" => Self::DeleteEdge,
            "Undo" => Self::Undo,
            "Redo" => Self::Redo,
            "Quit" => Self::Quit,
            _ => return None,
        })
    }
}

/// Normalize a key press to the string used in keymaps (`"j"`, `"Enter"`, …).
pub fn key_string(code: KeyCode) -> Option<String> {
    Some(match code {
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "Enter".into(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Backspace => "Backspace".into(),
        KeyCode::Up => "Up".into(),
        KeyCode::Down => "Down".into(),
        KeyCode::Left => "Left".into(),
        KeyCode::Right => "Right".into(),
        _ => return None,
    })
}

/// Key-to-action bindings for the navigator.
pub struct Keymap {
    nav: HashMap<String, NavAction>,
}

impl Keymap {
    /// The vim-style default bindings.
    pub fn defaults() -> Self {
        use NavAction::*;
        let pairs: &[(&str, NavAction)] = &[
            ("j", Down),
            ("Down", Down),
            ("k", Up),
            ("Up", Up),
            ("h", Ascend),
            ("Left", Ascend),
            ("l", Descend),
            ("Right", Descend),
            ("Tab", Descend),
            ("Enter", Descend),
            ("<", Back),
            ("Backspace", Back),
            (">", Forward),
            ("c", Edit),
            ("d", DeleteEdge),
            ("u", Undo),
            ("U", Redo),
            ("q", Quit),
            ("i", Quit),
            ("Esc", Quit),
        ];
        Self {
            nav: pairs.iter().map(|(k, a)| (k.to_string(), *a)).collect(),
        }
    }

    /// The defaults, with any `[keymap.nav]` config entries applied on top.
    /// Each entry is `key = "ActionName"`; an unknown action name is ignored.
    pub fn from_config(nav_overrides: Option<&toml::value::Table>) -> Self {
        let mut km = Self::defaults();
        if let Some(table) = nav_overrides {
            for (key, val) in table {
                if let Some(name) = val.as_str() {
                    if let Some(action) = NavAction::from_name(name) {
                        km.nav.insert(key.clone(), action);
                    }
                }
            }
        }
        km
    }

    /// The action bound to `code` in the navigator, if any.
    pub fn nav_action(&self, code: KeyCode) -> Option<NavAction> {
        key_string(code).and_then(|k| self.nav.get(&k).copied())
    }
}

impl Default for Keymap {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bindings() {
        let km = Keymap::defaults();
        assert_eq!(km.nav_action(KeyCode::Char('j')), Some(NavAction::Down));
        assert_eq!(km.nav_action(KeyCode::Enter), Some(NavAction::Descend));
        assert_eq!(km.nav_action(KeyCode::Char('<')), Some(NavAction::Back));
        assert_eq!(km.nav_action(KeyCode::Char('u')), Some(NavAction::Undo));
        assert_eq!(km.nav_action(KeyCode::Char('z')), None);
    }

    #[test]
    fn key_string_normalizes() {
        assert_eq!(key_string(KeyCode::Char('x')).as_deref(), Some("x"));
        assert_eq!(key_string(KeyCode::Tab).as_deref(), Some("Tab"));
        assert_eq!(key_string(KeyCode::F(1)), None);
    }

    #[test]
    fn config_remaps_keys() {
        // Rebind `x` to Edit and `Enter` to Back; leave the rest default.
        let mut table = toml::value::Table::new();
        table.insert("x".into(), toml::Value::String("Edit".into()));
        table.insert("Enter".into(), toml::Value::String("Back".into()));
        table.insert("bad".into(), toml::Value::String("Nonsense".into())); // ignored
        let km = Keymap::from_config(Some(&table));

        assert_eq!(km.nav_action(KeyCode::Char('x')), Some(NavAction::Edit));
        assert_eq!(km.nav_action(KeyCode::Enter), Some(NavAction::Back));
        // Unremapped defaults still apply.
        assert_eq!(km.nav_action(KeyCode::Char('j')), Some(NavAction::Down));
        // The invalid action name did not bind.
        assert_eq!(km.nav_action(KeyCode::Char('b')), None);
    }

    #[test]
    fn action_names_roundtrip() {
        for (name, action) in [
            ("Up", NavAction::Up),
            ("Descend", NavAction::Descend),
            ("DeleteEdge", NavAction::DeleteEdge),
            ("Redo", NavAction::Redo),
        ] {
            assert_eq!(NavAction::from_name(name), Some(action));
        }
        assert_eq!(NavAction::from_name("Frobnicate"), None);
    }
}
