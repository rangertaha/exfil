# Configuration

The first run writes a default TOML config to the user config directory
(e.g. `~/.config/exfil/config.toml`). Each plugin has its own
`[plugins.<name>]` table:

```toml
store = ".exfil"

[plugins.regex]
datasets = []            # empty = built-in security ruleset

[plugins.ast]
languages = ["go", "python", "javascript", "rust"]
```

Show the resolved config path and contents at any time with:

```sh
exfil config
```

## The findings store

The findings store (default `.exfil/`, override with `--store`) is local to the
scanned project and removed by `exfil clean`. Downloaded datasets live in the
config directory instead, so they survive cleaning.
