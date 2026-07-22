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

Some plugins also publish typed, validated settings beyond their
`[plugins.<name>]` table — see [`exfil plugin config`](commands.md#plugin-settings)
to override them interactively without editing this file. An override always
takes precedence over the value here.

## The findings store

The findings store (default `.exfil/`, override with `--store`) is local to the
scanned project and removed by `exfil store clean`. Downloaded rules/datasets
(the catalog) live in the user **data** directory instead — e.g.
`~/.local/share/exfil/catalog` on Linux — alongside their SurrealDB catalog
files, so they survive cleaning. Override with `$EXFIL_CATALOG_DIR`.

### System paths when running as root/Administrator

Running exfil with elevated privileges switches config, catalog, and the
default findings store to system-wide paths instead of the per-user ones
above:

| | Config | Catalog (downloaded rules) | Findings store (default) |
|---|---|---|---|
| Linux, as root | `/etc/exfil/config.toml` | `/var/lib/exfil/catalog` | `/var/lib/exfil/store` |
| Windows, elevated | `%ProgramData%\exfil\config.toml` | `%ProgramData%\exfil\catalog` | `%ProgramData%\exfil\store` |
| Otherwise (incl. macOS root) | per-user config dir | per-user data dir | `.exfil/` in the current directory |

`--store` and `$EXFIL_CATALOG_DIR` always override these. Note macOS and
Windows don't distinguish a config dir from a data dir, so the per-user
catalog and config paths coincide there — only Linux splits them
(`~/.config` vs `~/.local/share`).

## Database (`[database]`)

By default exfil uses an embedded, on-disk SurrealDB (no server to run). To
point every command at a remote SurrealDB server — or a **multi-instance
cluster** — set an endpoint (and, for a server, root credentials):

```toml
[database]
endpoint = "ws://db-cluster.internal:8000"   # or wss://, http(s)://, mem://
username = "root"
password = "change-me"
```

The endpoint's scheme selects the engine:

| Endpoint | Engine |
|---|---|
| *(unset)* | Embedded on-disk (findings under `--store`, catalog in the data dir) |
| `surrealkv:///abs/path` | Embedded on-disk at a specific path |
| `mem://` | Embedded in-memory (ephemeral) |
| `ws://host:8000`, `wss://…` | Remote SurrealDB server / cluster (WebSocket) |
| `http://host:8000`, `https://…` | Remote SurrealDB server / cluster (HTTP) |

For a cluster, run SurrealDB servers backed by a shared distributed store (e.g.
TiKV) and point `endpoint` at the cluster. When an endpoint is set, both the
findings and catalog databases live on that server (the `--store` path is
unused).
