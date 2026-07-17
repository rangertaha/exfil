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
| *(unset)* | Embedded on-disk (findings under `--store`, catalog in the config dir) |
| `surrealkv:///abs/path` | Embedded on-disk at a specific path |
| `mem://` | Embedded in-memory (ephemeral) |
| `ws://host:8000`, `wss://…` | Remote SurrealDB server / cluster (WebSocket) |
| `http://host:8000`, `https://…` | Remote SurrealDB server / cluster (HTTP) |

For a cluster, run SurrealDB servers backed by a shared distributed store (e.g.
TiKV) and point `endpoint` at the cluster. When an endpoint is set, both the
findings and catalog databases live on that server (the `--store` path is
unused).
