# Commands

Every command shares two global options:

| Option | Meaning |
|---|---|
| `-s, --store <PATH>` | Findings store location (default `.exfil`) |
| `-c, --config <PATH>` | Config file (default: user config dir, auto-created) |

Run `exfil <command> --help` for a command's own flags.

## Scanning

| Command | What it does |
|---|---|
| `exfil scan [path]` | Scan a directory tree for secrets and security issues (`--fail-on <severity>` to gate CI) |
| `exfil scan-remote [user@]host:/path` | Scan a remote host over SSH/SFTP |
| `exfil processes` | Scan the local host's running processes (command lines, exe paths) |
| `exfil scan-tcp host:port…` | Grab and scan TCP service banners *(authorized testing only)* |
| `exfil port-scan <ip/cidr>` | Sweep ports, grab banners, and scan them *(authorized testing only)* |
| `exfil scan-web <url> [--driver URL]` | Crawl a website and scan the pages; `--driver` renders JS-heavy sites via a WebDriver browser *(authorized testing only)* |

### Gating CI

`--fail-on <severity>` makes `scan` exit non-zero when any stored finding is at
or above the given level (`info|low|medium|high|critical`), so a pipeline step
fails the build on real problems:

```sh
exfil scan --fail-on high        # exit 1 if any high/critical finding exists
```

## Querying findings

| Command | What it does |
|---|---|
| `exfil search [query] [-n N]` | Query stored findings, worst-first (by field like `severity=critical`, or free text; `-n` caps output) |
| `exfil get <id>` | Print a stored record by id (e.g. `file:<blake3-hash>`) |
| `exfil rules [filter]` | Show the rules a scan would apply (filter by name/CWE/severity substring) |
| `exfil graph` | Emit the findings graph (finding → file / rule) as JSON or DOT |
| `exfil analyze` | Analyze the whole graph and render a report (`--format text\|json\|markdown`) |

## Correlation & enrichment

| Command | What it does |
|---|---|
| `exfil normalize` | Normalize findings into Splunk-CIM events for cross-source correlation |
| `exfil enrich` | Enrich findings with triage notes and (if pulled) authoritative MITRE CWE names |
| `exfil cwe <id>` | Look up a weakness in the local MITRE CWE catalog (e.g. `exfil cwe 798`) |
| `exfil check-dns` | Resolve observed domains and flag reserved/private resolutions *(online)* |
| `exfil check-whois` | WHOIS-check observed domains and flag newly-registered ones *(online)* |

## Datasets & IOC feeds

| Command | What it does |
|---|---|
| `exfil sources` | List the available dataset source plugins |
| `exfil pull [reference]` | Download datasets (a `reference`, or every configured update); `mitre://cwe` fetches the MITRE CWE catalog |
| `exfil datasets` | Manage catalog datasets (`list` default; `add`/`show`/`rm`) |
| `exfil feeds` | Manage the URL feed catalog and pull feeds into rule datasets (`list` default; `add`/`rm`/`pull`) |

## Store, interfaces & maintenance

| Command | What it does |
|---|---|
| `exfil tui` | Open the mutt-style TUI: scan, browse, and query the graph live |
| `exfil mcp` | Run an MCP server on stdio for AI agents |
| `exfil server [--addr H:P]` | Run a long-lived HTTP API service over the findings graph |
| `exfil config` | Show the resolved config path and contents |
| `exfil export` | Export the whole graph as a portable snapshot (CBOR or JSON) |
| `exfil gc` | Garbage-collect unreachable records |
| `exfil clean [-y]` | Delete the findings store (asks first on a terminal; `-y` skips) |
| `exfil completions <shell>` | Print a shell completion script (bash, zsh, fish, powershell, elvish) |

## Feed catalog

A **feed** is a URL that publishes detection data. `exfil feeds` keeps a catalog
of them and ingests each through a pipeline — **fetch → decompress → detect
format → parse → store** — turning it into a rule dataset that scans then apply:

```sh
exfil feeds add secrets https://example.com/rules.csv      # regex rules
exfil feeds add threats https://example.com/iocs.txt.gz    # IOC list (gzipped)
exfil feeds list
exfil feeds pull                                           # fetch all → datasets
```

Supported formats (auto-detected by extension, after unpacking `.gz`/`.zip`/
`.tar`/`.tar.gz`):

| Format | Becomes |
|---|---|
| `.json` | Native exfil dataset (name + rules) |
| `.csv` / `.tsv` | Regex rules — a header row maps `name`,`pattern`,`severity`,`cwe`,`description` |
| `.rss` / `.atom` / `.xml` | IOC rules — domains/IPs/URLs/hashes mined from item titles, links, and bodies |
| `.yar` / `.yara` | YARA rules — one per `rule { … }` block, compiled into the YARA scanner |
| other / `.txt` | IOC rules — one domain/IP/sha256 per line (`#` comments skipped) |

Each pulled feed becomes a dataset named after the feed; its rules join the
catalog and apply on the next scan.

## Shell completions

Generate a completion script for your shell and install it so `exfil <Tab>`
completes subcommands and flags:

```sh
# bash
exfil completions bash | sudo tee /etc/bash_completion.d/exfil > /dev/null

# zsh (ensure the dir is on your $fpath)
exfil completions zsh > ~/.zfunc/_exfil

# fish
exfil completions fish > ~/.config/fish/completions/exfil.fish
```

> The banner-grabbing and web/port scanners reach out over the network and are
> intended for **authorized security testing only**. The core filesystem, code,
> and archive scanning is fully offline.

### Dynamic sites (WebDriver)

Static crawling misses content that JavaScript builds at runtime. Point
`scan-web` at a running WebDriver server (geckodriver/chromedriver) to render
each page in a headless browser first:

```sh
geckodriver --port 4444 &                                  # or chromedriver
exfil scan-web https://app.example.com --driver http://localhost:4444
```

exfil connects to the driver you run (it doesn't launch the browser). The
rendered, post-JavaScript DOM flows through the same scanners, so secrets and
indicators injected by scripts are caught.

## HTTP API server

`exfil server` runs a long-lived, read-only HTTP service over the findings
store, shutting down gracefully on Ctrl-C or SIGTERM:

```sh
exfil server                       # binds 127.0.0.1:8080
exfil server --addr 0.0.0.0:9000   # serve other hosts
```

| Route | Returns |
|---|---|
| `GET /health` | `{"status":"ok","service":"exfil"}` |
| `GET /findings` | Every finding, worst-first (JSON array) |
| `GET /findings?q=<filter>` | Filtered — same grammar as `search` (`severity=high`, `path=…`, text) |
| `GET /rules` | The built-in ruleset |
| `GET /stats` | Total findings and a per-severity breakdown |
| `GET /graphql` | Interactive GraphiQL IDE |
| `POST /graphql` | Execute a GraphQL query |

It is read-only, so it is safe to expose, but bind it to loopback unless you
intend to serve other hosts.

### GraphQL

`POST /graphql` runs a query against a read-only schema (`health`, `findings`,
`rules`, `stats`), so a client can ask for exactly the fields it needs:

```graphql
{
  stats { total critical high }
  findings(query: "severity=critical") { rule path line severity cwe }
}
```

```sh
curl -s localhost:8080/graphql -H 'content-type: application/json' \
  -d '{"query":"{ stats { total critical } }"}'
```

Open `http://localhost:8080/graphql` in a browser for the GraphiQL IDE.
