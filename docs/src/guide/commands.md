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
| `exfil scan-web <url>` | Crawl a website from a seed URL and scan the pages *(authorized testing only)* |

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
| `exfil search [query]` | Query stored findings (by field like `severity=critical`, or free text) |
| `exfil get <id>` | Print a stored record by id (e.g. `file:<blake3-hash>`) |
| `exfil rules [filter]` | Show the rules a scan would apply (filter by name/CWE/severity substring) |
| `exfil graph` | Emit the findings graph (finding → file / rule) as JSON or DOT |
| `exfil analyze` | Analyze the whole graph and render a report (`--format text\|json\|markdown`) |

## Correlation & enrichment

| Command | What it does |
|---|---|
| `exfil normalize` | Normalize findings into Splunk-CIM events for cross-source correlation |
| `exfil enrich` | Run the offline LLM enrichment pass over the stored graph |
| `exfil check-dns` | Resolve observed domains and flag reserved/private resolutions *(online)* |
| `exfil check-whois` | WHOIS-check observed domains and flag newly-registered ones *(online)* |

## Datasets & IOC feeds

| Command | What it does |
|---|---|
| `exfil sources` | List the available dataset source plugins |
| `exfil pull [reference]` | Download datasets (a specific `reference`, or every configured update) |
| `exfil datasets` | Manage catalog datasets (`list` default; `add`/`show`/`rm`) |

## Store, interfaces & maintenance

| Command | What it does |
|---|---|
| `exfil tui` | Open the mutt-style TUI: scan, browse, and query the graph live |
| `exfil mcp` | Run an MCP server on stdio for AI agents |
| `exfil config` | Show the resolved config path and contents |
| `exfil export` | Export the whole graph as a portable snapshot (CBOR or JSON) |
| `exfil gc` | Garbage-collect unreachable records |
| `exfil clean [-y]` | Delete the findings store (asks first on a terminal; `-y` skips) |
| `exfil completions <shell>` | Print a shell completion script (bash, zsh, fish, powershell, elvish) |

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
