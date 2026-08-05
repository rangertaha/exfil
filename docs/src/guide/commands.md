# Commands

Every command shares two global options:

| Option | Meaning |
|---|---|
| `-s, --store <PATH>` | Findings store location (default `.exfil`) |
| `-c, --config <PATH>` | Config file (default: user config dir, auto-created) |

Run `exfil <command> --help` for a command's own flags.

## Scanning

Every scanner is one command, `exfil scan [TARGET] [OPTIONS]` — the **shape of
`TARGET`** decides what gets scanned:

| Target shape | What it does |
|---|---|
| *(none)*, or a local path | Scan that directory tree (passive) |
| `processes` | Scan the local host's running processes (command lines, exe paths) — passive |
| `host:port`, or `host1:port1,host2:port2,…` | Grab and scan TCP service banners — active *(authorized testing only)* |
| a host or IPv4 CIDR + `--ports <list\|ranges\|common>` | Sweep those ports across the host/CIDR, grab banners, and scan them — active *(authorized testing only)*. `common` sweeps the top N ports by real-world frequency (default 100 — see [Plugin settings](#plugin-settings)) |
| an `http://` or `https://` URL | Crawl the site and scan the pages; `--max-pages`/`--max-depth` bound the crawl, `--driver <webdriver-url>` renders JS-heavy sites — active *(authorized testing only)* |

`-a`/`--active` and `-p`/`--passive` label the scan's summary line explicitly
(otherwise it's inferred from the target shape above); they're cosmetic only
and don't change what gets scanned.

### Gating CI

`--fail-on <severity>` makes `scan` exit non-zero when any stored finding is at
or above the given level (`info|low|medium|high|critical`), so a pipeline step
fails the build on real problems — this applies to any target shape, not just
local paths:

```sh
exfil scan --fail-on high  # exit 1 if any high/critical finding exists
```

See [Continuous Integration](./ci.md) for a full GitHub Actions example that
also uploads a SARIF report to code scanning.

## Querying findings

| Command | What it does |
|---|---|
| `exfil search [query] [-n N]` | Query stored findings, worst-first (by field like `severity=critical`, or free text; `-n` caps output) |
| `exfil get <id>` | Print a stored record by id (e.g. `file:<blake3-hash>`) |
| `exfil analyze` | Summarize the graph: counts, severities, and where findings cluster |
| `exfil report` | Render the full report (`--format text\|json\|markdown\|junit\|sarif\|pdf`, `--out FILE`) |

The raw graph and the active ruleset are not CLI commands; they are available to
agents as the `graph` and `rules` tools over [`exfil mcp`](#mcp).

## Ranked scanning

exfil can learn which parts of a filesystem are worth looking at, from the scans
already in your store, and spend a capped amount of work where findings actually
are.

| Command | What it does |
|---|---|
| `exfil train [--model KIND]` | Fit a path model on stored scans (every recorded file is a sample; a finding on it is the label) |
| `exfil model score <path>` | The model's `P(finding)` for a path, with each component's contribution |
| `exfil model get [name]` | Kind, base rate, the ruleset it was trained under, and whatever that kind can report |
| `exfil model eval` | Measure whether the model actually helps — recall at each budget, against a directory-frequency baseline and blind selection |

### Two kinds of model

`--model` on `train` picks **what to fit**; `--model` on `scan` picks **which
fitted model to use**, by the name it was saved under. A model that does not
exist yet can only be named by kind; one that does can only be named by name.

| Kind | What it is | When to prefer it |
|---|---|---|
| `path-hmm` *(default)* | Two Markov chains over path tokens — conditions on the whole sequence, so `.ssh` under a home directory means something different from `.ssh` under `/tmp/build-1234` | Most trees |
| `dir-prior` | A Laplace-smoothed finding rate per parent directory. No sequence, no states, and calibrated by construction — a frequency already *is* a probability | When `exfil model eval` reports that the baseline ties. It trains instantly and needs no calibration set, so a `90c` budget works on corpora too small to calibrate an HMM |

```sh
exfil train                                   # path-hmm, saved as "default"
exfil train --model dir-prior --name cheap    # the baseline, saved as "cheap"
exfil scan ./project --model cheap --budget 20%
```

Naming a model that is not stored is an error rather than a quiet fall back to
walk order — you asked for a ranking, and a typo would otherwise produce a
differently-shaped scan under a summary that looks the same.

Then bound the work:

```sh
exfil scan ./project --ranked        # worst-first; still scans everything
exfil scan ./project --budget 20%    # worst-first, stop at 20% of files
exfil scan ./project --budget 30s    # …or after 30 seconds
exfil scan ./project --budget 500mb  # …or after reading 500 MB
exfil scan ./project --budget 90c    # …or once 90% of the *expected* findings
                                     #    are accounted for (adapts to the tree)
```

`--budget` takes a suffix: `%` of files, `s`/`m`/`h` wall time, `kb`/`mb`/`gb`
read, a bare file count, or `c` for a share of the *expected findings* rather
than of the work — the one that adapts to how concentrated a tree's risk is. Percentages and counts are reproducible; a time
budget is not, so the file set it produced is recorded in the scan record.

> **A budgeted scan does not certify anything.** It prints its coverage, and it
> cannot be combined with `--fail-on` — a clean result from a 20% scan is not
> evidence a tree is clean. `--ranked` on its own has no such caveat: it scans
> everything, just worst-first, so `--fail-on` trips sooner.

> **Check before you trust it.** `exfil model eval` holds out part of your stored
> scans, ranks them with a model fitted on the rest, and reports how much it
> recovers at each budget — next to a plain directory-frequency prior. If the
> baseline ties, ranked scanning still beats walk order, but the sequence model
> isn't adding anything on your corpus.

Changed files always outrank unchanged ones regardless of the model: only they
can produce new findings, and the incremental index knows which they are with
certainty. See the [architecture chapter](../architecture/ranking.md).

## Correlation & enrichment

| Command | What it does |
|---|---|
| `exfil cwe <id>` | Look up a weakness in the local MITRE CWE catalog (e.g. `exfil cwe 798`) |

CIM normalization, CWE annotation, and the online DNS/WHOIS checks over observed
domains run as the `normalize`, `enrich`, `check_dns` and `check_whois` tools
over [`exfil mcp`](#mcp), not as CLI commands.

## Datasets & IOC feeds

| Command | What it does |
|---|---|
| `exfil sources` | List the available dataset source plugins |
| `exfil dataset` | Manage catalog datasets (`list` default; `add`/`get`/`remove`/`update`) |

`exfil dataset add <name> <reference>` is how a dataset enters the catalog from
the CLI; `exfil dataset update` re-fetches what is already configured:

```sh
exfil dataset update                    # every [[update]] entry in the config
exfil dataset update security           # just that entry, by its config name
exfil dataset update https://example.com/rules.csv   # or any source reference
exfil dataset update mitre://cwe        # the MITRE CWE catalog `exfil cwe` reads
```

A target is resolved against the config's `[[update]]` names first and treated
as a source reference only when no entry matches, so a name and a URL share one
argument without either shadowing the other. A configured entry is stored under
*its* name, so the config decides what a dataset is called. One failed fetch is
reported and the rest still run — a feed being down should cost you that
dataset, not the whole update.

Feed management remains an MCP tool set (`feeds`, `feed_add`, `feed_rm`,
`pull`).

## Plugin settings {#plugin-settings}

Each plugin can publish its own configurable settings beyond its
`[plugins.<name>]` config-file table — typed, validated, and overridable
without editing the config file. Overrides are stored in the catalog
database, so they persist independently of the config file and survive
`exfil store clean`.

`exfil plugin config <plugin>` interactively walks every setting on a
plugin — a select menu for fixed choices, a validated prompt for numbers —
each pre-filled with its current effective value.

A setting's effective value is resolved in order: the catalog override, then
the config file's `[plugins.<name>]` table, then the plugin's own built-in
default. Today's built-in plugin settings:

| Plugin | Setting | Meaning |
|---|---|---|
| `scan` | `top-ports` (1-2000, default 100) | How many ports `--ports common` sweeps, ranked most-common-first |

```sh
exfil plugin config scan   # interactive: prompts for top-ports, pre-filled with 100
```

## Store, interfaces & maintenance

| Command | What it does |
|---|---|
| `exfil mcp` | Run an MCP server on stdio giving AI agents exfil's whole tool surface (30 tools: query, scan, catalog, model, maintenance) |
| `exfil config` | Show the resolved config path and contents |
| `exfil store export` | Export the whole graph as a portable snapshot (CBOR or JSON) |
| `exfil store gc` | Garbage-collect unreachable records |
| `exfil store clean [-y]` | Delete the findings store (asks first on a terminal; `-y` skips) |
| `exfil completions <shell>` | Print a shell completion script (bash, zsh, fish, powershell, elvish) |

## AI agents (MCP)

`exfil mcp` speaks [MCP](https://modelcontextprotocol.io/) over stdio, exposing
**30 tools** — everything the CLI does, not just reading results. Point any MCP
client at the binary:

```jsonc
{ "mcpServers": { "exfil": { "command": "exfil", "args": ["mcp"] } } }
```

An agent can then scan a tree, query what it found, follow the graph, and render
a report, all in one session:

| Group | Tools |
|---|---|
| Query results | `search` `graph` `neighbors` `get` `analyze` `stats` `export` |
| Inspect config | `rules` `cwe` `datasets` `feeds` `sources` `config` `plugin_settings` |
| Scan | `scan` (path, `processes`, `host:port`, host/CIDR + ports, or a URL) |
| Manage catalog | `pull` `feed_add` `feed_rm` `dataset_rm` `plugin_set` |
| Post-scan passes | `normalize` `annotate_cwe` `check_dns` `check_whois` |
| Path model | `hmm_train` `hmm_score` `hmm_status` `hmm_eval` |
| Maintenance | `gc` `clean` |

Every tool's description is prefixed with what it does beyond reading, so an
agent sees the consequence before it calls:

- `[read-only]` — changes nothing
- `[writes to the local store]` — modifies the findings store or catalog
- `[network: reaches remote systems]` — `scan` on a remote target, `pull`,
  `check dns`, `check whois`
- `[DESTRUCTIVE: deletes stored data]` — `clean`

> Pass `--store` / `--config` to `exfil mcp` as usual; the server honors them for
> every tool. Since the surface includes network scans and store deletion, point
> it at a store you're willing to let an agent drive, and only scan targets you
> are authorized to scan.

## Feed catalog

A **feed** is a URL that publishes detection data. The catalog keeps a list of
them and ingests each through a pipeline — **fetch → decompress → detect format
→ parse → store** — turning it into a rule dataset that scans then apply.

Feeds are managed by agents over [`exfil mcp`](#mcp) (`feed_add`, `feed_rm`,
`feeds`, `pull`); the CLI reads the result with `exfil dataset`.

Supported formats (auto-detected by extension, after unpacking `.gz`/`.zip`/
`.tar`/`.tar.gz`):

| Format | Becomes |
|---|---|
| `.json` | Native exfil dataset, **STIX 2.x**, or **MISP** — auto-detected by content |
| `.csv` / `.tsv` | Regex rules — a header row maps `name`,`pattern`,`severity`,`cwe`,`description` |
| `.rss` / `.atom` / `.xml` | IOC rules — domains/IPs/URLs/hashes mined from item text (`.xml` is auto-detected as OpenIOC vs RSS) |
| `.ioc` / `.openioc` | OpenIOC XML — IOCs from each `IndicatorItem` (context path + content) |
| `.yar` / `.yara` | YARA rules — one per `rule { … }` block, compiled into the YARA scanner |
| `.toml` | gitleaks config — each `[[rules]]` (`id`/`regex`/`description`) becomes a regex rule |
| `.stix` / `.misp` | STIX/MISP threat intel — IOCs from indicator patterns / event attributes |
| other / `.txt` | IOC rules — one domain/IP/sha256 per line (`#` comments skipped) |

Each pulled feed becomes a dataset named after the feed; its rules join the
catalog and apply on the next scan.

### TAXII 2.x collections

A feed URL prefixed `taxii2+` is polled over the [TAXII 2.x](https://oasis-open.github.io/cti-documentation/taxii/intro.html)
transport instead of downloaded as a file. Point it at a collection's
`objects/` endpoint; exfil sends the TAXII media type, follows `more`/`next`
pagination, and normalizes the returned STIX objects into IOC rules. Basic-auth
credentials for a private collection go in the URL:

```text
taxii2+https://taxii.example.com/api/collections/<id>/objects/
taxii2+https://user:pass@taxii.example.com/api/collections/<id>/objects/
```

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
`exfil scan <url>` at a running WebDriver server (geckodriver/chromedriver) to
render each page in a headless browser first:

```sh
geckodriver --port 4444 &                                  # or chromedriver
exfil scan https://app.example.com --driver http://localhost:4444
```

exfil connects to the driver you run (it doesn't launch the browser). The
rendered, post-JavaScript DOM flows through the same scanners, so secrets and
indicators injected by scripts are caught.
