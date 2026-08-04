# exfil CLI — design

A command surface, part shipped and part still proposed. When this was written
the CLI had 20 top-level commands that mixed verbs (`scan`, `pull`, `enrich`,
`normalize`, `check`) with nouns (`sources`, `datasets`, `feeds`, `rules`,
`config`, `store`, `plugin`), spelled the same concept four ways (`sources` /
`datasets` / `feeds` / `rules` are all "where rules come from"), and guessed
what you meant from the shape of a string.

It is 15 today. The **§0 status** below is what actually happened; everything
after it is the design as written, kept intact so the reasoning stays legible
next to the parts that have not been built.

Three principles drive the redesign:

1. **Nouns are managed, verbs are run.** Anything you *manage* is a singular
   noun carrying `list`, `get` and `remove`, plus whichever of `add`, `set` and
   `purge` mean something for it. Anything you *do* is a bare verb — `scan`,
   `train`, `search`. Nothing is both.
2. **Nothing is inferred that changes what the tool touches.** Today
   `exfil scan example.com:22` reaches the network because the string has a
   colon in it. Reaching a remote system is opt-in, never a parse result.
3. **Human output is for reading, machine output is exact.** Text is fitted to
   the window; `--format json` and file exports are never truncated.

---

## 0. Status

Today's surface, for comparison with §1: `sources` · `datasets` · `scan` ·
`search` · `analyze` · `report` · `train` · `model` · `cwe` · `config` ·
`store` · `mcp` · `get` · `completions` · `plugin`.

### Shipped as designed

| Design | Where |
|---|---|
| `train` promoted to a top-level verb | §3, deviation 6 |
| `model list · get · score · eval · remove` — the verbs that *read* a model back | §1 |
| `report` with `-f/--format` and `-o/--out`, `analyze` kept beside it | §1, deviation 5 |
| `dataset update [<name>]` | §1 |
| `--model <NAME>` on `scan` | §1 |
| `store export · gc · clean` left alone | §6 |
| Dropping `pull`, `feeds`, `rules`, `check`, `normalize`, `graph`, `enrich` | §6 |

### Shipped, but not the way §6 said

The dropped commands did **not** each become the CLI replacement the table
names. They became **MCP tools**, on the argument that a second way to ask the
same question from a shell is the thing worth removing, not the capability:

| §6 said | What happened |
|---|---|
| `rules` → `dataset search <query>` | MCP `rules` tool; `dataset search` unbuilt |
| `normalize` → `report -f cim` | MCP `normalize` tool |
| `graph` → `report -f dot` / `-f graph-json` | MCP `graph` tool |
| `check dns\|whois` → `scan -a -p dns\|whois` | MCP `check_dns` / `check_whois` tools |
| `pull <ref>` → `dataset add -n <name> <ref>` | `datasets add <name> <ref>` — positional, no `-n` |
| `pull mitre://cwe` → `dataset add` | `datasets update mitre://cwe` |
| `cwe <id>` → `dataset get mitre-cwe` | `cwe <id>` kept as its own command |
| the noun is `dataset` | it is `datasets`, plural, matching what was already typed |

Three further departures, all deliberate:

- **`run` was built and then removed** (deviation 3 said a name without a way to
  list runs is write-only). Runs are still named by `scan --name` and addressed
  by `analyze -n` and `search run=`; enumerating them is an MCP tool. The
  write-only concern stands — this is a known debt, not a resolved question.
- **`--confidence <P>` folded into `--budget 90c`.** One flag that answers "when
  do I stop", with a suffix saying which currency, beat two flags that both stop
  a scan. `--budget` and `--fail-on` conflict for the same reason.
- **`--model` means two things**, which the design did not anticipate: a *kind*
  on `train` (`path-hmm`, `dir-prior`) and a stored *name* on `scan`. A model
  that does not exist yet can only be named by kind; one that does, only by name.

### Not built

The headline idea is among these — §2 is still a proposal:

| Design | Note |
|---|---|
| `-p/--plugin` picks the scanner; the positional is only ever a target | §2. `scan` still infers from the target's shape |
| `-a/--active` as a **permission** rather than a summary label | §2, principle 2. Still cosmetic today |
| `sources` → `dataset add --help` | `sources` is still a command |
| `config` → `--show-config`, `completions <shell>` → `--completions` | both still commands |
| `plugin list · get · set · remove` | only the interactive `plugin config` exists |
| `dataset search <query>` | — |
| `search -n` → `--limit`/`-l`, freeing `-n` for *name* everywhere | `search -n` is still the limit |
| `-q/--quiet`, `-v/--verbose`, global `--format` | — |

---

## 1. The surface

```
SCAN                                     produce findings
  exfil scan [TARGET...]                 passive, current directory by default
      -n, --name <NAME>                  name this run
      -a, --active                       allow reaching remote systems
      -p, --plugin <LIST>                only these scanners
      -b, --budget <SPEC>                stop after N files / a time / a share
          --confidence <P>               stop at P estimated recall
          --model <NAME>                 rank with this model  [default]
          --fail-on <SEVERITY>           exit 2 at or above this severity

TRAIN                                    produce a model
  exfil train [-n <NAME>]                fit the path model on stored scans
          --states <N>                   latent states           [default: 12]
          --iterations <N>               max Baum-Welch passes   [default: 30]
          --vocab <N>                    distinct path tokens    [default: 4096]

READ                                     ask about findings
  exfil search <QUERY>                   matching findings, worst first
  exfil analyze [-n <RUN>]               counts, risk score, hotspots
  exfil report [-n <RUN>]                write a report to a file
      -f, --format <FMT>                 text·json·markdown·junit·sarif·pdf·dot
      -o, --out <FILE>                   default: stdout
  exfil get <ID>                         one record as JSON

RUN                                      named scans
  exfil run list                         newest first
  exfil run get <NAME>
  exfil run remove <NAME>

DATASET                                  bundles of rules
  exfil dataset list
  exfil dataset add -n <NAME> <URL>
  exfil dataset get <NAME>
  exfil dataset search <QUERY>
  exfil dataset update [<NAME>]          all when no name is given
  exfil dataset remove <NAME>
  exfil dataset purge <NAME>

PLUGIN                                   scanners and their settings
  exfil plugin list
  exfil plugin get <NAME>
  exfil plugin set <NAME> <KEY> <VALUE>
  exfil plugin remove <NAME> [KEY]

MODEL                                    inspect what training produced
  exfil model list
  exfil model get <NAME>                 states, vocabulary, base rate, ruleset
  exfil model score <PATH>               P(finding), with each contribution
  exfil model eval [--holdout <P>]       recall at budget, vs. two baselines
  exfil model remove <NAME>

STORE                                    the database itself
  exfil store export | gc | clean

AGENTS
  exfil mcp                              MCP over stdio

GLOBAL
  -s, --store <PATH>       -c, --config <FILE>      --color <WHEN>
  -q, --quiet              -v, --verbose            --format <text|json>
      --completions <SHELL>                     -h, --help    -V, --version
```

Twelve entry points instead of twenty. Four of them (`run`, `dataset`,
`plugin`, `model`) are nouns that behave identically; `store` is the deliberate
exception, since `export`/`gc`/`clean` are operations on the database rather
than on records in it.

---

## 2. Scan: say what you mean

The current `scan` takes one positional and works out from its shape whether it
is a path, the literal `processes`, a `host:port`, a CIDR to sweep, or a URL to
crawl — then attaches `--ports`, `--max-pages`, `--max-depth` and `--driver`,
each of which only applies to one of those shapes. That is one command wearing
five hats, and it is why its help text is the longest in the tool.

**`-p/--plugin` chooses the scanner; the positional is only ever the target.**

```sh
exfil scan                          # cwd, passive
exfil scan ~/project src/           # several paths
exfil scan -p process               # local processes
exfil scan -a -p port  10.0.0.0/28  # port sweep, network opt-in
exfil scan -a -p web   https://x.y  # crawl
exfil scan -a -p banner x.y:22,x.y:443
```

`--passive` is the default and needs no flag. `-a/--active` is what unlocks any
plugin that leaves the machine; without it those plugins refuse rather than
silently staying local, so a CI job that omits `-a` cannot accidentally touch
the network. Passive/active stops being a *label on the summary* — which is all
it is today — and becomes the permission it was always describing.

Plugin-specific options move behind the plugin, where they are discoverable and
cannot clutter a scan that will never use them:

```sh
exfil plugin set web max-pages 200
exfil plugin set web driver http://localhost:4444
exfil plugin set port list common
```

`exfil scan --help` then fits on a screen, and `exfil plugin get web` documents
exactly the knobs that apply.

### Names

`-n/--name` labels the run. Without one, a run is still recorded under a
generated name (`2026-08-03T14-22-scan`), so `-n` is a convenience, not a
requirement — nothing is unaddressable.

```sh
exfil scan -n nightly ~/project
exfil analyze -n nightly
exfil report  -n nightly -f pdf -o nightly.pdf
```

Runs need to be listable or `-n` is write-only, hence `exfil run list`. A run
name is also an ordinary search field, so the low-level path stays open:

```sh
exfil search 'run=nightly severity=critical'
```

---

## 3. Train: the second thing that produces something

`train` is top-level rather than `model train` because principle 1 puts it
there. Two commands in this tool do work and write a result; everything else
reads one back:

| Produced by | Read by |
|---|---|
| `exfil scan` → findings | `search` · `analyze` · `report` · `get` |
| `exfil train` → a model | `model get` · `model score` · `model eval` |

So `model` is left holding only what it should: the five management verbs over
models that already exist. `train` reads the scans `scan` wrote, which makes the
pairing visible at the top level instead of buried a level down.

```sh
exfil scan ~/project              # gather evidence
exfil train                       # learn from it
exfil scan -b 20% ~/project       # a fifth of the work, on the likeliest fifth
```

Training more than one model is then ordinary, not a special case — `-n` names
the model exactly as it names a run:

```sh
exfil train -n strict --states 24
exfil model eval                  # is `strict` actually better than default?
exfil scan --model strict ~/project
```

### `-n` always names the artifact

One rule covers every appearance of the flag, which is why the collision on
`search` in §7 matters: `-n` names the thing a command produces, or addresses
the thing it reads.

| | `-n` names |
|---|---|
| `scan -n nightly` | the run being produced |
| `train -n strict` | the model being produced |
| `dataset add -n security` | the dataset being produced |
| `analyze -n nightly` · `report -n nightly` | the run being read |

---

## 4. Dataset: one home for rules

`sources`, `pull`, `datasets`, `feeds` and `rules` collapse into `dataset`. The
URL scheme selects the source plugin, so there is no separate command for
listing sources — `exfil dataset add --help` lists the schemes it accepts:

```sh
exfil dataset add -n security builtin://security
exfil dataset add -n leaks    https://example.com/gitleaks.toml
exfil dataset add -n intel    stix://feeds.example.com/collections/1
exfil dataset add -n local    ./custom-rules.json
```

`get` and `search` replace the old `rules` command — and fix a real bug while
doing it. `exfil rules` claims to show "the rules a scan would apply" but
iterates only `exfil_scan::builtin_rules()`, so it silently under-reports every
rule that arrived from a dataset. Reading the catalog is the correct behaviour
and falls out of putting the command under the noun that owns the data.

```sh
exfil dataset search aws          # every rule matching, across all datasets
exfil dataset get security        # one dataset's rules
```

**`remove` vs `purge`** is a real distinction, not a synonym: `remove` drops the
rules but keeps the dataset registered, so `dataset update` re-fetches it;
`purge` also forgets where it came from. Reversible and irreversible get
different words.

---

## 5. Consistency rules

These are what make the surface learnable — knowing one noun teaches you the
rest.

| Verb | Means | Where |
|---|---|---|
| `list` | all of them, one line each | `dataset` `plugin` `run` `model` |
| `get <name>` | one of them, in full | `dataset` `plugin` `run` `model` |
| `remove <name>` | delete, reversibly | `dataset` `plugin` `run` `model` |
| `add` | create from an external reference | `dataset` |
| `set` | change one field | `plugin` |
| `purge <name>` | delete, and forget the source | `dataset` |

`list`, `get` and `remove` are the three every noun has; the rest appear only
where they mean something. A dataset comes from *outside*, so it has `add`; a
model is produced by `train`, so it does not. Plugin settings are edited in
place, so `plugin` has `set` and nothing else does.

Everything else follows from that:

- **Singular nouns.** `dataset`, `plugin`, `run`, `model` — not `datasets`.
  You act on one at a time; `list` is the plural.
- **`--format json` on every listing command**, with the same shape as the
  equivalent MCP tool result, so scripting never needs to parse a table.
- **Exit codes.** `0` success · `1` error · `2` `--fail-on` threshold met.
  Only `2` is a finding-driven outcome, so CI can tell "gate tripped" from
  "the tool broke".
- **`-q` suppresses progress, `-v` adds per-file detail.** Neither changes what
  is written to stdout, so redirecting is unaffected.
- **80 columns for humans, full length for machines.** Fitting applies only
  when stdout is a terminal; pipes, `--format json` and `-o <file>` are exact.

---

## 6. What happens to the commands being dropped

Nothing here disappears without a replacement, which is the point of listing it.

> **What actually happened.** The seven commands in the middle of this table
> were dropped, but their replacements are MCP tools rather than the CLI
> spellings below — see §0. The principle held; the destinations moved.

| Today | Becomes |
|---|---|
| `sources` | `exfil dataset add --help` (the accepted URL schemes) |
| `pull <ref>` | `exfil dataset add -n <name> <ref>` |
| `pull` (all) | `exfil dataset update` |
| `datasets` | `exfil dataset list` |
| `feeds …` | `exfil dataset …` (a feed is a dataset with a URL) |
| `rules [filter]` | `exfil dataset search <query>` — now including datasets |
| `check dns\|whois` | `exfil scan -a -p dns` / `-p whois` over indicators |
| `normalize` | `exfil report -f cim` |
| `enrich` | folded into `scan` — CWE names attached when the catalog has them |
| `cwe <id>` | `exfil dataset get mitre-cwe` / `dataset search <id>` |
| `graph` | `exfil report -f dot` and `-f graph-json` |
| `config` | `exfil --show-config` |
| `completions <shell>` | `exfil --completions <shell>` |
| `hmm train` | `exfil train` — promoted to a top-level verb (§3) |
| `hmm score\|status\|eval` | `exfil model score` / `model get` / `model eval` |
| `store export\|gc\|clean` | unchanged — deleting data keeps an explicit home |

`config` and `completions` become global flags because neither is a *thing you
manage*; they answer a question about the installation. `store` stays a command
because `clean` deletes data and that deserves to be typed in full.

---

## 7. Deviations from the sketch

Six places where this design does not follow `exfil scan -n|--name -p|--passive
-a|--active <target>` literally, each with the reason:

1. **`-p` is `--plugin`, not `--passive`.** The sketch used `-p` for both on
   consecutive lines. Passive is the default and needs no flag, which frees
   `-p` for the plugin list the second line wanted.
2. **`-n` on `search` collides.** `search -n` is `--limit` today. This design
   moves the limit to `--limit`/`-l` and keeps `-n` meaning *name* everywhere.
3. **`exfil run` is added.** `-n` names a run; without a way to list runs the
   name is write-only. *(Built, then removed — listing runs is an MCP tool now,
   so the write-only objection stands on the CLI. See §0.)*
4. **`plugin update` is `plugin set`.** "Update" is ambiguous between changing a
   setting and upgrading the plugin. `set`/`remove` say which.
5. **`analyze` and `report` both stay.** They are one operation with two sinks,
   so merging is tempting — but `analyze` is the thing you type constantly and
   `report -f text -o -` is a worse way to ask for it. Keeping both costs one
   command and saves every interactive invocation.
6. **`train` is top-level, not `model train`.** The sketch did not mention the
   model at all; putting training beside `scan` is what principle 1 asks for,
   since both do work and write a result. `model` keeps only the verbs that
   read one back — see §3.

---

## Appendix — original sketch

```
exfil mcp

# Scanning
exfil scan -n|--name <name>  -p|--passive -a|--active <target>
exfil scan -p|--plugin 'dns file ports'  <target>

# Search results
exfil search <query>

# Datasets
exfil dataset list
exfil dataset add -n|--name <name> <url>
exfil dataset get <name>
exfil dataset remove <name>
exfil dataset purge <name>
exfil dataset update <name>
exfil dataset update
exfil dataset search <query>

exfil analyze  -n <name>

# Save report
exfil report  -n|--name <name> -f|--format pdf -o|--out filename.pdf

# Plugin managemnt
exfil plugin list
exfil plugin get
exfil plugin update
exfil plugin remove
```
