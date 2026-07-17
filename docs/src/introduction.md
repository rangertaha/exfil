# Introduction

**exfil** — *Extra File Lang Lookup* — is an offline, cross-platform,
plugin-based **DevSecOps engine for static analysis**.

exfil performs static analysis across the whole delivery surface —
**application source code**, **infrastructure-as-code**, **operating systems**,
**container artifacts**, and more. It catches problems before they ship:
**privacy leaks**, **OPSEC violations**, **data leaks**, and **vulnerable code**
headed for deployment.

It walks a target in parallel, scans every file against security rulesets
(leaked credentials, dangerous code patterns, insecure configuration,
supply-chain compromise), and stores the results as a queryable **graph** —
files → findings → rules — in an embedded, pure-Rust database
([SurrealDB](https://surrealdb.com) on SurrealKV). Everything runs locally: no
network access is needed to analyze, and nothing leaves the machine — the same
property it helps you enforce on your own code.

## Where to go next

- **New here?** Start with [Installation](guide/installation.md) and the
  [Quick Start](guide/quick-start.md).
- **Day-to-day use** — the [Commands](guide/commands.md) reference, the
  [TUI](guide/tui.md), and [Configuration](guide/configuration.md).
- **What it covers** — [What exfil Analyzes](guide/surfaces.md) and the full
  [Features](guide/features.md) list.
- **How it's built** — the [Architecture Guide](architecture/README.md), a
  multi-page tour written for readers new to Rust.
