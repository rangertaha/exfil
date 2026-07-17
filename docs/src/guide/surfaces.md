# What exfil Analyzes

exfil covers the whole delivery surface, and every surface flows through the
same scanners and into the same findings graph.

## Analysis surfaces

- **Source code** — 17 languages parsed with tree-sitter (Python, JS/TS, C#,
  Rust, Go, C, C++, Java, Ruby, Dart, Bash, Lua, PowerShell, Swift, Kotlin,
  Groovy including `Jenkinsfile`s) for dangerous calls and taint flow, plus
  regex/secret scanning over any text file.
- **Infrastructure code** — Terraform/HCL, Dockerfiles, Kubernetes/YAML
  manifests, and other config formats scanned for hardcoded secrets and
  insecure directives.
- **Operating systems** — a local filesystem tree, or a remote host over
  SSH/SFTP (`exfil scan-remote user@host:/path`), walked and scanned in place;
  the local host's running processes can be scanned too.
- **Container & package artifacts** — zip/jar/war/tar/tar.gz/gz archives (image
  layers and build outputs included) are unpacked into virtual files that flow
  through the same scanners, depth- and size-capped against bombs.
- **Dependencies** — `package.json`, `requirements*.txt`, and `Cargo.toml`
  manifests checked for known-malicious packages, typosquats, and malicious
  install hooks.

## What it prevents

- **Privacy & data leaks** — regex/secret rules catch API keys, tokens,
  passwords-in-URLs, and other credentials before they land in a commit,
  image, or config; IOC/hash feeds flag known-bad content.
- **OPSEC violations** — hardcoded secrets, cleartext dependency sources, and
  insecure infrastructure directives are surfaced where they hide, in code and
  config alike.
- **Vulnerable code shipping to production** — tree-sitter AST analysis and
  taint tracking flag dangerous calls and attacker-controlled data flow, while
  ClamAV/YARA signatures and supply-chain checks catch malicious artifacts and
  dependencies.

## Indicators it extracts

Every scanned file is mined for **observables** — the indicators that other
checks and enrichments act on:

| Indicator | What it captures | Used by |
|---|---|---|
| **Email** | Addresses in file content | Breach-corpus leak check; PII redaction |
| **Domain** | Hostnames | Network-IOC match (bad domains + subdomains); typosquat / brand impersonation; live DNS resolution (reserved/private); WHOIS newly-registered flag |
| **IP** | IPv4 addresses | Network-IOC match (bad IPs) |
| **URL** | `http`/`https`/`ftp` URLs | Network-IOC match (bad URLs) |
| **Hash** | md5 / sha1 / sha256 strings | Surfaced as observables for correlation and viewing |

## Rule types it uses

A **rule** has a `pattern` whose scheme selects the engine — so datasets and
feeds can ship regexes and IOCs side by side:

| Rule type | Pattern form | Engine · detects |
|---|---|---|
| **Regex** | `<regex>` | Regex scanner — leaked secrets, credentials, PII patterns |
| **Domain IOC** | `domain:<host>` | Network IOC — known-bad domains (matches subdomains too) |
| **IP IOC** | `ip:<addr>` | Network IOC — known-bad IPs |
| **URL IOC** | `url:<url>` | Network IOC — known-bad URLs |
| **Hash IOC** | `md5:` / `sha1:` / `sha256:<hex>` | Hash scanner — a file's own content hash |
| **Breach email** | `breach-email:<addr\|sha1>` | Leak checker — addresses in a breach corpus |

Some detectors don't use the `Rule` pattern — they carry their own signatures or
logic and complement the pattern rules: **AST dangerous-call + taint** (built-in
sink list), **supply-chain** (dependency manifests), **typosquat** (protected
brand list), **ClamAV** (`.hdb`/`.hsb`/`.ndb` signature files), and **YARA**
(`.yar` rules).
