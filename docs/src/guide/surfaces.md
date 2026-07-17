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
