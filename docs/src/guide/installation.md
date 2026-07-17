# Installation

exfil is a single portable binary — pure Rust, building on Linux, macOS, and
Windows.

## From a source checkout

```sh
# install the binary onto your PATH
cargo install --path crates/exfil-cli

# or just build it
cargo build --release   # binary at target/release/exfil
```

## Verify

```sh
exfil --help
```

Once installed, head to the [Quick Start](quick-start.md).
