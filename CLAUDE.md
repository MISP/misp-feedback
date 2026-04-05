# CLAUDE.md

## Project overview

MISP Feedback is a high-performance warninglist lookup engine. It checks indicators of compromise (IOCs) against MISP warninglists to identify false positives and known identifiers. The project consists of three Rust crates in a workspace.

## Architecture

```
misp-fb-core/    Core library — matchers, engine, config, loader, protocol types
misp-fb/         CLI tool — talks to daemon over Unix socket
misp-fbd/        Daemon — serves lookups over Unix socket + optional HTTP (axum)
```

The warninglists are loaded from the `misp-warninglists/` git submodule.

## Build and test

```bash
# Build everything
cargo build --workspace

# Run unit tests (46 tests, takes ~8s due to warninglist loading)
cargo test --workspace

# Run benchmarks (starts daemon, requires release binaries)
cargo build --release --workspace
cargo test --release --package misp-fbd bench_10k -- --nocapture --ignored
```

## Running locally

```bash
# Start daemon (loads config.toml from current directory)
cargo run --release --package misp-fbd

# CLI queries (daemon must be running)
cargo run --release --package misp-fb -- check 8.8.8.8
cargo run --release --package misp-fb -- lists
```

## Key design decisions

- **Five matcher types**: CIDR (HashMap per prefix length), String (case-insensitive HashMap), Hostname (reversed-label trie), Substring (Aho-Corasick automaton), Regex (compiled RegexSet)
- **Engine is built once** at startup; lookups are lock-free reads via `RwLock` (write only on hot-reload)
- **Protocol**: HTTP-over-Unix-socket using axum on the daemon side and hyper on the CLI side. No custom binary protocol — JSON throughout
- **Hot-reload**: `notify` file watcher with 500ms debounce rebuilds the engine when warninglists change on disk
- **Category filtering**: warninglists have a `category` field (`false-positive` or `known`), defaulting to `false-positive` when absent. Lookups can filter by category via `false_positives_only` flag

## Code conventions

- Rust 2021 edition, stable toolchain
- `thiserror` for library errors, `anyhow` for binary errors
- `tracing` for logging (not `log`)
- `clap` derive API for CLI argument parsing
- Tests live in `#[cfg(test)] mod tests` blocks within each source file
- The benchmark integration test is `#[ignore]` and lives in `misp-fbd/tests/bench_lookups.rs`

## Configuration

See `config.toml` in the project root. Key options:
- `daemon.socket_path` — Unix socket path (default: `/tmp/misp-fbd.sock`)
- `daemon.http_bind` — optional TCP listener (e.g. `127.0.0.1:3000`)
- `daemon.warninglists_path` — path to warninglists directory
- `warninglists.lists` — filter: `[]` = all, `["a", "b"]` = include, `["!a"]` = exclude
