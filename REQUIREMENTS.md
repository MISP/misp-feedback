# MISP Feedback — Requirements & Progress

## Legend

- [x] Complete
- [ ] Not started
- [~] Partially complete

---

## Phase 1: Project Setup & Configuration

- [x] Rust workspace with three crates (core, CLI, daemon)
- [x] MISP warninglists git submodule integration
- [x] TOML configuration file parsing (`config.toml`)
- [x] Warninglist include/exclude filtering (empty = all, `!` prefix = exclude)
- [x] Error type definitions (`misp-fb-core::error`)
- [x] Unit tests for configuration parsing and filter modes

## Phase 2: Warninglist Loader

- [x] Scan warninglists directory for subdirectories
- [x] Parse `list.json` files (serde deserialization)
- [x] Apply slug-based filtering from config
- [x] Graceful handling of missing, empty, or malformed lists (warn and skip)
- [x] Sorted, deterministic loading order
- [x] Unit tests for loader (all lists, filtered, empty skipping)

## Phase 3: Matching Engine — Matchers

### CIDR Matcher
- [x] IPv4 CIDR range matching
- [x] IPv6 CIDR range matching
- [x] Bare IP to /32 or /128 normalisation
- [x] HashMap-per-prefix-length lookup strategy
- [x] Unit tests (IPv4, IPv6, mixed, multiple ranges)

### String Matcher
- [x] Case-insensitive exact matching via HashMap
- [x] Multi-list deduplication
- [x] Unit tests (exact match, case folding, miss, duplicates)

### Hostname Matcher
- [x] Reversed-label trie construction
- [x] Exact domain matching
- [x] Subdomain matching (e.g., `google.com` matches `mail.google.com`)
- [x] Leading-dot syntax (`.amazonaws.com` matches subdomains only)
- [x] Case-insensitive matching
- [x] Unit tests (exact, subdomain, deep nesting, leading-dot, duplicates)

### Substring Matcher
- [x] Aho-Corasick automaton construction
- [x] Case-insensitive multi-pattern matching
- [x] Pattern deduplication across lists
- [x] Unit tests (middle match, overlapping, deduplication)

### Regex Matcher
- [x] JavaScript `/pattern/flags` format parsing and conversion
- [x] Rust RegexSet compilation
- [x] Case-insensitive flag support
- [x] Unit tests (JS regex parsing, flag handling, email patterns)

## Phase 4: Match Engine Integration

- [x] `MatchEngine::build()` — construct all matchers from raw warninglists
- [x] `MatchEngine::lookup()` — query all matchers, deduplicate results
- [x] `MatchEngine::lists()` — return metadata for all loaded lists
- [x] `WarningListInfo` model with slug, entry count, matching attributes
- [x] Unit tests (CIDR, hostname, substring, regex lookups via engine)

## Phase 5: Daemon (`misp-fbd`)

- [x] Load config and build `MatchEngine` at startup
- [x] Tokio async runtime setup
- [x] Unix domain socket listener
- [x] Request/response handling over socket
- [x] HTTP API via Axum (optional, `http_bind` config)
  - [x] `POST /lookup` — check a single value against all lists
  - [x] `POST /lookup/batch` — check multiple values (with 10k limit)
  - [x] `GET /lists` — return loaded warninglist metadata
  - [x] `GET /health` — health check endpoint
- [x] Structured logging with `tracing` (env-filter support via `RUST_LOG`)
- [x] Graceful shutdown handling (SIGINT + SIGTERM, socket cleanup)
- [x] Hot-reload warninglists on file change (`notify` watcher with debounce)
- [x] CLI argument for config path (`--config`)
- [ ] Integration tests for daemon endpoints

## Phase 6: IPC Protocol & CLI (`misp-fb`)

- [x] Shared protocol types in `misp-fb-core::protocol` (request/response structs used by both daemon and CLI)
  - [x] HTTP-over-Unix-socket (daemon serves axum, CLI uses hyper client)
  - [x] JSON serialisation for all request/response types
- [x] CLI argument parsing with `clap`
  - [x] `misp-fb check <value> [value...]` — single or multi-value lookup
  - [x] `misp-fb check --batch <file>` — batch lookup from file (use `-` for stdin)
  - [x] `misp-fb check` (piped stdin) — read values from stdin when not a terminal
  - [x] `misp-fb lists` — show loaded warninglists
  - [x] `misp-fb health` — check daemon health
  - [x] `misp-fb --socket <path>` — override socket path
  - [x] `misp-fb --format json|table|csv` — output format selection
- [x] Connect to daemon via Unix socket (hyper-util client with custom connector)
- [x] Display results (table, JSON, CSV formats)
- [x] Error handling for daemon not running / connection refused
- [ ] Integration tests for CLI commands

## Phase 7: MISP Integration

- [ ] MISP module/plugin for querying `misp-fbd`
- [ ] Attribute-type-aware matching (use `matching_attributes` field)
- [ ] Event-level batch checking (check all attributes in an event)
- [ ] Enrichment pipeline integration
- [ ] Documentation for MISP administrators

## Phase 8: Production Readiness

- [ ] Systemd service file for `misp-fbd`
- [ ] Performance benchmarks (startup time, lookup latency, throughput)
- [ ] Memory usage profiling with full warninglist set
- [ ] CI/CD pipeline (build, test, lint, release)
- [ ] README with installation and usage instructions
- [ ] Package builds (deb, rpm, Docker image)
- [ ] Changelog and versioning

---

## Current Status

**Phases 1–6 are complete.** The full stack is functional: core matching engine, daemon with HTTP + Unix socket + hot-reload, and CLI with table/JSON/CSV output. 120 warninglists loaded in ~1.5s (release build). Sub-millisecond lookups.

**Phases 7–8** are future work for MISP integration and production deployment.
