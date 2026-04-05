# MISP Feedback

## Overview

MISP Feedback is a high-performance warninglist matching engine for the [MISP](https://www.misp-project.org/) threat intelligence sharing platform. It checks indicators of compromise (IOCs) against MISP's curated warninglists to identify false positives — known-good infrastructure, popular domains, reserved IP ranges, and other benign indicators that should not be flagged as malicious.

The project is designed to run as a standalone daemon (`misp-fbd`) alongside a MISP instance, serving fast lookups over a Unix domain socket or HTTP API. A CLI tool (`misp-fb`) provides ad-hoc queries for analysts and scripting.

## Problem Statement

Threat intelligence feeds inevitably contain indicators that match legitimate infrastructure: cloud provider IP ranges, top-1000 websites, public DNS resolvers, well-known certificate authorities, and so on. MISP maintains 120+ community-curated warninglists to flag these, but checking indicators against all of them at query time can be expensive and slow — especially for bulk operations or real-time enrichment pipelines.

MISP Feedback solves this by:

- **Pre-loading** all warninglists into optimised in-memory data structures at startup
- **Serving** sub-millisecond lookups across all lists simultaneously
- **Running** as a persistent daemon to amortise the one-time build cost across millions of queries
- **Supporting** all five warninglist matching types (CIDR, string, hostname, substring, regex)

## Architecture

```
                          ┌──────────────────────────────────────┐
                          │         misp-fb-core (library)       │
                          │                                      │
  config.toml ──────────> │  Config ─> Loader ─> MatchEngine     │
                          │                        │             │
  misp-warninglists/ ───> │            ┌───────────┼───────────┐ │
  (122 JSON lists)        │            │  Matchers │           │ │
                          │            │  ┌────────┴────────┐  │ │
                          │            │  │ CIDR   (ipnet)  │  │ │
                          │            │  │ String (HashMap) │  │ │
                          │            │  │ Hostname (Trie)  │  │ │
                          │            │  │ Substring (A-C)  │  │ │
                          │            │  │ Regex (RegexSet) │  │ │
                          │            │  └─────────────────┘  │ │
                          │            └───────────────────────┘ │
                          └──────────────────────────────────────┘
                                 ▲                    ▲
                                 │                    │
                    ┌────────────┘                    └────────────┐
                    │                                              │
           ┌───────┴────────┐                          ┌──────────┴──────────┐
           │  misp-fb (CLI)  │                          │  misp-fbd (daemon)  │
           │                 │                          │                     │
           │  clap args      │ ◄── Unix socket ──────► │  tokio runtime      │
           │  one-shot query │     (protocol.rs)       │  axum HTTP API      │
           │  batch mode     │                          │  socket listener    │
           └─────────────────┘                          │  hot reload (notify)│
                                                        └─────────────────────┘
```

### Core Library (`misp-fb-core`)

The core library is a pure Rust crate with no I/O runtime dependency. It provides:

- **Configuration** — TOML-based config with include/exclude filtering for warninglists
- **Loader** — Reads warninglist JSON files from disk, validates, and filters them
- **MatchEngine** — Builds optimised matchers and dispatches lookups across all five types
- **Matchers** — Five specialised matching algorithms, each tuned to its data type:

| Matcher | Data Structure | Lookup Complexity | Use Case |
|---------|---------------|-------------------|----------|
| CIDR | HashMap per prefix length | O(32) IPv4 / O(128) IPv6 | IP ranges (AWS, GCP, Cloudflare, RFC1918) |
| String | Case-insensitive HashMap | O(1) | Exact matches (hashes, known IOC false positives) |
| Hostname | Reversed-label trie | O(label count) | Domains with subdomain matching (Alexa, Tranco, Cisco top lists) |
| Substring | Aho-Corasick automaton | O(input length) | Pattern-in-string (sandbox URLs, dynamic DNS) |
| Regex | Compiled RegexSet | O(pattern set) | Flexible patterns (contact emails, common formats) |

### Daemon (`misp-fbd`)

The daemon loads all warninglists once at startup, builds the `MatchEngine`, and then serves queries over:

- **Unix domain socket** — Low-latency IPC for co-located MISP instances
- **HTTP API** (optional) — REST endpoints for remote or multi-instance setups

Planned features include hot-reloading warninglists when files change on disk (via `notify` filesystem watcher) and structured logging with `tracing`.

### CLI Tool (`misp-fb`)

The CLI provides a command-line interface for:

- Single indicator lookups (e.g., `misp-fb check 8.8.8.8`)
- Communication with a running daemon via the Unix socket
- Scripting and integration with shell pipelines

## Warninglists

The project includes the official [MISP warninglists](https://github.com/MISP/misp-warninglists) repository as a git submodule, providing 120+ curated lists across these categories:

| Category | Examples | Entries |
|----------|----------|---------|
| Cloud/Hosting providers | AWS, GCP, Azure, Cloudflare, Fastly, Akamai | Thousands of CIDR ranges |
| Top domain rankings | Alexa, Cisco Umbrella, Tranco, Majestic Million | 1K to 1M domains |
| Public DNS | Google, Cloudflare, OpenDNS, Quad9 | IPv4 and IPv6 resolvers |
| Reserved/RFC ranges | RFC1918, RFC5735, link-local, multicast | Standard ranges |
| Security scanners | Shodan, Censys, Rapid7 | Scanner infrastructure |
| Certificate authorities | Mozilla root and intermediate CAs | Certificate fingerprints |
| Dynamic DNS providers | DynDNS, No-IP, DuckDNS | Hostname patterns |
| Known false positives | Common IOC false positives, EICAR, NIOC hashes | Specific indicators |
| Contact emails | RFC 2142 standard mailbox names | Regex patterns |

## Configuration

Configuration is via a single `config.toml` file:

```toml
[daemon]
socket_path = "/tmp/misp-fbd.sock"       # Unix domain socket path
# http_bind = "127.0.0.1:3000"           # Optional HTTP listener
warninglists_path = "./misp-warninglists/lists"

[warninglists]
# Empty = load all lists
# Include mode: lists = ["amazon-aws", "google-gcp"]
# Exclude mode: lists = ["!alexa", "!tranco"]
lists = []
```

## Query Examples

```
Input: "8.8.8.8"
Matched: public-dns-v4, google (CIDR matches against known Google DNS ranges)

Input: "google.com"
Matched: alexa, cisco_top1000, cisco_top5k, cisco_top10k, cisco_top20k, tranco, ... (hostname trie matches)

Input: "abuse@example.com"
Matched: common-contact-emails (regex: /^(security|noc|soc|abuse)\@.*\..*$/i)

Input: "https://capesandbox.com/analysis/12345"
Matched: automated-malware-analysis (substring: "capesandbox.com")
```

## Technology Stack

- **Language:** Rust (2021 edition)
- **Async runtime:** Tokio
- **HTTP framework:** Axum
- **Matching:** ipnet, aho-corasick, regex
- **Configuration:** TOML (serde)
- **File watching:** notify
- **Logging:** tracing / tracing-subscriber
- **CLI parsing:** clap

## License

MIT License (Copyright 2026 Andras Iklody)
