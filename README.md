# MISP Feedback

A high-performance warninglist lookup engine that checks indicators of compromise (IOCs) against [MISP warninglists](https://github.com/MISP/misp-warninglists). It identifies false positives by matching values against 120+ curated lists of known-good infrastructure: cloud provider IP ranges, top domain rankings, public DNS resolvers, certificate authorities, and more.

MISP Feedback runs as a daemon (`misp-fbd`) that loads all warninglists into memory once and serves sub-millisecond lookups over a Unix socket and/or HTTP. A CLI tool (`misp-fb`) provides convenient command-line access.

## Installation

### Prerequisites

- Rust toolchain (1.70+) &mdash; install via [rustup](https://rustup.rs/)
- Git (for cloning and the warninglists submodule)

### Build from source

```bash
git clone --recurse-submodules https://github.com/MISP/misp-feedback.git
cd misp-feedback
cargo build --release
```

The binaries will be at `target/release/misp-fbd` (daemon) and `target/release/misp-fb` (CLI).

If you cloned without `--recurse-submodules`, fetch the warninglists separately:

```bash
git submodule update --init
```

Copy the example config file:

```bash
cp config.toml.example config.toml
```

### Configuration

Generate a config file interactively:

```bash
$ misp-fb config
MISP Feedback configuration

Unix socket path [/tmp/misp-fbd.sock]:
Enable HTTP listener? [y/N]: y
HTTP bind address [127.0.0.1:3000]:
Warninglists directory [./misp-warninglists/lists]:
Which warninglists to load?:
> All lists
  Only selected lists
  All except selected lists

--- Generated config ---
[daemon]
socket_path = "/tmp/misp-fbd.sock"
http_bind = "127.0.0.1:3000"
warninglists_path = "./misp-warninglists/lists"

[warninglists]
lists = []

Config written to config.toml
```

Use `--output` to write to a different path, and `--warninglists-path` if your lists directory is elsewhere:

```bash
$ misp-fb config --output /etc/misp-feedback/config.toml --warninglists-path /opt/misp-warninglists/lists
```

When choosing "Only selected lists" or "All except selected lists", the tool scans the warninglists directory and presents a multi-select list of all available warninglists to pick from.

Or edit `config.toml` directly (copy from `config.toml.example` if you haven't already):

```toml
[daemon]
socket_path = "/tmp/misp-fbd.sock"
# http_bind = "127.0.0.1:3000"    # uncomment to enable HTTP listener
warninglists_path = "./misp-warninglists/lists"

[warninglists]
# Empty list = load all warninglists
# Include mode: lists = ["amazon-aws", "google-gcp", "cloudflare"]
# Exclude mode: lists = ["!alexa", "!tranco", "!cisco_top1000"]
lists = []
```

| Option | Default | Description |
|--------|---------|-------------|
| `daemon.socket_path` | `/tmp/misp-fbd.sock` | Unix domain socket path |
| `daemon.http_bind` | *(disabled)* | TCP address for the HTTP listener (e.g. `127.0.0.1:3000`) |
| `daemon.warninglists_path` | `./misp-warninglists/lists` | Path to the warninglists directory |
| `warninglists.lists` | `[]` (all) | Filter which lists to load. Prefix with `!` to exclude. |

### Starting the daemon

```bash
# Start with default config.toml in the current directory
./target/release/misp-fbd

# Start with a specific config file
./target/release/misp-fbd --config /etc/misp-feedback/config.toml
```

The daemon logs to stderr. Control verbosity with the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug ./target/release/misp-fbd
```

The daemon watches the warninglists directory for changes and automatically reloads when files are added, modified, or removed.

## Usage (CLI)

The CLI tool (`misp-fb`) communicates with a running `misp-fbd` daemon over the Unix socket.

### Check a single value

```bash
$ misp-fb check 8.8.8.8
8.8.8.8: 2 match(es)
  - public-dns-v4 (List of known IPv4 public DNS resolvers)
  - vpn-ipv4 (Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters)
```

### Check multiple values

```bash
$ misp-fb check 8.8.8.8 google.com abuse@example.com
8.8.8.8: 2 match(es)
  - public-dns-v4 (List of known IPv4 public DNS resolvers)
  - vpn-ipv4 (Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters)

google.com: 11 match(es)
  - cisco_top1000 (Top 1000 websites from Cisco Umbrella)
  - cisco_top10k (Top 10 000 websites from Cisco Umbrella)
  - ...

abuse@example.com: 1 match(es)
  - common-contact-emails (Common contact e-mail addresses)
```

### Filtering by category

Warninglists have a `category` field that is either `false-positive` (the default) or `known`. False-positive lists contain known-good infrastructure that should not be flagged as malicious (e.g. public DNS, cloud IP ranges, top domains). Known-identifier lists provide context about a value (e.g. the value belongs to a particular organization) without necessarily meaning it is benign.

By default, lookups match against all warninglists regardless of category. Use `--false-positives-only` to restrict results to false-positive lists only:

```bash
$ misp-fb check --false-positives-only 8.8.8.8
```

### Batch check from a file

```bash
$ misp-fb check --batch indicators.txt
```

Or pipe from stdin:

```bash
$ cat indicators.txt | misp-fb check
$ echo -e "8.8.8.8\ngoogle.com\nabuse@example.com" | misp-fb check
```

Piping and `--batch` both send a single batch request to the daemon, making them significantly faster than invoking `misp-fb check` in a loop. Use these for any bulk workload.

### Integrating with other tools

The CLI is designed to fit into standard Unix pipelines. A few examples:

```bash
# Extract unique IPs from a web server log and check them
grep -oP '\d+\.\d+\.\d+\.\d+' access.log | sort -u | misp-fb check

# Check a list of domains and keep only the ones that are NOT on any warninglist
cat domains.txt | misp-fb -f csv check | grep ",false," | cut -d, -f1

# Check indicators and keep only the hits, in JSON for further processing
cat iocs.txt | misp-fb -f json check | jq 'select(.matched)'

# Enrich a CSV of indicators with warninglist context
cat indicators.txt | misp-fb -f csv check > enriched.csv

# Pull indicators from a MISP event via the API and check them
curl -s -H "Authorization: YOUR_API_KEY" \
  https://misp.example.com/attributes/restSearch -d '{"eventid": 1234}' \
  | jq -r '.response.Attribute[].value' \
  | misp-fb check

# Check IOCs from a Zeek (Bro) connection log
zeek-cut id.resp_h < conn.log | sort -u | misp-fb check

# Diff two runs to find newly flagged indicators
comm -13 <(cat baseline.txt | misp-fb -f csv check | sort) \
         <(cat current.txt  | misp-fb -f csv check | sort)
```

### Output formats

Use `--format` (`-f`) to switch between `table` (default), `json`, and `csv`:

```bash
# JSON output
$ misp-fb -f json check 8.8.8.8
{
  "value": "8.8.8.8",
  "matched": true,
  "matches": [
    {
      "slug": "public-dns-v4",
      "name": "List of known IPv4 public DNS resolvers",
      "list_type": "cidr",
      "category": "false-positive",
      "matching_attributes": ["ip-src", "ip-dst", "domain|ip", ...]
    }
  ]
}

# CSV output
$ misp-fb -f csv check 8.8.8.8 google.com nothing.zzz
8.8.8.8,true,public-dns-v4,List of known IPv4 public DNS resolvers
8.8.8.8,true,vpn-ipv4,Specialized list of vpn-ipv4 addresses belonging to common VPN providers and datacenters
google.com,true,cisco_top1000,Top 1000 websites from Cisco Umbrella
...
nothing.zzz,false,,
```

### List loaded warninglists

```bash
$ misp-fb lists
SLUG                                     TYPE        ENTRIES  NAME
----------------------------------------------------------------------------------------------------
akamai                                   cidr            268  List of known Akamai IP ranges
alexa                                    hostname       1000  Top 1000 website from Alexa
amazon-aws                               cidr           3602  List of known Amazon AWS IP address ranges
...
----------------------------------------------------------------------------------------------------
120 warninglists loaded
```

### Check daemon health

```bash
$ misp-fb health
Status: ok
Lists loaded: 120
```

### CLI options

```
Usage: misp-fb [OPTIONS] <COMMAND>

Commands:
  check   Check one or more values against warninglists
  lists   List all loaded warninglists
  health  Check daemon health
  config  Interactively generate a config.toml file

Options:
  -s, --socket <SOCKET>  Path to the daemon Unix socket [default: /tmp/misp-fbd.sock]
  -f, --format <FORMAT>  Output format [default: table] [possible values: table, json, csv]
  -h, --help             Print help
```

## Usage (HTTP)

Enable the HTTP listener by uncommenting `http_bind` in `config.toml`:

```toml
[daemon]
http_bind = "127.0.0.1:3000"
```

The HTTP API is also always available over the Unix socket (the CLI uses this internally).

### Endpoints

#### `GET /health`

Returns daemon status.

```bash
$ curl http://localhost:3000/health
```

```json
{
  "status": "ok",
  "lists_loaded": 120
}
```

#### `POST /lookup`

Check a single value against all warninglists.

```bash
$ curl -X POST http://localhost:3000/lookup \
  -H 'Content-Type: application/json' \
  -d '{"value": "8.8.8.8"}'
```

```json
{
  "value": "8.8.8.8",
  "matched": true,
  "matches": [
    {
      "slug": "public-dns-v4",
      "name": "List of known IPv4 public DNS resolvers",
      "description": "Event contains one or more public IPv4 DNS resolvers as attribute with an IDS flag set",
      "list_type": "cidr",
      "category": "false-positive",
      "matching_attributes": ["ip-src", "ip-dst", "domain|ip", "ip-src|port", "ip-dst|port"]
    }
  ]
}
```

To only match against false-positive warninglists, add `"false_positives_only": true` to the request body:

```bash
$ curl -X POST http://localhost:3000/lookup \
  -H 'Content-Type: application/json' \
  -d '{"value": "8.8.8.8", "false_positives_only": true}'
```

#### `POST /lookup/batch`

Check multiple values in a single request (up to 10,000).

```bash
$ curl -X POST http://localhost:3000/lookup/batch \
  -H 'Content-Type: application/json' \
  -d '{"values": ["8.8.8.8", "google.com", "abuse@example.com"]}'
```

The `false_positives_only` flag is also supported on batch requests:

```bash
$ curl -X POST http://localhost:3000/lookup/batch \
  -H 'Content-Type: application/json' \
  -d '{"values": ["8.8.8.8", "google.com"], "false_positives_only": true}'
```

```json
{
  "results": [
    {
      "value": "8.8.8.8",
      "matched": true,
      "matches": [...]
    },
    {
      "value": "google.com",
      "matched": true,
      "matches": [...]
    },
    {
      "value": "abuse@example.com",
      "matched": true,
      "matches": [...]
    }
  ]
}
```

#### `GET /lists`

Return metadata for all loaded warninglists.

```bash
$ curl http://localhost:3000/lists
```

```json
{
  "count": 120,
  "lists": [
    {
      "slug": "amazon-aws",
      "name": "List of known Amazon AWS IP address ranges",
      "description": "Amazon AWS IP address ranges...",
      "version": 20260403,
      "list_type": "cidr",
      "category": "false-positive",
      "entry_count": 3602,
      "matching_attributes": ["ip-src", "ip-dst", "domain|ip"]
    }
  ]
}
```

#### `GET /openapi.json`

Returns the OpenAPI 3.1 specification as JSON.

#### `GET /docs`

Interactive API documentation powered by [Swagger UI](https://swagger.io/tools/swagger-ui/). Browse to `http://localhost:3000/docs` to explore all endpoints and execute test queries directly from the browser.

### Using the HTTP API over the Unix socket

All endpoints are also available over the Unix socket, without enabling `http_bind`:

```bash
$ curl --unix-socket /tmp/misp-fbd.sock http://localhost/lookup \
  -X POST -H 'Content-Type: application/json' \
  -d '{"value": "8.8.8.8"}'
```

## HTTPS with a Reverse Proxy

The daemon serves plain HTTP. For TLS, place a reverse proxy in front of it. This guide covers obtaining a certificate via Let's Encrypt and configuring either Nginx or Apache.

### Prerequisites

Enable the HTTP listener in `config.toml` (bind to localhost only — the reverse proxy handles external traffic):

```toml
[daemon]
http_bind = "127.0.0.1:3000"
```

### Obtaining a certificate with Let's Encrypt

Install [Certbot](https://certbot.eff.org/) and request a certificate for your domain:

```bash
# Debian/Ubuntu
sudo apt install certbot

# For Nginx
sudo apt install python3-certbot-nginx

# For Apache
sudo apt install python3-certbot-apache
```

If you already have Nginx or Apache configured (see below), Certbot can obtain and install the certificate automatically:

```bash
# Nginx
sudo certbot --nginx -d misp-feedback.example.com

# Apache
sudo certbot --apache -d misp-feedback.example.com
```

Alternatively, obtain a certificate in standalone mode first, then configure the web server manually:

```bash
sudo certbot certonly --standalone -d misp-feedback.example.com
```

Certificates are stored in `/etc/letsencrypt/live/misp-feedback.example.com/`. Certbot sets up automatic renewal via a systemd timer or cron job.

### Nginx

Create `/etc/nginx/sites-available/misp-feedback`:

```nginx
server {
    listen 443 ssl;
    server_name misp-feedback.example.com;

    ssl_certificate     /etc/letsencrypt/live/misp-feedback.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/misp-feedback.example.com/privkey.pem;

    # Recommended TLS settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Increase body size for large batch requests
    client_max_body_size 10m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name misp-feedback.example.com;
    return 301 https://$host$request_uri;
}
```

Enable and restart:

```bash
sudo ln -s /etc/nginx/sites-available/misp-feedback /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

You can also proxy directly to the Unix socket instead of the TCP listener (this way `http_bind` does not need to be enabled):

```nginx
    location / {
        proxy_pass http://unix:/tmp/misp-fbd.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
```

### Apache

Enable the required modules:

```bash
sudo a2enmod ssl proxy proxy_http headers
```

Create `/etc/apache2/sites-available/misp-feedback.conf`:

```apache
<VirtualHost *:80>
    ServerName misp-feedback.example.com
    Redirect permanent / https://misp-feedback.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName misp-feedback.example.com

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/misp-feedback.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/misp-feedback.example.com/privkey.pem

    # Recommended TLS settings
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite HIGH:!aNULL:!MD5

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

Enable and restart:

```bash
sudo a2ensite misp-feedback
sudo apache2ctl configtest
sudo systemctl reload apache2
```

To proxy to the Unix socket instead (requires `mod_proxy_unix`, available in Apache 2.4.7+):

```apache
    ProxyPass / unix:/tmp/misp-fbd.sock|http://localhost/
    ProxyPassReverse / unix:/tmp/misp-fbd.sock|http://localhost/
```

### Restricting access

For production deployments, consider adding authentication or IP-based access control at the reverse proxy level:

```nginx
# Nginx: restrict to specific IP ranges
location / {
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;
    proxy_pass http://127.0.0.1:3000;
}
```

```apache
# Apache: restrict to specific IP ranges
<Location />
    Require ip 10.0.0.0/8 192.168.0.0/16
</Location>
```

## Performance

Benchmark results from a development machine, with **120 warninglists loaded (2,512,729 total entries)** across all five matcher types (CIDR, hostname, string, substring, regex). The test corpus consists of 10,000 lookups with an 84% hit rate and an average of 3.8 matching warninglists per hit.

### Engine (direct, no I/O)

| Metric | Value |
|--------|-------|
| 10k lookups | 6.8ms |
| Per lookup (avg) | 676ns |
| Throughput | **1,478,000 lookups/sec** |

### HTTP API

| Mode | 10k lookups | Per lookup | Throughput |
|------|-------------|------------|------------|
| Individual `POST /lookup` | 1.08s | 108µs | **9,300 req/s** |
| Single `POST /lookup/batch` | 144ms | 14µs | **69,500 val/s** |

### CLI (`misp-fb`)

| Mode | Time | Per value | Throughput |
|------|------|-----------|------------|
| Individual `misp-fb check <value>` | 536ms / 200 calls | 2.7ms | **373 inv/s** |
| Batch `misp-fb check --batch` | 134ms / 10k values | 13µs | **74,400 val/s** |

Individual CLI invocations are dominated by process startup overhead (fork/exec, runtime init, socket connect), not lookup time. For bulk workloads, use `--batch` or pipe via stdin to get batch-level throughput.

### Running the benchmarks

```bash
# Engine-level benchmark (no daemon needed)
cargo test --release --package misp-fb-core perf_10k -- --nocapture

# Full stack benchmark (starts daemon, tests HTTP + CLI)
cargo build --release --workspace
cargo test --release --package misp-fbd bench_10k -- --nocapture --ignored
```

## License

MIT License - see [LICENSE](LICENSE) for details.

* Copyright (C) 2026 Andras Iklody
