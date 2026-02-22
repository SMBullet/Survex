# Survex

A modular Attack Surface Management (ASM) and automated pentesting CLI. Point it at any combination of domains, IPs, CIDRs, or host lists — choose any subset of **28 scan modules** — and get structured JSON output, a dark-theme HTML report, risk-scored findings, and Discord/Slack alerts.

---

## Table of Contents

1. [Overview](#overview)
2. [Web UI](#web-ui)
3. [Module Reference](#module-reference)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [CLI Reference](#cli-reference)
7. [Scan Profiles](#scan-profiles)
8. [Port Profiles](#port-profiles)
9. [Config File Reference](#config-file-reference)
10. [Risk Rules](#risk-rules)
11. [Nuclei Template Coverage](#nuclei-template-coverage)
12. [Output Files](#output-files)
13. [Alerting (Webhooks)](#alerting-webhooks)
14. [CI/CD Integration](#cicd-integration)
15. [Project Structure](#project-structure)

---

## Overview

Survex runs a **28-step pipeline** against your targets combining passive recon, active scanning, and automated vulnerability testing:

```
Targets → Subdomain Enum → DNS Brute Force → DNS Resolution →
Zone Transfer → Takeover Check → Email Security →
Port Scan → HTTP Probe → TLS → WAF → Headers → CORS → Cookies →
S3/Cloud → Historical URLs (GAU) → Crawl (Katana) → JS Secret Scan →
API Discovery → GraphQL → Content Discovery (ffuf) →
Open Redirect → XSS (dalfox) → SQLi (sqlmap) →
Nuclei → Screenshots → Shodan → GitHub Exposure →
Diff → Risk Scoring → Webhooks → Persist → Output
```

**Comparison with other tools:**

| Feature | Survex | SpiderFoot | Amass | Sn1per |
|---------|--------|-----------|-------|--------|
| Subdomain enum (multi-source) | ✓ | ✓ | ✓ | partial |
| DNS brute-force + permutations | ✓ | ✗ | ✓ | ✗ |
| DNS zone transfer (AXFR) | ✓ | ✗ | ✓ | ✗ |
| Port scanning (6 profiles) | ✓ | partial | ✗ | ✓ |
| HTTP probing + tech stack | ✓ | ✗ | ✗ | partial |
| TLS analysis | ✓ | partial | ✗ | ✗ |
| WAF detection (pure Go) | ✓ | ✗ | ✗ | ✗ |
| Security headers audit (A–F) | ✓ | ✗ | ✗ | ✗ |
| CORS misconfiguration testing | ✓ | ✗ | ✗ | ✗ |
| Cookie security analysis | ✓ | ✗ | ✗ | ✗ |
| Cloud storage (S3/GCS/Azure) | ✓ | partial | ✗ | ✗ |
| Historical URLs (GAU) | ✓ | ✗ | ✗ | ✗ |
| JS-aware web crawling (Katana) | ✓ | ✗ | ✗ | ✗ |
| JavaScript secret scanning | ✓ | ✗ | ✗ | ✗ |
| Content discovery (ffuf) | ✓ | ✗ | ✗ | ✓ |
| XSS scanning (dalfox) | ✓ | ✗ | ✗ | partial |
| SQL injection (sqlmap) | ✓ | ✗ | ✗ | ✓ |
| Open redirect detection | ✓ | ✗ | ✗ | ✗ |
| GraphQL introspection | ✓ | ✗ | ✗ | ✗ |
| API/Swagger discovery | ✓ | ✗ | ✗ | ✗ |
| Nuclei CVE/vuln scanning | ✓ | partial | ✗ | ✓ |
| Subdomain takeover detection | ✓ | ✗ | ✗ | partial |
| Email security (SPF/DMARC/DKIM) | ✓ | ✗ | ✗ | ✗ |
| GitHub code exposure search | ✓ | ✓ | ✗ | ✗ |
| Shodan enrichment | ✓ | ✓ | ✗ | ✓ |
| Screenshots | ✓ | ✗ | ✗ | ✓ |
| Scan diff / history | ✓ | ✓ | ✗ | ✗ |
| Continuous watch mode | ✓ | ✗ | ✗ | ✗ |
| Slack/Discord webhooks | ✓ | ✗ | ✗ | ✗ |
| Dark-theme HTML report | ✓ | ✓ | ✗ | partial |
| CI/CD exit codes | ✓ | ✗ | ✗ | ✗ |

---

## Web UI

Survex ships with a full web platform — authentication, live scan management, WebSocket log streaming, and an HTML report viewer — accessible from any browser.

### Architecture

```
survex serve          ← Go API server (Fiber + WebSocket)
├── REST API          ← /api/v1/auth, /api/v1/scans
├── WebSocket logs    ← /api/v1/scans/:id/logs
├── Scan queue        ← single-worker, captures all log output
├── SQLite DB         ← users + scan job history
└── Next.js frontend  ← served as static files from web/out/
```

### Prerequisites

**Node.js** is required to build the frontend. On WSL or Linux:

```bash
# Install nvm + Node 20 (one-time setup)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc          # or restart your terminal
nvm install 20
nvm use 20
node --version            # v20.x.x
```

On Windows (native): download the installer from [nodejs.org](https://nodejs.org).

### Build & Run

```bash
# 1. Build the Go binary
go build -o survex ./cmd/survex/

# 2. Install frontend dependencies and build
cd web
npm install
npm run build             # outputs to web/out/
cd ..

# 3. Start the web server
./survex serve --frontend web/out

# Open http://localhost:8080 in your browser
# Register an account, then start scanning.
```

### `survex serve` Flags

```
--addr string       Listen address (default "0.0.0.0:8080")
--db string         SQLite database path (default "survex-web.db")
--frontend string   Path to built Next.js output (web/out).
                    Omit to run in API-only mode.
```

```bash
# Listen on a specific interface
./survex serve --addr 127.0.0.1:8080 --frontend web/out

# Custom database location
./survex serve --db /var/lib/survex/survex-web.db --frontend web/out

# API-only mode (no frontend, useful if you deploy frontend separately)
./survex serve --addr 0.0.0.0:8080
```

### Development Mode

Run the API and frontend dev server separately for hot-reload:

```bash
# Terminal 1 — API server (no frontend flag)
./survex serve --addr 0.0.0.0:8080

# Terminal 2 — Next.js dev server
cd web
npm run dev               # http://localhost:3000
```

The Next.js app proxies API calls to `http://localhost:8080` automatically.

### Web UI Features

| Feature | Description |
|---------|-------------|
| Authentication | Email + password, JWT tokens (7-day expiry) |
| Dashboard | All scans with status, findings, severity, and time |
| New Scan Wizard | Visual profile picker, module selector, target input |
| Live Logs | Real-time WebSocket terminal with color-coded output |
| Pipeline Tracker | Step-by-step progress indicator (Initialising → Complete) |
| Cancel Scan | Stop running or queued scans instantly |
| Open Report | View the HTML report directly in the browser |
| Dark/Light Theme | Toggle between dark and light mode |

### Scan Queue

The web server processes scans **one at a time** via an internal queue. This prevents log output from multiple concurrent scans from interleaving. Queued scans show a waiting indicator in the dashboard; they start automatically when the current scan finishes.

---

## Module Reference

Run `survex modules` to see live installation status on your system.

### Recon & Enumeration

| Module | Type | Depends On | What It Finds |
|--------|------|-----------|---------------|
| `subfinder` | external | subfinder binary | Subdomains via passive OSINT (50+ sources) |
| `amass` | external | amass binary | Subdomains via additional OSINT + brute force |
| `crts` | built-in | none | Subdomains from certificate transparency (crt.sh) |
| `dns` | built-in | none | A, CNAME, MX, TXT records + zone transfer attempt |
| `dnsbrute` | built-in | none | DNS brute-force (1,500-word embedded wordlist) + permutation engine |
| `nmap` | external | nmap binary | Open ports, service/version detection |
| `httpx` | external | httpx binary | Live HTTP/S services, status codes, page titles, tech stack |
| `tls` | built-in | none | TLS cert expiry, version (1.0/1.1/1.2/1.3), issuer, SANs, self-signed |
| `waf` | built-in | none | WAF vendor fingerprinting (Cloudflare, Akamai, AWS WAF, F5, Imperva, Sucuri, Fastly) |
| `shodan` | API | Shodan API key | Passive enrichment: open ports, CVEs, ISP, country, tags |
| `gau` | external | gau binary | Historical URLs from Wayback Machine and Common Crawl |
| `katana` | external | katana binary | JS-aware web crawling — finds endpoints passive sources miss |
| `screenshot` | external | gowitness + Chrome | Visual recon — screenshot every live HTTP service |
| `github` | API | GitHub token (optional) | Code exposure in public repos: secrets, config files, source code leaks |

### Web Security Testing

| Module | Type | Depends On | What It Finds |
|--------|------|-----------|---------------|
| `headers` | built-in | none | Security headers audit (HSTS, CSP, X-Frame-Options, etc.) — grades A–F |
| `cors` | built-in | none | CORS misconfiguration: origin reflection, wildcard, null origin, credentials bypass |
| `cookies` | built-in | none | Cookie flags: Secure, HttpOnly, SameSite — per URL |
| `s3` | built-in | none | Public/listable cloud buckets (AWS S3, GCS, Azure Blob) |
| `takeover` | built-in | none | Subdomain takeover: dangling CNAME + HTTP fingerprint (25 services) |
| `email` | built-in | none | Email security: SPF record, DMARC policy, DKIM selectors |
| `jsscan` | built-in | none | JavaScript secret scanning: AWS keys, GitHub tokens, Stripe, JWT, private keys (37 patterns) |
| `apidiscovery` | built-in | none | API surface: Swagger/OpenAPI specs, WSDL/SOAP, Spring Boot actuator, REST base paths |
| `graphql` | built-in | none | GraphQL introspection: detects exposed schemas, extracts type names |
| `openredirect` | built-in | none | Open redirect: tests 20+ redirect parameters with 13 payloads each |

### Active Vulnerability Scanning

| Module | Type | Depends On | What It Finds |
|--------|------|-----------|---------------|
| `ffuf` | external | ffuf binary | Content/directory bruteforce: hidden endpoints, admin panels, backup files, config leaks |
| `dalfox` | external | dalfox binary | Reflected and DOM XSS on all parametrized URLs from gau/katana/ffuf |
| `sqlmap` | external | sqlmap (Python) | SQL injection: boolean, time-based, UNION, error-based, stacked queries |
| `nuclei` | external | nuclei binary | CVEs, misconfigurations, default credentials, exposures, takeovers (17 template dirs) |

### Module Groups

| Group | Modules |
|-------|---------|
| `all` | Every module |
| Passive recon | `crts`, `dns`, `shodan` |
| Subdomain enum | `subfinder`, `amass`, `crts`, `dnsbrute` |
| Active recon | `nmap`, `httpx`, `tls`, `waf` |
| Web security | `headers`, `cors`, `cookies`, `takeover`, `email` |
| Secret hunting | `jsscan`, `github` |
| API surface | `apidiscovery`, `graphql` |
| Active pentest | `ffuf`, `dalfox`, `sqlmap`, `openredirect`, `nuclei` |
| Cloud | `s3` |

---

## Installation

### 1. Build Survex

```bash
git clone https://github.com/SMBullet/Survex
cd Survex
go build -o survex ./cmd/survex/
```

### 2. Install External Tools

Use `survex install` to auto-install Go tools. Built-in modules need nothing extra.

```bash
# Install everything automatically (no sudo needed for Go tools)
./survex install

# Or install specific tools
./survex install subfinder httpx nuclei ffuf dalfox

# System tools (requires sudo/admin)
sudo apt install nmap sqlmap          # Linux (Debian/Ubuntu)
brew install nmap && pip install sqlmap  # macOS

# Update nuclei templates after first install
nuclei -update-templates
```

> **Note:** Never run `survex install` with `sudo` for Go tools. Go installs to `~/go/bin` which belongs to your user. Only `nmap` and `sqlmap` need system-level installation.

### 3. Verify Installation

```bash
./survex modules
```

Output example:
```
MODULE         TYPE       STATUS      DESCRIPTION
subfinder      go-tool    installed   Subdomain enumeration via OSINT sources
amass          go-tool    missing     Subdomain enumeration via OSINT (more sources, slower)
crts           built-in   built-in    Certificate transparency lookup (crt.sh)
dns            built-in   built-in    DNS resolution (A, CNAME, MX, TXT records)
dnsbrute       built-in   built-in    DNS brute-force + permutation engine (1500-word wordlist)
nmap           system     installed   Nmap 7.94
httpx          go-tool    installed   httpx v1.6.x
...
ffuf           go-tool    installed   ffuf v2.1.0
dalfox         go-tool    installed   Dalfox v2.12.0
sqlmap         system     installed   sqlmap 1.8.4
openredirect   built-in   built-in    Open redirect parameter fuzzing
graphql        built-in   built-in    GraphQL introspection probe
apidiscovery   built-in   built-in    API endpoint discovery
```

### Go Version

Requires Go 1.21+. Check with `go version`.

---

## Quick Start

```bash
# List module status
./survex modules

# Fast check — built-ins only, no external tools needed
./survex scan -t example.com -m "crts,dns,tls,headers,cors,cookies,email,takeover,dnsbrute" --client example

# Full web assessment from a YAML config
./survex scan --config clients/example.yaml

# Bug bounty: single target, no subdomain enumeration
./survex scan -t app.example.com --no-subs \
  -m "httpx,tls,waf,headers,cors,cookies,gau,katana,jsscan,apidiscovery,graphql,ffuf,openredirect,dalfox,nuclei" \
  --client bb-example

# Automated pentest: all active modules
./survex scan -t example.com \
  -m "subfinder,crts,dnsbrute,dns,nmap,httpx,tls,waf,headers,cors,cookies,gau,katana,jsscan,ffuf,openredirect,dalfox,sqlmap,graphql,apidiscovery,nuclei" \
  --client pentest-example

# Passive recon only (zero active probing)
./survex scan -t example.com --passive --client example

# Continuous monitoring (runs every 24h)
./survex watch --config clients/example.yaml --interval 24h

# View findings from last scan
./survex report --client example

# Diff last two scans
./survex diff --client example

# Scan history
./survex history --client example

# Update nuclei templates
./survex update --nuclei
```

---

## CLI Reference

### `survex scan`

```
Target Selection:
  -c, --config <file>              Path to client config YAML
  -t, --target <targets>           Comma-separated targets: domains, IPs, CIDRs, .txt files
  -m, --modules <modules>          Comma-separated modules, or "all"
      --client <name>              Client name for storage and reports (required with -t)
  -o, --output <dir>               Output directory (overrides config)

Scan Behavior:
      --no-subs                    Skip all subdomain enumeration (subfinder, amass, crts,
                                   dnsbrute, TLS-SAN). Treats provided targets as final host list.
                                   Critical for bug bounty scope compliance.
      --passive                    Passive recon only (crts, dns, shodan). No active scanning.
      --profile <profile>          Scan profile: quick|web|full|passive|stealth|cloud
      --ports <spec>               Port profile: top-100|top-1000|full|web|db|stealth
                                   or custom: "80,443,8080-8090"
      --rate <n>                   Max requests/second (default: 150)
      --threads <n>                HTTP concurrency (default: 50)
      --timeout <n>                Per-request timeout in seconds (default: 10)
      --proxy <url>                HTTP proxy: http://127.0.0.1:8080 or socks5://...

Nuclei Control:
      --nuclei-severity <s>        Severity filter (default: "critical,high,medium,info")
      --nuclei-tags <tags>         Include tags: "cve,rce,sqli"
      --nuclei-exclude <tags>      Exclude tags: "dos,fuzz"
      --nuclei-templates <dirs>    Additional template dirs (comma-separated)
      --update-templates           Run nuclei -update-templates before scan

API Keys:
      --shodan-key <key>           Shodan API key (enables shodan module)
      --github-token <token>       GitHub personal access token (improves rate limits)

Alerting:
      --fail-on <severity>         Exit 1 if findings at or above: low|medium|high|critical
      --webhook <url>              Webhook URL(s) for notifications (comma-separated).
                                   Slack, Discord, or generic HTTP POST supported.
```

### `survex watch`

Continuous monitoring mode — runs the full scan pipeline on a loop.

```bash
./survex watch --config clients/example.yaml --interval 24h
./survex watch -t example.com -m all --client example --interval 6h
```

```
      -c, --config <file>          Client config YAML
      -t, --target <targets>       Targets (same as scan)
      -m, --modules <modules>      Modules (same as scan)
          --client <name>          Client name
          --interval <duration>    Time between scans: 1h, 6h, 24h, 7d (default: 24h)
```

Press `Ctrl+C` to stop gracefully.

### `survex modules`

Lists all 28 modules with type, status, and description.

### `survex install`

Installs or checks all Go-tool dependencies.

```bash
./survex install                        # Check and install everything
./survex install ffuf dalfox nuclei     # Install specific tools
```

### `survex serve`

Start the web UI (see [Web UI](#web-ui) section for full setup):

```bash
./survex serve --frontend web/out              # default: 0.0.0.0:8080
./survex serve --addr 127.0.0.1:9000 --frontend web/out
./survex serve --db /data/survex.db --frontend web/out
```

```
--addr string       Listen address (default "0.0.0.0:8080")
--db string         SQLite database path (default "survex-web.db")
--frontend string   Path to built Next.js output dir (web/out)
```

### `survex update`

```bash
./survex update --nuclei    # Update nuclei templates
./survex update --all       # Update all supported templates
```

### `survex diff`

```bash
./survex diff --client <name>
./survex diff --config clients/example.yaml
```

Shows JSON diff (new/removed subdomains, new ports, TLS changes) between the last two scans.

### `survex report`

```bash
./survex report --client <name>
```

Prints findings JSON from the most recent scan.

### `survex history`

```bash
./survex history --client <name>
```

Lists the 20 most recent scans for a client with timestamps and finding counts.

---

## Scan Profiles

Profiles resolve to a fixed module list. Used when `--profile` is set and `--modules` is not.

| Profile | Modules | Use Case |
|---------|---------|----------|
| `quick` | crts, dns, httpx, tls, headers | Fast passive+HTTP check. No port scan or vuln scan. |
| `web` | subfinder, crts, amass, dns, httpx, tls, waf, headers, cors, cookies, nuclei | Full web-focused with enumeration and vulnerability scanning. |
| `full` | all | Every module. Slowest, most thorough. |
| `passive` | crts, dns, shodan | Zero active probing. Certificates, DNS, Shodan only. |
| `stealth` | crts, dns, httpx, tls, waf | Minimal footprint. No port scan or vuln scan. |
| `cloud` | subfinder, crts, dns, httpx, s3, nuclei | Cloud asset discovery and bucket exposure. |

---

## Port Profiles

| Profile | Ports | Use Case |
|---------|-------|----------|
| `top-100` | 100 most common ports | Fast initial check |
| `top-1000` | 1000 most common ports | **Default** |
| `full` | All 65535 ports | Exhaustive (slow) |
| `web` | 80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,9443 | Web services only |
| `db` | 3306,5432,27017,6379,1433,1521,5984,9200,9300,11211,27018 | Database ports only |
| `stealth` | Top-100 with `-T2` slow timing | Minimal footprint |
| `"80,443,8080"` | Custom comma-separated list | Specific ports |

---

## Config File Reference

```yaml
# ── Identity ──────────────────────────────────────────────────────────────────
client: example-corp

# ── Targets ───────────────────────────────────────────────────────────────────
targets:
  - example.com            # domain → full enumeration (subfinder, crts, amass, dns)
  # - app.example.com      # single subdomain → use scan.no_subs: true
  # - 10.0.0.1             # bare IP → domain-only modules skipped
  # - 192.168.1.0/24       # CIDR (max /16) → expanded to individual IPs
  # - hosts.txt            # file → loaded line-by-line, comments (#) ignored

# ── Modules ───────────────────────────────────────────────────────────────────
# Built-in (no external tools):
#   crts  dns  dnsbrute  tls  waf  headers  cors  cookies  s3
#   takeover  email  jsscan  openredirect  graphql  apidiscovery
# External Go tools (auto-installed via 'survex install'):
#   subfinder  amass  httpx  gau  katana  screenshot  nuclei  ffuf  dalfox
# System tools:
#   nmap (apt/brew/choco)  sqlmap (pip/apt)
# API (require keys):
#   shodan  github
modules:
  - all

# ── Scan behavior ──────────────────────────────────────────────────────────────
scan:
  # no_subs: skip subdomain enumeration (subfinder, amass, crts, dnsbrute, tls-san).
  # REQUIRED for bug bounty to avoid scanning out-of-scope hosts.
  no_subs: false

  # passive: crts, dns, shodan only — no active port/HTTP/vuln scanning.
  passive: false

  # ports: port profile for nmap.
  #   top-100 | top-1000 | full | web | db | stealth | "80,443,8080"
  ports: top-1000

  # profile: predefined module set (when modules is not specified).
  #   quick | web | full | passive | stealth | cloud
  profile: ""

  rate: 150       # max requests/second
  threads: 50     # HTTP concurrency
  timeout: 10     # per-request timeout in seconds

  # proxy: route all HTTP requests through a proxy.
  # proxy: http://127.0.0.1:8080
  proxy: ""

# ── Nuclei ────────────────────────────────────────────────────────────────────
nuclei:
  severity: "critical,high,medium,info"
  tags: []                   # include only templates with these tags
  exclude_tags:
    - dos
    - fuzz
    - generic-tokens
    - tls-sni-proxy
  templates: []              # additional template directories
  update_before_scan: false  # run nuclei -update-templates before scan

# ── Shodan ────────────────────────────────────────────────────────────────────
shodan:
  api_key: ""
  enabled: false

# ── GitHub code exposure ──────────────────────────────────────────────────────
github:
  token: ""       # PAT with no scopes needed for public repos
  enabled: false  # automatically true when modules includes "github"

# ── Output ────────────────────────────────────────────────────────────────────
output:
  dir: reports/example-corp
  format: json
  keep_history: true

# ── Alerting ──────────────────────────────────────────────────────────────────
alerts:
  # Exit code 1 if findings at or above this severity are found.
  fail_on: high

  # Webhooks: send notifications when scan completes or new findings appear.
  # Supported: Slack incoming webhooks, Discord webhooks, generic HTTP POST.
  webhooks: []
  # webhooks:
  #   - url: https://discord.com/api/webhooks/ID/TOKEN
  #     on: new_findings      # always | new_findings | new_subdomains
  #   - url: https://hooks.slack.com/services/T.../B.../...
  #     on: always
```

---

## Risk Rules

### Port Rules (60+ ports)

| Severity | Ports |
|----------|-------|
| **CRITICAL** | 502 (Modbus/ICS), 2181 (Zookeeper), 2375 (Docker daemon), 2379 (etcd), 5984 (CouchDB), 6379 (Redis), 9200 (Elasticsearch), 9300, 11211 (Memcached), 27017-27019 (MongoDB), 1433 (MSSQL), 1521 (Oracle), 3306 (MySQL), 5432 (PostgreSQL) |
| **HIGH** | 23 (Telnet), 102 (S7 PLC), 445 (SMB), 512-514 (RSH), 623 (IPMI/BMC), 2376 (Docker TLS), 3389 (RDP), 4444 (Metasploit), 4848 (GlassFish), 5672 (RabbitMQ), 5900 (VNC), 7001 (WebLogic), 8009 (AJP Ghostcat), 8161 (ActiveMQ), 9092 (Kafka), 10250 (Kubelet), 15672 (RabbitMQ UI), 16992 (Intel AMT), 50000 (SAP/Spark), 61616 (ActiveMQ broker) |
| **MEDIUM** | 21 (FTP), 22 (SSH), 25 (SMTP), 69 (TFTP), 110 (POP3), 143 (IMAP), 389 (LDAP), 873 (rsync), 902/903 (VMware), 5985/5986 (WinRM), 8888 (Jupyter), 9090 (Prometheus) |
| **LOW** | 53 (DNS), 79 (Finger), 636 (LDAPS), 8080, 8443 |

### HTTP Rules

| Severity | Trigger |
|----------|---------|
| **HIGH** | Page title contains admin keywords: admin, dashboard, jenkins, grafana, phpmyadmin, kibana, portainer, vault, consul, prometheus, zabbix, splunk, rundeck, rancher, sonarqube, nexus |
| **LOW** | Live HTTP service on cleartext port |

### TLS Rules

| Severity | Trigger |
|----------|---------|
| **HIGH** | Certificate expired |
| **HIGH** | Certificate expires in ≤ 14 days |
| **MEDIUM** | Certificate expires in ≤ 30 days |
| **MEDIUM** | Self-signed certificate |
| **MEDIUM** | TLS 1.0 or TLS 1.1 negotiated |

### Security Headers

| Severity | Missing Header |
|----------|---------------|
| **MEDIUM** | `Strict-Transport-Security` — HTTPS downgrade risk |
| **LOW** | `X-Frame-Options` — clickjacking risk |
| **LOW** | `X-Content-Type-Options` — MIME sniffing |
| **INFO** | `Content-Security-Policy` — XSS amplifier |
| **INFO** | `Referrer-Policy` — referrer leakage |
| **INFO** | `Permissions-Policy` — browser feature access |

Grade scale: A+ → A → B → C → D → F based on number of headers present.

### CORS Rules

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | Arbitrary origin reflected + `Access-Control-Allow-Credentials: true` |
| **CRITICAL** | Wildcard ACAO + credentials allowed |
| **HIGH** | Wildcard `Access-Control-Allow-Origin: *` |
| **MEDIUM** | Arbitrary origin reflected (no credentials) |
| **MEDIUM** | Null origin accepted |

### Cookie Security

| Severity | Trigger |
|----------|---------|
| **MEDIUM** | Cookie missing `Secure` flag |
| **LOW** | Cookie missing `HttpOnly` flag |
| **INFO** | Cookie missing `SameSite` attribute |

### Cloud Storage

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | S3/GCS/Azure bucket publicly listable |
| **HIGH** | S3/GCS/Azure bucket publicly accessible |

### DNS Rules

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | DNS zone transfer (AXFR) succeeded — full zone dumped |

### Email Security

| Severity | Trigger |
|----------|---------|
| **MEDIUM** | Missing SPF record — anyone can spoof email from this domain |
| **MEDIUM** | Missing DMARC record — no enforcement against spoofed email |
| **LOW** | No DKIM record found |

### Subdomain Takeover

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | Confirmed takeover — unclaimed service behind CNAME |

### JavaScript Secrets

| Severity | Secret Type |
|----------|------------|
| **CRITICAL** | AWS Access Key, Private Key/RSA, GitHub PAT, GitHub Actions token, Stripe live secret key |
| **HIGH** | Google API key, Slack bot/webhook token, Stripe publishable key, SendGrid key |
| **MEDIUM** | Hardcoded API keys, JWT tokens, generic secrets, Azure/GCP credentials |
| **LOW** | Internal URLs, S3/GCS/Azure storage URLs in JS files |

### GitHub Exposure

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | Target domain found in repo named password/secret/credential/.env |
| **HIGH** | Target domain found in any public GitHub repository |

### Content Discovery (ffuf)

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | Backup file exposed (.bak, .sql, .tar.gz, .zip, db dump) |
| **CRITICAL** | Configuration file exposed (.env, config.php, web.config, .htpasswd) |
| **HIGH** | Admin panel discovered (/admin, /administrator, /wp-admin, /phpmyadmin, etc.) |
| **MEDIUM** | API endpoint discovered (/api, /v1, /swagger, /graphql) |

### Active Vulnerability Testing

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | SQL injection confirmed (sqlmap) |
| **HIGH** | XSS confirmed (dalfox) |
| **MEDIUM** | Open redirect confirmed |
| **MEDIUM** | GraphQL introspection enabled (schema leaked) |
| **MEDIUM** | Swagger/OpenAPI spec publicly accessible |
| **HIGH** | Spring Boot actuator endpoint exposed (/actuator/env, /actuator/heapdump, etc.) |

### Shodan

| Severity | Trigger |
|----------|---------|
| **HIGH** | Shodan reports a CVE for the host |

### Scan Diff (continuous monitoring)

| Severity | Trigger |
|----------|---------|
| **INFO** | New subdomain discovered since last scan |
| **INFO** | Subdomain removed since last scan |
| **MEDIUM** | TLS certificate issuer changed |

---

## Nuclei Template Coverage

Survex runs nuclei with **17 template directories**:

| Template Dir | What It Finds |
|-------------|---------------|
| `http/takeovers/` | Subdomain takeovers: dangling DNS, expired services |
| `http/cves/` | CVEs: Log4Shell, Spring4Shell, MOVEit, Confluence, Exchange, etc. |
| `http/vulnerabilities/` | Generic vulns: XSS, SQLi, SSRF, path traversal, RCE |
| `http/exposures/` | Sensitive files: .env, .git/config, SSH keys, docker-compose |
| `http/exposures/tokens/` | API key and token exposure in HTTP responses |
| `http/file-inclusion/` | Local/remote file inclusion |
| `http/exposed-panels/` | Admin and management panels exposed to internet |
| `http/default-logins/` | Default credentials: Jenkins, Grafana, Kibana, Tomcat, WebLogic (190+ vendors) |
| `http/misconfiguration/` | CORS, open redirects, debug endpoints |
| `http/technologies/` | Technology fingerprinting for asset mapping |
| `ssl/` | TLS: deprecated versions, weak ciphers, expired/self-signed certs |
| `dns/` | DNS takeovers, misconfigurations |
| `cloud/` | Cloud service misconfigs: S3, GCS, Azure |
| `network/default-login/` | Network-level default creds: Redis, FTP, MSSQL, PostgreSQL |
| `network/misconfig/` | Open proxy, exposed memcached, unauthenticated services |
| `network/exposures/` | Network-level data exposure |
| `network/detection/` | Network service detection |

Always excluded: `dos`, `fuzz`, `generic-tokens`, `tls-sni-proxy` (configurable via `nuclei.exclude_tags`).

---

## Output Files

Each scan creates: `reports/{client}/{scan-id}/`

```
reports/example-corp/
└── 2026-02-21T15-30-45/
    ├── report.html              ← Self-contained dark-theme HTML dashboard
    ├── summary.json             ← Metadata + counts for all module results
    ├── findings.json            ← Risk-scored findings sorted by severity
    │
    ├── subdomains.json          ← All hosts with IPs and discovery sources
    ├── dns.json                 ← A, CNAME, MX, TXT records
    ├── services.json            ← Open ports with service/version info
    ├── http.json                ← Live HTTP services: URL, status, title, tech stack
    ├── tls.json                 ← TLS cert details: expiry, version, SANs
    ├── waf.json                 ← WAF detection results
    │
    ├── security_headers.json    ← Headers audit with A–F grade per URL
    ├── cors.json                ← CORS test results
    ├── cookies.json             ← Cookie security flags per URL
    ├── s3.json                  ← Cloud storage bucket findings
    ├── takeovers.json           ← Subdomain takeover results
    ├── email_security.json      ← SPF/DMARC/DKIM per domain
    ├── zone_transfers.json      ← Successful AXFR results
    │
    ├── historical_urls.json     ← URLs from GAU and Katana (capped at 1,000)
    ├── js_secrets.json          ← Secrets found in JavaScript files
    ├── github_exposures.json    ← Code exposure hits from GitHub Search API
    │
    ├── api_endpoints.json       ← Discovered Swagger/OpenAPI/WSDL/actuator endpoints
    ├── graphql.json             ← GraphQL endpoint results + introspection data
    ├── ffuf_results.json        ← Content discovery hits (paths, admin panels, backups)
    ├── xss_results.json         ← Confirmed XSS findings from dalfox
    ├── sqli_results.json        ← Confirmed SQLi findings from sqlmap
    ├── open_redirects.json      ← Confirmed open redirect findings
    │
    ├── vulnerabilities.json     ← Raw nuclei findings
    ├── shodan.json              ← Shodan host enrichment data
    ├── screenshots.json         ← Screenshot metadata
    ├── diff.json                ← Changes since previous scan
    │
    └── screenshots/             ← PNG screenshots (if gowitness ran)
        └── https_example_com.png
```

### Summary JSON

`summary.json` contains all count fields:

```json
{
  "subdomain_count": 42,
  "service_count": 15,
  "http_count": 8,
  "tls_count": 8,
  "cors_vuln_count": 1,
  "s3_count": 0,
  "takeover_count": 0,
  "zone_transfer_count": 0,
  "email_count": 3,
  "js_secret_count": 2,
  "github_exposure_count": 0,
  "ffuf_count": 47,
  "xss_count": 0,
  "sqli_count": 0,
  "open_redirect_count": 1,
  "graphql_count": 1,
  "api_endpoint_count": 3,
  "vuln_count": 5,
  "finding_count": 12,
  "max_severity": "high"
}
```

### SQLite Scan History

All scans are persisted to `survex.db` in your working directory. Powers `survex diff`, `survex report`, and `survex history`.

---

## Alerting (Webhooks)

Survex can send notifications to Slack, Discord, or any HTTP endpoint when a scan completes or new findings are detected.

### Triggers

| Value | When it fires |
|-------|--------------|
| `always` | Every scan completion, even with 0 findings |
| `new_findings` | Only when at least one finding is generated |
| `new_subdomains` | Only when new subdomains are discovered vs last scan |

### Discord Setup

1. Server Settings → Integrations → Webhooks → **New Webhook**
2. Copy the URL: `https://discord.com/api/webhooks/ID/TOKEN`
3. Add to YAML:

```yaml
alerts:
  webhooks:
    - url: https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
      on: new_findings
```

### Slack Setup

1. Create an Incoming Webhook at `api.slack.com/apps`
2. Add to YAML:

```yaml
alerts:
  webhooks:
    - url: https://hooks.slack.com/services/T.../B.../...
      on: always
```

### Multiple Webhooks

```yaml
alerts:
  fail_on: high
  webhooks:
    - url: https://discord.com/api/webhooks/...
      on: new_findings
    - url: https://hooks.slack.com/services/...
      on: always
```

Webhook also works via CLI:
```bash
./survex scan -t example.com -m all --client example \
  --webhook "https://discord.com/api/webhooks/ID/TOKEN"
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: ASM Scan
on:
  schedule:
    - cron: '0 6 * * 1'   # Weekly, Monday 06:00 UTC
  push:
    branches: [main]

jobs:
  survex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Build Survex
        run: go build -o survex ./cmd/survex/

      - name: Install tools
        run: |
          ./survex install subfinder httpx nuclei ffuf dalfox
          sudo apt-get install -y nmap sqlmap
          nuclei -update-templates -silent

      - name: Run scan
        run: |
          ./survex scan --config clients/example.yaml --fail-on high
        continue-on-error: false

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: survex-report
          path: reports/
```

### Minimal CI (zero external tools)

```bash
# Only built-in modules — no external dependencies at all
./survex scan -t example.com \
  -m "crts,dns,dnsbrute,tls,headers,cors,cookies,s3,email,takeover,apidiscovery,graphql,openredirect" \
  --client ci --fail-on medium
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no findings at or above `--fail-on` threshold |
| `1` | Findings at or above `--fail-on` severity detected |

---

## Project Structure

```
Survex/
├── cmd/survex/
│   └── main.go                   ← CLI: scan, serve, watch, modules, install, update, diff, report, history
├── internal/
│   ├── api/
│   │   ├── auth.go               ← JWT authentication: register, login, /me handlers
│   │   ├── scans.go              ← Scan CRUD + WebSocket log streaming
│   │   └── server.go             ← Fiber app setup, CORS, routes, error handler
│   ├── db/
│   │   └── db.go                 ← SQLite schema for users + scan_jobs (web UI)
│   ├── queue/
│   │   └── queue.go              ← Single-worker scan queue with log capture + WebSocket fan-out
│   ├── config/
│   │   └── config.go             ← Config structs + GitHubEnabled(), ResolveProfile()
│   ├── models/
│   │   └── models.go             ← 28 data types including ScanResult aggregate
│   ├── scan/
│   │   └── scan.go               ← 28-step pipeline orchestration
│   ├── tools/
│   │   ├── install.go            ← Tool registry, survex install/modules logic
│   │   ├── subfinder.go          ← subfinder wrapper
│   │   ├── amass.go              ← amass wrapper
│   │   ├── crts.go               ← crt.sh pure-Go HTTP client
│   │   ├── dns.go                ← pure-Go DNS resolver + AXFR zone transfer
│   │   ├── dnsbrute.go           ← DNS brute-force + permutation (embedded wordlist)
│   │   ├── wordlist.txt          ← 1,500-entry subdomain wordlist (embedded)
│   │   ├── nmap.go               ← nmap wrapper + 6 port profiles
│   │   ├── httpx.go              ← ProjectDiscovery httpx wrapper
│   │   ├── tls.go                ← pure-Go TLS handshake analysis
│   │   ├── waf.go                ← pure-Go WAF fingerprinting (7 vendors)
│   │   ├── headers.go            ← pure-Go HTTP security headers audit
│   │   ├── cors.go               ← pure-Go CORS misconfiguration testing
│   │   ├── cookies.go            ← pure-Go cookie security analysis
│   │   ├── s3.go                 ← pure-Go cloud storage bucket detection
│   │   ├── takeover.go           ← pure-Go subdomain takeover (25 services)
│   │   ├── email.go              ← pure-Go SPF/DMARC/DKIM checks
│   │   ├── jsscan.go             ← pure-Go JS secret scanning (37 patterns)
│   │   ├── apidiscovery.go       ← pure-Go API/Swagger/actuator discovery (50 probes)
│   │   ├── graphql.go            ← pure-Go GraphQL introspection (14 paths)
│   │   ├── paramfuzz.go          ← pure-Go parameter extraction + open redirect testing
│   │   ├── ffuf.go               ← ffuf wrapper + embedded wordlist (805 entries)
│   │   ├── ffuf_wordlist.txt     ← Content discovery wordlist (embedded)
│   │   ├── dalfox.go             ← dalfox XSS scanner wrapper
│   │   ├── sqlmap.go             ← sqlmap SQLi scanner wrapper
│   │   ├── gau.go                ← gau historical URL wrapper
│   │   ├── katana.go             ← katana web crawler wrapper
│   │   ├── screenshot.go         ← gowitness screenshot wrapper
│   │   ├── nuclei.go             ← nuclei wrapper (17 template dirs)
│   │   ├── shodan.go             ← Shodan REST API client
│   │   ├── github.go             ← GitHub Search API client
│   │   └── notify.go             ← Slack/Discord/generic webhook notifications
│   ├── risk/
│   │   └── risk.go               ← Risk scoring: 80+ rules across all modules
│   ├── diff/
│   │   └── diff.go               ← Scan comparison engine
│   ├── store/
│   │   └── store.go              ← SQLite persistence (pure Go, no CGO)
│   └── report/
│       └── report.go             ← Dark-theme HTML report (20+ sections)
├── web/                          ← Next.js frontend
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx        ← Root layout with AuthProvider + ThemeProvider
│   │   │   ├── page.tsx          ← Redirect: /dashboard or /login
│   │   │   ├── login/page.tsx    ← Login + register (split-panel design)
│   │   │   ├── dashboard/page.tsx← Scan list + stats dashboard
│   │   │   └── scans/
│   │   │       ├── new/page.tsx  ← New scan wizard (profile cards + module picker)
│   │   │       └── [id]/page.tsx ← Scan detail: pipeline tracker + live log terminal
│   │   ├── components/
│   │   │   ├── nav.tsx           ← Navigation bar with theme toggle
│   │   │   ├── severity-badge.tsx← Colored severity chip (critical/high/medium/low/info)
│   │   │   └── ui/               ← shadcn/ui component library
│   │   └── lib/
│   │       ├── api.ts            ← API client (fetch wrapper + WebSocket URL helpers)
│   │       └── auth.tsx          ← AuthContext: login, register, logout, user state
│   ├── package.json
│   ├── next.config.ts            ← output: 'export' for static build
│   └── out/                      ← Built static files (after npm run build)
├── clients/
│   ├── example.yaml              ← Full config template with all options documented
│   └── onsexprime.yaml           ← Bug bounty example (no-subs, conservative rate)
└── go.mod
```

---

## Technology Stack

### CLI + Backend

| Component | Technology |
|-----------|-----------|
| Language | Go 1.21+ |
| CLI framework | `github.com/spf13/cobra` |
| Web API server | `github.com/gofiber/fiber/v2` |
| WebSocket | `github.com/gofiber/websocket/v2` |
| Authentication | JWT (`golang-jwt/jwt/v5`) + bcrypt |
| Config parsing | `gopkg.in/yaml.v3` |
| Database (CLI) | `modernc.org/sqlite` — scan history, findings |
| Database (Web) | `modernc.org/sqlite` — users, scan jobs |
| DNS | `net.Resolver` + raw TCP for AXFR |
| TLS analysis | `crypto/tls` (standard library) |
| HTTP clients | `net/http` (standard library) |
| HTML reports | `html/template` (standard library) |
| External Go tools | subfinder, amass, httpx, nuclei, gau, katana, gowitness, ffuf, dalfox |
| External system tools | nmap, sqlmap |
| API integrations | Shodan REST API, GitHub Search API |

### Web Frontend

| Component | Technology |
|-----------|-----------|
| Framework | Next.js 15 (App Router, static export) |
| Language | TypeScript |
| Styling | Tailwind CSS v4 |
| UI Components | shadcn/ui (Radix UI primitives) |
| Icons | lucide-react |
| Themes | next-themes (dark/light toggle) |
| Real-time logs | WebSocket (native browser API) |
