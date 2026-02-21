# Survex

A competitive, fully modular Attack Surface Management (ASM) CLI. Point it at any combination of domains, IPs, CIDRs, or host lists — choose any subset of 17 scan modules — and get structured JSON output, a dark-theme HTML report, and risk-scored findings. Competitive with SpiderFoot, Amass, and the ProjectDiscovery ecosystem.

---

## Table of Contents

1. [Overview](#overview)
2. [Module Reference](#module-reference)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [CLI Reference](#cli-reference)
6. [Scan Profiles](#scan-profiles)
7. [Port Profiles](#port-profiles)
8. [Config File Reference](#config-file-reference)
9. [Risk Rules](#risk-rules)
10. [Nuclei Template Coverage](#nuclei-template-coverage)
11. [Output Files](#output-files)
12. [CI/CD Integration](#cicd-integration)
13. [Project Structure](#project-structure)

---

## Overview

Survex runs a 20-step pipeline against your targets:

```
Targets → Subdomain Enumeration → DNS → Port Scan → HTTP Probe →
TLS Analysis → WAF Detection → Security Headers → CORS Testing →
Cookie Analysis → S3/Cloud Detection → Historical URLs (GAU) →
Web Crawl (Katana) → Nuclei Vuln Scan → Screenshots → Shodan →
Diff → Risk Scoring → Persist → Output
```

**What makes it competitive:**

| Feature | Survex | SpiderFoot | Amass | theHarvester |
|---------|--------|-----------|-------|--------------|
| Subdomain enum | ✓ (subfinder + amass + crts + TLS-SAN) | ✓ | ✓ | ✓ |
| Port scanning | ✓ (nmap, 6 port profiles) | partial | ✗ | ✗ |
| HTTP probing + tech stack | ✓ | ✗ | ✗ | ✗ |
| TLS analysis | ✓ | partial | ✗ | ✗ |
| WAF detection | ✓ (7 vendors, pure Go) | ✗ | ✗ | ✗ |
| Security headers audit | ✓ (pure Go, A–F grade) | ✗ | ✗ | ✗ |
| CORS testing | ✓ (pure Go, 3 test vectors) | ✗ | ✗ | ✗ |
| Cookie security | ✓ (Secure/HttpOnly/SameSite) | ✗ | ✗ | ✗ |
| Cloud storage exposure | ✓ (AWS/GCS/Azure, pure Go) | partial | ✗ | ✗ |
| Historical URLs | ✓ (GAU) | ✗ | ✗ | ✗ |
| JS/endpoint crawling | ✓ (Katana) | ✗ | ✗ | ✗ |
| Vuln scanning (CVEs) | ✓ (nuclei, 17 template dirs) | partial | ✗ | ✗ |
| Screenshots | ✓ (gowitness) | ✗ | ✗ | ✗ |
| Shodan enrichment | ✓ (API) | ✓ | ✗ | ✗ |
| Scan history & diff | ✓ (SQLite) | ✓ | ✗ | ✗ |
| HTML report | ✓ (dark-theme, self-contained) | ✓ | ✗ | ✗ |
| CI/CD ready (exit codes) | ✓ | ✗ | ✗ | ✗ |

---

## Module Reference

Run `survex modules` to see installation status on your system.

| Module | Type | Depends On | What It Finds |
|--------|------|-----------|---------------|
| `subfinder` | external | subfinder binary | Subdomains via passive OSINT (50+ sources) |
| `amass` | external | amass binary | Subdomains via additional OSINT sources |
| `crts` | built-in | none | Subdomains from certificate transparency (crt.sh) |
| `dns` | built-in | none | A, CNAME, MX, TXT DNS records |
| `nmap` | external | nmap binary | Open ports with service/version detection |
| `httpx` | external | httpx binary | Live HTTP/S services, status, title, tech stack |
| `tls` | built-in | none | TLS cert expiry, version, issuer, SANs, self-signed |
| `waf` | built-in | none | WAF vendor detection (Cloudflare, Akamai, AWS, F5, Imperva, Sucuri, Fastly) |
| `headers` | built-in | none | HTTP security headers audit (HSTS, CSP, X-Frame-Options, etc.) — A/B/C/D/F grade |
| `cors` | built-in | none | CORS misconfiguration (origin reflection, wildcard, null origin, credentials bypass) |
| `cookies` | built-in | none | Cookie security flags (Secure, HttpOnly, SameSite) |
| `s3` | built-in | none | AWS S3, GCS, Azure Blob public/listable bucket detection |
| `gau` | external | gau binary | Historical URLs from Wayback Machine and Common Crawl |
| `katana` | external | katana binary | JS-aware web crawler — discovers endpoints missed by passive sources |
| `screenshot` | external | gowitness + Chrome | Visual recon — screenshot every live HTTP service |
| `nuclei` | external | nuclei binary | Vulnerability scanning: CVEs, misconfigs, exposures, default creds, takeovers |
| `shodan` | API | Shodan API key | Passive host enrichment: ports, CVEs, ISP, country |

### Module Groups

| Group | Modules Included |
|-------|-----------------|
| `all` | Every module listed above |
| Subdomain-only | `subfinder`, `amass`, `crts`, `dns` |
| Active recon | `nmap`, `httpx`, `tls`, `waf` |
| Web security | `headers`, `cors`, `cookies` |
| Cloud | `s3` |
| Historical | `gau`, `katana` |
| Vuln scanning | `nuclei` |

---

## Installation

### 1. Install Survex

```bash
git clone https://github.com/SMBullet/Survex
cd Survex
go build -o survex ./cmd/survex/
# Or install globally:
go install ./cmd/survex/
```

### 2. Install External Tools

All external tools are optional — Survex skips them gracefully if not found. Built-in modules (DNS, TLS, WAF, headers, CORS, cookies, S3) require nothing extra.

```bash
# Subdomain enumeration
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master

# Port scanning
apt install nmap          # Linux
choco install nmap        # Windows

# HTTP probing (must be ProjectDiscovery's httpx, not Python's)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability scanning
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # Download/update template library

# Historical URLs
go install github.com/lc/gau/v2/cmd/gau@latest

# JS/endpoint crawling
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Screenshots (also requires Google Chrome or Chromium)
go install github.com/sensepost/gowitness@latest
```

Make sure `~/go/bin` is in your PATH:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## Quick Start

```bash
# 1. List module status
survex modules

# 2. Quick scan (no port scanning or vuln scan — fast)
survex scan -t example.com -m all --profile quick --client example

# 3. Full scan from config file
survex scan --config clients/example.yaml

# 4. Scan a single subdomain (no enumeration)
survex scan -t app.example.com -m "httpx,tls,headers,cors,cookies,nuclei" --no-subs --client example

# 5. Web-focused scan with CVE coverage
survex scan -t example.com -m "subfinder,crts,dns,httpx,tls,headers,cors,cookies,nuclei" --client example

# 6. Passive recon only (zero active probing)
survex scan -t example.com -m all --passive --client example

# 7. View diff from last scan
survex diff --client example

# 8. View findings from last scan
survex report --client example

# 9. View scan history
survex history --client example

# 10. Update nuclei templates
survex update --nuclei
```

---

## CLI Reference

### `survex scan`

```
FLAGS:

  Target Selection:
    -c, --config <file>         Path to client config YAML
    -t, --target <targets>      Comma-separated: domains, IPs, CIDRs, .txt files
    -m, --modules <modules>     Comma-separated modules, or "all"
        --client <name>         Client name for storage and reports (required with -t)
    -o, --output <dir>          Output directory (overrides config)

  Scan Behavior:
        --no-subs               Skip subdomain enumeration — treat targets as final host list
                                (useful when scanning a single subdomain or specific hosts)
        --passive               Passive recon only: crts, dns, shodan — no active scanning
        --profile <profile>     Scan profile: quick|web|full|passive|stealth|cloud
        --ports <spec>          Port profile: top-100|top-1000|full|web|db|stealth
                                or custom: "80,443,8080-8090"
        --rate <n>              Max requests/second (default: 150)
        --threads <n>           HTTP concurrency (default: 50)
        --timeout <n>           Per-request timeout in seconds (default: 10)
        --proxy <url>           HTTP proxy: http://127.0.0.1:8080 or socks5://...

  Nuclei Control:
        --nuclei-severity <s>   Severity filter (default: "critical,high,medium,info")
        --nuclei-tags <tags>    Include tags: "cve,rce,sqli"
        --nuclei-exclude <tags> Exclude tags: "dos,fuzz"
        --nuclei-templates <t>  Additional template dirs (comma-separated)
        --update-templates      Run nuclei -update-templates before scan

  Shodan:
        --shodan-key <key>      Shodan API key (enables shodan module)

  Alerting:
        --fail-on <severity>    Exit 1 if findings at or above this level: low|medium|high|critical
```

### `survex diff`

```
survex diff --config <file>
survex diff --client <name>
```

Shows JSON diff (new/removed subdomains, new ports, TLS changes) from the last two scans.

### `survex report`

```
survex report --config <file>
survex report --client <name>
```

Shows findings JSON from the most recent scan.

### `survex history`

```
survex history --client <name>
survex history --config <file>
```

Lists the 20 most recent scans for a client.

### `survex modules`

Lists all 17 modules with type (built-in/external/api) and installation status.

### `survex update`

```
survex update --nuclei    # Update nuclei templates
survex update --all       # Update all supported tool templates
```

---

## Scan Profiles

Use `--profile` to select a predefined module set. Profiles are used when `--modules` is not specified.

| Profile | Modules | Use Case |
|---------|---------|----------|
| `quick` | crts, dns, httpx, tls, headers | Fast passive+HTTP check. No port scan or vuln scan. |
| `web` | subfinder, crts, amass, dns, httpx, tls, waf, headers, cors, cookies, nuclei | Full web-focused scan with enumeration and vulnerability scanning. |
| `full` | all | Every module. Slowest but most thorough. |
| `passive` | crts, dns, shodan | Zero active probing. Certificate transparency, DNS records, Shodan only. |
| `stealth` | crts, dns, httpx, tls, waf | Minimal footprint. Avoid port scanning and nuclei. |
| `cloud` | subfinder, crts, dns, httpx, s3, nuclei | Cloud asset discovery and S3/GCS/Azure exposure. |

**Examples:**

```bash
# Quick check — no port scan, no vuln scan
survex scan -t example.com --profile quick --client example

# Full web assessment
survex scan -t example.com --profile web --client example

# Cloud-focused
survex scan -t example.com --profile cloud --client example

# Passive only (for authorized monitoring)
survex scan -t example.com --profile passive --client example
```

---

## Port Profiles

| Profile | Ports Scanned | Use Case |
|---------|--------------|----------|
| `top-100` | 100 most common ports | Fast initial check |
| `top-1000` | 1000 most common ports | **Default** — good balance |
| `full` | All 65535 ports | Exhaustive scan (slow) |
| `web` | 80,443,8080,8443,8000,8888,3000,4000,5000,9000,9090,9443 | Web services only |
| `db` | 3306,5432,27017,6379,1433,1521,5984,9200,9300,11211,27017,27018 | Database ports only |
| `stealth` | Top-100 with `-T2` (slow timing) | Minimal footprint |
| `"80,443,8080"` | Custom list | Any specific ports |

```bash
# Full port scan
survex scan -t 10.0.0.0/24 -m nmap --ports full --client internal

# Database ports only
survex scan -t db.example.com -m nmap --ports db --no-subs --client example

# Custom ports
survex scan -t example.com -m "nmap,httpx" --ports "80,443,3000,8080,8443" --client example
```

---

## Config File Reference

```yaml
# ── Identity ──────────────────────────────────────────────────────────────────
client: example-corp              # Required. Used for storage grouping and reports.

# ── Targets ───────────────────────────────────────────────────────────────────
targets:
  - example.com                   # Domain → full enumeration
  - app.example.com               # Use scan.no_subs: true to skip enumeration
  - 10.0.0.1                      # IP → domain-only modules skipped
  - 192.168.1.0/24                # CIDR (max /16) → expanded
  - hosts.txt                     # File → loaded line-by-line

# ── Modules ───────────────────────────────────────────────────────────────────
modules:
  - all
  # Or list specific modules:
  # - subfinder
  # - amass
  # - crts
  # - dns
  # - nmap
  # - httpx
  # - tls
  # - waf
  # - headers
  # - cors
  # - cookies
  # - s3
  # - gau
  # - katana
  # - screenshot
  # - nuclei
  # - shodan

# ── Scan Options ──────────────────────────────────────────────────────────────
scan:
  no_subs: false                  # Skip subfinder/amass/crts/tls-san
  passive: false                  # crts, dns, shodan only — no active probing
  ports: top-1000                 # Port profile (see Port Profiles)
  profile: ""                     # Scan profile (see Scan Profiles)
  rate: 150                       # Max requests/second
  threads: 50                     # HTTP concurrency (httpx --threads)
  timeout: 10                     # Per-request timeout (seconds)
  proxy: ""                       # HTTP/SOCKS proxy URL

# ── Nuclei Options ────────────────────────────────────────────────────────────
nuclei:
  severity: "critical,high,medium,info"
  tags: []                        # Include only templates with these tags
  exclude_tags:                   # Skip templates with these tags
    - dos
    - fuzz
    - generic-tokens
    - tls-sni-proxy
  templates: []                   # Additional template directories
  exclude_templates: []           # Specific templates to exclude
  update_before_scan: false       # Run nuclei -update-templates first

# ── Shodan ────────────────────────────────────────────────────────────────────
shodan:
  api_key: ""                     # Shodan API key
  enabled: false                  # Must be true to enable

# ── Output ────────────────────────────────────────────────────────────────────
output:
  dir: reports/example-corp       # Output directory
  format: json                    # json (only supported format)
  keep_history: true              # Preserve previous scan directories

# ── CI/CD Alerting ────────────────────────────────────────────────────────────
alerts:
  fail_on: high                   # Exit 1 if max severity >= this level
```

---

## Risk Rules

### Port Rules (50+ ports mapped)

| Severity | Ports | Reason |
|----------|-------|--------|
| **CRITICAL** | 1433 (MSSQL), 1521 (Oracle), 2375 (Docker), 2379 (etcd), 3306 (MySQL), 5432 (PostgreSQL), 5984 (CouchDB), 6379 (Redis), 9200 (Elasticsearch), 9300, 11211 (Memcached), 27017-27019 (MongoDB), 502 (Modbus), 2181 (Zookeeper) | Unauthenticated by default or critical infrastructure |
| **HIGH** | 23 (Telnet), 445 (SMB), 512-514 (RSH), 623 (IPMI/BMC), 2376 (Docker TLS), 3389 (RDP), 5672 (RabbitMQ), 5900 (VNC), 4444 (Metasploit), 7001 (WebLogic), 8009 (AJP Ghostcat), 8161 (ActiveMQ), 9092 (Kafka), 10250 (Kubelet), 15672 (RabbitMQ UI), 16992 (Intel AMT), 50000 (Spark/SAP), 61616 (ActiveMQ broker), 102 (S7 PLC) | Common attack vectors or remote management |
| **MEDIUM** | 21 (FTP), 22 (SSH), 25 (SMTP), 69 (TFTP), 110 (POP3), 143 (IMAP), 389 (LDAP), 873 (rsync), 902/903 (VMware), 5985/5986 (WinRM), 8888 (Jupyter), 9090 (Prometheus) | Exposed services with credential risk |
| **LOW** | 53 (DNS), 79 (Finger), 636 (LDAPS), 8080 (HTTP alt), 8443 (HTTPS alt) | Lower risk but worth noting |

### HTTP Rules

| Severity | Trigger |
|----------|---------|
| **HIGH** | Page title contains admin keywords (admin, dashboard, jenkins, grafana, phpmyadmin, kibana, portainer, vault, consul, prometheus, zabbix, splunk, ...) |
| **LOW** | Live HTTP service accessible over cleartext HTTP |

### TLS Rules

| Severity | Trigger |
|----------|---------|
| **HIGH** | Certificate is expired |
| **HIGH** | Certificate expires in ≤ 14 days |
| **MEDIUM** | Certificate expires in ≤ 30 days |
| **MEDIUM** | Self-signed certificate |
| **MEDIUM** | TLS 1.0 or TLS 1.1 negotiated |

### Security Headers Rules

| Severity | Missing Header |
|----------|---------------|
| **MEDIUM** | `Strict-Transport-Security` (HSTS) |
| **LOW** | `X-Frame-Options` (clickjacking) |
| **LOW** | `X-Content-Type-Options` |
| **INFO** | `Content-Security-Policy` |
| **INFO** | `Referrer-Policy` |
| **INFO** | `Permissions-Policy` |

**Grade Scale:** A+ (10 headers) → A (8-9) → B (7) → C (5-6) → D (3-4) → F (0-2)

### CORS Rules

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | Arbitrary origin reflected + `Access-Control-Allow-Credentials: true` |
| **CRITICAL** | Wildcard ACAO (`*`) + credentials allowed |
| **HIGH** | Wildcard `Access-Control-Allow-Origin: *` |
| **MEDIUM** | Arbitrary origin reflected without credentials |
| **MEDIUM** | Null origin accepted |

### Cookie Security Rules

| Severity | Trigger |
|----------|---------|
| **MEDIUM** | Cookie missing `Secure` flag |
| **LOW** | Cookie missing `HttpOnly` flag |
| **INFO** | Cookie missing `SameSite` attribute |

### Cloud Storage Rules

| Severity | Trigger |
|----------|---------|
| **CRITICAL** | S3/GCS/Azure bucket is publicly listable |
| **HIGH** | S3/GCS/Azure bucket is publicly accessible (not listable) |

### Shodan Rules

| Severity | Trigger |
|----------|---------|
| **HIGH** | Shodan reports a CVE for the host |

### Diff Rules (monitoring)

| Severity | Trigger |
|----------|---------|
| **INFO** | New subdomain discovered since last scan |
| **INFO** | Subdomain removed since last scan |
| **MEDIUM** | TLS certificate issuer changed |

---

## Nuclei Template Coverage

Survex runs nuclei with 17 template directories (expanded from the original 10):

| Template Dir | What It Finds |
|-------------|---------------|
| `http/takeovers/` | Subdomain takeovers (dangling DNS, expired services) |
| `http/cves/` | **NEW** — Actual CVEs: Log4Shell, Spring4Shell, MOVEit, Confluence, Exchange, etc. |
| `http/vulnerabilities/` | **NEW** — Generic vulns: XSS, SQLi, SSRF, path traversal, RCE |
| `http/exposures/` | Sensitive file exposure: .env, .git/config, SSH keys, docker-compose |
| `http/exposures/tokens/` | **NEW** — API key and token exposure in HTTP responses |
| `http/file-inclusion/` | **NEW** — Local/remote file inclusion |
| `http/exposed-panels/` | Admin and management panels exposed to internet |
| `http/default-logins/` | Default credentials: Jira, Jenkins, Grafana, Kibana, Tomcat, WebLogic (190+ vendors) |
| `http/misconfiguration/` | CORS, open redirects, security headers, exposed debug endpoints |
| `http/technologies/` | **NEW** — Technology identification for asset mapping |
| `ssl/` | TLS: deprecated versions, weak ciphers, expired/self-signed/revoked certs |
| `dns/` | DNS takeovers (Azure, ElasticBeanstalk), DNS misconfigurations |
| `cloud/` | **NEW** — Cloud service misconfigs: S3, GCS, Azure |
| `network/default-login/` | Network-level default creds: Redis, FTP, MSSQL, PostgreSQL, SMTP |
| `network/misconfig/` | Open proxy, exposed memcached, unauthenticated services |
| `network/exposures/` | Network-level data exposure |
| `network/detection/` | **NEW** — Network service detection |

**Severity coverage:** `critical`, `high`, `medium`, `info` (info is required for takeover + panel detection)

**Always excluded:** `dos`, `fuzz`, `generic-tokens`, `tls-sni-proxy` (configurable via `nuclei.exclude_tags`)

---

## Output Files

Each scan creates a timestamped directory: `reports/{client}/{scan-id}/`

```
reports/example-corp/
└── 2026-02-21T15-30-45/
    ├── report.html            ← Self-contained dark-theme HTML dashboard
    ├── summary.json           ← Scan metadata and counts
    ├── findings.json          ← All risk-scored findings, sorted by severity
    ├── subdomains.json        ← All discovered hosts with IP and discovery sources
    ├── services.json          ← Open ports with service/version info
    ├── http.json              ← Live HTTP services: URL, status, title, tech stack
    ├── dns.json               ← A, CNAME, MX, TXT records
    ├── tls.json               ← TLS cert details: expiry, version, SANs, self-signed
    ├── waf.json               ← WAF detection results
    ├── security_headers.json  ← Security headers audit with A–F grade per URL
    ├── cors.json              ← CORS test results (all tested URLs)
    ├── cookies.json           ← Cookie security flags per URL
    ├── s3.json                ← Cloud storage bucket findings
    ├── historical_urls.json   ← URLs from GAU and Katana
    ├── screenshots.json       ← Screenshot metadata (paths relative to scan dir)
    ├── shodan.json            ← Shodan host enrichment data
    ├── vulnerabilities.json   ← Raw nuclei findings
    ├── diff.json              ← Changes since previous scan
    └── screenshots/           ← PNG screenshots (if gowitness ran)
        ├── https_example_com.png
        └── ...
```

### SQLite Scan History

All scans are also persisted to `survex.db` in your working directory. This powers:
- `survex diff` — compare current vs previous scan
- `survex report` — access findings from last scan
- `survex history` — list scan history

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
          go-version: '1.21'

      - name: Install tools
        run: |
          go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
          go install github.com/projectdiscovery/httpx/cmd/httpx@latest
          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          go install github.com/SMBullet/Survex/cmd/survex@latest
          nuclei -update-templates -silent

      - name: Run ASM scan
        run: |
          survex scan --config clients/example.yaml --fail-on high
        continue-on-error: false

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: survex-report
          path: reports/
```

### Inline CI (minimal dependencies)

```bash
# Quick scan with only built-in modules (zero external tool deps)
survex scan -t example.com -m "crts,dns,tls,headers,cors,cookies,s3" --client ci --fail-on medium
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
│   └── main.go                  ← CLI: 6 subcommands, 20+ flags
├── internal/
│   ├── config/
│   │   └── config.go            ← Config structs: ScanOptions, NucleiOptions, ShodanOptions
│   ├── models/
│   │   └── models.go            ← All data types: 15 structs, ScanResult
│   ├── scan/
│   │   └── scan.go              ← 20-step pipeline orchestration
│   ├── tools/
│   │   ├── subfinder.go         ← subfinder wrapper
│   │   ├── amass.go             ← amass wrapper (NEW)
│   │   ├── crts.go              ← crt.sh pure-Go HTTP client
│   │   ├── dns.go               ← pure-Go DNS resolver
│   │   ├── nmap.go              ← nmap wrapper + 6 port profiles (UPDATED)
│   │   ├── httpx.go             ← ProjectDiscovery httpx wrapper
│   │   ├── tls.go               ← pure-Go TLS handshake analysis
│   │   ├── waf.go               ← pure-Go WAF fingerprinting (7 vendors)
│   │   ├── headers.go           ← pure-Go HTTP security headers (NEW)
│   │   ├── cors.go              ← pure-Go CORS testing (NEW)
│   │   ├── cookies.go           ← pure-Go cookie security (NEW)
│   │   ├── s3.go                ← pure-Go cloud storage detection (NEW)
│   │   ├── gau.go               ← gau wrapper (NEW)
│   │   ├── katana.go            ← katana wrapper (NEW)
│   │   ├── screenshot.go        ← gowitness wrapper (NEW)
│   │   ├── nuclei.go            ← nuclei wrapper + 17 template dirs (UPDATED)
│   │   └── shodan.go            ← Shodan REST API client (NEW)
│   ├── risk/
│   │   └── risk.go              ← Risk scoring: 50+ rules across all module types (UPDATED)
│   ├── diff/
│   │   └── diff.go              ← Scan comparison engine
│   ├── store/
│   │   └── store.go             ← SQLite persistence (pure Go, no CGO)
│   └── report/
│       └── report.go            ← Dark-theme HTML report with 12 sections (UPDATED)
├── clients/
│   ├── example.yaml             ← Full template with all options documented (UPDATED)
│   ├── scanme.yaml
│   ├── targeted.yaml
│   ├── tesla.yaml
│   ├── testfire.yaml
│   └── vulnweb.yaml
└── go.mod
```

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.21+ |
| CLI framework | `github.com/spf13/cobra` |
| Config parsing | `gopkg.in/yaml.v3` |
| Database | `modernc.org/sqlite` (pure Go, no CGO) |
| DNS | `net.Resolver` (standard library) |
| TLS analysis | `crypto/tls` (standard library) |
| HTTP clients | `net/http` (standard library) |
| HTML reports | `html/template` (standard library) |
| External tools | subfinder, amass, nmap, httpx, nuclei, gau, katana, gowitness |
| Shodan | REST API (pure Go HTTP client) |
