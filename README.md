# Survex

A command-line Attack Surface Management (ASM) tool. Point it at a domain and get a structured inventory of subdomains, open ports, live HTTP services, TLS certificates, WAF presence, and vulnerability findings — all in one run. Use it locally or drop it into any CI/CD pipeline.

---

## How It Works

1. Create a YAML config file for a client (target domain, scan options, output path)
2. Run `survex scan --config clients/acme.yaml`
3. The tool executes the full reconnaissance pipeline in sequence
4. All results are saved as JSON files under the output directory
5. A diff is computed automatically against the previous scan
6. A self-contained HTML report is generated
7. Exit code is `0` by default; `1` only if `--fail-on` is set and the threshold is met

---

## Scan Pipeline

Each scan runs 11 steps in order:

| Step | What it does |
|------|-------------|
| 1. Subdomain enumeration | Runs `subfinder`, queries `crt.sh` (certificate transparency), and extracts SANs from TLS certs — all deduplicated |
| 2. DNS resolution | Resolves A, CNAME, MX, and TXT records for every discovered host via Go's `net` package |
| 3. Port scanning | Runs `nmap` across all hosts in a single invocation (`--top-ports 1000 -sV -T4 --open`) |
| 4. HTTP probing | Runs `httpx` to discover live HTTP/S services, page titles, tech stack, and web server |
| 5. TLS deep analysis | Dials port 443 on each host directly (no external tool) — captures expiry, version, SANs, self-signed flag |
| 6. WAF detection | Sends a probe request and fingerprints response headers for 7 WAF vendors |
| 7. Vulnerability scanning | Runs `nuclei` with 10 ASM-focused template directories |
| 8. Diff | Compares current results against the last stored scan |
| 9. Risk scoring | Applies rule-based severity scoring to all findings |
| 10. Persist | Saves the full result to a local SQLite database for history |
| 11. Report | Writes JSON files and a self-contained HTML report |

---

## Installation

```bash
# Clone and build
git clone https://github.com/SMBullet/Survex.git
cd Survex
go build -o survex ./cmd/survex

# Build for Linux (cross-compile from any OS)
make build-linux
```

### External Tool Dependencies

Survex wraps best-in-class recon tools. Install them wherever Survex runs:

| Tool       | Purpose                    | Install                                                                      |
|------------|----------------------------|------------------------------------------------------------------------------|
| `subfinder` | Subdomain enumeration     | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`  |
| `nmap`      | Port scanning             | OS package manager (`apt install nmap` / `brew install nmap`)                |
| `httpx`     | HTTP probing              | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`              |
| `nuclei`    | Vulnerability scanning    | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`         |

> `crt.sh`, TLS analysis, and WAF detection require no external tools — they are implemented in pure Go.

After installing nuclei, pull the latest templates once:

```bash
nuclei -update-templates
```

---

## Usage

```bash
# Full scan
survex scan --config clients/acme.yaml

# Fail the pipeline if any HIGH or CRITICAL findings are detected
survex scan --config clients/acme.yaml --fail-on high

# Show the diff between the last two scans
survex diff --config clients/acme.yaml

# Show all findings from the last scan
survex report --config clients/acme.yaml
```

---

## Client Config File

Each client has a YAML config file. Commit these to your ops repo.

```yaml
# clients/acme.yaml

client: acme
target: acme.com

scan:
  subdomains: true   # subdomain enumeration (subfinder + crt.sh + TLS SAN)
  dns: true          # DNS record resolution
  ports: true        # nmap port scan
  http: true         # httpx HTTP probing
  nuclei: true       # nuclei vulnerability scan (requires nuclei in PATH)
  screenshot: false  # headless screenshot (not yet implemented)

output:
  dir: reports/acme
  format: json
  keep_history: true

alerts:
  fail_on: ""        # empty = never exit 1; set to: low|medium|high|critical
```

---

## Output

Each scan creates a timestamped directory:

```
reports/acme/
  2026-02-21T00-11-18/
    subdomains.json       # all discovered hosts + IP + sources
    dns.json              # A, CNAME, MX, TXT records
    services.json         # open ports with service names and banners
    http.json             # live HTTP services, titles, tech stack
    tls.json              # TLS cert details, expiry, version, SANs
    waf.json              # WAF detection results per host
    vulnerabilities.json  # nuclei findings
    findings.json         # risk-scored findings sorted by severity
    diff.json             # changes since last scan
    summary.json          # scan metadata and counts
    report.html           # self-contained HTML report (dark theme)
```

### Example `findings.json`

```json
[
  {
    "asset": "admin.acme.com",
    "port": 3389,
    "severity": "high",
    "title": "RDP exposed to internet",
    "detail": "",
    "new": true
  },
  {
    "asset": "db.acme.com",
    "port": 5432,
    "severity": "critical",
    "title": "PostgreSQL exposed to internet",
    "detail": "",
    "new": false
  }
]
```

### Example `diff.json`

```json
{
  "new_subdomains": ["staging.acme.com"],
  "removed_subdomains": [],
  "new_open_ports": [{"host": "staging.acme.com", "port": 443, "protocol": "tcp", "service_name": "https"}],
  "removed_ports": [],
  "tls_changes": []
}
```

---

## Risk Rules

### Port-Based

| Port(s) | Severity | Title |
|---------|----------|-------|
| 3389 | HIGH | RDP exposed |
| 5432, 3306, 1433, 27017, 6379, 9200, 5984, 7474 | CRITICAL | Database / data store exposed |
| 2375, 2376 | CRITICAL | Docker daemon exposed |
| 2379, 2380 | CRITICAL | etcd exposed |
| 8888 | HIGH | Jupyter Notebook exposed |
| 9090 | HIGH | Prometheus exposed |
| 4848 | HIGH | GlassFish Admin exposed |
| 11211 | HIGH | Memcached exposed |
| 8500 | HIGH | Consul UI exposed |
| 23 | HIGH | Telnet exposed |
| 21 | MEDIUM | FTP exposed |
| 22 | MEDIUM | SSH exposed |
| 25, 587, 465 | MEDIUM | SMTP exposed |
| 161 | MEDIUM | SNMP exposed |
| 8080, 8443, 8888, 9000 | LOW | Non-standard HTTP port |

### TLS-Based

| Condition | Severity |
|-----------|----------|
| Certificate expired | HIGH |
| Expires in < 14 days | HIGH |
| Expires in < 30 days | MEDIUM |
| Self-signed certificate | MEDIUM |
| TLS 1.0 or 1.1 in use | MEDIUM |

### Other

| Condition | Severity |
|-----------|----------|
| Admin/management panel keyword in URL or title | HIGH |
| nuclei finding (critical/high/medium/info) | As reported by nuclei |
| New subdomain discovered (diff) | INFO |
| New open port discovered (diff) | INFO |
| TLS certificate change (diff) | MEDIUM |

---

## Nuclei Templates

The vulnerability scanner runs nuclei against 10 ASM-focused template directories:

| Directory | What it covers |
|-----------|----------------|
| `http/takeovers/` | Subdomain takeovers (highest business impact) |
| `http/exposures/` | Exposed sensitive files: `.env`, SSH keys, `.git/config`, AWS creds |
| `http/exposed-panels/` | Admin and management panels exposed to the internet |
| `http/default-logins/` | Default credentials across 190+ vendors (Jira, Jenkins, Grafana…) |
| `http/misconfiguration/` | CORS, open redirects, exposed debug endpoints |
| `ssl/` | Deprecated TLS versions, weak ciphers, expired/self-signed/wildcard certs |
| `dns/` | DNS-based takeovers (Azure, ElasticBeanstalk) and DNS misconfigs |
| `network/default-login/` | Default credentials for network services (Redis, FTP, MSSQL, PostgreSQL) |
| `network/misconfig/` | Exposed memcached, open proxies |
| `network/exposures/` | Network-level data exposure |

Severity includes `info` — this is intentional. Subdomain takeover templates are tagged `info` or `medium` by nuclei but are critical for ASM.

Excluded tags: `dos`, `fuzz`, `generic-tokens`, `tls-sni-proxy`

---

## WAF Detection

Survex fingerprints WAF presence by analyzing HTTP response headers:

| WAF | Header / Cookie checked |
|-----|------------------------|
| Cloudflare | `CF-Ray` |
| Akamai | `X-Check-Cacheable`, `AkamaiGHost` server |
| Sucuri | `X-Sucuri-ID` |
| AWS CloudFront | `X-Amz-Cf-Id` |
| Fastly | `X-Served-By` |
| F5 BIG-IP | `BIGipServer*` cookie |
| Imperva | `X-Iinfo` |

---

## Pipeline Integration

**GitHub Actions:**

```yaml
- name: Run ASM scan
  run: |
    ./survex-linux-amd64 scan --config clients/acme.yaml --fail-on high
  artifacts:
    paths:
      - reports/
```

**GitLab CI:**

```yaml
asm-scan:
  script:
    - ./survex-linux-amd64 scan --config clients/$CLIENT.yaml --fail-on high
  artifacts:
    paths:
      - reports/
```

Exit code `1` only when `--fail-on` is set and findings meet or exceed the configured severity. Default exit is always `0`.

---

## Project Structure

```
cmd/
  survex/             CLI entrypoint (cobra: scan, diff, report)

internal/
  config/             YAML config loading and validation
  scan/               11-step scan orchestrator
  tools/
    subfinder.go      Subdomain enumeration via subfinder
    crts.go           Certificate transparency via crt.sh (no external tool)
    nmap.go           Port scanning via nmap (all hosts in one invocation)
    httpx.go          HTTP probing via httpx
    dns.go            DNS resolution via Go net package
    tls.go            TLS handshake analysis (pure Go)
    waf.go            WAF fingerprinting (pure Go)
    nuclei.go         Vulnerability scanning via nuclei v3
  diff/               Diff engine (compare consecutive scans)
  risk/               Rule-based severity scoring
  store/              SQLite scan history (pure Go, no CGO)
  report/             Self-contained HTML report generation

clients/              Client YAML config files
reports/              Scan output (gitignored)
```

---

## Technology Stack

| Component     | Technology                                    |
|---------------|-----------------------------------------------|
| Language      | Go                                            |
| CLI           | [Cobra](https://github.com/spf13/cobra)       |
| Config        | YAML (`gopkg.in/yaml.v3`)                     |
| Storage       | SQLite (`modernc.org/sqlite` — pure Go, no CGO) |
| External tools | subfinder, nmap, httpx, nuclei               |
| Pure-Go recon | crt.sh HTTP, TLS handshake, WAF fingerprinting |

No database server required. SQLite keeps full scan history in a single local file.
