# subtake — Subdomain Takeover Checker

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**subtake** is a fast, production-quality CLI tool for detecting dangling DNS records and potential subdomain takeover vulnerabilities. It resolves CNAME chains, matches them against a registry of 30+ known-vulnerable hosted services, and confirms each finding via HTTP body-signature probing.

---

## What is Subdomain Takeover?

When a company creates a DNS CNAME record pointing `blog.company.com` to a third-party service (e.g., `company.github.io`) and later deletes their account on that service **without** removing the DNS record, an attacker can claim the same service account and begin serving content on `blog.company.com`.

This is called a **subdomain takeover**, and it enables:

- Phishing attacks using legitimate company subdomains
- Session cookie theft (same-origin policy bypass)
- Bypassing CSP/CORS whitelists
- Reputation damage

**subtake** automates the detection of these dangling DNS records across large domain lists.

---

## How It Works

At a high level, **subtake** identifies vulnerable subdomains in three simple steps:

1. **Check DNS (CNAME Resolution):** It resolves the subdomain's DNS records to see if it points to an external third-party service (such as GitHub Pages, AWS S3, Heroku, Shopify, etc.).
2. **Match Service Fingerprints:** If a CNAME is found, it checks whether the destination matches any of 30+ known hosted services.
3. **Probe & Confirm:** It sends an HTTP/HTTPS request to the subdomain and inspects the response. If the provider returns an unclaimed error signature (e.g., *"There isn't a GitHub Pages site here"* or *"No such app"*), the domain is flagged as **vulnerable**.

If a CNAME points to a destination that no longer resolves at all (`NXDOMAIN`), it is flagged as **suspicious** (dangling DNS).

---

## Installation

### From source (recommended)

```bash
# Clone / download the project
cd "Subdomain Takeover checker"

# Install with pip (editable mode for development)
pip install -e .

# Or install normally
pip install .
```

The `subtake` command is now available in your PATH.

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `dnspython` | ≥ 2.6 | CNAME chain DNS resolution |
| `httpx` | ≥ 0.27 | Async-capable HTTP probing |
| `tqdm` | ≥ 4.66 | Live progress bar |

---

## Quick Start

```bash
# Basic scan (saves to reports/ by default)
subtake --input domains.txt

# Discover subdomains using crt.name first, then scan
subtake --input domains.txt --discover

# Full scan with custom concurrency and verbose logs
subtake --input domains.txt --threads 20 --verbose

# Include clean domains in CSV too
subtake --input domains.txt --all --output reports/all_results.csv
```

---

## CLI Reference

```
subtake [OPTIONS]

Options:
  --input FILE,  -i FILE   (Required) Newline-separated list of domains
  --output FILE, -o FILE   CSV output path          [default: reports/results.csv]
  --threads N,   -t N      Concurrent worker threads [default: 10]
  --report-md FILE         Markdown report path     [default: reports/report.md]
  --report-html FILE       HTML report path         [default: reports/report.html]
  --all                    Include all findings in CSV (not just vuln/susp)
  --verbose, -v            Enable debug logging
  --version, -V            Show version and exit
  --help, -h               Show this message and exit

Discovery Options:
  --discover, -d           Enumerate subdomains via crt.name before checking
  --discover-only          Enumerate subdomains only and exit
  --discovered-out FILE    Save discovered subdomains [default: reports/discovered.txt]
  --no-dates               Omit first-seen dates for faster crt.name queries
```

---

## Input File Format

Plain text, one domain per line. Comments (`#`) and blank lines are ignored.

```
# Production subdomains
blog.company.com
help.company.com
status.company.com

# Partner redirects
partner.company.com
```

---

## Output Files

### CSV (`--output`)

Contains vulnerable and suspicious findings (all findings with `--all`):

| Column | Description |
|--------|-------------|
| `domain` | Input domain |
| `vulnerable` | `True` if confirmed vulnerable |
| `suspicious` | `True` if suspicious (unconfirmed) |
| `service` | Matched hosted service name |
| `confidence` | HIGH / MEDIUM / LOW |
| `final_cname` | Last CNAME target in chain |
| `cname_chain` | Full CNAME chain (`a -> b -> c`) |
| `http_status` | HTTP response code from probe |
| `body_snippet` | Short excerpt from response body |
| `notes` | Human-readable explanation |

### Markdown Report (`--report-md`)

Summary statistics + tabular findings, rendered by any Markdown viewer or GitHub.

### HTML Report (`--report-html`)

Self-contained, styled HTML with colour-coded status badges. No external dependencies — open directly in any browser.

---

## How Detection Works

```
Input domains
     │
     ▼
DNS CNAME resolution (dnspython)
     │
     ├── No CNAME?  → CLEAN
     │
     ▼
CNAME pattern matching (30+ service fingerprints)
     │
     ├── No match?  → CLEAN
     │
     ▼
HTTP probe (httpx, HTTPS → HTTP fallback)
     │
     ├── Body matches unclaimed signature? → VULNERABLE ✗
     ├── NXDOMAIN on CNAME target?        → SUSPICIOUS ⚠
     └── Neither?                          → CLEAN ✓
```

**Confidence levels:**

- `HIGH` — Service's unclaimed page signature is unique and reliable
- `MEDIUM` — Signature may have false positives; manual verification recommended  
- `LOW` — Heuristic only; treat as a lead, not a confirmed finding

---

## Adding Custom Fingerprints

Edit [`subtake/fingerprints.py`](subtake/fingerprints.py) and append a new `Fingerprint` to the `FINGERPRINTS` list:

```python
from subtake.fingerprints import Fingerprint, FINGERPRINTS

FINGERPRINTS.append(Fingerprint(
    service="My Custom Service",
    cname_patterns=["mycustomcdn.com", "myservice.io"],
    http_fingerprints=[
        "This account has been suspended",
        "No site configured",
    ],
    confidence="HIGH",
    nxdomain_vulnerable=False,
))
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `service` | `str` | Human-readable service name |
| `cname_patterns` | `list[str]` | Substrings matched case-insensitively against CNAME targets |
| `http_fingerprints` | `list[str]` | Substrings matched case-insensitively against HTTP response body |
| `confidence` | `str` | `"HIGH"`, `"MEDIUM"`, or `"LOW"` |
| `nxdomain_vulnerable` | `bool` | Flag as vulnerable on NXDOMAIN alone (no HTTP probe needed) |

---

## Project Structure

```
Subdomain Takeover checker/
├── pyproject.toml          # Build config and dependencies
├── README.md               # This file
├── subtake/
│   ├── __init__.py         # Package metadata
│   ├── __main__.py         # CLI entry point (argparse + tqdm)
│   ├── resolver.py         # CNAME chain resolution (dnspython)
│   ├── fingerprints.py     # 30+ service fingerprint registry
│   ├── prober.py           # HTTP probing (httpx)
│   ├── checker.py          # Orchestration + ThreadPoolExecutor
│   ├── reporter.py         # CSV / Markdown / HTML writers
│   └── utils.py            # Logging, domain sanitiser, banner
└── examples/
    └── sample_domains.txt  # 10 sample domains for testing
```

---

## License

MIT License — see `LICENSE` for details.
