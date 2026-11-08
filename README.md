<div align="center">

# XploitScope

### Web Security Assessment — Kali Linux First

**See the signal. Understand the evidence. Know the limits.**

[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)](#installation)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go&logoColor=white)](#requirements)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#requirements)
[![Mode](https://img.shields.io/badge/testing-passive%20by%20default-2E8B57?style=flat-square)](#safe-use)
[![Price](https://img.shields.io/badge/price-free-brightgreen?style=flat-square)](#free-and-open-source)

```text
 __  __     _     _ _   ___
 \ \/ /_ __| |___(_) |_/ __| __ ___ _ __  ___
  >  <| '_ \ / _ \ |  _\__ \/ _/ _ \ '_ \/ -_)
 /_/\_\ .__/_\___/_|\__|___/\__\___/ .__/\___|
      |_|                          |_|

                 Developer : Hex
                 Discord   : 0x7v7
```

[Quick Start](#quick-start) · [Features](#what-it-does) · [Usage](#usage) · [Safety](#safe-use)

</div>

---

> **Project status: early development.** XploitScope currently provides
> passive HTTP/TLS checks for one explicitly authorized URL and offline
> analysis of saved HTTP observations. It is not a full web vulnerability
> scanner, and it does not verify exploitability.

## What it does

XploitScope combines a small Go command-line application with modular Python
checks. It is designed to make results easy to read and review:

- Severity-sorted terminal findings with optional color.
- Evidence, affected URL/location, OWASP mapping, confidence, and a suggested fix.
- JSON reports for saving or downstream processing.
- Passive checks for response headers, cookie attributes, CORS metadata,
  database-error disclosure, and supplied-value reflection in saved captures.
- One-request HTTP/TLS configuration review for a public URL, with explicit
  authorization confirmation.
- No third-party Python packages; no Windows-specific runtime components.

Findings are **indicators for human review**, not confirmed vulnerabilities.
No findings does not mean an application is secure.

## Free and open source

XploitScope is free to download and use, with no subscriptions, paid tiers, or
usage fees. The source is openly available, and contributions are welcome.

The project is released under the [MIT License](./LICENSE). You may use, copy,
modify, publish, distribute, sublicense, and sell copies of the software,
subject to including the copyright and license notice. The software is
provided without warranty. “Without restrictions” is not literal: the MIT
notice condition and applicable laws still apply.

## Contact

- **Developer:** Hex
- **Discord:** `0x7v7`

## Quick Start

### Install on Kali Linux

Install Go 1.22+ and Python 3.10+ if they are not already available, then run
from the project directory:

```sh
sh scripts/install.sh
xploitscope doctor
```

The installer builds the CLI and installs it under `~/.local/bin`, with the
Python worker under `${XDG_DATA_HOME:-~/.local/share}/xploitscope`. It does not
use `sudo` or install system packages. Add `~/.local/bin` to your `PATH` if
needed.

### Inspect an authorized website

Interactive mode asks for the URL and requires you to type `yes` to confirm
authorization:

```sh
xploitscope scan
```

Or provide the target and acknowledgement directly:

```sh
xploitscope scan \
  --url https://your-authorized-site.example \
  --authorized \
  --output report.json
```

### Analyze a saved response

Analysis runs **all available checks by default**. You normally do not need to
choose `sqli`, `xss`, or other modules:

```sh
xploitscope analyze --input capture.json
```

Use JSON output when piping results into another tool:

```sh
xploitscope analyze --input capture.json --format json
```

Narrow the checks only when needed, and optionally save the JSON report while
keeping the readable terminal summary:

```sh
xploitscope analyze \
  --input capture.json \
  --module sqli,cors \
  --output findings.json
```

## Usage

```text
xploitscope help
xploitscope version
xploitscope doctor
xploitscope modules
xploitscope scan --url https://HOST --authorized [--output report.json]
xploitscope analyze --input capture.json [--module NAME[,NAME...]]
                       [--format text|json] [--output report.json]
```

### Example terminal report

```text
XploitScope | Passive Analysis
Observations: 1 | Modules: access_control, cookies, cors, headers, sqli, ssrf, xss
--------------------------------------------------------------------
Indicators: 2 | MEDIUM 1 | LOW 1

[MEDIUM] 01. Database error text appears in the response
    Check:    sqli | OWASP A05:2025 Injection
    Triage:   potential | confidence 6/10
    URL:      https://app.example.test/item?id=%5BREDACTED%5D
    Location: response body, line 12
    Evidence: SQL syntax error near 'MySQL'
    Fix:      Review server-side error handling. This indicator alone does not confirm SQL injection.
```

### Offline input format

`analyze` reads a local JSON file containing an `observations` array:

```json
{
  "observations": [
    {
      "url": "https://app.example.test/item?id=redact-me",
      "status_code": 200,
      "request_headers": {
        "Origin": "https://other.example.test"
      },
      "headers": {
        "Content-Type": "text/html",
        "Set-Cookie": "session=REDACTED; Path=/"
      },
      "body": "Response body from an authorized test capture",
      "reflected_values": []
    }
  ]
}
```

The input is limited to 10 MiB and 500 observations per analysis. Remove
credentials, tokens, personal information, and other sensitive values before
sharing captures or reports. Query parameter values are redacted in finding
URLs.

## Checks and coverage

| Check | What it can indicate | Important limitation |
|---|---|---|
| `headers` | Missing selected browser-security headers, verbose server headers, deprecated negotiated TLS | A header's absence is not automatically a vulnerability; app context matters |
| `cookies` | Missing `Secure`, `HttpOnly`, or `SameSite` attributes | Cookie purpose and deployment context affect risk |
| `cors` | Saved request/response evidence of reflected origins with credentials | Offline analysis only sees the headers present in the capture |
| `sqli` | Recognizable database error text in a saved response | Error disclosure is not proof of SQL injection |
| `xss` | Exact caller-supplied values reflected in a saved response | Does not send payloads or determine browser execution context |
| `access_control` | Manual-review reminder | No identity or authorization testing |
| `ssrf` | Manual-review reminder | No URL-fetch or SSRF testing |

### OWASP Top 10:2025

XploitScope reports mappings using the current [OWASP Top 10:2025](https://owasp.org/Top10/2025/).
Its one-request passive scan provides only **partial indicators** for security
misconfiguration, cryptographic failures, and injection. It does not assess
the other categories. In particular, access control, supply-chain security,
authentication, insecure design, integrity, logging, and business logic
require source review, authenticated testing, operational context, or other
evidence that a single public HTTP response cannot provide.

For broader assessment guidance, see the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
and [OWASP ASVS 5.0.0](https://asvs.owasp.org/). Automated checks complement
expert review; they do not replace it.

## Safe use

- Only assess systems you own or have explicit written permission to test.
- `scan` makes one GET request and permits at most two same-origin redirects.
- It does not crawl, log in, submit forms, or send exploit payloads.
- Private, local, and reserved IP destinations are blocked; only standard
  HTTP/HTTPS ports are allowed.
- The response body is capped at 1 MiB. URL query strings are omitted from
  scan reports to reduce accidental secret exposure.
- Review every indicator manually and follow the rules of engagement for the
  target.

## Requirements

- Kali Linux or another Linux distribution
- Go 1.22 or newer
- Python 3.10 or newer

The Python worker uses only the standard library.

## Development

```sh
go test ./...
go vet ./...
python3 -m unittest discover -s python
go run ./cmd/xploitscope help
```

The CLI is in `cmd/xploitscope/`; passive Python checks are separate modules
under `python/xploitscope_detector/`. Contributions that add checks should
include evidence-based findings, accurate OWASP mapping, clear limitations,
and tests for both positive and negative cases.

##  c

## License

[MIT License](./LICENSE) · Copyright (c) 2026 Hex
