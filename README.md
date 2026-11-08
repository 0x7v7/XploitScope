# XploitScope

XploitScope is a Linux-first web security assessment framework under
development. Its planned architecture uses Go for the CLI and HTTP/task
management, Python for detection modules, SQLite for scan data, and JSON for
component communication.

## Current status

The current foundation provides a Go CLI, a Python JSON Lines worker, offline
analysis for local HTTP snapshots, and an explicitly authorized, single-request
passive HTTP/TLS configuration check. It does not crawl targets or perform
active vulnerability testing.

## Requirements

- Linux (Kali Linux is the primary target)
- Go 1.22 or newer
- Python 3.10 or newer

The current worker uses only the Python standard library. No Windows-specific
components or third-party Python packages are required.

## Install

From the project directory:

```sh
sh scripts/install.sh
```

The installer checks Go and Python, builds the CLI, and installs it under
`~/.local/bin` and the worker under
`${XDG_DATA_HOME:-~/.local/share}/xploitscope`. It does not use `sudo` or
install system packages. If `~/.local/bin` is not on `PATH`, add it using your
shell's normal profile configuration.

To choose a different binary install directory:

```sh
XPLOITSCOPE_BIN_DIR="$HOME/bin" sh scripts/install.sh
```

## Commands

```text
xploitscope help
xploitscope version
xploitscope doctor
xploitscope modules
xploitscope analyze --input response.json --output findings.json --module sqli,xss
xploitscope scan --url https://your-authorized-site.example --authorized --output report.json
```

You can also run `xploitscope scan` in an interactive terminal; it will ask
for the URL and require you to type `yes` to confirm authorization. For
automation, pass both `--url` and `--authorized`.

`doctor` verifies that Python 3 and the installed worker are available and that
the Go/Python protocol responds. For development, run it from the project root.
To use a worker at a custom location, set `XPLOITSCOPE_WORKER` to its path.

`analyze` only reads a local JSON file and prints JSON to standard output (or
writes it to `--output`). Use `--module` to select comma-separated modules;
unknown module names are rejected. Input must contain an `observations` array. Each
observation may contain a URL, response status, headers, body, and
`reflected_values` (known values from an existing, authorized test capture):

```json
{
  "observations": [
    {
      "url": "https://example.test/",
      "status_code": 200,
      "headers": {
        "Content-Type": "text/html",
        "Set-Cookie": "session=REDACTED; Path=/"
      },
      "body": "Response body from a saved test capture",
      "reflected_values": []
    }
  ]
}
```

The input limit is 10 MiB and each analysis accepts at most 500 observations.
The `sqli` module identifies database-error text, while `xss` only reports
verbatim reflection of explicitly supplied values. Neither confirms a
vulnerability; findings are labeled as potential and require manual review.
The `headers` and `cookies` modules check response configuration. `ssrf` and
`access_control` are listed as manual-review modules and do not probe anything.
Redact credentials, tokens, and personal data from captures before analysis.

`scan` is a low-impact, passive HTTP configuration check for one public URL. It
requires the explicit `--authorized` acknowledgement, sends a single GET
request (at most two same-origin redirects), limits the response body to 1 MiB,
blocks private/local/reserved destinations, only permits standard HTTP/HTTPS
ports, and never crawls or submits forms.
It reports response-header and cookie indicators, HTTP status, and negotiated
TLS version. Reports omit URL query strings to avoid leaking tokens.

This is **not a full OWASP Top 10 scanner**. A passive request cannot reliably
confirm injection, access-control, authentication, SSRF, vulnerable-component,
or business-logic weaknesses. The report lists coverage limitations and
requires manual validation; absence of findings is not assurance that a site
is secure. Only run it against systems you own or have written authorization
to assess.

## Development

```sh
go test ./...
python3 -m unittest discover -s python
go run ./cmd/xploitscope doctor
```

The Go/Python bridge uses versioned JSON Lines for health checks, module
discovery, and offline analysis. Standard output is reserved for protocol
messages; worker diagnostics belong on standard error. No active exploit
testing functionality is included.
