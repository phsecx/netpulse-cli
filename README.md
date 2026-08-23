# netpulse-cli

`netpulse-cli` is a fast, asynchronous network security and SSL auditing utility for Python 3.10 and newer. It concurrently inspects multiple websites and records HTTP response behavior, TLS certificate expiration data, and the presence of three important security headers: HSTS, Content-Security-Policy, and X-Frame-Options.

> **Authorized use:** Scan only websites or systems for which you have explicit permission. This utility performs a lightweight configuration audit; it is not a penetration-testing or vulnerability-exploitation framework.

## Language separation

All repository documentation, report content, code comments, identifiers, docstrings, function definitions, and Git metadata use formal technical English. The command-line interface intentionally uses friendly Roman Urdu / Hinglish for progress messages, alerts, and terminal-facing errors.

## Features

| Capability | Details |
| --- | --- |
| Concurrent scanning | Uses `asyncio`, `aiohttp`, and a configurable concurrency limit. |
| Website response audit | Records HTTP status, final URL, redirect behavior, content type, response time, and response headers. |
| SSL audit | Performs a TLS handshake and records certificate validity dates, expiry countdown, issuer, and subject. |
| Security-header audit | Checks HSTS, Content-Security-Policy, and X-Frame-Options and calculates a percentage score. |
| Report generation | Produces Markdown, JSON, or both report formats. |
| Input sources | Accepts direct targets or a newline-separated target file. |
| CLI output | Provides friendly Roman Urdu / Hinglish progress and alert messages. |

## Installation

Install Python 3.10 or newer, create a virtual environment, and install the runtime dependency:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Quick start

Scan one or more targets:

```bash
python -m netpulse.main example.com https://www.python.org
```

The terminal interface provides Roman Urdu / Hinglish status messages, including scan progress, certificate alerts, and report locations.

Scan targets from a file:

```bash
python -m netpulse.main --file targets.txt --format both --output reports
```

The input file accepts one hostname or HTTP(S) URL per line. Empty lines and lines beginning with `#` are ignored.

## Command-line options

| Option | Default | Description |
| --- | ---: | --- |
| `targets` | — | Direct hostnames or HTTP(S) URLs. |
| `--file` | — | A newline-separated target file. |
| `--format` | `both` | Select `markdown`, `json`, or `both`. |
| `--output` | `reports` | Destination directory for generated reports. |
| `--concurrency` | `20` | Maximum number of targets processed concurrently. |
| `--timeout` | `10` | Request and TLS timeout in seconds. |

Example with conservative network settings:

```bash
python -m netpulse.main \
  --file targets.txt \
  --concurrency 5 \
  --timeout 15 \
  --format markdown \
  --output audit-output
```

## Report format

The Markdown report contains a summary table and detailed findings for each target. The JSON report provides a machine-readable object with the tool name, generation timestamp, and result list:

```json
{
  "tool": "netpulse-cli",
  "createdAt": "2026-08-23T12:00:00+00:00",
  "results": []
}
```

The SSL result includes `expiresInDays`, which represents the certificate expiry countdown. The CLI displays an alert when a certificate is expired or has 30 days or fewer remaining. The security-header score is the percentage of required headers that are present.

## Project layout

```text
netpulse-cli/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── tests/
│   └── testcli.py
└── netpulse/
    ├── __init__.py
    ├── core.py
    ├── utils.py
    └── main.py
```

`netpulse/core.py` contains the asynchronous network checks. `netpulse/utils.py` provides target normalization and report rendering. `netpulse/main.py` handles command-line arguments, terminal output, and exit codes.

## Tests

Run the test suite from the repository root:

```bash
python -m unittest discover -s tests -p 'test*.py' -v
```

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for the complete terms.
