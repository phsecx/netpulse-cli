# netpulse-cli

`netpulse-cli` ek fast, asynchronous network security aur SSL auditor hai. Yeh Python 3.10+ par chalta hai aur multiple websites ko concurrently inspect karta hai. Har target ke liye HTTP response status, response time, redirect behavior, SSL certificate expiry, aur teen important security headers check hote hain: HSTS, CSP, aur X-Frame-Options.

> **Safe use:** Sirf un websites ya systems ko scan karein jinhein scan karne ki aapko permission hai. Yeh tool lightweight audit ke liye bana hai, penetration testing ya vulnerability exploitation ke liye nahi.

## Features

| Capability | Details |
| --- | --- |
| Concurrent scanning | `asyncio`, `aiohttp`, aur configurable concurrency limit |
| Website response | HTTP status, final URL, redirects, content type, response time |
| SSL audit | TLS handshake, certificate validity dates, expiry countdown, issuer and subject |
| Header audit | HSTS, Content-Security-Policy, aur X-Frame-Options presence and score |
| Reports | Markdown, JSON, ya dono formats |
| Friendly CLI | Natural Roman Urdu / English progress and alert messages |
| Input sources | Direct targets ya newline-separated target file |

## Installation

Python 3.10 ya newer install karein, phir project directory mein dependencies install karein:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Quick start

Ek ya multiple targets scan karein:

```bash
python -m netpulse.main example.com https://www.python.org
```

CLI messages simple aur friendly honge, misal ke taur par:

```text
[+] Website scan ho rahi hai: 2 target(s), concurrency 20.
[+] https://example.com: HTTP 200, response 84.21 ms, SSL days left 71.
[!] Alert: SSL Certificate expire hone wala hai!
[+] Report ready hai: reports/netpulse-report-20260823-120000.md
```

Targets file se scan karne ke liye:

```bash
python -m netpulse.main --file targets.txt --format both --output reports
```

## Options

| Option | Default | Purpose |
| --- | ---: | --- |
| `targets` | — | Direct hostnames ya HTTP(S) URLs |
| `--file` | — | Newline-separated targets; `#` se shuru hone wali lines ignore hoti hain |
| `--format` | `both` | `markdown`, `json`, ya `both` |
| `--output` | `reports` | Report files ka destination folder |
| `--concurrency` | `20` | Ek waqt mein maximum scans |
| `--timeout` | `10` | Request aur TLS timeout seconds mein |

Example with conservative settings:

```bash
python -m netpulse.main \
  --file targets.txt \
  --concurrency 5 \
  --timeout 15 \
  --format markdown \
  --output audit-output
```

## Reports

Markdown report mein summary table aur har target ki detailed findings hoti hain. JSON report machine-readable payload deta hai:

```json
{
  "tool": "netpulse-cli",
  "createdAt": "2026-08-23T12:00:00+00:00",
  "results": []
}
```

SSL result mein `expiresInDays` field expiry countdown deti hai. Thirty days ya us se kam expiry par CLI alert print karta hai. Header score teen required headers mein present headers ka percentage hai.

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

`netpulse/core.py` asynchronous network checks rakhta hai. `netpulse/utils.py` input normalization aur report rendering handle karta hai. `netpulse/main.py` CLI arguments, progress output, aur exit codes manage karta hai.

## Tests

Repository root se tests run karein:

```bash
python -m unittest discover -s tests -p 'test*.py' -v
```

## License

MIT License. Details ke liye [LICENSE](LICENSE) file dekhein.
