# SurfaceScope

A CLI scanner that maps and tests the attack surface of web applications and REST/GraphQL APIs. It crawls a target, discovers pages, forms and OpenAPI endpoints, then checks for common web (OWASP Top 10 2021) and API (OWASP API Top 10 2023) weaknesses. Output is nuclei-style, with JSON export and CI-friendly exit codes.

## Features

**Web (default)**
- Breadth-first crawler with de-duplicated pages and forms
- SQL injection (DB error signatures compared against a baseline response)
- Reflected XSS, and CSRF token checks on POST forms
- Sensitive file exposure (content-validated: `.env`, `.git/config`, backups, admin panels)
- Missing security headers, cookie flags (Secure / HttpOnly / SameSite)
- Open redirect, HTTP vs HTTPS

**API (`--api`)**
- OpenAPI/Swagger auto-discovery and exposed-docs detection (API9)
- Endpoints that require auth in the spec but answer anonymously (API2)
- Sensitive fields in responses (API3)
- BOLA/IDOR across two accounts (API1, needs `--token2`)
- JWT: `alg=none` forgery test, missing expiry (API2)
- CORS misconfiguration, missing rate limiting (API4)
- Verbose error leakage, GraphQL introspection, version disclosure, HTTP TRACE (API8)

Every finding carries its OWASP reference.

## Installation

```bash
git clone https://github.com/Ayan946/SurfaceScope.git
cd SurfaceScope
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Usage

```bash
surfacescope -t http://target.com                      # web scan
surfacescope -t https://api.target.com --api           # + API checks (auto-discovers the spec)
surfacescope -t https://api.target.com --api --token $A --token2 $B   # authenticated + BOLA
surfacescope -t http://target.com -H "X-API-Key: abc" --safe --json out.json -o out.txt
python -m surfacescope -t http://target.com            # same thing, no install script needed
```

| Flag | Purpose |
|---|---|
| `-t, --target` | Target URL |
| `--max-pages N` | Max pages to crawl (default 20) |
| `--api` | Run API checks |
| `--spec URL` | OpenAPI/Swagger JSON URL (default: auto-discover) |
| `--token / --token2` | Bearer tokens for two accounts |
| `-H "Name: value"` | Extra header, repeatable |
| `--safe` | Skip injection tests on POST forms |
| `--json FILE` | Write findings as JSON |
| `-o FILE` | Save console output |
| `-V, --version` | Print version |

Exit code is `1` if any HIGH or CRITICAL finding exists and `0` otherwise, so it can gate a CI pipeline.

## Safety

API checks use GET only (plus one read-only GraphQL introspection query). Web injection tests submit forms, which can create data on a live app; use `--safe` to skip POST forms. The rate-limit check sends a burst of 30 requests.

## Tests

```bash
python tests/test_surfacescope.py
```

Scans a deliberately vulnerable local server and asserts every check fires, with no false positive on a page that merely mentions "SQL syntax".

## Known limitations

- The crawler parses static HTML and does not execute JavaScript, so SPAs expose few forms.
- Specs must be JSON (no YAML), and only GET operations are scanned.
- BOLA needs two valid accounts and tests object id `1`; confirm hits manually, since shared data can match.
- Mass assignment, SSRF and body-parameter fuzzing are out of scope (they need write requests or an out-of-band listener).

## Disclaimer

For authorized security testing only. You are responsible for having permission to test any target.
