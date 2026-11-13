import random
import re
import string
from urllib.parse import urlparse

import requests

from surfacescope.crawler import TIMEOUT, log

SKIP_TYPES = {"submit", "button", "image", "file", "reset"}
SQLI_PAYLOADS = ["'", "' OR '1'='1"]
# Specific DB error signatures; bare words like "sql" or "syntax" match ordinary pages.
SQLI_ERRORS = [
    "you have an error in your sql syntax", "sqlite3.operationalerror", "sqlstate",
    "unclosed quotation mark", "syntax error at or near", "unterminated quoted string",
    "psycopg2.errors", "ora-00933", "ora-01756", "mysql_fetch", "pg_query()",
]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
REQUIRED_HEADERS = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"]
# path -> (content check, severity). Content checks avoid soft-404 false positives.
SENSITIVE = {
    ".env": (lambda r: re.search(r"(?m)^[A-Z][A-Z0-9_]*=", r.text), "HIGH"),
    ".git/config": (lambda r: "[core]" in r.text, "HIGH"),
    "backup.zip": (lambda r: r.content[:2] == b"PK", "HIGH"),
    "config.php": (lambda r: "<?php" in r.text, "HIGH"),
    "admin/": (lambda r: "password" in r.text.lower(), "MEDIUM"),
    "wp-admin/": (lambda r: "password" in r.text.lower(), "MEDIUM"),
}


def finding(vuln, severity, detail, ref=""):
    return {"vuln": vuln, "severity": severity, "detail": detail, "ref": ref}


def emit(findings, output_file=None):
    for f in findings:
        ref = f" [{f['ref']}]" if f["ref"] else ""
        log(f"[{f['severity']}] {f['vuln']}{ref} — {f['detail']}", output_file)
    return findings


def _submit(session, form, data):
    if form["method"] == "post":
        return session.post(form["action"], data=data, timeout=TIMEOUT)
    return session.get(form["action"], params=data, timeout=TIMEOUT)


def _inject(session, forms, payloads, hit, vuln, severity, ref, safe):
    """Send each payload into each field; `hit(text, payload, baseline_text)` decides."""
    out = []
    for form in forms:
        if safe and form["method"] == "post":
            continue
        base = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
        try:
            baseline = _submit(session, form, base).text
        except requests.RequestException:
            continue
        for field in form["inputs"]:
            if not field["name"] or field["type"] in SKIP_TYPES:
                continue
            for payload in payloads:
                try:
                    r = _submit(session, form, {**base, field["name"]: payload})
                except requests.RequestException:
                    continue
                if hit(r.text, payload, baseline):
                    out.append(finding(vuln, severity,
                               f"{form['action']} param '{field['name']}' payload: {payload}", ref))
                    break
    return out


def check_sqli(session, forms, safe=False):
    def hit(text, payload, baseline):
        t, b = text.lower(), baseline.lower()
        return any(e in t and e not in b for e in SQLI_ERRORS)
    return _inject(session, forms, SQLI_PAYLOADS, hit, "SQL Injection", "CRITICAL", "A03:2021", safe)


def check_xss(session, forms, safe=False):
    hit = lambda text, payload, baseline: payload in text and payload not in baseline
    return _inject(session, forms, XSS_PAYLOADS, hit, "XSS", "HIGH", "A03:2021", safe)


def check_csrf(session, forms):
    out = []
    for form in forms:
        if form["method"] == "post":
            has_token = any("csrf" in i["name"].lower() or "token" in i["name"].lower()
                            for i in form["inputs"] if i["name"])
            if not has_token:
                out.append(finding("CSRF", "HIGH", f"{form['action']} has no CSRF token", "A01:2021"))
    return out


def check_sensitive_files(session, base_url):
    out, root = [], base_url.rstrip("/")
    try:
        probe = "".join(random.choices(string.ascii_lowercase, k=12))
        soft_404 = session.get(f"{root}/surfacescope-{probe}", timeout=TIMEOUT).status_code == 200
    except requests.RequestException:
        soft_404 = False
    for path, (is_hit, severity) in SENSITIVE.items():
        if soft_404 and severity == "MEDIUM":  # login-keyword check is unreliable on catch-all sites
            continue
        try:
            r = session.get(f"{root}/{path}", timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and is_hit(r):
            out.append(finding("Sensitive File Exposure", severity, f"{path} publicly accessible", "A05:2021"))
    return out


def check_headers(session, base_url):
    try:
        r = session.get(base_url, timeout=TIMEOUT)
    except requests.RequestException:
        return []
    missing = [h for h in REQUIRED_HEADERS if h not in r.headers]
    return [finding("Missing Security Headers", "MEDIUM", ", ".join(missing), "A05:2021")] if missing else []


def check_cookies(session, base_url):
    out = []
    try:
        r = session.get(base_url, timeout=TIMEOUT)
    except requests.RequestException:
        return out
    for raw in r.raw.headers.getlist("Set-Cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = [p.strip().lower() for p in raw.split(";")[1:]]
        if "secure" not in attrs:
            out.append(finding("Insecure Cookie", "MEDIUM", f"'{name}' missing Secure flag", "A05:2021"))
        if "httponly" not in attrs:
            out.append(finding("Insecure Cookie", "LOW", f"'{name}' missing HttpOnly flag", "A05:2021"))
        if not any(a.startswith("samesite") for a in attrs):
            out.append(finding("Insecure Cookie", "LOW", f"'{name}' missing SameSite attribute", "A05:2021"))
    return out


def check_open_redirect(session, pages):
    out = []
    for page in sorted(pages)[:5]:  # sorted: crawl order must not change what gets tested
        for param in ["redirect", "url", "next", "return"]:
            try:
                r = session.get(page, params={param: "https://evil.com"}, timeout=TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                continue
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and urlparse(loc).netloc == "evil.com":
                out.append(finding("Open Redirect", "MEDIUM", f"{page} param '{param}'", "A01:2021"))
    return out


def check_ssl(session, base_url):
    if base_url.startswith("http://"):
        return [finding("No HTTPS", "HIGH", "Site served over unencrypted HTTP", "A02:2021")]
    return []


def run_all_checks(session, crawl_data, base_url, output_file=None, safe=False):
    forms, findings = crawl_data["forms"], []
    runners = [
        (check_sqli, (session, forms, safe)),
        (check_xss, (session, forms, safe)),
        (check_csrf, (session, forms)),
        (check_sensitive_files, (session, base_url)),
        (check_headers, (session, base_url)),
        (check_cookies, (session, base_url)),
        (check_open_redirect, (session, crawl_data["pages"])),
        (check_ssl, (session, base_url)),
    ]
    for fn, args in runners:
        findings += emit(fn(*args), output_file)
    return findings
