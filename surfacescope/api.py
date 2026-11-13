import base64
import json
import re
from urllib.parse import urljoin, urlparse

import requests

from surfacescope.checks import emit, finding
from surfacescope.crawler import TIMEOUT, log, new_session

API1, API2, API3, API4, API8, API9 = (f"API{n}:2023" for n in (1, 2, 3, 4, 8, 9))
EVIL = "https://evil.com"
BURST = 30  # shortcut: fixed 30-request burst, raise it for APIs with lenient limits
MAX_ENDPOINTS = 50
SPEC_PATHS = ["openapi.json", "swagger.json", "v2/api-docs", "v3/api-docs", "api-docs",
              "api/openapi.json", "api/swagger.json", "swagger/v1/swagger.json", "docs/openapi.json"]
SENSITIVE_KEYS = re.compile(
    r'"(password|password_hash|passwd|secret|api_?key|access_token|refresh_token|ssn|credit_card|card_number|cvv|private_key)"\s*:', re.I)
ERRORS = re.compile(
    r"traceback \(most recent|stack ?trace|\bat (java|org|com)\.\w|exception in thread|sqlstate|"
    r"system\.\w+exception|werkzeug debugger|/node_modules/|fatal error:", re.I)
RATE_HEADER = re.compile(r"ratelimit|rate-limit|retry-after", re.I)


def _get(session, url, **kw):
    try:
        return session.get(url, timeout=TIMEOUT, **kw)
    except requests.RequestException:
        return None


def fill(url, value="1"):
    return re.sub(r"\{[^}]+\}", value, url)


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _unb64(s):
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))


def load_spec(session, origin, spec_url=None):
    for url in [spec_url] if spec_url else [f"{origin}/{p}" for p in SPEC_PATHS]:
        r = _get(session, url)
        try:
            spec = r.json() if r is not None and r.status_code == 200 else None
        except ValueError:
            continue
        if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec):
            return url, spec
    return None, None


def endpoints(spec, origin):
    """GET operations only: scanning must never change server state."""
    servers = spec.get("servers")
    prefix = urlparse(servers[0].get("url", "")).path if servers and isinstance(servers[0], dict) else spec.get("basePath", "")
    out = []
    for path, item in (spec.get("paths") or {}).items():
        op = item.get("get") if isinstance(item, dict) else None
        if isinstance(op, dict):
            out.append({"path": path, "url": origin + prefix.rstrip("/") + path,
                        "secured": bool(op.get("security", spec.get("security")))})
    return out[:MAX_ENDPOINTS]


def check_spec(spec):
    schemes = {**spec.get("securityDefinitions", {}), **spec.get("components", {}).get("securitySchemes", {})}
    return [finding("API Key in Query String", "MEDIUM", f"scheme '{n}' ({s.get('name')})", API2)
            for n, s in schemes.items()
            if isinstance(s, dict) and s.get("type") == "apiKey" and s.get("in") == "query"]


def check_unauth(anon, eps):
    out = []
    for e in eps:
        r = _get(anon, fill(e["url"])) if e["secured"] else None
        if r is not None and r.status_code == 200:
            out.append(finding("Broken Authentication", "HIGH",
                               f"{e['path']} requires auth in spec but returned 200 without credentials", API2))
    return out


def check_exposure(auth, eps):
    out = []
    for e in eps:
        r = _get(auth, fill(e["url"]))
        m = SENSITIVE_KEYS.search(r.text) if r is not None and r.status_code == 200 else None
        if m:
            out.append(finding("Excessive Data Exposure", "HIGH", f"{e['path']} returns field '{m.group(1)}'", API3))
    return out


def check_errors(auth, eps):
    out = []
    for e in eps:
        if "{" not in e["url"]:
            continue
        for bad in ("%27", "abc"):
            r = _get(auth, fill(e["url"], bad))
            if r is not None and ERRORS.search(r.text):
                out.append(finding("Verbose Error Messages", "MEDIUM", f"{e['path']} leaks internals on id '{bad}'", API8))
                break
    return out


def check_bola(auth, anon, eps, token2):
    """Two accounts reading the same non-public object = likely missing ownership check."""
    out = []
    if not token2:
        return out
    for e in eps:
        if "{" not in e["url"]:
            continue
        u = fill(e["url"])
        a, b, public = _get(auth, u), _get(anon, u, headers={"Authorization": f"Bearer {token2}"}), _get(anon, u)
        if (a is not None and b is not None and a.status_code == 200 and b.status_code == 200
                and a.text.strip() and a.text == b.text and (public is None or public.status_code != 200)):
            out.append(finding("Possible BOLA/IDOR", "HIGH",
                               f"{e['path']} object 1 readable by both accounts; confirm it is not shared data", API1))
    return out


def check_cors(anon, urls):
    for u in urls:
        r = _get(anon, u, headers={"Origin": EVIL})
        if r is None:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if acao == EVIL:
            return [finding("CORS Misconfiguration", "HIGH" if creds else "MEDIUM",
                            f"{u} reflects arbitrary Origin" + (" with credentials" if creds else ""), API8)]
        if acao == "*":
            return [finding("CORS Misconfiguration", "LOW", f"{u} allows any origin (*)", API8)]
    return []


def check_rate_limit(auth, url):
    for _ in range(BURST):
        r = _get(auth, url)
        if r is None or r.status_code == 429 or any(RATE_HEADER.search(h) for h in r.headers):
            return []
    return [finding("No Rate Limiting", "MEDIUM", f"{url} not throttled after {BURST} rapid requests", API4)]


def check_jwt(auth, anon, urls):
    out, bearer = [], auth.headers.get("Authorization", "")
    if not bearer.lower().startswith("bearer ") or bearer.count(".") != 2:
        return out
    head_b, body_b, _ = bearer[7:].strip().split(".")
    try:
        head, body = _unb64(head_b), _unb64(body_b)
    except ValueError:
        return out
    if not isinstance(head, dict) or not isinstance(body, dict):
        return out
    if str(head.get("alg", "")).lower() == "none":
        out.append(finding("JWT alg=none", "HIGH", "your token is unsigned", API2))
    if "exp" not in body:
        out.append(finding("JWT Missing Expiry", "MEDIUM", "token has no 'exp' claim", API2))
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{body_b}."
    for u in urls[:5]:
        a, b = _get(anon, u), _get(auth, u)
        if a is not None and b is not None and a.status_code in (401, 403) and b.status_code == 200:
            r = _get(anon, u, headers={"Authorization": f"Bearer {forged}"})
            if r is not None and r.status_code == 200:
                out.append(finding("JWT alg=none Accepted", "CRITICAL", f"{u} accepts unsigned tokens", API2))
            break
    return out


def check_graphql(anon, origin):
    for p in ("graphql", "api/graphql"):
        try:
            r = anon.post(f"{origin}/{p}", json={"query": "{__schema{queryType{name}}}"}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and "__schema" in r.text:
            return [finding("GraphQL Introspection Enabled", "MEDIUM", f"/{p}", API8)]
    return []


def check_server(anon, base_url):
    out, r = [], _get(anon, base_url)
    if r is None:
        return out
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if re.search(r"\d+\.\d+", r.headers.get(h, "")):
            out.append(finding("Version Disclosure", "LOW", f"{h}: {r.headers[h]}", API8))
    try:
        t = anon.request("TRACE", base_url, timeout=TIMEOUT)
        if t.status_code == 200 and "TRACE" in t.text:
            out.append(finding("HTTP TRACE Enabled", "MEDIUM", base_url, API8))
    except requests.RequestException:
        pass
    return out


def run_api_checks(auth, base_url, output_file=None, spec_url=None, token2=None):
    p = urlparse(base_url)
    origin = f"{p.scheme}://{p.netloc}"
    anon = new_session()  # no cookies/tokens: used to prove what an unauthenticated caller can do
    found, spec = load_spec(anon, origin, spec_url)
    eps = endpoints(spec, origin) if spec else []
    log(f"[INF] API checks — spec: {found or 'not found'}, {len(eps)} GET endpoints", output_file)
    urls = [fill(e["url"]) for e in eps]
    secured = [fill(e["url"]) for e in eps if e["secured"]] or [base_url]

    findings = []
    if spec and not spec_url:
        findings += emit([finding("API Documentation Exposed", "LOW", found, API9)], output_file)
    runners = [
        (check_spec, (spec or {},)),
        (check_unauth, (anon, eps)),
        (check_exposure, (auth, eps)),
        (check_errors, (auth, eps)),
        (check_bola, (auth, anon, eps, token2)),
        (check_cors, (anon, [base_url] + urls[:3])),
        (check_rate_limit, (auth, urls[0] if urls else base_url)),
        (check_jwt, (auth, anon, secured)),
        (check_graphql, (anon, origin)),
        (check_server, (anon, base_url)),
    ]
    for fn, args in runners:
        findings += emit(fn(*args), output_file)
    return findings
