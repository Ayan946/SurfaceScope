"""Self-check: scans a deliberately vulnerable local server. Run: python tests/test_surfacescope.py"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from surfacescope.api import _b64, _unb64, run_api_checks
from surfacescope.checks import run_all_checks
from surfacescope.crawler import crawl, new_session

GOOD = f"{_b64({'alg': 'HS256'})}.{_b64({'sub': 'a'})}.sig"  # no exp on purpose
GOOD2 = f"{_b64({'alg': 'HS256'})}.{_b64({'sub': 'b'})}.sig"
PAGE = ('<a href="/about">about</a><form method="post" action="/login"><input name="username">'
        '<input type="submit" value="Go"></form><form action="/search"><input name="q"></form>')
OWN = {"get": {"security": [{"b": []}]}}
SPEC = {"openapi": "3.0.0", "servers": [{"url": "/"}],
        "paths": {"/api/users/{id}": OWN, "/api/orders/{id}": OWN},
        "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "query", "name": "key"}}}}


class Vulnerable(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="text/html", extra=()):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        if self.headers.get("Origin"):
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        t = self.headers.get("Authorization", "")[7:]
        if t in (GOOD, GOOD2):
            return True
        try:  # vulnerable on purpose: trusts alg=none
            return _unb64(t.split(".")[0]).get("alg") == "none"
        except Exception:
            return False

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        if "next" in q:
            return self.send(302, "", extra=[("Location", q["next"][0])])
        if p == "/":
            return self.send(200, PAGE, extra=[("Set-Cookie", "sid=1; Path=/")])
        if p == "/about":
            return self.send(200, "<a href='/'>home</a>")
        if p == "/search":
            return self.send(200, "Learn SQL syntax tips")  # must NOT be flagged as SQLi
        if p == "/.env":
            return self.send(200, "DB_PASS=hunter2\n", "text/plain")
        if p == "/.git/config":
            return self.send(200, "[core]\n\tbare = false\n", "text/plain")
        if p == "/openapi.json":
            return self.send(200, json.dumps(SPEC), "application/json")
        if p.startswith("/api/users/"):
            if not p.rsplit("/", 1)[1].isdigit():
                return self.send(500, "Traceback (most recent call last):\n  File app.py", "text/plain")
            return self.send(200, '{"id":1,"password_hash":"x"}', "application/json")
        if p.startswith("/api/orders/"):
            if not self.authed():
                return self.send(401, "{}", "application/json")
            return self.send(200, '{"id":1,"owner":"a"}', "application/json")
        self.send(404, "nf")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.path == "/graphql":
            return self.send(200, '{"data":{"__schema":{"queryType":{"name":"Q"}}}}', "application/json")
        user = parse_qs(body).get("username", [""])[0]
        if "'" in user:
            return self.send(500, "You have an error in your SQL syntax near ''")
        self.send(200, f"<p>{user}</p>")


def test_scan():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Vulnerable)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    s = new_session({"Authorization": f"Bearer {GOOD}"})
    try:
        data = crawl(base, 10, s)
        web = run_all_checks(s, data, base)
        api = run_api_checks(s, base, token2=GOOD2)
        safe = run_all_checks(s, data, base, safe=True)
    finally:
        srv.shutdown()

    got = {f["vuln"] for f in web + api}
    want = {"SQL Injection", "XSS", "CSRF", "Sensitive File Exposure", "Missing Security Headers",
            "Insecure Cookie", "Open Redirect", "No HTTPS", "API Documentation Exposed",
            "API Key in Query String", "Broken Authentication", "Excessive Data Exposure",
            "Verbose Error Messages", "Possible BOLA/IDOR", "CORS Misconfiguration", "No Rate Limiting",
            "JWT Missing Expiry", "JWT alg=none Accepted", "GraphQL Introspection Enabled", "Version Disclosure"}
    assert want <= got, f"missed: {want - got}"
    sqli = [f["detail"] for f in web if f["vuln"] == "SQL Injection"]
    assert sqli and all("/login" in d for d in sqli), sqli  # /search mentions 'sql syntax': no false positive
    assert sum(f["vuln"] == "Sensitive File Exposure" for f in web) == 2
    assert not [f for f in safe if f["vuln"] in ("SQL Injection", "XSS")], "--safe must skip POST forms"
    print(f"PASS: {len(got)} distinct vulnerability types detected")


if __name__ == "__main__":
    test_scan()
