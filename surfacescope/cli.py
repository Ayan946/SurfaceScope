import argparse
import json

from surfacescope import __version__
from surfacescope.api import run_api_checks
from surfacescope.checks import run_all_checks
from surfacescope.crawler import crawl, new_session

ART = r"""
   _____            ____               _____
  / ___/__  _______/ __/___ _________ / ___/_________  ____  ___
  \__ \/ / / / ___/ /_/ __ `/ ___/ _ \\__ \/ ___/ __ \/ __ \/ _ \
 ___/ / /_/ / /  / __/ /_/ / /__/  __/__/ / /__/ /_/ / /_/ /  __/
/____/\__,_/_/  /_/  \__,_/\___/\___/____/\___/\____/ .___/\___/
                                                   /_/
"""

BANNER = (
    "\033[36m" + ART + "\033[0m\n"
    "\033[90m  Web & API Attack Surface Scanner  |  v" + __version__ + "\n"
    "  github.com/Ayan946/SurfaceScope  |  authorized testing only\033[0m\n"
)


def parse_args():
    p = argparse.ArgumentParser(prog="surfacescope", description="SurfaceScope: Web & API Attack Surface Scanner")
    p.add_argument("-t", "--target", required=True, help="Target URL")
    p.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl")
    p.add_argument("-o", "--output", help="Save output to file")
    p.add_argument("--api", action="store_true", help="Also run API checks (OpenAPI, auth, CORS, JWT, rate limit, GraphQL)")
    p.add_argument("--spec", help="OpenAPI/Swagger JSON URL (default: auto-discover)")
    p.add_argument("--token", help="Bearer token for authenticated scanning")
    p.add_argument("--token2", help="Second account's bearer token (enables BOLA/IDOR check)")
    p.add_argument("-H", "--header", action="append", default=[], help="Extra header 'Name: value' (repeatable)")
    p.add_argument("--safe", action="store_true", help="Skip injection tests on POST forms")
    p.add_argument("--json", help="Write findings as JSON to this file")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args()


def print_summary(findings, output_file=None):
    sev_count = {}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    lines = ["", "[INF] ─────────────────────────────────────", "[INF] Scan completed"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"[INF] {sev}: {sev_count.get(sev, 0)}")
    lines.append(f"[INF] Total findings: {len(findings)}")
    lines.append("[INF] ─────────────────────────────────────")

    for line in lines:
        print(line)
        if output_file:
            output_file.write(line + "\n")


def main():
    print(BANNER)
    args = parse_args()
    target = args.target if args.target.startswith(("http://", "https://")) else f"http://{args.target}"
    headers = {}
    for h in args.header:
        name, sep, value = h.partition(":")
        if not sep:
            raise SystemExit(f"Bad header (expected 'Name: value'): {h}")
        headers[name.strip()] = value.strip()
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    output_file = open(args.output, "w") if args.output else None

    try:
        print(f"[INF] Target: {target}\n")
        session = new_session(headers)
        crawl_data = crawl(target, args.max_pages, session, output_file)
        print()
        findings = run_all_checks(session, crawl_data, target, output_file, args.safe)
        if args.api:
            print()
            findings += run_api_checks(session, target, output_file, args.spec, args.token2)
        print_summary(findings, output_file)
        if args.json:
            with open(args.json, "w") as f:
                json.dump(findings, f, indent=2)
    finally:
        if output_file:
            print(f"\n[INF] Output saved to {args.output}")
            output_file.close()
    # non-zero exit lets CI fail the build on serious findings
    return 1 if any(f["severity"] in ("CRITICAL", "HIGH") for f in findings) else 0
