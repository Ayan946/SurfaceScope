from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
TIMEOUT = 8


def log(msg, output_file=None):
    print(msg)
    if output_file:
        output_file.write(msg + "\n")


def new_session(headers=None):
    # verify=False so self-signed targets work for the crawl AND every check
    s = requests.Session()
    s.headers.update(HEADERS)
    s.headers.update(headers or {})
    s.verify = False
    return s


def _norm(url):
    # drop #fragment and make "http://h" and "http://h/" the same page
    u = urlparse(urldefrag(url)[0])
    return u._replace(path=u.path or "/").geturl()


def crawl(base_url, max_pages=20, session=None, output_file=None):
    session = session or new_session()
    host = lambda u: urlparse(u).netloc.lower().removeprefix("www.")
    base_host = host(base_url)
    start = _norm(base_url)
    seen, queue, pages, forms, form_keys = {start}, deque([start]), [], [], set()

    log(f"[INF] Crawling {base_url}", output_file)
    while queue and len(pages) < max_pages:
        url = queue.popleft()
        try:
            r = session.get(url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        pages.append(url)
        log(f"[CRL] {url} [{r.status_code}]", output_file)
        if "html" not in r.headers.get("Content-Type", "").lower():
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            inputs = [{"name": i.get("name", ""), "value": i.get("value", "test"),
                       "type": (i.get("type") or "text").lower()}
                      for i in form.find_all(["input", "textarea", "select"])]
            f = {"action": urljoin(url, form.get("action", url)),
                 "method": (form.get("method") or "get").lower(), "inputs": inputs}
            key = (f["action"], f["method"], tuple(i["name"] for i in inputs))
            if key not in form_keys:  # same form repeated on many pages is tested once
                form_keys.add(key)
                forms.append(f)
        for a in soup.find_all("a", href=True):
            link = _norm(urljoin(url, a["href"]))
            if link.startswith(("http://", "https://")) and host(link) == base_host and link not in seen:
                seen.add(link)
                queue.append(link)

    log(f"[INF] Crawled {len(pages)} pages, found {len(forms)} forms", output_file)
    return {"pages": pages, "forms": forms}
