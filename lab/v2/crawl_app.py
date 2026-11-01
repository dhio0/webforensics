"""Crawl a pristine scenario app internally before background replay."""

from __future__ import annotations

import argparse
import json
import posixpath
import re
import xml.etree.ElementTree as ET
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener

BASE = "http://wp"
SEEDS = ("forensics", "incident", "security", "report", "wordpress")
STATIC_PATH = re.compile(r"\.(?:css|js|map|jpe?g|png|gif|svg|webp|ico|woff2?|ttf|eot)$", re.I)


def crawl_query(query: str) -> str:
    """Drop phpMyFAQ's per-visit tracking IDs so crawling cannot manufacture variants."""
    fields = parse_qsl(query, keep_blank_values=True)
    if not any(key == "sid" for key, _value in fields):
        return query
    return urlencode([(key, value) for key, value in fields if key != "sid"])


def static_html_fallback(path: str, content_type: str) -> bool:
    return bool(STATIC_PATH.search(path)) and "html" in content_type.lower()


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[str] = []
        self.forms: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        fields = dict(attrs)
        if tag == "form":
            self.forms.append(((fields.get("method") or "GET").upper(), fields.get("action") or ""))
        for name in ("href", "src"):
            value = fields.get(name)
            if value:
                self.values.append(value)


def crawl(output: Path, base: str = BASE) -> int:
    opener = build_opener(ProxyHandler({}))
    host = urlsplit(base).netloc
    queue = deque([base.rstrip("/") + "/"])
    if host == "wp":
        queue.extend((BASE + "/wp-login.php", BASE + "/wp-sitemap.xml"))
        for kind in ("pages", "posts", "media"):
            queue.append(f"{BASE}/wp-json/wp/v2/{kind}?per_page=100")
        queue.extend(f"{BASE}/?s={quote(term)}" for term in SEEDS)
    else:
        queue.extend(
            f"{base.rstrip('/')}{path}"
            for path in ("/login.php", "/search.php", "/admin/index.php")
        )
        queue.extend(f"{base.rstrip('/')}/search.php?search={quote(term)}" for term in SEEDS)
    visited: set[str] = set()
    urls: set[str] = set()
    methods: dict[str, set[str]] = {"POST": set(), "PUT": set(), "PATCH": set()}

    def normalize(value: str, base_url: str) -> str | None:
        parts = urlsplit(urljoin(base_url, value))
        if parts.scheme != "http" or parts.netloc not in {host, "edge"}:
            return None
        path = posixpath.normpath(parts.path or "/")
        if parts.path.endswith("/") and path != "/":
            path += "/"
        segments = [segment for segment in path.split("/") if segment]
        for start in range(len(segments)):
            for width in range(1, (len(segments) - start) // 2 + 1):
                if segments[start : start + width] == segments[start + width : start + 2 * width]:
                    return None
        return urlunsplit(("http", host, path, crawl_query(parts.query), ""))

    while queue and len(visited) < 250:
        url = normalize(queue.popleft(), base)
        if url is None:
            continue
        parts = urlsplit(url)
        if parts.netloc != host or parts.scheme != "http" or url in visited:
            continue
        visited.add(url)
        try:
            request = Request(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/131.0.0.0 Safari/537.36"
                    )
                },
            )
            with opener.open(request, timeout=5) as response:
                body = response.read(1_000_000)
                content_type = response.headers.get("Content-Type", "")
        except Exception:
            continue
        if static_html_fallback(parts.path, content_type):
            continue
        urls.add(parts.path + (("?" + parts.query) if parts.query else ""))
        if "json" in content_type:
            for match in re.findall(rb'"link"\s*:\s*"([^"\\]+)', body):
                candidate = match.decode("utf-8", "ignore").replace("\\/", "/")
                normalized = normalize(candidate, response.geturl())
                if normalized:
                    queue.append(normalized)
        elif "xml" in content_type or parts.path.endswith(".xml"):
            try:
                root = ET.fromstring(body)
                for element in root.iter():
                    if element.text and element.tag.endswith("loc"):
                        normalized = normalize(element.text, response.geturl())
                        if normalized:
                            queue.append(normalized)
            except ET.ParseError:
                pass
        elif "html" in content_type or not content_type:
            parser = Links()
            parser.feed(body.decode("utf-8", "replace"))
            for method, action in parser.forms:
                normalized = normalize(action, response.geturl())
                if normalized and method in methods and not STATIC_PATH.search(
                    urlsplit(normalized).path
                ):
                    form = urlsplit(normalized)
                    methods[method].add(form.path + (f"?{form.query}" if form.query else ""))
            for href in parser.values:
                normalized = normalize(href, response.geturl())
                if normalized:
                    queue.append(normalized)
    if host == "wp":
        urls.update({"/", "/wp-login.php", *(f"/?s={quote(term)}" for term in SEEDS)})
    else:
        urls.update({"/", "/login.php", *(f"/search.php?search={quote(term)}" for term in SEEDS)})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")
    output.with_name("app_methods.json").write_text(
        json.dumps({key: sorted(values) for key, values in methods.items()}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"crawled={len(visited)} app_urls={len(urls)}")
    return len(urls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--base", default=BASE)
    args = parser.parse_args()
    crawl(args.output, args.base)
