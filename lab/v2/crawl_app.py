"""Crawl a pristine scenario app internally before background replay."""

from __future__ import annotations

import argparse
import re
import xml.etree.ElementTree as ET
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener

BASE = "http://wp"
SEEDS = ("forensics", "incident", "security", "report", "wordpress")


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        fields = dict(attrs)
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

    def normalize(value: str, base: str = BASE) -> str | None:
        parts = urlsplit(urljoin(base, value))
        if parts.scheme != "http" or parts.netloc not in {host, "edge"}:
            return None
        return urlunsplit(("http", host, parts.path or "/", parts.query, ""))

    while queue and len(visited) < 250:
        url = normalize(queue.popleft())
        if url is None:
            continue
        parts = urlsplit(url)
        if parts.netloc != host or parts.scheme != "http" or url in visited:
            continue
        visited.add(url)
        urls.add(parts.path + (("?" + parts.query) if parts.query else ""))
        try:
            request = Request(url, headers={"User-Agent": "M8-pristine-app-crawler"})
            with opener.open(request, timeout=5) as response:
                body = response.read(1_000_000)
                content_type = response.headers.get("Content-Type", "")
        except Exception:
            continue
        if "json" in content_type:
            for match in re.findall(rb'"link"\s*:\s*"([^"\\]+)', body):
                candidate = match.decode("utf-8", "ignore").replace("\\/", "/")
                normalized = normalize(candidate)
                if normalized:
                    queue.append(normalized)
        elif "xml" in content_type or parts.path.endswith(".xml"):
            try:
                root = ET.fromstring(body)
                for element in root.iter():
                    if element.text and element.tag.endswith("loc"):
                        normalized = normalize(element.text)
                        if normalized:
                            queue.append(normalized)
            except ET.ParseError:
                pass
        elif "html" in content_type or not content_type:
            parser = Links()
            parser.feed(body.decode("utf-8", "replace"))
            for href in parser.values:
                normalized = normalize(href, url)
                if normalized:
                    queue.append(normalized)
    if host == "wp":
        urls.update({"/", "/wp-login.php", *(f"/?s={quote(term)}" for term in SEEDS)})
    else:
        urls.update({"/", "/login.php", *(f"/search.php?search={quote(term)}" for term in SEEDS)})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")
    print(f"crawled={len(visited)} app_urls={len(urls)}")
    return len(urls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--base", default=BASE)
    args = parser.parse_args()
    crawl(args.output, args.base)
