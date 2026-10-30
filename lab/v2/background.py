"""Replay public access-log requests through the isolated lab edge proxy."""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^]]+\] "(?P<method>[A-Z]+) '
    r'(?P<target>\S+) HTTP/[^\"]+" (?P<status>\d{3}) \S+ '
    r'"[^\"]*" "(?P<ua>[^\"]*)"'
)
NASA = re.compile(
    r'^(?P<ip>\S+) (?:\S+ \S+ )?\[[^]]+\] '
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/[^\"]+" '
    r'(?P<status>\d{3}) \S+'
)
ALLOWED_TARGETS = {"wp", "smallapp", "dvwa"}
ATTACKER_NETWORK = ipaddress.ip_network("192.0.2.128/25")
LAB_NETWORKS = (
    ipaddress.ip_network("172.31.0.0/16"),
    ipaddress.ip_network("10.255.0.0/16"),
)
BACKGROUND_POOLS = (
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("10.0.0.0/8"),
)
RESERVED_ZERO = ipaddress.ip_network("0.0.0.0/8")
SAFE_METHODS = {"GET", "HEAD", "POST"}


class NoRedirects(HTTPRedirectHandler):
    """Stop responses from redirecting traffic outside the lab."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class IPMapper:
    """Assign distinct background addresses in deterministic first-seen order."""

    def __init__(self, seed: int = 0) -> None:
        self.mapping: dict[str, str] = {}
        self._excluded = (ATTACKER_NETWORK, *LAB_NETWORKS)
        self._pool_index = 0
        self._next = int(BACKGROUND_POOLS[0].network_address) + 1
        self.seed = seed

    def assign(self, source_ip: str) -> str:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            source_ip = source_ip.strip().rstrip(".").lower()
            if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?", source_ip):
                raise ValueError(f"invalid source host identity: {source_ip!r}") from None
        existing = self.mapping.get(source_ip)
        if existing is not None:
            return existing
        while self._pool_index < len(BACKGROUND_POOLS):
            network = BACKGROUND_POOLS[self._pool_index]
            last = int(network.broadcast_address) - 1
            if self._next > last:
                self._pool_index += 1
                if self._pool_index < len(BACKGROUND_POOLS):
                    self._next = int(BACKGROUND_POOLS[self._pool_index].network_address) + 1
                continue
            candidate = ipaddress.ip_address(self._next)
            self._next += 1
            if any(candidate in subnet for subnet in (*self._excluded, RESERVED_ZERO)):
                continue
            mapped = str(candidate)
            self.mapping[source_ip] = mapped
            return mapped
        raise RuntimeError("background IP pool exhausted")

    def write_tsv(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="ascii", newline="\n") as output:
            output.write(f"#seed={self.seed}\n")
            output.write("source_address_or_host\tmapped_ip\n")
            for source_ip, mapped_ip in self.mapping.items():
                output.write(f"{source_ip}\t{mapped_ip}\n")


def parse_line(line: str, fallback_user_agent: str) -> dict[str, str] | None:
    """Read Combined or NASA requests; NASA has no source user-agent field."""
    clean = line.rstrip("\r\n")
    match = COMBINED.match(clean)
    if match:
        return match.groupdict()
    match = NASA.match(clean)
    if match:
        row = match.groupdict()
        row["ua"] = fallback_user_agent
        return row
    return None


def target_url(target: str, service: str) -> str:
    """Build an origin-form URL at /; one scenario's edge selects the app upstream."""
    if service not in ALLOWED_TARGETS:
        raise ValueError(f"service must be one of {sorted(ALLOWED_TARGETS)}")
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        raise ValueError("source request target must be an origin-form path")
    if any(ord(char) < 32 for char in target):
        raise ValueError("control character in request target")
    encoded = quote(target, safe="/%?=&;:@+$,~-._")
    return f"http://edge{encoded}"


@dataclass
class ReplayStats:
    attempted: int = 0
    parsed: int = 0
    failures: Counter[str] = field(default_factory=Counter)
    started_at: str | None = None
    ended_at: str | None = None

    def to_json(self, source: Path, seed: int, pace: float) -> dict[str, object]:
        return {
            "source": source.name,
            "seed": seed,
            "pace_seconds": pace,
            "attempted": self.attempted,
            "parsed": self.parsed,
            "failures": dict(sorted(self.failures.items())),
            "started_at_utc": self.started_at,
            "ended_at_utc": self.ended_at,
        }


class BackgroundReplay:
    """A joinable replay that scenario runners start concurrently with the attack."""

    def __init__(
        self,
        source: Path,
        service: str,
        *,
        pace: float = 0.001,
        limit: int = 30_000,
        fallback_user_agent: str = "unknown-public-log-client",
        timeout: float = 5.0,
        seed: int = 0,
        ip_mapper: IPMapper | None = None,
    ) -> None:
        if service not in ALLOWED_TARGETS:
            raise ValueError("target service is not allowlisted")
        if pace < 0 or limit < 1 or timeout <= 0:
            raise ValueError("pace, limit, and timeout are invalid")
        self.source = source
        self.service = service
        self.pace = pace
        self.limit = limit
        self.fallback_user_agent = fallback_user_agent
        self.timeout = timeout
        self.seed = seed
        self.ip_mapper = ip_mapper or IPMapper(seed=seed)
        self.stats = ReplayStats()
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run_guarded, name="v2-background-replay")

    def start(self) -> BackgroundReplay:
        self._thread.start()
        return self

    def join(self, timeout: float | None = None) -> ReplayStats:
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise TimeoutError("background replay did not finish before join timeout")
        if self.error is not None:
            raise RuntimeError("background replay failed") from self.error
        return self.stats

    def _run_guarded(self) -> None:
        try:
            self._run()
        except BaseException as exc:  # forward worker errors to the scenario runner
            self.error = exc

    def _run(self) -> None:
        opener = build_opener(ProxyHandler({}), NoRedirects())
        self.stats.started_at = datetime.now(UTC).isoformat()
        file_opener = gzip.open if self.source.suffix == ".gz" else Path.open
        with file_opener(self.source, "rt", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, 1):
                if self.stats.attempted >= self.limit:
                    break
                row = parse_line(line, self.fallback_user_agent)
                if row is None:
                    continue
                self.stats.parsed += 1
                method = row["method"]
                if method not in SAFE_METHODS:
                    continue
                mapped_ip = self.ip_mapper.assign(row["ip"])
                request = Request(
                    target_url(row["target"], self.service),
                    headers={
                        "User-Agent": re.sub(r"[\r\n]", " ", row["ua"])[:512],
                        "X-Lab-Client-IP": mapped_ip,
                        "X-Background-Source-Line": str(line_number),
                    },
                    method=method,
                    # Public access logs have no request bodies; POSTs replay empty.
                    data=b"" if method == "POST" else None,
                )
                self.stats.attempted += 1
                try:
                    with opener.open(request, timeout=self.timeout) as response:
                        response.read(1)
                except HTTPError:
                    self.stats.failures["http_error"] += 1
                except TimeoutError:
                    self.stats.failures["timeout"] += 1
                except ConnectionError:
                    self.stats.failures["connection_error"] += 1
                except URLError as exc:
                    reason = exc.reason
                    if isinstance(reason, TimeoutError):
                        self.stats.failures["timeout"] += 1
                    elif isinstance(reason, ConnectionError):
                        self.stats.failures["connection_error"] += 1
                    else:
                        self.stats.failures["url_error"] += 1
                if self.pace:
                    time.sleep(self.pace)
        self.stats.ended_at = datetime.now(UTC).isoformat()

    def write_records(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.stats.to_json(self.source, self.seed, self.pace), indent=2) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--service", required=True, choices=sorted(ALLOWED_TARGETS))
    parser.add_argument("--pace", type=float, default=0.001)
    parser.add_argument("--limit", type=int, default=30_000)
    parser.add_argument("--fallback-user-agent", default="unknown-public-log-client")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--ip-map", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    args = parser.parse_args()
    try:
        replay = BackgroundReplay(
            args.source,
            args.service,
            pace=args.pace,
            limit=args.limit,
            fallback_user_agent=args.fallback_user_agent,
            timeout=args.timeout,
            seed=args.seed,
        ).start()
        stats = replay.join()
    except (ValueError, OSError, RuntimeError, TimeoutError) as exc:
        parser.error(str(exc))
    replay.ip_mapper.write_tsv(args.ip_map)
    replay.write_records(args.records)
    print(json.dumps(stats.to_json(args.source, args.seed, args.pace), sort_keys=True))


if __name__ == "__main__":
    main()
