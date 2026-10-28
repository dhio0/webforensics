"""Deterministic background noise for benchmark evidence (precision tests).

The noise goes into a second log file (`noise_access.log`, like another vhost or a
rotated file) so the scenario's own line numbers, which the ground truth cites, stay
the same. Every client below is innocent of the incident; none may end up blamed.
"""

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from tests.correlate_helpers import file_ev, request, since_t0
from webforensics.models import FileCollection, FileEvidence, LogCollection, LogEvent

NOISE_LOG = "noise_access.log"
ADMIN = "192.0.2.50"
CRAWLER = "66.249.66.1"
SCANNER = "198.18.200.1"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
PAGES = ["/", "/index.php", "/product.php?id=1", "/product.php?id=2", "/product.php?id=7",
         "/about.php", "/css/site.css", "/js/app.js", "/img/logo.png", "/admin/login.php"]
BOT_PAYLOADS = [
    "/product.php?id=1%27+OR+%271%27%3D%271",
    "/product.php?id=1+UNION+SELECT+1,2,3--",
    "/admin/login.php?username=admin%27+OR+%271%27%3D%271+--+&password=",
]


@dataclass(frozen=True)
class Noisy:
    logs: LogCollection
    files: FileCollection
    innocent_ips: frozenset[str]
    benign_files: tuple[str, ...]


class _Log:
    def __init__(self) -> None:
        self.rows: list[tuple[datetime, str, dict]] = []

    def add(self, when: datetime, target: str, **kwargs) -> None:
        self.rows.append((when, target, kwargs))

    def events(self) -> list[LogEvent]:
        ordered = sorted(self.rows, key=lambda row: row[0])
        return [request(n, since_t0(when), target, log_file=NOISE_LOG, **kwargs)
                for n, (when, target, kwargs) in enumerate(ordered, start=1)]


def _visitors(log: _Log, rng: random.Random, start: datetime, seconds: int) -> set[str]:
    ips = [f"198.18.{i // 200}.{i % 200 + 1}" for i in range(300)]
    for _ in range(seconds // 2):
        ip = rng.choice(ips)
        when = start + timedelta(seconds=rng.uniform(0, seconds))
        log.add(when, rng.choice(PAGES), ip=ip, ua=BROWSER, size=rng.randrange(300, 9000))
    return set(ips)


def _bots(log: _Log, rng: random.Random, start: datetime, seconds: int) -> set[str]:
    """Bots spray SQLi, including the same login bypass, and repeat it (200, 359 bytes)."""
    ips = [f"198.18.100.{i}" for i in range(1, 16)]
    for ip in ips:
        base = start + timedelta(seconds=rng.uniform(0, seconds - 60))
        for k, payload in enumerate(BOT_PAYLOADS * 2):
            log.add(base + timedelta(seconds=3 * k), payload, ip=ip, ua="python-requests/2.31",
                    size=359 if "login" in payload else 223)
    return set(ips)


def _scanner(log: _Log, start: datetime, seconds: int) -> None:
    probes = [("/uploads/shell.php", "GET", 404), ("/admin/upload.php", "POST", 403),
              ("/.env", "GET", 404), ("/../../etc/passwd", "GET", 400)]
    step = seconds / (len(probes) * 10)
    for i in range(len(probes) * 10):
        target, method, status = probes[i % len(probes)]
        log.add(start + timedelta(seconds=i * step), target, method=method, status=status,
                ip=SCANNER, ua="sqlmap/1.7.2")


def make_noisy(logs: LogCollection, files: FileCollection, upload_ts: datetime,
               marker_url: str, seed: int = 7) -> Noisy:
    """Wrap a scenario's evidence in an hour of realistic traffic on each side."""
    rng = random.Random(seed)
    first = min(e.ts for e in logs.events) - timedelta(hours=1)
    seconds = int((max(e.ts for e in logs.events) - first).total_seconds()) + 3600
    log = _Log()
    innocent = _visitors(log, rng, first, seconds) | _bots(log, rng, first, seconds)
    _scanner(log, first, seconds)

    # A real admin logs in and uploads a photo 60 s before the attacker's upload.
    admin_at = upload_ts - timedelta(seconds=60)
    log.add(admin_at - timedelta(seconds=20), "/admin/login.php", method="POST", status=302,
            ip=ADMIN, ua=BROWSER, size=0)
    log.add(admin_at - timedelta(seconds=10), "/admin/dashboard.php", ip=ADMIN, ua=BROWSER)
    log.add(admin_at, "/admin/upload.php", method="POST", ip=ADMIN, ua=BROWSER, size=44)
    # The CMS writes a page-cache .php after a comment is posted (never requested by URL).
    cache_at = upload_ts - timedelta(seconds=30)
    log.add(cache_at, "/comment.php", method="POST", ip="198.18.0.9", ua=BROWSER)
    # A crawler fetches the attacker's file once it is linked somewhere.
    log.add(upload_ts + timedelta(seconds=40), marker_url, ip=CRAWLER, ua="Googlebot/2.1")
    innocent |= {ADMIN, CRAWLER, SCANNER, "198.18.0.9"}

    extra: list[FileEvidence] = [
        _born("uploads/photo-2026.jpg", admin_at),
        _born("cache/page-1.php", cache_at),
    ]
    noisy_logs = logs.merged(LogCollection(events=tuple(log.events())))
    noisy_files = files.model_copy(update={"files": files.files + tuple(extra)})
    return Noisy(noisy_logs, noisy_files, frozenset(innocent),
                 tuple(sorted(f.path for f in extra)))


def _born(path: str, when: datetime) -> FileEvidence:
    seconds = since_t0(when)
    return file_ev(path, btime=seconds, ctime=seconds, mtime=seconds, content=path)
