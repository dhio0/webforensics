"""Reproducible performance benchmark: synthetic nginx log + manifest-like file set.

    python scripts/bench.py --lines 1000000 --seeds 50 [--memory]

Writes the log to a temporary directory, then times parsing and correlation separately.
`--memory` adds a second run under tracemalloc (much slower, so times from that run are
not reported). Traffic is random but seeded, so runs are comparable across machines.
"""

import argparse
import hashlib
import random
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

from webforensics.adapters.file_adapter import LogFileSource, url_paths_for
from webforensics.correlate import correlate
from webforensics.models import FileCollection, FileEvidence, TimestampSource, stable_id

T0 = datetime(2026, 10, 20, tzinfo=UTC)
PAGES = ["/", "/product.php?id=3", "/about.php", "/img/a.png", "/css/s.css",
         "/admin/login.php", "/search.php?q=shoes", "/product.php?id=1+OR+1%3D1"]
AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "Googlebot/2.1", "curl/8.0"]


def write_log(path: Path, lines: int) -> datetime:
    rng = random.Random(1)
    with path.open("w", newline="\n", encoding="utf-8") as out:
        for i in range(lines):
            ts = T0 + timedelta(seconds=i * 0.6)
            ip = f"198.51.{rng.randrange(40)}.{rng.randrange(250)}"
            out.write(f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "GET {rng.choice(PAGES)} '
                      f'HTTP/1.1" 200 {rng.randrange(200, 9000)} "-" "{rng.choice(AGENTS)}"\n')
        upload = T0 + timedelta(seconds=lines * 0.6 + 1)
        out.write(f'203.0.113.7 - - [{upload:%d/%b/%Y:%H:%M:%S +0000}] '
                  '"POST /admin/upload.php HTTP/1.1" 200 44 "-" "x"\n')
    return upload


def _file(path: str, when: datetime) -> FileEvidence:
    return FileEvidence(
        evidence_id=stable_id("file", "webroot", path), adapter="file", source=path,
        path=path, url_paths=url_paths_for(path),
        sha256=hashlib.sha256(path.encode()).hexdigest(), size=1,
        timestamp_source=TimestampSource.MANIFEST, btime=when, ctime=when, mtime=when,
    )


def make_files(upload: datetime, seeds: int) -> FileCollection:
    deploy = T0 - timedelta(days=30)
    items = [_file(f"app/f{i}.php", deploy) for i in range(300)]
    items += [_file(f"uploads/s{i}.php", upload - timedelta(seconds=3000 * (i + 1)))
              for i in range(seeds - 1)]
    items.append(_file("uploads/x.php", upload))
    return FileCollection(files=tuple(items))


def run(log: Path, files: FileCollection) -> tuple[float, float, int]:
    start = time.perf_counter()
    logs = LogFileSource([log]).load_logs()
    parsed = time.perf_counter()
    result = correlate(logs, files)
    done = time.perf_counter()
    assert result.root_cause is not None
    return parsed - start, done - parsed, len(logs.events)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lines", type=int, default=200_000)
    parser.add_argument("--seeds", type=int, default=10)
    parser.add_argument("--memory", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "access.log"
        files = make_files(write_log(log, args.lines), args.seeds)
        parse_s, correlate_s, events = run(log, files)
        print(f"lines={events} seeds={args.seeds} parse={parse_s:.1f}s "
              f"correlate={correlate_s:.1f}s total={parse_s + correlate_s:.1f}s")
        if args.memory:
            tracemalloc.start()
            run(log, files)
            print(f"peak_memory={tracemalloc.get_traced_memory()[1] / 1e6:.0f}MB")


if __name__ == "__main__":
    main()
