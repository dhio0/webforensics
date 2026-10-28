"""Guards against the engine going back to "every event x every file" loops.

Bounds are generous (about 10x the local time) so slow CI machines don't flake; a
quadratic regression is far slower than that. Real numbers: scripts/bench.py and
docs/performance.md.
"""

import time
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from tests.correlate_helpers import file_ev, files, request
from webforensics.correlate import correlate
from webforensics.models import LogCollection


def _busy_log(n: int) -> LogCollection:
    pages = ["/", "/product.php?id=3", "/img/a.png", "/admin/login.php?u=x&p=y"]
    events = [request(i + 1, i * 0.5, pages[i % 4], ip=f"198.51.{i % 40}.{i % 250}",
                      status=200 if i % 7 else 401) for i in range(n)]
    events.append(request(n + 1, n * 0.5 + 1, "/admin/upload.php", method="POST"))
    return LogCollection(events=tuple(events))


def test_correlation_scales_with_log_size_plus_seeds():
    n = 40_000
    logs = _busy_log(n)
    seeds = [file_ev(f"uploads/s{i}.php", btime=n * 0.5 - 900 * i, ctime=n * 0.5 - 900 * i,
                     mtime=n * 0.5 - 900 * i, content=str(i)) for i in range(30)]
    seeds.append(file_ev("uploads/x.php", btime=n * 0.5 + 1, ctime=n * 0.5 + 1,
                         mtime=n * 0.5 + 1))
    start = time.perf_counter()
    result = correlate(logs, files(*seeds))
    elapsed = time.perf_counter() - start
    assert result.root_cause is not None
    assert elapsed < 10, f"correlation took {elapsed:.1f}s for {n} events and 31 seeds"


def test_log_event_is_light_immutable_and_utc():
    event = request(1, 0, "/")
    assert not hasattr(event, "__dict__")  # slotted: no per-instance dict
    with pytest.raises(FrozenInstanceError):
        event.status = 500  # type: ignore[misc]
    wib = timezone(timedelta(hours=7))
    local = request(1, 0, "/").__class__(**{
        **{f: getattr(event, f) for f in event.__dataclass_fields__},
        "ts": datetime(2026, 10, 27, 17, 0, tzinfo=wib)})
    assert local.ts.utcoffset() == timedelta(0) and local.ts.hour == 10
    with pytest.raises(ValueError):
        event.__class__(**{**{f: getattr(event, f) for f in event.__dataclass_fields__},
                           "ts": datetime(2026, 10, 27, 17, 0)})
    with pytest.raises(ValueError):
        event.__class__(**{**{f: getattr(event, f) for f in event.__dataclass_fields__},
                           "line_no": 0})
