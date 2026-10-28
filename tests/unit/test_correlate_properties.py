"""Property-style checks on randomly generated evidence (seeded, so reproducible).

Whatever the input, the engine must not crash, every timeline row must cite evidence,
the timeline must be sorted, the root cause must point at a timeline row, and two runs
must give identical output.
"""

import random
from datetime import timedelta

import pytest

from tests.correlate_helpers import T0, file_ev, files, request
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.models import CitationKind, LogCollection
from webforensics.parsers.error_log import ErrorLogFormat, parse_error_line

IPS = ["203.0.113.7", "198.51.100.20", "192.0.2.5", "10.0.0.1"]
XFF = [None, "203.0.113.7", "1.1.1.1, 198.51.100.20", "garbage"]
TARGETS = [
    ("GET", "/"), ("GET", "/product.php?id=1"), ("GET", "/product.php?id=1+OR+1%3D1"),
    ("GET", "/admin/login.php"), ("POST", "/admin/login.php"),
    ("GET", "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+"),
    ("POST", "/admin/upload.php"), ("POST", "/contact.php"), ("GET", "/uploads/s.php"),
    ("GET", "/uploads/t.phtml?cmd=id"), ("GET", "/../../etc/passwd"),
]
PATHS = ["uploads/s.php", "uploads/t.phtml", "index.php", "images/logo.png", "lib/x.php",
         "app/a.php", "app/b.php"]


def _random_case(seed: int):
    rng = random.Random(seed)
    clock, events = 0.0, []
    for line_no in range(1, rng.randint(1, 40) + 1):
        clock += rng.choice([1, 2, 5, 30, 4000]) if rng.random() < 0.95 else 0
        method, target = rng.choice(TARGETS)
        events.append(request(line_no, clock, target, method=method, ip=rng.choice(IPS),
                              status=rng.choice([200, 200, 302, 401, 404, 500]),
                              xff=rng.choice(XFF), size=rng.choice([10, 500])))
    evidence = []
    for path in rng.sample(PATHS, rng.randint(0, len(PATHS))):
        born = rng.uniform(-100, clock + 100)
        times = {"btime": born, "ctime": born + rng.choice([0, 0, 500]),
                 "mtime": born + rng.choice([0, -90000])}
        if rng.random() < 0.3:
            times = {"mtime": times["mtime"]}
        evidence.append(file_ev(path, **times))
    errors = []
    for n in range(rng.randint(0, 3)):
        when = T0 + timedelta(seconds=rng.uniform(0, clock + 1))
        method, target = rng.choice(TARGETS)
        line = (f"{when:%Y/%m/%d %H:%M:%S} [error] 1#1: *1 demo, client: {rng.choice(IPS)}, "
                f'server: _, request: "{method} {target} HTTP/1.1"')
        errors.append(parse_error_line(line, "error.log", n + 1, ErrorLogFormat.NGINX))
    proxies = ("10.0.0.0/8",) if rng.random() < 0.5 else ()
    logs = LogCollection(events=tuple(events), errors=tuple(errors))
    return logs, files(*evidence), CorrelationConfig(trusted_proxies=proxies)


@pytest.mark.parametrize("seed", range(100))
def test_engine_invariants(seed):
    logs, evidence, config = _random_case(seed)
    result = correlate(logs, evidence, config=config)
    again = correlate(logs, evidence, config=config)
    assert result.model_dump(mode="json") == again.model_dump(mode="json")

    times = [e.ts for e in result.timeline]
    assert times == sorted(times)
    for event in result.timeline:
        assert event.citations
        for citation in event.citations:
            assert (citation.line_no is not None) or (citation.kind is CitationKind.FILE)
    ids = {e.event_id for e in result.timeline}
    if result.root_cause:
        assert result.root_cause.event_id in ids
        assert sum(e.is_root_cause for e in result.timeline) == 1
    for gap in result.gaps:
        assert set(gap.affects) <= ids
