"""Unit tests for the small correlation building blocks."""

import pytest

from tests.correlate_helpers import at, file_ev, files, numbered, request
from webforensics.correlate import requests as rq
from webforensics.correlate.anchor import choose_anchor, timestomp_signal
from webforensics.correlate.baseline import apply_baseline
from webforensics.correlate.confidence import cap, lower
from webforensics.correlate.config import CorrelationConfig
from webforensics.correlate.gaps import parse_error_gaps, silence_gaps
from webforensics.models import (
    BaselineStatus,
    Confidence,
    LogCollection,
    ParseFailure,
    TimestampBasis,
    TimestampSource,
)

CFG = CorrelationConfig()


def test_confidence_cap_and_lower():
    assert cap(Confidence.HIGH, Confidence.MEDIUM) is Confidence.MEDIUM
    assert cap(Confidence.LOW, Confidence.HIGH) is Confidence.LOW
    assert lower(Confidence.HIGH) is Confidence.MEDIUM
    assert lower(Confidence.LOW) is Confidence.LOW


@pytest.mark.parametrize(("path", "expected"), [
    ("/admin/login.php", True), ("/wp-login.php", True), ("/api/auth", True),
    ("/user/sign-in", True), ("/admin/auth_upload.php", False), ("/auth/upload.php", False),
    ("/blog/logins-history.php", False),
])
def test_login_endpoint(path, expected):
    assert rq.is_login_endpoint(path) is expected


def test_login_attempt_needs_credentials_not_just_the_form():
    assert not rq.is_login_attempt(request(1, 0, "/login.php"))
    assert rq.is_login_attempt(request(1, 0, "/login.php", method="POST"))
    assert rq.is_failed_login(request(1, 0, "/login.php?u=a&p=b", status=401))


def test_area_matching():
    assert rq.area("/admin/login.php") == "/admin/"
    assert rq.area("/login.php") == "/"
    assert rq.shares_area("/admin/login.php", "/admin/sub/upload.php")
    assert not rq.shares_area("/admin/login.php", "/shop/upload.php")
    assert rq.shares_area("/login.php", "/admin/upload.php")


@pytest.mark.parametrize(("method", "path", "level"), [
    ("POST", "/admin/upload.php", rq.WriteLevel.LIKELY),
    ("PUT", "/x", rq.WriteLevel.LIKELY),
    ("POST", "/contact.php", rq.WriteLevel.POSSIBLE),
    ("GET", "/upload.php", rq.WriteLevel.NONE),
])
def test_write_level(method, path, level):
    assert rq.write_level(request(1, 0, path, method=method), []) is level


def test_anchor_prefers_btime_then_ctime_then_mtime():
    assert choose_anchor(file_ev("a", btime=0, ctime=1, mtime=1), CFG).basis is TimestampBasis.BTIME
    changed = choose_anchor(file_ev("a", btime=0, ctime=900, mtime=900), CFG)
    assert changed.basis is TimestampBasis.CTIME and changed.ts == at(900)
    only_m = choose_anchor(file_ev("a", mtime=5), CFG)
    assert only_m.basis is TimestampBasis.MTIME and only_m.max_confidence is Confidence.MEDIUM
    assert choose_anchor(file_ev("a"), CFG) is None


def test_copied_timestamps_cap_at_low():
    anchor = choose_anchor(file_ev("a", ctime=1, source=TimestampSource.COPIED), CFG)
    assert anchor.max_confidence is Confidence.LOW


def test_timestomp_signals():
    assert timestomp_signal(file_ev("a", btime=100, ctime=100, mtime=-500), CFG).key == (
        "timestomp.mtime_before_btime")
    assert timestomp_signal(file_ev("a", ctime=1000, mtime=0), CFG).key == (
        "timestomp.mtime_older_than_ctime")
    assert timestomp_signal(file_ev("a", btime=0, ctime=2, mtime=2), CFG) is None


def test_baseline_statuses_and_deleted():
    base = files(file_ev("same.php"), file_ev("edit.php"), file_ev("gone.php"))
    now = files(file_ev("same.php"), file_ev("edit.php", content="changed"), file_ev("new.php"))
    labeled, deleted = apply_baseline(now, base)
    status = {f.path: f.baseline_status for f in labeled.files}
    assert status == {"same.php": BaselineStatus.UNCHANGED, "edit.php": BaselineStatus.MODIFIED,
                      "new.php": BaselineStatus.NEW}
    assert deleted == ("gone.php",)


def test_silence_gap_uses_merged_logs_and_threshold():
    logs = numbered((0, "/"), (2, "/"), (4, "/"), (4000, "/"))
    gaps = silence_gaps(list(logs.events), CFG)
    assert len(gaps) == 1 and gaps[0].start == at(4) and gaps[0].end == at(4000)
    assert silence_gaps(list(numbered((0, "/"), (300, "/")).events), CFG) == []


def test_parse_errors_become_bounded_gaps():
    events = numbered((0, "/"), (10, "/"), (20, "/"), (30, "/"), (40, "/")).events
    kept = tuple(e for e in events if e.line_no not in (2, 3))
    failures = tuple(ParseFailure(source="access.log", line_no=n, reason="format_mismatch")
                     for n in (2, 3))
    gaps = parse_error_gaps(LogCollection(events=kept, failures=failures))
    assert len(gaps) == 1
    assert (gaps[0].start, gaps[0].end) == (at(0), at(30))
    assert gaps[0].detail.params["count"] == "2"
