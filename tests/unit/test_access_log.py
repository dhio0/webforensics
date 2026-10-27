import gzip
from datetime import UTC, datetime

import pytest

from webforensics.models import LogEvent, ParseFailure, TsSemantics
from webforensics.parsers.access_log import (
    AccessLogFormat,
    iter_access_log,
    parse_access_line,
    parse_clf_time,
    unescape_log_field,
)

NGINX = AccessLogFormat.NGINX_COMBINED
APACHE = AccessLogFormat.APACHE_COMBINED


def _parse_all(path, fmt=NGINX):
    results = list(iter_access_log(path, path.name, fmt))
    events = [r for r in results if isinstance(r, LogEvent)]
    failures = [r for r in results if isinstance(r, ParseFailure)]
    return events, failures


def test_nginx_fixture_line_numbers_and_failures(fixtures_dir):
    events, failures = _parse_all(fixtures_dir / "logs" / "nginx_access.log")
    # Line 3 is blank: skipped, but still counted in line numbering.
    assert [e.line_no for e in events] == [1, 2, 4, 5, 7, 8]
    assert [(f.line_no, f.reason) for f in failures] == [
        (6, "format_mismatch"),
        (9, "bad_timestamp"),
    ]


def test_nginx_fields_and_utc_time(fixtures_dir):
    events, _ = _parse_all(fixtures_dir / "logs" / "nginx_access.log")
    upload = next(e for e in events if e.line_no == 4)
    assert upload.ts == datetime(2026, 10, 27, 3, 6, 40, tzinfo=UTC)
    assert upload.ts_semantics is TsSemantics.REQUEST_END
    assert (upload.method, upload.path, upload.query) == ("POST", "/admin/upload.php", None)
    assert upload.status == 200
    assert upload.bytes_sent == 312
    assert upload.referer == "http://shop.example/admin/"
    assert upload.citation().line_no == 4
    assert upload.citation().source == "nginx_access.log"

    sqli = next(e for e in events if e.line_no == 2)
    assert sqli.path == "/product.php"
    assert sqli.query == "id=1%27%20OR%201=1--%20-"
    assert sqli.user_agent == "sqlmap/1.8"


def test_nginx_escaped_quotes_and_xff(fixtures_dir):
    events, _ = _parse_all(fixtures_dir / "logs" / "nginx_access.log")
    search = next(e for e in events if e.line_no == 8)
    assert search.query == 'q="hello"'
    assert search.xff == "10.0.0.5"


def test_binary_request_line_is_kept_not_crashed(fixtures_dir):
    events, _ = _parse_all(fixtures_dir / "logs" / "nginx_access.log")
    tls = next(e for e in events if e.line_no == 7)
    assert tls.status == 400
    assert tls.method is None
    assert tls.path is None
    assert tls.user_agent is None


def test_apache_fixture(fixtures_dir):
    events, failures = _parse_all(fixtures_dir / "logs" / "apache_access.log", APACHE)
    assert not failures
    first, second = events
    assert first.ts_semantics is TsSemantics.REQUEST_START
    assert first.remote_user == "alice"
    assert first.bytes_sent == 0  # Apache logs "-" for zero bytes
    assert first.user_agent == 'Mozilla/5.0 "quoted" agent'
    assert second.ts == datetime(2026, 10, 27, 3, 15, 30, tzinfo=UTC)  # -0500 → UTC
    assert second.method == "HEAD"


def test_crlf_gzip_and_invalid_utf8(tmp_path):
    line = b'192.0.2.1 - - [27/Oct/2026:10:00:00 +0700] "GET /\xff HTTP/1.1" 200 1 "-" "ua"\r\n'
    plain = tmp_path / "access.log"
    plain.write_bytes(line * 2)
    zipped = tmp_path / "access.log.1.gz"
    zipped.write_bytes(gzip.compress(line))

    events, failures = _parse_all(plain)
    assert not failures
    assert [e.line_no for e in events] == [1, 2]
    assert events[0].raw.endswith('"ua"')  # no trailing \r
    assert events[0].path == "/\\xff"

    gz_events, _ = _parse_all(zipped)
    assert gz_events[0].path == events[0].path


def test_overlong_line_is_a_failure(tmp_path):
    path = tmp_path / "access.log"
    path.write_bytes(b"x" * (64 * 1024 + 1) + b"\n")
    _, failures = _parse_all(path)
    assert failures[0].reason == "line_too_long"


def test_evidence_id_is_stable():
    raw = '192.0.2.1 - - [27/Oct/2026:10:00:00 +0700] "GET / HTTP/1.1" 200 1 "-" "ua"'
    first = parse_access_line(raw, "access.log", 5, NGINX)
    second = parse_access_line(raw, "access.log", 5, NGINX)
    assert isinstance(first, LogEvent)
    assert first.evidence_id == second.evidence_id


@pytest.mark.parametrize(
    "value",
    ["27/Oct/2026:10:00:00", "27/oct/2026:10:00:00 +0700", "32/Oct/2026:10:00:00 +0700"],
)
def test_bad_clf_times(value):
    with pytest.raises(ValueError):
        parse_clf_time(value)


def test_unescape_handles_both_servers():
    assert unescape_log_field(r"a\x22b") == 'a"b'
    assert unescape_log_field(r"a\"b\\c") == 'a"b\\c'
    assert unescape_log_field("plain") == "plain"
