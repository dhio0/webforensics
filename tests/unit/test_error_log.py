from datetime import UTC, datetime

import pytest

from webforensics.adapters.file_adapter import ErrorLogFileSource
from webforensics.models import ErrorLogEvent, ParseFailure
from webforensics.parsers.error_log import ErrorLogFormat, parse_error_line, parse_offset

NGINX = (
    '2026/10/27 17:00:10 [error] 31#31: *7 open() "/var/www/html/x.png" failed (2: No such '
    'file or directory), client: 203.0.113.7, server: _, request: "GET /x.png?a=1 HTTP/1.1", '
    'host: "lab"'
)
APACHE = ("[Tue Oct 27 10:00:10.123456 2026] [php:warn] [pid 12:tid 34] "
          "[client 203.0.113.7:51234] PHP Warning:  demo in /var/www/html/a.php on line 2")


def test_nginx_entry_parsed_with_offset():
    event = parse_error_line(NGINX, "error.log", 3, ErrorLogFormat.NGINX, "+0700")
    assert isinstance(event, ErrorLogEvent)
    assert event.ts == datetime(2026, 10, 27, 10, 0, 10, tzinfo=UTC)
    assert (event.level, event.client_ip, event.method, event.path) == (
        "error", "203.0.113.7", "GET", "/x.png")
    assert event.assumed_utc_offset == "+0700"
    assert event.citation().line_no == 3


def test_apache_entry_parsed_and_port_stripped():
    event = parse_error_line(APACHE, "error_log", 1, ErrorLogFormat.APACHE)
    assert isinstance(event, ErrorLogEvent)
    assert event.ts == datetime(2026, 10, 27, 10, 0, 10, tzinfo=UTC)
    assert (event.level, event.client_ip, event.path) == ("warn", "203.0.113.7", None)


@pytest.mark.parametrize("line", ["PHP Stack trace:", "#0 {main}", "  thrown in x"])
def test_continuation_lines_are_failures(line):
    result = parse_error_line(line, "error.log", 1, ErrorLogFormat.NGINX)
    assert isinstance(result, ParseFailure) and result.reason == "not_entry_start"


def test_bad_offset_rejected():
    assert parse_offset("-03:30").utcoffset(None).total_seconds() == -12600
    with pytest.raises(ValueError):
        parse_offset("WIB")


def test_error_source_keeps_failures_apart(tmp_path):
    log = tmp_path / "error.log"
    log.write_text(NGINX + "\nPHP Stack trace:\n", encoding="utf-8")
    logs = ErrorLogFileSource([log], utc_offset="+0700", base_dir=tmp_path).load_logs()
    assert len(logs.errors) == 1 and len(logs.error_failures) == 1
    assert logs.events == () and logs.failures == ()
    assert logs.sources[0].path == "error.log"
