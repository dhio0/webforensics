"""Parser for nginx and Apache "combined" access logs.

Both servers use the same field layout; they differ in what the timestamp means
(nginx: request end, Apache: request start) and in how they escape quotes
(nginx: \\x22, Apache: \\"). An optional trailing quoted field is read as
X-Forwarded-For, a common nginx customization.

Lines that don't match yield a ParseFailure instead of raising, so one corrupt line
never hides the rest of the log.
"""

import gzip
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from sys import intern
from typing import BinaryIO

from webforensics.models import LogEvent, ParseFailure, TsSemantics, stable_id

MAX_LINE_BYTES = 64 * 1024


class AccessLogFormat(StrEnum):
    NGINX_COMBINED = "nginx_combined"
    APACHE_COMBINED = "apache_combined"


_TS_SEMANTICS = {
    AccessLogFormat.NGINX_COMBINED: TsSemantics.REQUEST_END,
    AccessLogFormat.APACHE_COMBINED: TsSemantics.REQUEST_START,
}

_QUOTED = r'(?:[^"\\]|\\.)*'
_COMBINED_RE = re.compile(
    rf"^(?P<client_ip>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] "
    rf'"(?P<request>{_QUOTED})" (?P<status>\d{{3}}) (?P<bytes>\d+|-) '
    rf'"(?P<referer>{_QUOTED})" "(?P<user_agent>{_QUOTED})"'
    rf'(?: "(?P<xff>{_QUOTED})")?$'
)
_REQUEST_RE = re.compile(
    r"^(?P<method>[A-Za-z]+) (?P<target>\S+)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?$"
)
_TIME_RE = re.compile(
    r"^(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$"
)
MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}
_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})|\\(.)")
_SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}


def parse_clf_time(value: str) -> datetime:
    """Parse `27/Oct/2026:10:00:01 +0700` into a UTC datetime, independent of locale."""
    match = _TIME_RE.match(value)
    if match is None or match.group(2) not in MONTHS:
        raise ValueError(f"bad timestamp: {value!r}")
    day, month, year, hour, minute, second, sign, off_h, off_m = match.groups()
    offset = timedelta(hours=int(off_h), minutes=int(off_m))
    if sign == "-":
        offset = -offset
    local = datetime(
        int(year), MONTHS[month], int(day), int(hour), int(minute), int(second),
        tzinfo=timezone(offset),
    )
    return local.astimezone(UTC)


def unescape_log_field(value: str) -> str:
    """Undo nginx (\\xHH) and Apache (\\", \\\\, \\xHH) escaping inside a quoted field."""
    if "\\" not in value:
        return value
    out = bytearray()
    pos = 0
    for match in _ESCAPE_RE.finditer(value):
        out += value[pos : match.start()].encode("utf-8")
        if match.group(1) is not None:
            out.append(int(match.group(1), 16))
        else:
            out += _SIMPLE_ESCAPES.get(match.group(2), match.group(0)).encode("utf-8")
        pos = match.end()
    out += value[pos:].encode("utf-8")
    return out.decode("utf-8", "backslashreplace")


def _dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "-") else value


def _shared(value: str | None) -> str | None:
    """Intern values that repeat across lines (IPs, agents, paths) to save memory."""
    return intern(value) if value is not None else None


def parse_access_line(
    raw: str,
    source: str,
    line_no: int,
    fmt: AccessLogFormat,
    adapter: str = "file",
) -> LogEvent | ParseFailure:
    match = _COMBINED_RE.match(raw)
    if match is None:
        return ParseFailure(source=source, line_no=line_no, reason="format_mismatch", excerpt=raw)
    try:
        ts = parse_clf_time(match["time"])
    except ValueError:
        return ParseFailure(source=source, line_no=line_no, reason="bad_timestamp", excerpt=raw)

    request_raw = unescape_log_field(match["request"])
    method = target = protocol = None
    if request := _REQUEST_RE.match(request_raw):
        method, target, protocol = request["method"].upper(), request["target"], request["protocol"]
    path, _, query = target.partition("?") if target else (None, "", "")
    method, protocol, path = _shared(method), _shared(protocol), _shared(path)

    referer = match["referer"]
    user_agent = match["user_agent"]
    xff = match["xff"]
    return LogEvent(
        evidence_id=stable_id(adapter, source, str(line_no)),
        adapter=adapter,
        source=source,
        log_file=source,
        line_no=line_no,
        raw=raw,
        ts=ts,
        ts_semantics=_TS_SEMANTICS[fmt],
        client_ip=intern(match["client_ip"]),
        remote_user=_shared(_dash_to_none(match["remote_user"])),
        request_raw=intern(request_raw),
        method=method,
        path=path,
        query=query or None,
        protocol=protocol,
        status=int(match["status"]),
        bytes_sent=0 if match["bytes"] == "-" else int(match["bytes"]),
        referer=_shared(_dash_to_none(unescape_log_field(referer))),
        user_agent=_shared(_dash_to_none(unescape_log_field(user_agent))),
        xff=_shared(_dash_to_none(unescape_log_field(xff))) if xff is not None else None,
    )


def open_log(path: Path) -> BinaryIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")  # type: ignore[return-value]
    return path.open("rb")


def iter_access_log(
    path: Path,
    source: str,
    fmt: AccessLogFormat,
    adapter: str = "file",
) -> Iterator[LogEvent | ParseFailure]:
    """Yield one result per non-blank line. Line numbers count every physical line.

    For .gz files, line numbers refer to the decompressed content.
    Invalid UTF-8 bytes are kept as \\xHH, matching nginx's own escaping.
    """
    with open_log(path) as handle:
        for line_no, raw_bytes in enumerate(handle, start=1):
            line = raw_bytes.rstrip(b"\r\n")
            if not line.strip():
                continue
            if len(line) > MAX_LINE_BYTES:
                excerpt = line[:200].decode("utf-8", "backslashreplace")
                yield ParseFailure(
                    source=source, line_no=line_no, reason="line_too_long", excerpt=excerpt
                )
                continue
            raw = line.decode("utf-8", "backslashreplace")
            yield parse_access_line(raw, source, line_no, fmt, adapter)
