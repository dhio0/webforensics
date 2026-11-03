"""Parser for nginx and Apache 2.4 error logs.

Error-log timestamps carry no UTC offset, so the caller passes the server's offset
(e.g. "+0700"; the manifest header records it). Lines that are not the start of an
entry (PHP stack traces, wrapped messages) become ParseFailures and are expected.
"""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path

from webforensics.models import ErrorLogEvent, ParseFailure, stable_id
from webforensics.parsers.access_log import MAX_LINE_BYTES, MONTHS, open_log, readable_lines


class ErrorLogFormat(StrEnum):
    NGINX = "nginx"
    APACHE = "apache"


_NGINX_RE = re.compile(
    r"^(?P<y>\d{4})/(?P<mo>\d{2})/(?P<d>\d{2}) (?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) "
    r"\[(?P<level>\w+)\] \d+#\d+: (?:\*\d+ )?(?P<msg>.*)$"
)
_NGINX_CLIENT = re.compile(r", client: (?P<client>[^,\s]+)")
_NGINX_REQUEST = re.compile(r', request: "(?P<method>[A-Z]+) (?P<target>\S+)(?: HTTP/[\d.]+)?"')
_APACHE_RE = re.compile(
    r"^\[\w{3} (?P<mon>\w{3}) (?P<d>\d{1,2}) (?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})(?:\.\d+)? "
    r"(?P<y>\d{4})\] \[(?:[\w-]+:)?(?P<level>\w+)\] \[pid \d+(?::tid \d+)?\]"
    r"(?: \[client (?P<client>[^\]]+)\])? (?P<msg>.*)$"
)
_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def parse_offset(value: str) -> timezone:
    match = _OFFSET_RE.match(value.strip())
    if match is None:
        raise ValueError(f"bad UTC offset: {value!r} (expected e.g. +0700)")
    sign, hours, minutes = match.groups()
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    return timezone(-offset if sign == "-" else offset)


def _strip_port(client: str) -> str:
    """`1.2.3.4:5678` -> `1.2.3.4`; IPv6 `::1:5678` keeps all but the last group."""
    host, sep, port = client.rpartition(":")
    return host.strip("[]") if sep and port.isdigit() and host else client


def _event(raw: str, source: str, line_no: int, ts: datetime, offset: str, level: str,
           client: str | None, msg: str, adapter: str) -> ErrorLogEvent:
    method = path = None
    if request := _NGINX_REQUEST.search(msg):
        method, path = request["method"], request["target"].partition("?")[0]
    return ErrorLogEvent(
        evidence_id=stable_id(adapter, source, str(line_no)), adapter=adapter, source=source,
        log_file=source, line_no=line_no, raw=raw, ts=ts.astimezone(UTC),
        assumed_utc_offset=offset, level=level.lower(),
        client_ip=_strip_port(client) if client else None, method=method, path=path,
        message=msg,
    )


def parse_error_line(raw: str, source: str, line_no: int, fmt: ErrorLogFormat,
                     offset: str = "+0000", adapter: str = "file"
                     ) -> ErrorLogEvent | ParseFailure:
    tz = parse_offset(offset)
    if fmt is ErrorLogFormat.NGINX:
        match = _NGINX_RE.match(raw)
        if match is None:
            return ParseFailure(source=source, line_no=line_no, reason="not_entry_start",
                                excerpt=raw)
        month = int(match["mo"])
        client_match = _NGINX_CLIENT.search(match["msg"])
        client = client_match["client"] if client_match else None
    else:
        match = _APACHE_RE.match(raw)
        if match is None or match["mon"] not in MONTHS:
            return ParseFailure(source=source, line_no=line_no, reason="not_entry_start",
                                excerpt=raw)
        month = MONTHS[match["mon"]]
        client = match["client"]
    try:
        ts = datetime(int(match["y"]), month, int(match["d"]), int(match["h"]),
                      int(match["mi"]), int(match["s"]), tzinfo=tz)
    except ValueError:
        return ParseFailure(source=source, line_no=line_no, reason="bad_timestamp", excerpt=raw)
    return _event(raw, source, line_no, ts, offset, match["level"], client, match["msg"],
                  adapter)


def iter_error_log(path: Path, source: str, fmt: ErrorLogFormat, offset: str = "+0000",
                   adapter: str = "file") -> Iterator[ErrorLogEvent | ParseFailure]:
    parse_offset(offset)  # fail fast on a bad offset
    with open_log(path) as handle:
        for line_no, raw_bytes in enumerate(readable_lines(handle), start=1):
            if raw_bytes is None:
                yield ParseFailure(source=source, line_no=line_no,
                                   reason="truncated_or_corrupt_compressed_file")
                return
            line = raw_bytes.rstrip(b"\r\n")
            if not line.strip():
                continue
            if len(line) > MAX_LINE_BYTES:
                yield ParseFailure(source=source, line_no=line_no, reason="line_too_long",
                                   excerpt=line[:200].decode("utf-8", "backslashreplace"))
                continue
            raw = line.decode("utf-8", "backslashreplace")
            yield parse_error_line(raw, source, line_no, fmt, offset, adapter)
