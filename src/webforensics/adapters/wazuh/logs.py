"""Web log events from a recording -> LogCollection (D75).

Wazuh's web decoder keeps only source IP, method, URL and status, so the raw line in
`full_log` goes through the same parser as the FileAdapter. The request time therefore
comes from the log line, not from Wazuh's `timestamp` (manager processing time).

Wazuh does not record the line number in the original file, so citations point at the
line of the recording that holds the event: `<recording>:<line>`.
"""

from webforensics.adapters.wazuh import schema_v4 as schema
from webforensics.adapters.wazuh.recording import RecordedHit, RecordingHeader, Stream
from webforensics.models import (
    ErrorLogEvent,
    LogCollection,
    LogEvent,
    ParseFailure,
    SourceFile,
)
from webforensics.parsers.access_log import MAX_LINE_BYTES, AccessLogFormat, parse_access_line
from webforensics.parsers.error_log import ErrorLogFormat, parse_error_line

ADAPTER = "wazuh"


def _raw_line(hit: RecordedHit) -> str | None:
    value = hit.source.get(schema.FULL_LOG)
    return value if isinstance(value, str) else None


def web_events(header: RecordingHeader, hits: list[RecordedHit], source: SourceFile,
               access_format: AccessLogFormat, error_format: ErrorLogFormat,
               error_offset: str) -> LogCollection:
    events: list[LogEvent] = []
    failures: list[ParseFailure] = []
    errors: list[ErrorLogEvent] = []
    error_failures: list[ParseFailure] = []
    access, error = set(header.access_logs), set(header.error_logs)
    for hit in hits:
        if hit.stream is not Stream.WEB:
            continue
        location = hit.source.get(schema.LOCATION)
        raw = _raw_line(hit)
        if raw is None:
            failures.append(ParseFailure(source=source.path, line_no=hit.line_no,
                                         reason="wazuh_no_full_log"))
            continue
        if len(raw.encode("utf-8")) > MAX_LINE_BYTES:
            failures.append(ParseFailure(source=source.path, line_no=hit.line_no,
                                         reason="line_too_long", excerpt=raw[:200]))
            continue
        if location in access:
            item = parse_access_line(raw, source.path, hit.line_no, access_format, ADAPTER)
            (events if isinstance(item, LogEvent) else failures).append(item)
        elif location in error:
            parsed = parse_error_line(raw, source.path, hit.line_no, error_format,
                                      error_offset, ADAPTER)
            (errors if isinstance(parsed, ErrorLogEvent) else error_failures).append(parsed)
    return LogCollection(
        events=tuple(events), failures=tuple(failures), sources=(source,),
        errors=tuple(errors), error_failures=tuple(error_failures),
        complete=header.archives,
    )
