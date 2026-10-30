"""Builders for synthetic correlation inputs (no files on disk needed)."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from webforensics.adapters.file_adapter import LogFileSource, ManifestFileSource, url_paths_for
from webforensics.models import (
    FileCollection,
    FileEvidence,
    LogCollection,
    LogEvent,
    TimestampSource,
    TsSemantics,
    stable_id,
)

T0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC)
ATTACKER = "203.0.113.7"
VISITOR = "198.51.100.20"
SCENARIOS = Path(__file__).parent.parent / "benchmark" / "scenarios"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def since_t0(when: datetime) -> float:
    return (when - T0).total_seconds()


def request(line_no: int, seconds: float, target: str, *, method: str = "GET",
            status: int = 200, ip: str = ATTACKER, ua: str = "test-agent",
            log_file: str = "access.log", xff: str | None = None,
            size: int = 10) -> LogEvent:
    path, _, query = target.partition("?")
    raw = f'{ip} - - [{at(seconds):%d/%b/%Y:%H:%M:%S +0000}] "{method} {target} HTTP/1.1" ' \
          f'{status} {size} "-" "{ua}"'
    return LogEvent(
        evidence_id=stable_id("file", log_file, str(line_no)), adapter="file", source=log_file,
        log_file=log_file, line_no=line_no, raw_inline=raw, ts=at(seconds),
        ts_semantics=TsSemantics.REQUEST_END, client_ip=ip,
        method=method, path=path, query=query or None, protocol="HTTP/1.1", status=status,
        bytes_sent=size, user_agent=ua, xff=xff,
    )


def numbered(*specs: tuple) -> LogCollection:
    """Each spec is (seconds, target, kwargs...) and gets the next line number."""
    events = []
    for line_no, spec in enumerate(specs, start=1):
        seconds, target, *rest = spec
        events.append(request(line_no, seconds, target, **(rest[0] if rest else {})))
    return LogCollection(events=tuple(events))


def file_ev(path: str, *, btime: float | None = None, ctime: float | None = None,
            mtime: float | None = None, content: str = "inert",
            source: TimestampSource = TimestampSource.MANIFEST) -> FileEvidence:
    times = {k: at(v) for k, v in (("btime", btime), ("ctime", ctime), ("mtime", mtime))
             if v is not None}
    return FileEvidence(
        evidence_id=stable_id("file", "webroot", path), adapter="file", source=path, path=path,
        url_paths=url_paths_for(path), sha256=hashlib.sha256(content.encode()).hexdigest(),
        size=len(content), timestamp_source=source, **times,
    )


def files(*items: FileEvidence) -> FileCollection:
    return FileCollection(files=items)


def load_scenario(name: str) -> tuple[LogCollection, FileCollection]:
    evidence = SCENARIOS / name / "evidence"
    logs = LogFileSource([evidence / "access.log"], base_dir=evidence).load_logs()
    manifest = ManifestFileSource(evidence / "manifest.tsv", base_dir=evidence).load_files()
    return logs, manifest


def line_of(result, event) -> int | None:
    log = next((c for c in event.citations if c.line_no is not None), None)
    return log.line_no if log else None


def root_event(result):
    assert result.root_cause is not None
    return next(e for e in result.timeline if e.event_id == result.root_cause.event_id)
