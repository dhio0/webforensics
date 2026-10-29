"""Builders for Wazuh recordings in tests. Hit shapes copy real lab output (Wazuh 4.14.9,
docs/wazuh-notes.md §10): archive events carry the raw line in `full_log`, FIM alerts a
`syscheck` object, and `timestamp` is the manager time with a UTC offset."""

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from webforensics.adapters.wazuh.recording import RecordingHeader, Stream, write_recording

AGENT = "wf-lab-agent"
DOCROOT = "/var/www/html"
ACCESS = "/var/log/nginx/access.log"
ERROR = "/var/log/nginx/error.log"
UTC7 = timezone(timedelta(hours=7))


def wazuh_ts(when: datetime, tz: timezone = UTC) -> str:
    """Format like the manager: 2026-10-29T10:40:56.338+0700."""
    local = when.astimezone(tz)
    return local.strftime("%Y-%m-%dT%H:%M:%S.") + f"{local.microsecond // 1000:03d}" + \
        local.strftime("%z")


def web_hit(full_log: str, when: datetime, location: str = ACCESS, n: int = 0,
            tz: timezone = UTC) -> dict[str, object]:
    return {"_index": "wazuh-archives-4.x-2026.10.29", "_id": f"web{n}", "_source": {
        "@timestamp": when.astimezone(UTC).isoformat(), "agent": {"id": "003", "name": AGENT},
        "decoder": {"name": "web-accesslog"}, "full_log": full_log, "id": f"1793.{n}",
        "input": {"type": "log"}, "location": location, "manager": {"name": "wazuh.manager"},
        "timestamp": wazuh_ts(when, tz)}}


def fim_hit(path: str, event: str, when: datetime, *, sha256: str | None = "0" * 64,
            mode: str = "realtime", mtime: datetime | None = None, size: int = 24,
            n: int = 0, tz: timezone = UTC) -> dict[str, object]:
    """`mtime_after` is written like the manager does: local time, offset cut off."""
    rule = {"added": "554", "modified": "550", "deleted": "553"}[event]
    syscheck: dict[str, object] = {"event": event, "mode": mode, "path": path,
                                   "size_after": str(size), "uid_after": "82",
                                   "perm_after": "rw-r--r--", "inode_after": "1234"}
    if sha256 is not None:
        syscheck["sha256_after"] = sha256
    stamp = (mtime or when).astimezone(tz)
    syscheck["mtime_after"] = stamp.strftime("%Y-%m-%dT%H:%M:%S")
    return {"_index": "wazuh-alerts-4.x-2026.10.29", "_id": f"fim{n}", "_source": {
        "@timestamp": when.astimezone(UTC).isoformat(), "agent": {"id": "003", "name": AGENT},
        "decoder": {"name": "syscheck_new_entry"}, "location": "syscheck",
        "full_log": f"File '{path}' {event}\nMode: {mode}\n", "id": f"1794.{n}",
        "rule": {"id": rule, "level": 5}, "syscheck": syscheck,
        "timestamp": wazuh_ts(when, tz)}}


def header(*, archives: bool = True, since: datetime | None = None,
           error_logs: tuple[str, ...] = ()) -> RecordingHeader:
    start = since or datetime(2026, 10, 27, tzinfo=UTC)
    return RecordingHeader(
        tool_version="test", pulled_at=start + timedelta(days=3), agent=AGENT, since=start,
        until=start + timedelta(days=2), docroot=DOCROOT, access_logs=(ACCESS,),
        error_logs=error_logs, archives=archives,
        web_index="wazuh-archives-4.x-*" if archives else "wazuh-alerts-4.x-*",
        fim_index="wazuh-alerts-4.x-*")


def recording(path: Path, web: list[dict[str, object]], fim: list[dict[str, object]],
              **header_args: object) -> Path:
    hits = [(Stream.WEB, h) for h in web] + [(Stream.FIM, h) for h in fim]
    write_recording(path, header(**header_args), hits)  # type: ignore[arg-type]
    return path


def recording_lines(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
