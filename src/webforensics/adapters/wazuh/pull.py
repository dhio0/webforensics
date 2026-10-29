"""`webforensics pull`: copy Wazuh evidence for one agent and time window into a recording.

This is the only code path that makes network calls, and only when the user runs `pull`.
It reads; it never writes to the indexer. The lab uses a read-only indexer user (D78).
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from webforensics import __version__
from webforensics.adapters.wazuh import schema_v4 as schema
from webforensics.adapters.wazuh.client import IndexerClient
from webforensics.adapters.wazuh.recording import (
    RecordingHeader,
    Stream,
    utc_window,
    write_recording,
)


class PullError(RuntimeError):
    """The indexer does not have what a 4.x pull needs."""


@dataclass(frozen=True)
class PullRequest:
    agent: str
    since: datetime
    until: datetime
    docroot: str
    access_logs: tuple[str, ...]
    error_logs: tuple[str, ...] = ()
    page_size: int = 1000


def pull(client: IndexerClient, request: PullRequest, out: Path,
         now: datetime | None = None) -> RecordingHeader:
    """Write the recording to `out` and return its header (with hit counts)."""
    since, until = utc_window(request.since, request.until)
    if not client.has_indices(schema.ALERTS):
        raise PullError(
            f"no {schema.ALERTS} index is readable. This adapter supports Wazuh 4.x; "
            "Wazuh 5.x uses different indices (docs/wazuh-notes.md section 1).")
    archives = client.has_indices(schema.ARCHIVES)
    web_index = schema.ARCHIVES if archives else schema.ALERTS
    header = RecordingHeader(
        tool_version=__version__, pulled_at=now or datetime.now(UTC), agent=request.agent,
        since=since, until=until, docroot=request.docroot, access_logs=request.access_logs,
        error_logs=request.error_logs, archives=archives, web_index=web_index,
        fim_index=schema.ALERTS,
    )
    locations = request.access_logs + request.error_logs
    streams = (
        (Stream.WEB, web_index, schema.web_query(request.agent, locations, since, until)),
        (Stream.FIM, schema.ALERTS, schema.fim_query(request.agent, since, until)),
    )

    def all_hits() -> Iterator[tuple[Stream, dict[str, object]]]:
        for stream, index, query in streams:
            for hit in client.iter_hits(index, query, schema.SORT, request.page_size):
                yield stream, hit

    return write_recording(out, header, all_hits())
