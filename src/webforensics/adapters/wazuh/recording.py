"""Recordings: what `pull` fetched from the Wazuh indexer, kept as an evidence copy (D78).

JSONL. Line 1 is the header; every other line is one hit as the indexer returned it
(`_index`, `_id`, `_source`; values unchanged, keys sorted), plus its stream. Citations
point at these line numbers, so a reader can open the recording and find the event.
Analysis reads only the recording, never the network, so it is reproducible.
"""

import json
import shutil
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from webforensics.models import UtcDatetime

RECORDING_FORMAT = "webforensics-wazuh-recording/1"


class RecordingError(ValueError):
    """The file is not a readable recording."""


class Stream(StrEnum):
    WEB = "web"  # web log lines, from archives (or alerts in alerts-only mode)
    FIM = "fim"  # FIM alerts


class RecordingHeader(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    format: str = RECORDING_FORMAT
    tool_version: str
    pulled_at: UtcDatetime
    agent: str = Field(min_length=1)
    since: UtcDatetime
    until: UtcDatetime
    # Path of the webroot on the monitored host, e.g. /var/www/html.
    docroot: str = Field(pattern=r"^/")
    access_logs: tuple[str, ...] = Field(min_length=1)  # logcollector `location` values
    error_logs: tuple[str, ...] = ()
    # False: archives were missing, web events come from alerts only (D74).
    archives: bool
    web_index: str
    fim_index: str
    counts: dict[str, int] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RecordedHit:
    line_no: int
    stream: Stream
    index: str
    doc_id: str
    source: dict[str, object]


def _line(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def write_recording(path: Path, header: RecordingHeader,
                    hits: Iterable[tuple[Stream, dict[str, object]]]) -> RecordingHeader:
    """Write the header (with per-stream counts) and the hits; returns the final header.

    Hits are streamed to a side file first, so the counts can go into line 1 without
    holding the recording in memory. Nothing is left at `path` if fetching fails.
    """
    counts: Counter[str] = Counter()
    part = path.with_name(path.name + ".part")
    try:
        with part.open("w", encoding="utf-8", newline="\n") as body:
            for stream, hit in hits:
                body.write(_line({"stream": stream.value, "_index": hit["_index"],
                                  "_id": hit["_id"], "_source": hit["_source"]}))
                counts[stream.value] += 1
        final = header.model_copy(update={"counts": {s.value: counts[s.value] for s in Stream}})
        with path.open("w", encoding="utf-8", newline="\n") as out, \
                part.open(encoding="utf-8") as body:
            out.write(_line({"header": final.model_dump(mode="json")}))
            shutil.copyfileobj(body, out)
    finally:
        part.unlink(missing_ok=True)
    return final


def _hit(line_no: int, raw: str) -> RecordedHit:
    try:
        item = json.loads(raw)
        stream = Stream(item["stream"])
        source = item["_source"]
        if not isinstance(source, dict):
            raise TypeError("_source is not an object")
        return RecordedHit(line_no, stream, str(item["_index"]), str(item["_id"]), source)
    except (ValueError, KeyError, TypeError) as exc:
        raise RecordingError(f"line {line_no}: not a recorded hit ({exc})") from exc


def iter_recording(path: Path) -> tuple[RecordingHeader, Iterator[RecordedHit]]:
    """Header plus a lazy iterator over hits. Raises RecordingError on a malformed file."""
    handle = path.open(encoding="utf-8")
    first = handle.readline()
    try:
        header = RecordingHeader.model_validate(json.loads(first)["header"])
    except (ValueError, KeyError, TypeError) as exc:
        handle.close()
        raise RecordingError(f"{path.name}: not a Wazuh recording ({exc})") from exc
    if header.format != RECORDING_FORMAT:
        handle.close()
        raise RecordingError(f"{path.name}: unsupported recording format {header.format!r}")

    def hits() -> Iterator[RecordedHit]:
        with handle:
            for line_no, raw in enumerate(handle, start=2):
                if raw.strip():
                    yield _hit(line_no, raw)

    return header, hits()


def read_recording(path: Path) -> tuple[RecordingHeader, list[RecordedHit]]:
    header, hits = iter_recording(path)
    return header, list(hits)


def utc_window(since: datetime, until: datetime) -> tuple[datetime, datetime]:
    if since.tzinfo is None or until.tzinfo is None:
        raise ValueError("--since and --until need a UTC offset, e.g. 2026-10-29T09:00:00+07:00")
    if until <= since:
        raise ValueError("--until must be after --since")
    return since, until
