"""Find evidence gaps: stretches of time or kinds of data the conclusions cannot see.

A gap only lowers confidence when it overlaps the time window a conclusion depends on
(see `engine._apply_gaps`); otherwise it is listed so the reader knows about it.
"""

from array import array
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import pairwise
from statistics import median

from webforensics.correlate.config import CorrelationConfig
from webforensics.models import (
    EvidenceGap,
    GapKind,
    LogCollection,
    LogEvent,
    Reason,
    stable_id,
)


def make_gap(kind: GapKind, source: str | None, start: datetime | None, end: datetime | None,
             key: str, params: dict[str, str] | None = None) -> EvidenceGap:
    parts = (kind.value, source or "", start.isoformat() if start else "",
             end.isoformat() if end else "")
    return EvidenceGap(
        gap_id=stable_id("gap", *parts), kind=kind, source=source, start=start, end=end,
        detail=Reason(key=key, params=params or {}),
    )


def local_thresholds(deltas: list[float], config: CorrelationConfig) -> list[float]:
    """Per-interval silence threshold from the spacing of nearby intervals (not itself).

    A local median keeps a quiet night from being reported as missing logs, while a
    missing hour in the middle of busy traffic still stands out.
    """
    k = config.silence_neighbors
    floor = float(config.silence_min_s)
    out = []
    for i, delta in enumerate(deltas):
        if delta <= floor:
            out.append(floor)  # can never exceed the threshold, so skip the median
            continue
        nearby = deltas[max(0, i - k):i] + deltas[i + 1:i + 1 + k]
        typical = median(nearby) if nearby else 0.0
        out.append(max(floor, config.silence_factor * typical))
    return out


def silence_gaps(events: list[LogEvent], config: CorrelationConfig) -> list[EvidenceGap]:
    """Log silence much longer than the nearby request spacing, across all logs merged.

    Merging matters: rotated files (access.log.1, access.log) are one stream, and the
    rotation boundary is exactly where lines tend to go missing.
    """
    ordered = sorted(events, key=lambda e: (e.ts, e.log_file, e.line_no))
    # A compact array, and a median only for intervals above the floor: with millions of
    # lines, a list of pairs and of floats cost ~100 bytes per line (D88). Same result as
    # local_thresholds().
    deltas = array("d", ((after.ts - before.ts).total_seconds()
                         for before, after in pairwise(ordered)))
    k, floor = config.silence_neighbors, float(config.silence_min_s)
    gaps = []
    for i, silence in enumerate(deltas):
        if silence <= floor:
            continue
        nearby = deltas[max(0, i - k):i] + deltas[i + 1:i + 1 + k]
        threshold = max(floor, config.silence_factor * (median(nearby) if nearby else 0.0))
        if silence > threshold:
            before, after = ordered[i], ordered[i + 1]
            gaps.append(make_gap(
                GapKind.NO_LOG_LINES, before.log_file, before.ts, after.ts, "gap.log_silence",
                {"seconds": str(int(silence)), "threshold": str(int(threshold))},
            ))
    return gaps


def parse_error_gaps(logs: LogCollection) -> list[EvidenceGap]:
    """One gap per run of unparsed lines, bounded by the parsed lines around it."""
    parsed: dict[str, dict[int, LogEvent]] = defaultdict(dict)
    for event in logs.events:
        parsed[event.log_file][event.line_no] = event
    gaps = []
    runs: dict[str, list[list[int]]] = defaultdict(list)
    for failure in sorted(logs.failures, key=lambda f: (f.source, f.line_no or 0)):
        line = failure.line_no or 0
        file_runs = runs[failure.source]
        if file_runs and line == file_runs[-1][-1] + 1:
            file_runs[-1].append(line)
        else:
            file_runs.append([line])
    for source, file_runs in sorted(runs.items()):
        lines = parsed.get(source, {})
        for run in file_runs:
            before = [lines[n].ts for n in lines if n < run[0]]
            after = [lines[n].ts for n in lines if n > run[-1]]
            gaps.append(make_gap(
                GapKind.PARSE_ERRORS, source, max(before) if before else None,
                min(after) if after else None, "gap.parse_errors",
                {"first_line": str(run[0]), "last_line": str(run[-1]), "count": str(len(run))},
            ))
    return gaps


def coverage_gap(anchor_ts: datetime, path: str, span: tuple[datetime, datetime] | None,
                 config: CorrelationConfig) -> EvidenceGap | None:
    """The file was written at a time the logs do not cover at all.

    `span` is the (first, last) access-log timestamp, or None when there are no logs.
    """
    window_start = anchor_ts - timedelta(seconds=config.creation_window_s)
    window_end = anchor_ts + timedelta(seconds=config.clock_skew_s)
    if span is not None:
        first, last = span
        if first <= window_start and last >= window_end:
            return None
        if first <= anchor_ts <= last:
            return None  # partially covered; silence gaps handle the rest
        start, end = (last, anchor_ts) if anchor_ts > last else (anchor_ts, first)
    else:
        start, end = window_start, window_end
    return make_gap(GapKind.NO_LOG_LINES, path, start, end, "gap.no_log_coverage",
                    {"path": path})
