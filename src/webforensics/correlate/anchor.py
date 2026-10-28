"""Pick the time a suspicious file was written, and how much that time can be trusted.

Order of preference: btime (birth), then ctime, then mtime. Userland `touch` can set
mtime but not ctime or btime, so an mtime-only anchor caps confidence at medium, and
timestamps from a plain copy cap it at low (D10).
"""

from datetime import datetime, timedelta
from typing import NamedTuple

from webforensics.correlate.config import CorrelationConfig
from webforensics.models import (
    Confidence,
    FileEvidence,
    Reason,
    TimestampBasis,
    TimestampSource,
)


class Anchor(NamedTuple):
    ts: datetime
    basis: TimestampBasis
    max_confidence: Confidence
    reasons: tuple[Reason, ...]


def choose_anchor(file: FileEvidence, config: CorrelationConfig) -> Anchor | None:
    skew = timedelta(seconds=config.clock_skew_s)
    born_and_untouched = file.btime and (file.ctime is None or file.ctime - file.btime <= skew)
    # If mtime looks forged, a later ctime is probably the `touch` itself, not a content
    # change, so the birth time is the better guess for when the content was written.
    stomped_with_birth = file.btime and timestomp_signal(file, config) is not None
    if file.btime and (born_and_untouched or stomped_with_birth):
        ts, basis, best = file.btime, TimestampBasis.BTIME, Confidence.HIGH
        reasons = [Reason(key="anchor.btime")]
    elif file.ctime:
        # Changed after it was born (or no birth time): the last change is what we can date.
        ts, basis, best = file.ctime, TimestampBasis.CTIME, Confidence.HIGH
        reasons = [Reason(key="anchor.ctime")]
    elif file.mtime:
        ts, basis, best = file.mtime, TimestampBasis.MTIME, Confidence.MEDIUM
        reasons = [Reason(key="anchor.mtime_only")]
    else:
        return None
    if file.timestamp_source is TimestampSource.COPIED:
        best = Confidence.LOW
        reasons.append(Reason(key="anchor.copied_timestamps"))
    return Anchor(ts=ts, basis=basis, max_confidence=best, reasons=tuple(reasons))


def timestomp_signal(file: FileEvidence, config: CorrelationConfig) -> Reason | None:
    """Why this file's mtime looks forged, or None.

    Only meaningful for files already suspected: deploys with `tar`/`cp -p` also keep old
    mtimes, so applying this to every file would be noisy.
    """
    if file.mtime is None:
        return None
    skew = timedelta(seconds=config.clock_skew_s)
    if file.btime and file.mtime < file.btime - skew:
        return Reason(key="timestomp.mtime_before_btime",
                      params={"mtime": file.mtime.isoformat(), "btime": file.btime.isoformat()})
    if file.ctime and file.ctime - file.mtime > timedelta(seconds=config.timestomp_min_s):
        return Reason(key="timestomp.mtime_older_than_ctime",
                      params={"mtime": file.mtime.isoformat(), "ctime": file.ctime.isoformat()})
    return None
