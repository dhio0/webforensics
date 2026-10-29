"""Pick the time a suspicious file was written, and how much that time can be trusted.

Order of preference: btime (birth), then ctime, then mtime. Userland `touch` can set
mtime but not ctime or btime, so an mtime-only anchor caps confidence at medium, and
timestamps from a plain copy cap it at low (D10).

Wazuh FIM gives no btime or ctime (D76). With realtime or whodata FIM, the alert for the
write is the anchor: an upper bound seconds after the write, measured by the manager's
clock rather than the web server's, so it is capped at medium. Scheduled FIM alerts up to
`frequency` seconds late, so the mtime stays the anchor, capped at low.

On Windows filesystems (D84) a program can set the birth time like any other timestamp,
and copying or unpacking a file often keeps an old one. Birth time is then used only while
nothing changed the file afterwards; a later ctime (MFT entry change) is the better date,
and every anchor is capped at medium.
"""

from datetime import datetime, timedelta
from typing import NamedTuple

from webforensics.correlate.config import CorrelationConfig
from webforensics.models import (
    Confidence,
    FileEvidence,
    FimMode,
    Reason,
    TimestampBasis,
    TimestampSource,
)

_PROMPT_FIM = (FimMode.REALTIME, FimMode.WHODATA)


class Anchor(NamedTuple):
    ts: datetime
    basis: TimestampBasis
    max_confidence: Confidence
    reasons: tuple[Reason, ...]


def _fim_anchor(file: FileEvidence) -> Anchor | None:
    written = file.fim_written
    if written is not None and written.mode in _PROMPT_FIM:
        return Anchor(ts=written.ts, basis=TimestampBasis.FIM, max_confidence=Confidence.MEDIUM,
                      reasons=(Reason(key="anchor.fim_realtime",
                                      params={"mode": written.mode.value}),))
    if file.mtime is None:
        return None
    return Anchor(ts=file.mtime, basis=TimestampBasis.MTIME, max_confidence=Confidence.LOW,
                  reasons=(Reason(key="anchor.fim_scheduled"),))


def choose_anchor(file: FileEvidence, config: CorrelationConfig) -> Anchor | None:
    if file.timestamp_source is TimestampSource.WAZUH_FIM:
        return _fim_anchor(file)
    skew = timedelta(seconds=config.clock_skew_s)
    born_and_untouched = file.btime and (file.ctime is None or file.ctime - file.btime <= skew)
    # If mtime looks forged, a later ctime is probably the `touch` itself, not a content
    # change, so the birth time is the better guess for when the content was written.
    stomped_with_birth = (file.btime and not config.birth_time_settable
                          and timestomp_signal(file, config) is not None)
    # On Windows the "cannot be set with touch" argument does not hold (D84).
    suffix = "_settable" if config.birth_time_settable else ""
    if file.btime and (born_and_untouched or stomped_with_birth):
        ts, basis, best = file.btime, TimestampBasis.BTIME, Confidence.HIGH
        reasons = [Reason(key=f"anchor.btime{suffix}")]
    elif file.ctime:
        # Changed after it was born (or no birth time): the last change is what we can date.
        ts, basis, best = file.ctime, TimestampBasis.CTIME, Confidence.HIGH
        reasons = [Reason(key=f"anchor.ctime{suffix}")]
    elif file.mtime:
        ts, basis, best = file.mtime, TimestampBasis.MTIME, Confidence.MEDIUM
        reasons = [Reason(key="anchor.mtime_only")]
    else:
        return None
    if file.timestamp_source is TimestampSource.COPIED:
        best = Confidence.LOW
        reasons.append(Reason(key="anchor.copied_timestamps"))
    elif config.birth_time_settable and best is Confidence.HIGH:
        best = Confidence.MEDIUM
    return Anchor(ts=ts, basis=basis, max_confidence=best, reasons=tuple(reasons))


def timestomp_signal(file: FileEvidence, config: CorrelationConfig) -> Reason | None:
    """Why this file's mtime looks forged, or None.

    Only meaningful for files already suspected: deploys with `tar`/`cp -p` also keep old
    mtimes, so applying this to every file would be noisy.
    """
    if file.mtime is None:
        return None
    skew = timedelta(seconds=config.clock_skew_s)
    written = file.fim_written
    if (written is not None and written.mode in _PROMPT_FIM
            and written.ts - file.mtime > timedelta(seconds=config.timestomp_min_s)):
        # Realtime FIM saw this content appear long after the time the file claims.
        return Reason(key="timestomp.mtime_before_fim",
                      params={"mtime": file.mtime.isoformat(), "fim": written.ts.isoformat()})
    if file.btime and file.mtime < file.btime - skew:
        return Reason(key="timestomp.mtime_before_btime",
                      params={"mtime": file.mtime.isoformat(), "btime": file.btime.isoformat()})
    if file.ctime and file.ctime - file.mtime > timedelta(seconds=config.timestomp_min_s):
        return Reason(key="timestomp.mtime_older_than_ctime",
                      params={"mtime": file.mtime.isoformat(), "ctime": file.ctime.isoformat()})
    return None
