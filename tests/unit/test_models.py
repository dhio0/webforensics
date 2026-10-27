from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from webforensics.models import (
    Citation,
    CitationKind,
    Confidence,
    EvidenceGap,
    FileEvidence,
    GapKind,
    Reason,
    TimelineEvent,
    TimestampBasis,
    TimestampSource,
    check_relative_path,
    stable_id,
)

SHA = "0" * 64
WIB = timezone(timedelta(hours=7))


def _event(**overrides):
    fields = {
        "event_id": "e1",
        "ts": datetime(2026, 10, 27, 10, 6, 40, tzinfo=WIB),
        "ts_basis": TimestampBasis.LOG,
        "description": Reason(key="timeline.upload"),
        "citations": (Citation(kind=CitationKind.LOG_LINE, source="access.log", line_no=4),),
        "confidence": Confidence.HIGH,
    }
    fields.update(overrides)
    return TimelineEvent(**fields)


def test_timeline_event_without_citation_is_rejected():
    with pytest.raises(ValidationError, match="at least 1"):
        _event(citations=())


def test_timeline_event_time_is_normalized_to_utc():
    assert _event().ts == datetime(2026, 10, 27, 3, 6, 40, tzinfo=UTC)
    assert _event().ts.utcoffset() == timedelta(0)


def test_naive_datetime_is_rejected():
    with pytest.raises(ValidationError):
        _event(ts=datetime(2026, 10, 27, 10, 0, 0))


def test_log_citation_needs_line_number():
    with pytest.raises(ValidationError, match="line_no"):
        Citation(kind=CitationKind.LOG_LINE, source="access.log")


def test_file_citation_needs_sha256():
    with pytest.raises(ValidationError, match="sha256"):
        Citation(kind=CitationKind.FILE, source="uploads/x.php")
    with pytest.raises(ValidationError):
        Citation(kind=CitationKind.FILE, source="uploads/x.php", sha256="XYZ")


def test_citation_excerpt_is_truncated():
    citation = Citation(kind=CitationKind.LOG_LINE, source="a", line_no=1, excerpt="x" * 1000)
    assert len(citation.excerpt) == 300
    assert citation.excerpt.endswith("…")


def test_models_are_immutable():
    event = _event()
    with pytest.raises(ValidationError):
        event.confidence = Confidence.LOW


@pytest.mark.parametrize("path", ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a\x00b"])
def test_unsafe_paths_are_rejected(path):
    with pytest.raises(ValueError):
        check_relative_path(path)


def test_file_evidence_citation_and_hidden_content_ref():
    evidence = FileEvidence(
        evidence_id="f1",
        adapter="file",
        source="m:1",
        path="uploads/x.php",
        sha256=SHA,
        size=31,
        timestamp_source=TimestampSource.MANIFEST,
        content_ref="/tmp/case/webroot/uploads/x.php",
    )
    citation = evidence.citation()
    assert citation.kind is CitationKind.FILE
    assert citation.sha256 == SHA
    assert "content_ref" not in evidence.model_dump()


def test_gap_end_before_start_is_rejected():
    start = datetime(2026, 10, 27, 3, 0, tzinfo=UTC)
    with pytest.raises(ValidationError):
        EvidenceGap(gap_id="g", kind=GapKind.NO_LOG_LINES, start=start,
                    end=start - timedelta(seconds=1))


def test_stable_id_is_deterministic_and_part_sensitive():
    assert stable_id("file", "access.log", "4") == stable_id("file", "access.log", "4")
    assert stable_id("a", "bc") != stable_id("ab", "c")
