"""M3 acceptance: correlation on the committed benchmark evidence (no Docker needed)."""

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from tests.correlate_helpers import line_of, load_scenario, root_event
from webforensics.correlate import correlate
from webforensics.models import Confidence, GapKind, LogCollection, TimestampBasis

SHIFT = timedelta(hours=1)


def _ground_truth(name: str) -> dict:
    from tests.correlate_helpers import SCENARIOS

    return json.loads((SCENARIOS / name / "ground_truth.json").read_text(encoding="utf-8"))


def _line(truth: dict, step_id: str) -> int:
    return next(s["line_no"] for s in truth["steps"] if s["id"] == step_id)


def test_scenario_a_blames_upload_not_sqli_probe():
    truth = _ground_truth("a")
    result = correlate(*load_scenario("a"))
    root = root_event(result)

    assert line_of(result, root) == _line(truth, truth["root_cause_step"])
    assert result.root_cause.vuln_class == "unrestricted_file_upload"
    probe = [e for e in result.timeline if line_of(result, e) == _line(truth, "get_sqli_probe")]
    assert len(probe) == 1 and not probe[0].is_root_cause
    assert probe[0].description.key == "timeline.exploit_attempt"
    assert [f.path for f in result.affected_files] == [f["path"] for f in truth["files"]]
    # Absence of a login is not proof the upload was unauthenticated.
    assert result.root_cause.confidence is Confidence.MEDIUM


def test_scenario_f_backtracks_from_file_to_sqli_login_in_order():
    truth = _ground_truth("f")
    result = correlate(*load_scenario("f"))
    root = root_event(result)
    assert line_of(result, root) == _line(truth, "sqli_login_bypass")
    assert result.root_cause.vuln_class == "sql_injection_auth_bypass"

    keys = [e.description.key for e in result.timeline]
    chain = ["timeline.auth_bypass_sqli", "timeline.file_write_request",
             "timeline.file_created", "timeline.file_invoked"]
    positions = [keys.index(k) for k in chain]
    assert positions == sorted(positions)
    write = result.timeline[keys.index("timeline.file_write_request")]
    assert line_of(result, write) == _line(truth, "authenticated_marker_upload")
    file_event = result.timeline[keys.index("timeline.file_created")]
    assert file_event.ts_basis is TimestampBasis.BTIME
    assert file_event.citations[0].sha256 == truth["files"][0]["sha256"]


@pytest.mark.parametrize("name", ["a", "f"])
def test_every_event_cites_evidence_and_ids_are_stable(name):
    first = correlate(*load_scenario(name))
    second = correlate(*load_scenario(name))
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    for event in first.timeline:
        assert event.citations
    assert first.iocs.ips == ("172.30.0.1",)


def _shift_tail(logs: LogCollection, from_line: int, drop: set[int] = frozenset()):
    events = tuple(
        replace(e, ts=e.ts + SHIFT) if e.line_no >= from_line else e
        for e in logs.events if e.line_no not in drop
    )
    return logs.model_copy(update={"events": events})


def _shift_files(files, path_prefix: str):
    shifted = tuple(
        f.model_copy(update={k: getattr(f, k) + SHIFT for k in ("btime", "ctime", "mtime")})
        if f.path.startswith(path_prefix) else f
        for f in files.files
    )
    return files.model_copy(update={"files": shifted})


def test_gap_between_bypass_and_upload_lowers_root_confidence():
    logs, files = load_scenario("f")
    baseline = correlate(logs, files)
    gapped = correlate(_shift_tail(logs, 6), _shift_files(files, "uploads/scenario-f"))

    silence = [g for g in gapped.gaps if g.kind is GapKind.NO_LOG_LINES]
    assert len(silence) == 1
    assert gapped.root_cause.event_id == baseline.root_cause.event_id
    assert gapped.root_cause.event_id in silence[0].affects
    assert baseline.root_cause.confidence is Confidence.MEDIUM
    assert gapped.root_cause.confidence is Confidence.LOW


def test_deleted_log_hour_hides_creation_and_says_so():
    logs, files = load_scenario("f")
    # The hour holding the upload request is gone; the file still exists.
    result = correlate(_shift_tail(logs, 7, drop={6}),
                       _shift_files(files, "uploads/scenario-f"))
    created = next(e for e in result.timeline if e.description.key == "timeline.file_created")
    keys = [r.key for r in created.confidence_reasons]
    assert "creation.no_http_request_found" in keys
    assert "confidence.gap_overlap" in keys
    # An inert marker with its writer deleted from the log: nothing but its path and time
    # says it is the attacker's, so the accusation is low (D100).
    assert "accusation.weak" in keys
    assert created.confidence is Confidence.LOW
    assert result.root_cause is None
    gap = next(g for g in result.gaps if g.kind is GapKind.NO_LOG_LINES)
    assert created.event_id in gap.affects
