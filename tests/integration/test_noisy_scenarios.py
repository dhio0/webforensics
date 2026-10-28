"""Precision on the benchmark scenarios wrapped in realistic background traffic.

The same root cause must be found, and no innocent client (visitors, SQLi-spraying bots,
a scanner, a crawler that fetches the shell URL, a real admin who uploads a photo, a CMS
writing a .php cache file) may be blamed.
"""

import json

import pytest

from tests.correlate_helpers import SCENARIOS, line_of, load_scenario, root_event
from tests.noise import CRAWLER, NOISE_LOG, make_noisy
from webforensics.correlate import correlate


def _truth(name: str) -> dict:
    return json.loads((SCENARIOS / name / "ground_truth.json").read_text(encoding="utf-8"))


def _step_line(truth: dict, step_id: str) -> int:
    return next(s["line_no"] for s in truth["steps"] if s["id"] == step_id)


UPLOAD_STEP = {"a": "upload_inert_marker", "f": "authenticated_marker_upload"}


def _noisy(name: str):
    truth = _truth(name)
    logs, files = load_scenario(name)
    upload_line = _step_line(truth, UPLOAD_STEP[name])
    upload_ts = next(e.ts for e in logs.events if e.line_no == upload_line)
    marker_url = "/" + truth["files"][0]["path"]
    return truth, logs, files, make_noisy(logs, files, upload_ts, marker_url)


@pytest.mark.parametrize("name", ["a", "f"])
def test_noise_does_not_change_the_root_cause(name):
    truth, logs, files, noisy = _noisy(name)
    clean = correlate(logs, files)
    result = correlate(noisy.logs, noisy.files)

    assert len(noisy.logs.events) > 3000
    root = root_event(result)
    assert root.citations[0].source == "access.log"
    assert line_of(result, root) == _step_line(truth, truth["root_cause_step"])
    assert result.root_cause.vuln_class == clean.root_cause.vuln_class
    assert result.root_cause.confidence is clean.root_cause.confidence
    assert result.root_cause.alternative_event_ids == ()


@pytest.mark.parametrize("name", ["a", "f"])
def test_no_innocent_client_is_blamed(name):
    truth, _, _, noisy = _noisy(name)
    result = correlate(noisy.logs, noisy.files)

    assert set(result.iocs.ips) == set(truth["attacker_ips"])
    assert not set(result.iocs.ips) & noisy.innocent_ips
    assert [f.path for f in result.affected_files] == [f["path"] for f in truth["files"]]
    # Only the crawler's plain fetch of the file may appear, as a use of the file.
    for event in result.timeline:
        if event.actor in noisy.innocent_ips:
            assert event.actor == CRAWLER
            assert event.description.key == "timeline.file_invoked"
            assert not event.is_root_cause


@pytest.mark.parametrize("name", ["a", "f"])
def test_noise_is_kept_but_set_aside(name):
    _, _, _, noisy = _noisy(name)
    result = correlate(noisy.logs, noisy.files)
    # The CMS cache file is listed for review, not treated as part of the attack.
    assert "cache/page-1.php" in result.unexplained_changes
    # Bot SQLi is still reported as findings, just not attributed to the incident.
    noise_ids = {e.evidence_id for e in noisy.logs.events if e.log_file == NOISE_LOG}
    unattributed = {f.subject for f in result.findings
                    if f.finding_id in result.unattributed_finding_ids}
    assert len(unattributed & noise_ids) >= 30
    # The bots' repeated bypass (same 200/359 response) must not make the attacker's
    # real bypass look like a failure (scenario F).
    keys = [e.description.key for e in result.timeline]
    assert ("timeline.auth_bypass_sqli" in keys) is (name == "f")


def test_noisy_run_is_deterministic():
    _, _, _, noisy = _noisy("f")
    first = correlate(noisy.logs, noisy.files).model_dump(mode="json")
    assert first == correlate(noisy.logs, noisy.files).model_dump(mode="json")
