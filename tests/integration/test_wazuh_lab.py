"""M6 "done" test against the live lab: one replay, two adapters, same conclusions.

For each scenario: replay with Wazuh on, take the FileAdapter evidence (access log, error
log, manifest) and a `pull` recording from the same run, and require the same root cause
request, affected files and attacker IPs. Citations and confidence may differ (FIM time vs
btime/ctime). Needs `python lab/wazuh/setup.py up` first; run with
`WF_LAB_WAZUH=1 pytest -m lab tests/integration/test_wazuh_lab.py` (several minutes).
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from webforensics.adapters.wazuh.client import Credentials, IndexerClient
from webforensics.adapters.wazuh.pull import PullRequest, pull
from webforensics.analysis import EvidenceInputs, load_evidence
from webforensics.correlate import correlate
from webforensics.evaluate import scenario_inputs
from webforensics.models import CitationKind, CorrelationResult

ROOT = Path(__file__).resolve().parents[2]
WAZUH = ROOT / "lab" / "wazuh"
CA = WAZUH / ".upstream/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem"

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(os.environ.get("WF_LAB_WAZUH") != "1",
                       reason="needs the Wazuh lab: WF_LAB_WAZUH=1 pytest -m lab"),
]


def _reader_password() -> str:
    for line in (WAZUH / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("WAZUH_READER_PASSWORD="):
            return line.split("=", 1)[1].strip().strip('"')
    raise KeyError("WAZUH_READER_PASSWORD")


def _collect_manifest(destination: Path) -> None:
    spec = importlib.util.spec_from_file_location("collect", ROOT / "lab/collect_scenario.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._collect_manifest(f"/tmp/wf-test-{uuid.uuid4().hex}", destination)


def _summary(result: CorrelationResult) -> tuple:
    root = None
    if result.root_cause is not None:
        event = next(e for e in result.timeline if e.event_id == result.root_cause.event_id)
        params = event.description.params
        root = (params.get("method"), params.get("path"), event.ts)
    return root, sorted(f.path for f in result.affected_files), result.iocs.ips


def _replay(scenario: str, evidence: Path) -> None:
    """Run the replay. D and E write a fresh baseline into the benchmark folder mid-run:
    use that same-run baseline here, and put the committed one back."""
    committed = ROOT / "benchmark/scenarios" / scenario / "evidence" / "baseline.tsv"
    original = committed.read_bytes() if committed.is_file() else None
    try:
        subprocess.run([sys.executable, str(ROOT / f"lab/attacks/scenario_{scenario}.py")],
                       check=True, cwd=ROOT, env={**os.environ, "WF_LAB_WAZUH": "1"})
        if original is not None:
            shutil.copy2(committed, evidence / "baseline.tsv")
    finally:
        if original is not None:
            committed.write_bytes(original)


@pytest.mark.parametrize("scenario", ["a", "b", "d", "e", "f"])
def test_wazuh_and_file_adapters_agree_on_one_replay(scenario, tmp_path):
    since = datetime.now(UTC)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _replay(scenario, evidence)
    for name in ("access.log", "error.log"):
        if (ROOT / "lab/logs" / name).is_file():
            shutil.copy2(ROOT / "lab/logs" / name, evidence / name)
    _collect_manifest(evidence / "manifest.tsv")

    client = IndexerClient("https://127.0.0.1:9200",
                           Credentials("webforensics_reader", _reader_password()),
                           ca_file=str(CA), server_name="wazuh.indexer")
    recording = tmp_path / "recording.jsonl"
    header = pull(client, PullRequest(
        agent="wf-lab-agent", since=since, until=datetime.now(UTC) + timedelta(seconds=5),
        docroot="/var/www/html", access_logs=("/var/log/nginx/access.log",),
        error_logs=("/var/log/nginx/error.log",)), recording)
    assert header.archives

    truth_dir = ROOT / "benchmark/scenarios" / scenario
    truth = json.loads((truth_dir / "ground_truth.json").read_text(encoding="utf-8"))
    inputs, config = scenario_inputs(truth_dir, truth)
    file_inputs = EvidenceInputs(
        logs=(evidence / "access.log",), manifest=evidence / "manifest.tsv",
        error_logs=(evidence / "error.log",) if inputs.error_logs else (),
        error_format=inputs.error_format,
        baseline=evidence / "baseline.tsv" if inputs.baseline else None, base_dir=evidence)
    by_file = load_evidence(file_inputs)
    by_wazuh = load_evidence(EvidenceInputs(wazuh_recording=recording, base_dir=tmp_path))
    file_result = correlate(by_file.logs, by_file.files, baseline=by_file.baseline,
                            config=config)
    wazuh_result = correlate(by_wazuh.logs, by_wazuh.files, config=config)

    assert _summary(wazuh_result) == _summary(file_result)
    assert (wazuh_result.root_cause is None) == (truth.get("root_cause_step") is None)

    lines = recording.read_text(encoding="utf-8").splitlines()
    for event in wazuh_result.timeline:
        for citation in event.citations:
            if citation.kind is CitationKind.LOG_LINE and citation.source == "recording.jsonl":
                held = json.loads(lines[citation.line_no - 1])["_source"]["full_log"]
                assert held == citation.excerpt
