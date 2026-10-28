"""Golden reports for the benchmark scenarios, and the `analyze` command end to end.

Regenerate after an intended change with:  UPDATE_GOLDEN=1 pytest tests/integration
then review the diff of tests/golden/ like any other code change.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.correlate_helpers import SCENARIOS
from webforensics import evaluate
from webforensics.analysis import analyze
from webforensics.cli import app
from webforensics.report import FORMATS, render
from webforensics.report.text import parse_display_offset

GOLDEN = Path(__file__).parents[1] / "golden"
WHEN = datetime(2026, 10, 28, 2, 0, tzinfo=UTC)
WHEN_ARG = "2026-10-28T09:00:00+07:00"
runner = CliRunner()
# Every benchmark scenario has golden reports, analyzed with its own `analysis` options.
ALL_SCENARIOS = sorted(p.parent.name for p in SCENARIOS.glob("*/ground_truth.json"))


def _rendered(name: str) -> dict[str, str]:
    folder = SCENARIOS / name
    truth = json.loads((folder / "ground_truth.json").read_text(encoding="utf-8"))
    inputs, config = evaluate.scenario_inputs(folder, truth)
    report = analyze(inputs, config, WHEN)
    return render(report, parse_display_offset("+07:00"), strict=True)


@pytest.mark.parametrize("name", ALL_SCENARIOS)
@pytest.mark.parametrize("ext", FORMATS)
def test_report_matches_golden_file(name, ext):
    text = _rendered(name)[ext]
    golden = GOLDEN / f"scenario_{name}.{ext}"
    if os.environ.get("UPDATE_GOLDEN"):
        golden.parent.mkdir(exist_ok=True)
        golden.write_bytes(text.encode("utf-8"))
    assert text == golden.read_bytes().decode("utf-8")


def _cli(evidence: Path, out: Path, *extra: str):
    return runner.invoke(app, [
        "analyze", "--log", str(evidence / "access.log"), "--manifest",
        str(evidence / "manifest.tsv"), "--out", str(out), "--generated-at", WHEN_ARG, *extra,
    ])


@pytest.mark.parametrize("name", ["a", "f"])
def test_analyze_gives_the_same_bytes_from_any_working_directory(name, tmp_path,
                                                                 monkeypatch):
    evidence = SCENARIOS / name / "evidence"
    monkeypatch.chdir(evidence)
    first = _cli(evidence, tmp_path / "1")
    monkeypatch.chdir(tmp_path)  # outside the evidence: names must not change
    second = _cli(evidence, tmp_path / "2")
    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    for ext in FORMATS:
        one = (tmp_path / "1" / f"report.{ext}").read_bytes()
        assert one == (tmp_path / "2" / f"report.{ext}").read_bytes()
        assert one == (GOLDEN / f"scenario_{name}.{ext}").read_bytes()
        assert b"\r\n" not in one
        # No analyst-machine paths leak into the report.
        for local in (str(SCENARIOS.parent.parent), SCENARIOS.parent.parent.as_posix(),
                      str(tmp_path), tmp_path.as_posix()):
            assert local.encode() not in one
    assert "Root cause (medium)" in first.output


def test_inputs_in_sibling_folders_are_named_from_their_common_folder(tmp_path):
    evidence = SCENARIOS / "f" / "evidence"
    case = tmp_path / "case01"
    (case / "logs").mkdir(parents=True)
    (case / "logs" / "access.log").write_bytes((evidence / "access.log").read_bytes())
    (case / "manifest.tsv").write_bytes((evidence / "manifest.tsv").read_bytes())
    result = runner.invoke(app, ["analyze", "--log", str(case / "logs"), "--manifest",
                                 str(case / "manifest.tsv"), "--out", str(tmp_path / "o"),
                                 "--format", "md", "--generated-at", WHEN_ARG])
    assert result.exit_code == 0, result.output
    md = (tmp_path / "o" / "report.md").read_text(encoding="utf-8")
    assert "logs/access.log:5" in md and "| manifest.tsv |" in md
    assert tmp_path.as_posix() not in md


def test_analyze_writes_only_requested_formats(tmp_path):
    evidence = SCENARIOS / "a" / "evidence"
    result = _cli(evidence, tmp_path, "--format", "html")
    assert result.exit_code == 0, result.output
    assert [p.name for p in tmp_path.iterdir()] == ["report.html"]


def test_analyze_uses_source_date_epoch_when_no_time_given(tmp_path, monkeypatch):
    evidence = SCENARIOS / "a" / "evidence"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(WHEN.timestamp())))
    result = runner.invoke(app, ["analyze", "--log", str(evidence / "access.log"),
                                 "--manifest", str(evidence / "manifest.tsv"),
                                 "--out", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert '"generated_at": "2026-10-28T02:00:00Z"' in (tmp_path / "report.json").read_text(
        encoding="utf-8")


@pytest.mark.parametrize("extra", [
    ("--format", "pdf"),
    ("--generated-at", "2026-10-28T09:00:00"),  # no offset
    ("--display-offset", "WIB"),
])
def test_analyze_rejects_bad_options(extra, tmp_path):
    evidence = SCENARIOS / "a" / "evidence"
    result = runner.invoke(app, ["analyze", "--log", str(evidence / "access.log"),
                                 "--manifest", str(evidence / "manifest.tsv"),
                                 "--out", str(tmp_path), *extra])
    assert result.exit_code == 2
    assert not list(tmp_path.iterdir())


def test_analyze_needs_file_evidence_and_existing_logs(tmp_path):
    evidence = SCENARIOS / "a" / "evidence"
    no_files = runner.invoke(app, ["analyze", "--log", str(evidence / "access.log"),
                                   "--out", str(tmp_path)])
    assert no_files.exit_code == 2 and "manifest or a webroot" in no_files.output
    missing = runner.invoke(app, ["analyze", "--log", str(tmp_path / "nope.log"),
                                  "--manifest", str(evidence / "manifest.tsv"),
                                  "--out", str(tmp_path / "o")])
    assert missing.exit_code == 2
