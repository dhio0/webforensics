"""Interactive viewer (`webforensics view`): determinism, safety, and catalog coverage."""

import base64
import hashlib
import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.correlate_helpers import file_ev, files, numbered
from webforensics.cli import app, load_report
from webforensics.correlate import correlate
from webforensics.models import CaseInfo, RunInfo
from webforensics.report import build_report, render_viewer
from webforensics.report import messages_id as m
from webforensics.report.document import gap_labels
from webforensics.report.text import Texts, parse_display_offset
from webforensics.report.viewer import CATEGORY, TABS, build_view

GOLDEN = Path(__file__).parents[1] / "golden"
ASSETS = Path(__file__).parents[2] / "src" / "webforensics" / "report" / "viewer_assets"
WIB = parse_display_offset("+07:00")
runner = CliRunner()

EVIL_UA = '</script><script>alert(1)</script> "><img src=x onerror=alert(2)>'
EVIL_PATH = "/uploads/x.php?a=</SCRIPT ><svg/onload=alert(3)>&amp;" + chr(0x2028)
EVIL_FILE = "uploads/<b>x</b>.php"


def _golden(name: str):
    return load_report(GOLDEN / f"scenario_{name}.json")


def _texts(report) -> Texts:
    return Texts(tz=WIB, gap_labels=gap_labels(report.result.gaps), strict=True)


def _data(page: str) -> dict:
    found = re.search(r'<script type="application/json" id="data">(.*?)</script>', page, re.S)
    assert found
    return json.loads(found.group(1))


def _evil_report():
    logs = numbered(
        (0, "/admin/upload.php", {"method": "POST", "ua": EVIL_UA}),
        (2, EVIL_PATH, {"ua": EVIL_UA}),
    )
    evidence = files(file_ev(EVIL_FILE, btime=0, ctime=0, mtime=0))
    run = RunInfo(tool_version="t", ruleset_version="r",
                  generated_at=datetime(2026, 10, 28, 2, 0, tzinfo=UTC))
    report = build_report(correlate(logs, evidence), logs,
                          CaseInfo(case_id="WF-<i>X</i>", title="T</title><script>"), run)
    assert report.result.affected_files  # the evil strings really reach the report
    return report


@pytest.mark.parametrize("name", ["a", "b", "d", "e", "f"])
def test_viewer_is_byte_identical_across_runs(name):
    report = _golden(name)
    assert render_viewer(report, WIB) == render_viewer(report, WIB)


def test_evidence_strings_cannot_leave_the_data_block():
    page = render_viewer(_evil_report(), WIB)
    lowered = page.lower()
    # Exactly two script elements: the JSON data block and the viewer script.
    assert lowered.count("<script") == 2 and lowered.count("</script") == 2
    assert "<img" not in lowered and "<svg" not in lowered and "<b>" not in lowered
    assert "<title>T&lt;/title&gt;&lt;script&gt;</title>" in page
    # The data still holds the original text, so the page shows it literally.
    data = json.dumps(_data(page), ensure_ascii=False)
    assert "alert(1)" in data and "x.php" in data


def test_csp_allows_only_the_bundled_script_and_no_network():
    page = render_viewer(_golden("f"), WIB)
    script = re.findall(r"<script>(.*?)</script>", page, re.S)
    assert len(script) == 1
    digest = base64.b64encode(hashlib.sha256(script[0].encode("utf-8")).digest()).decode()
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert f"script-src 'sha256-{digest}'" in csp
    for directive in ("default-src 'none'", "connect-src 'none'", "img-src 'none'",
                      "form-action 'none'", "base-uri 'none'"):
        assert directive in csp
    assert re.search(r"\b(?:src|href)=", page) is None  # nothing is loaded from anywhere


def test_page_script_never_builds_markup_from_strings():
    script = (ASSETS / "viewer.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                 "new Function", "fetch(", "XMLHttpRequest"):
        assert sink not in script


def test_every_ui_string_the_script_uses_exists():
    script = (ASSETS / "viewer.js").read_text(encoding="utf-8")
    used = set(re.findall(r'U\["([a-z_.]+)"\]', script))
    used |= set(re.findall(r"\bU\.([a-z_]+)", script))
    assert used and sorted(used - set(m.VIEWER)) == []


def test_every_timeline_message_has_a_category():
    keys = {k for k in m.MESSAGES if k.startswith("timeline.")}
    assert sorted(keys - set(CATEGORY)) == []


def test_view_model_of_scenario_f():
    report = _golden("f")
    view = build_view(report, _texts(report))
    roots = [e for e in view["events"] if e["root"]]
    assert len(roots) == 1 and view["verdict"]["root"]["n"] == roots[0]["n"]
    assert view["verdict"]["compromised"] is True
    assert [e["n"] for e in view["events"]] == list(range(1, len(report.result.timeline) + 1))
    assert {e["cat"] for e in view["events"]} >= {"exploit", "write", "file", "use"}
    story = [e["n"] for e in view["events"] if e["story"]]
    assert roots[0]["n"] in story
    # Every event cites evidence, and the citation text is there to show.
    assert all(e["cites"] for e in view["events"])
    assert all(view["cites"][i]["ref"] for e in view["events"] for i in e["cites"])
    assert [t["id"] for t in view["tabs"]] == [t for t, _ in TABS]
    assert view["offsetMin"] == 7 * 60


def test_view_model_without_a_compromise():
    report = _golden("d")
    view = build_view(report, _texts(report))
    assert view["verdict"]["compromised"] is False and view["verdict"]["root"] is None
    assert not any(e["story"] for e in view["events"])


def test_bursts_collapse_into_runs():
    probes = [(i, f"/item.php?id={i}%27%20UNION%20SELECT%20{i}--", {"status": 500})
              for i in range(5)]
    logs = numbered(*probes, (20, "/admin/upload.php", {"method": "POST"}),
                    (22, "/uploads/s.php", {}))
    evidence = files(file_ev("uploads/s.php", btime=20, ctime=20, mtime=20))
    run = RunInfo(tool_version="t", ruleset_version="r",
                  generated_at=datetime(2026, 10, 28, 2, 0, tzinfo=UTC))
    report = build_report(correlate(logs, evidence), logs, CaseInfo(case_id="X", title="T"), run)
    view = build_view(report, _texts(report))
    assert len(view["runs"]) == 1
    burst = view["runs"][0]
    assert (burst["first"], burst["last"], burst["count"]) == (1, 5, 5)
    assert "/item.php x5" in burst["text"] and " s.d. " in burst["time"]
    assert [e["run"] for e in view["events"]] == [0] * 5 + [None] * 3


def test_cli_view_writes_next_to_the_report(tmp_path):
    source = tmp_path / "report.json"
    shutil.copy(GOLDEN / "scenario_f.json", source)
    result = runner.invoke(app, ["view", str(source)])
    assert result.exit_code == 0, result.output
    page = (tmp_path / "viewer.html").read_text(encoding="utf-8")
    assert _data(page)["verdict"]["compromised"] is True


def test_cli_view_refuses_other_json(tmp_path):
    bad = tmp_path / "other.json"
    bad.write_text('{"format": "something-else/1"}', encoding="utf-8")
    result = runner.invoke(app, ["view", str(bad)])
    assert result.exit_code == 2
    assert "not a webforensics-report/1 report" in result.output
