"""The evaluator must catch mistakes, not just print 100 %.

Most tests feed it ground truth that disagrees with the analysis on purpose, and check
that each kind of error is reported.
"""

import copy
import json
import shutil

import pytest
from typer.testing import CliRunner

from tests.correlate_helpers import ATTACKER, SCENARIOS, VISITOR, file_ev, files, numbered
from webforensics import evaluate
from webforensics.cli import app
from webforensics.correlate import correlate
from webforensics.evaluate import RootVerdict, root_verdict, score

runner = CliRunner()
BENCHMARK = SCENARIOS.parent


def _truth(name: str) -> dict:
    return json.loads((SCENARIOS / name / "ground_truth.json").read_text(encoding="utf-8"))


def _upload_case():
    logs = numbered(
        (0, "/"),
        (5, "/admin/upload.php", {"method": "POST"}),
        (7, "/uploads/x.php"),
        (9, "/uploads/x.php", {"ip": VISITOR, "method": "POST"}),
    )
    return correlate(logs, files(file_ev("uploads/x.php", btime=5, ctime=5, mtime=5)))


def _case_truth(**changes) -> dict:
    truth = {
        "scenario_id": "t", "description": "d", "attacker_ips": [ATTACKER],
        "steps": [
            {"id": "home", "category": "benign_request", "mitre": [], "log_file": "access.log",
             "line_no": 1, "is_root_cause": False},
            {"id": "upload", "category": "unrestricted_upload", "mitre": [],
             "log_file": "access.log", "line_no": 2, "is_root_cause": True},
            {"id": "use", "category": "marker_invocation", "mitre": [],
             "log_file": "access.log", "line_no": 3, "is_root_cause": False},
        ],
        "files": [{"path": "uploads/x.php", "sha256": "0" * 64, "change": "created"}],
        "root_cause_step": "upload",
    }
    truth.update(changes)
    return truth


def test_every_benchmark_scenario_is_fully_correct():
    # Regression guard: a rule change that breaks any scenario fails CI. A failing
    # held-out scenario is reported as it is, never fixed by tuning on it (docs/evaluation.md).
    scores = evaluate.evaluate_all(evaluate.scenario_folders(BENCHMARK))
    assert all(s.passed for s in scores), evaluate.details(scores)
    assert {(s.scenario_id, s.adapter) for s in scores} == {
        (sid, adapter) for sid in "abdef" for adapter in ("file", "wazuh")}
    by_id = {s.scenario_id: s for s in scores if s.adapter == "file"}
    assert (by_id["a"].steps_expected, by_id["f"].steps_expected) == (3, 4)  # benign not counted


def test_recording_citations_are_mapped_to_the_same_runs_log_lines():
    """Both adapters use one ground truth: every recorded web line maps to the log line
    with the same text, and without that mapping no step would count."""
    folder = BENCHMARK / "scenarios" / "b"
    truth = _truth("b")
    mapping = evaluate.recording_line_map(folder, truth)
    access = (folder / "evidence" / "access.log").read_text(encoding="utf-8").splitlines()
    errors = (folder / "evidence" / "error.log").read_text(encoding="utf-8").splitlines()
    assert sorted(mapping.values()) == sorted(
        [("access.log", n) for n in range(1, len(access) + 1)]
        + [("error.log", n) for n in range(1, len(errors) + 1)])
    mapped = evaluate.evaluate_scenario(folder, "wazuh")
    assert mapped.passed
    inputs, config = evaluate.scenario_inputs(folder, truth)
    evidence = evaluate.load_evidence(evaluate.EvidenceInputs(
        wazuh_recording=folder / "evidence" / evaluate.RECORDING, base_dir=inputs.base_dir))
    unmapped = score(truth, evaluate.correlate(evidence.logs, evidence.files, config=config), 0)
    assert unmapped.steps_found == 0 and unmapped.root is not RootVerdict.CORRECT


def test_correct_case_passes():
    s = score(_case_truth(), _upload_case(), 0.0)
    # The visitor POSTed to the shell, so it is implicated: a real false accusation here.
    assert s.false_ips == (VISITOR,) and not s.passed
    s = score(_case_truth(attacker_ips=[ATTACKER, VISITOR]), _upload_case(), 0.0)
    assert s.passed and s.step_recall == 1.0


def test_wrong_root_cause_is_reported():
    truth = _case_truth()
    truth["steps"][1]["is_root_cause"] = False
    truth["steps"][0]["is_root_cause"] = True
    truth["root_cause_step"] = "home"
    assert root_verdict(truth, _upload_case()) is RootVerdict.WRONG


def test_missed_root_and_false_root_are_reported():
    no_root = correlate(numbered((0, "/")), files())
    assert root_verdict(_case_truth(), no_root) is RootVerdict.MISSED
    clean = _case_truth(root_cause_step=None, attacker_ips=[], files=[])
    for step in clean["steps"]:
        step["is_root_cause"] = False
    assert root_verdict(clean, _upload_case()) is RootVerdict.FALSE_ROOT
    assert root_verdict(clean, no_root) is RootVerdict.CORRECT


def test_root_cause_found_only_as_alternative_is_not_counted_correct():
    logs = numbered((0, "/admin/upload.php", {"method": "POST"}),
                    (0, "/admin/upload.php", {"method": "POST", "ip": VISITOR}))
    result = correlate(logs, files(file_ev("uploads/x.php", btime=1, ctime=1, mtime=1)))
    assert result.root_cause.alternative_event_ids
    truth = _case_truth()
    truth["steps"][1]["line_no"] = next(
        c.line_no for e in result.timeline if e.event_id in result.root_cause.alternative_event_ids
        for c in e.citations if c.line_no)
    assert root_verdict(truth, result) is RootVerdict.ALTERNATIVE


def test_missed_steps_files_and_rules_are_listed():
    truth = _case_truth(files=[{"path": "uploads/x.php", "sha256": "0" * 64, "change": "created"},
                               {"path": "uploads/y.php", "sha256": "1" * 64, "change": "created"}],
                        expected_rule_ids=["FILE-ANTIFORENSICS-TIMESTOMP"],
                        attacker_ips=[ATTACKER, VISITOR])
    truth["steps"].append({"id": "later", "category": "marker_invocation", "mitre": [],
                           "log_file": "access.log", "line_no": 40, "is_root_cause": False})
    s = score(truth, _upload_case(), 0.0)
    assert s.missed_steps == ("later",) and (s.steps_found, s.steps_expected) == (2, 3)
    assert s.missed_files == ("uploads/y.php",)
    assert s.missed_rules == ("FILE-ANTIFORENSICS-TIMESTOMP",)
    assert not s.passed


def test_benign_steps_can_be_opted_in_and_attack_steps_opted_out():
    truth = _case_truth(attacker_ips=[ATTACKER, VISITOR])
    truth["steps"][0]["expected_in_timeline"] = True  # actor_first_seen cites it
    truth["steps"][2]["expected_in_timeline"] = False
    s = score(truth, _upload_case(), 0.0)
    assert (s.steps_expected, s.steps_found) == (2, 2)


def _copy_benchmark(tmp_path, mutate=None):
    target = tmp_path / "bench" / "scenarios" / "a"
    shutil.copytree(SCENARIOS / "a", target)
    if mutate is not None:
        truth = json.loads((target / "ground_truth.json").read_text(encoding="utf-8"))
        mutate(truth)
        (target / "ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")
    return tmp_path / "bench"


def test_cli_reports_a_disagreeing_ground_truth(tmp_path):
    def blame_the_probe(truth):
        for step in truth["steps"]:
            step["is_root_cause"] = step["id"] == "get_sqli_probe"
        truth["root_cause_step"] = "get_sqli_probe"
        truth["attacker_ips"] = []

    result = runner.invoke(app, ["eval", str(_copy_benchmark(tmp_path, blame_the_probe)),
                                 "--no-runtime"])
    assert result.exit_code == 0, result.output
    assert "| A | file | dev | 3/3 | wrong | 1 | 0 | 0.00 |" in result.output
    assert "| A | wazuh | dev | 3/3 | wrong | 1 | 0 | 0.00 |" in result.output
    assert "A: root cause: wrong; false IPs: 172.30.0.1" in result.output


def test_cli_writes_deterministic_markdown_and_json(tmp_path):
    md1, md2, out = tmp_path / "1.md", tmp_path / "2.md", tmp_path / "s.json"
    for md in (md1, md2):
        result = runner.invoke(app, ["eval", str(BENCHMARK), "--no-runtime",
                                     "--markdown", str(md), "--json", str(out)])
        assert result.exit_code == 0, result.output
    assert md1.read_bytes() == md2.read_bytes()
    data = json.loads(out.read_text(encoding="utf-8"))
    for adapter in ("file", "wazuh"):
        dev = data["totals"][adapter]["dev"]
        assert dev["root_cause_correct"] == dev["scenarios"]


def test_cli_held_out_scenarios_are_summarized_apart(tmp_path):
    bench = _copy_benchmark(tmp_path, lambda t: t.update(split="held_out"))
    shutil.copytree(SCENARIOS / "f", bench / "scenarios" / "f")
    result = runner.invoke(app, ["eval", str(bench), "--no-runtime"])
    assert "**file, dev**: 1/1" in result.output and "**file, held_out**: 1/1" in result.output


def test_cli_can_score_one_adapter(tmp_path):
    result = runner.invoke(app, ["eval", str(BENCHMARK), "--no-runtime", "--adapter", "file"])
    assert result.exit_code == 0 and "| wazuh |" not in result.output
    bad = runner.invoke(app, ["eval", str(BENCHMARK), "--adapter", "splunk"])
    assert bad.exit_code == 2 and "unknown --adapter" in bad.output


@pytest.mark.parametrize("args", [["--scenario", "zz"], ["nowhere"]])
def test_cli_rejects_unknown_scenarios_and_folders(args, tmp_path):
    target = [str(BENCHMARK)] if args[0] == "--scenario" else [str(tmp_path / "nowhere")]
    result = runner.invoke(app, ["eval", *target, *(args if args[0] == "--scenario" else [])])
    assert result.exit_code == 2


def test_scenario_inputs_follow_the_analysis_block(tmp_path):
    truth = copy.deepcopy(_truth("a"))
    truth["analysis"] = {"access_logs": ["logs/x.log"], "error_logs": ["e.log"],
                         "error_log_utc_offset": "+0700", "trusted_proxies": ["10.0.0.1"],
                         "baseline": "baseline.tsv"}
    inputs, config = evaluate.scenario_inputs(tmp_path, truth)
    evidence = tmp_path / "evidence"
    assert inputs.logs == (evidence / "logs" / "x.log",)
    assert inputs.error_logs == (evidence / "e.log",) and inputs.error_utc_offset == "+0700"
    assert inputs.baseline == evidence / "baseline.tsv" and inputs.base_dir == evidence
    assert config.trusted_proxies == ("10.0.0.1",)
