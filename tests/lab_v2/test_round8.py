"""Review regressions and deterministic evidence-only round-eight fixes."""

import copy
import json
from pathlib import Path

import pytest
from lab.v2.self_check import check_file_roles

ROOT = Path(__file__).resolve().parents[2]


def test_s07_file_role_regression() -> None:
    scenario = ROOT / "benchmark/v2/s07"
    truth = json.loads((scenario / "ground_truth.json").read_text())
    records = json.loads((scenario / "replay/records.json").read_text())
    check_file_roles(truth, records)
    old = copy.deepcopy(truth)
    side_effect = next(item for item in old["files"] if "fm_backup" in item["path"])
    side_effect["role"] = "unclassified_change"
    side_effect.pop("expected_in_report")
    with pytest.raises(ValueError, match="no scenario justification"):
        check_file_roles(old, records)


@pytest.mark.parametrize("role", ["side_effect", "unknown_future_role", "unclassified_change"])
def test_non_attacker_files_require_explicit_exclusion(role: str) -> None:
    item = {"path": "example.txt", "role": role}
    records = {"files": [{**item, "classification_justification": "Reviewed ordinary change"}]}
    with pytest.raises(ValueError, match="expected_in_report false"):
        check_file_roles({"files": [item]}, records)
    check_file_roles({"files": [{**item, "expected_in_report": False}]}, records)


def test_benign_role_and_all_twelve_current_scenarios() -> None:
    check_file_roles({"files": [{"path": "cache.txt", "role": "benign_cache"}]}, {})
    for scenario in sorted((ROOT / "benchmark/v2").glob("s[0-9][0-9]")):
        check_file_roles(
            json.loads((scenario / "ground_truth.json").read_text()),
            json.loads((scenario / "replay/records.json").read_text()),
        )
