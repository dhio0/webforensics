"""Review regressions and deterministic evidence-only round-eight fixes."""

import copy
import json
from pathlib import Path

import pytest
from lab.v2 import background
from lab.v2.remap_background_ips import mapping_from_inputs
from lab.v2.self_check import check_file_roles, private_client_count

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


def test_overflow_keeps_first_documentation_addresses_and_uses_benchmark_pool() -> None:
    mapper = background.IPMapper(42)
    values = [mapper.assign(f"client-{n}") for n in range(10384)]
    assert values[:2] == ["198.51.100.1", "198.51.100.2"]
    assert values[634] == "192.0.2.127"
    assert values[635] == "198.18.0.1"
    assert len(set(values)) == len(values)
    assert private_client_count(values) == 0
    assert private_client_count(["10.0.0.1", "172.16.0.1", "192.168.1.1", "198.18.0.1"]) == 3


def test_recorded_address_mapping_rerun(tmp_path: Path) -> None:
    for scenario in sorted((ROOT / "benchmark/v2").glob("s[0-9][0-9]")):
        replay = scenario / "replay"
        expected = (replay / "ip_map.tsv").read_bytes()
        seed = int(expected.splitlines()[0].split(b"=")[1])
        output = tmp_path / f"{scenario.name}.tsv"
        mapping_from_inputs(replay, seed, output)
        assert output.read_bytes() == expected
