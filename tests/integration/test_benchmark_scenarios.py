"""Validate committed benchmark ground truth without requiring Docker."""

import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
SCENARIOS = ROOT / "benchmark" / "scenarios"
SCHEMA_PATH = ROOT / "benchmark" / "schema" / "ground_truth.schema.json"


def _manifest_hashes(path: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 11:
            raise AssertionError(f"invalid manifest row in {path}: {line!r}")
        rel_path = bytes.fromhex(fields[0]).decode("utf-8")
        hashes[rel_path] = fields[10]
    return hashes


def _access_logs(ground_truth: dict) -> list[str]:
    return ground_truth.get("analysis", {}).get("access_logs", ["access.log"])


def _analysis_paths(ground_truth: dict) -> list[str]:
    analysis = ground_truth.get("analysis", {})
    paths = [*_access_logs(ground_truth), *analysis.get("error_logs", []),
             analysis.get("manifest", "manifest.tsv")]
    return paths + ([analysis["baseline"]] if "baseline" in analysis else [])


def _expected(step: dict) -> bool:
    return step.get("expected_in_timeline", step["category"] != "benign_request")


def test_all_scenario_ground_truth_matches_schema_and_evidence():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    ground_truth_files = sorted(SCENARIOS.glob("*/ground_truth.json"))
    assert ground_truth_files, "no benchmark scenario ground truth files found"

    for ground_truth_path in ground_truth_files:
        scenario_dir = ground_truth_path.parent
        evidence_dir = scenario_dir / "evidence"
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(ground_truth), key=lambda error: list(error.path))
        assert not errors, "\n".join(error.message for error in errors)

        steps = ground_truth["steps"]
        step_ids = [step["id"] for step in steps]
        assert len(step_ids) == len(set(step_ids)), f"duplicate step id in {ground_truth_path}"
        root_steps = [step["id"] for step in steps if step["is_root_cause"]]
        root = ground_truth["root_cause_step"]
        assert root_steps == ([root] if root is not None else [])
        if root is None:  # nothing compromised: nothing may be listed as changed by an attack
            assert ground_truth["files"] == [] and ground_truth["attacker_ips"] == []
        for rel in _analysis_paths(ground_truth):
            assert (evidence_dir / rel).is_file(), f"missing {rel} for {ground_truth_path}"

        manifest = evidence_dir / "manifest.tsv"
        assert manifest.is_file(), f"missing manifest for {ground_truth_path}"
        file_hashes = _manifest_hashes(manifest)

        vulnerable_code = ground_truth.get("vulnerable_code")
        if vulnerable_code:
            source_path = Path(vulnerable_code["file"])
            webroot_path = source_path.relative_to(Path("lab/app")).as_posix()
            assert file_hashes.get(webroot_path) == vulnerable_code["sha256"], (
                f"vulnerable code hash mismatch for {source_path} in {ground_truth_path}"
            )
            source_bytes = (ROOT / source_path).read_bytes()
            if hashlib.sha256(source_bytes).hexdigest() == vulnerable_code["sha256"]:
                source_line_count = len(source_bytes.splitlines())
                assert vulnerable_code["line"] <= source_line_count, (
                    f"vulnerable code line is outside {source_path} in {ground_truth_path}"
                )

        for step in steps:
            log_file = Path(step["log_file"])
            assert not log_file.is_absolute() and ".." not in log_file.parts
            cited_log = (evidence_dir / log_file).resolve()
            assert cited_log.is_relative_to(evidence_dir.resolve())
            assert cited_log.is_file(), f"missing log {step['log_file']} for {ground_truth_path}"
            lines = cited_log.read_text(encoding="utf-8", errors="replace").splitlines()
            assert step["line_no"] <= len(lines), (
                f"missing line {step['line_no']} in {step['log_file']} for {ground_truth_path}"
            )

        # Attack steps in the access log must not share a second, so their order is
        # unambiguous. Benign background steps (busy multi-client traffic) may.
        timestamps = []
        for step in steps:
            if step["log_file"] not in _access_logs(ground_truth) or not _expected(step):
                continue
            log_lines = (evidence_dir / step["log_file"]).read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            timestamp = re.search(r"\[([^]]+)\]", log_lines[step["line_no"] - 1])
            assert timestamp, f"missing combined-log timestamp for {step['id']}"
            timestamps.append(timestamp.group(1))
        assert len(timestamps) == len(set(timestamps)), (
            f"scenario steps share a timestamp in {ground_truth_path}"
        )

        for file_item in ground_truth["files"]:
            assert file_hashes.get(file_item["path"]) == file_item["sha256"], (
                f"manifest hash mismatch for {file_item['path']} in {ground_truth_path}"
            )


def test_ground_truth_log_paths_are_relative():
    for ground_truth_path in SCENARIOS.glob("*/ground_truth.json"):
        data = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        for step in data["steps"]:
            assert not re.match(r"^[A-Za-z]:", step["log_file"])
