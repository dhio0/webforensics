"""Run the required per-scenario integrity and diversity checks without analysis."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from . import background, collect, label
    from .prepare_background import SCANNER_UA
except ImportError:  # direct script execution from lab/v2
    import background
    import collect
    import label
    from prepare_background import SCANNER_UA


def _rows(path: Path, parser) -> list[dict[str, Any]]:
    opener = gzip.open if path.suffix == ".gz" else Path.open
    output = []
    with opener(path, "rt", encoding="utf-8", errors="replace") as source:
        for line in source:
            row = parser(line, "")
            if row is None:
                raise ValueError(f"unparseable source row in {path}")
            output.append(row)
    return output


def check_scenario(root: Path, scenario_id: str) -> dict[str, Any]:
    scenario = root / "benchmark" / "v2" / scenario_id
    evidence = scenario / "evidence"
    replay = scenario / "replay"
    records = json.loads((replay / "records.json").read_text(encoding="utf-8"))
    truth_path = scenario / "ground_truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))

    access_name = truth["analysis"]["access_logs"][0]
    access_rows = label.access_index(evidence / access_name)
    sidecar_path = replay / "labels.log.gz"
    label.join_log_rows(label.sidecar_rows(sidecar_path), access_rows)
    generated = label.make_ground_truth(records, evidence, sidecar_path, scenario_id)
    with tempfile.TemporaryDirectory(prefix="v2-self-check-") as temporary:
        generated_path = Path(temporary) / "ground_truth.json"
        generated_path.write_text(
            json.dumps(generated, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        regenerated = generated_path.read_bytes()
    if regenerated != truth_path.read_bytes():
        raise ValueError("label.py regeneration differs from committed ground truth")

    schema = json.loads((root / "benchmark" / "schema" / "ground_truth.schema.json").read_text())
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError("jsonschema is required for the scenario self-check") from exc
    jsonschema.Draft202012Validator(schema).validate(truth)

    steps = truth["steps"]
    if any(not (1 <= step["line_no"] <= len(access_rows)) for step in steps):
        raise ValueError("a ground-truth step points outside the access log")
    by_line = {row["line_no"]: row for row in access_rows}
    root_step = next((step for step in steps if step["is_root_cause"]), None)
    if root_step:
        row = by_line[root_step["line_no"]]
        if row["client_ip"] not in truth["attacker_ips"] or not 200 <= row["status"] < 300:
            raise ValueError("root cause is not an attacker request with a 2xx answer")

    source = _rows(replay / "background.log.gz", background.parse_line)
    mapped: dict[str, str] = {}
    with (replay / "ip_map.tsv").open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle):
            if line_number < 2 or not line.strip():
                continue
            source_ip, mapped_ip = line.rstrip("\n").split("\t")
            mapped[source_ip] = mapped_ip
    expected_background = [mapped[row["ip"]] for row in source]
    mapped_values = set(mapped.values())
    actual_background = [row for row in access_rows if row["client_ip"] in mapped_values]
    if len(actual_background) != len(source):
        raise ValueError("background request count does not match its access-log rows")
    for expected_ip, actual in zip(expected_background, actual_background, strict=True):
        if expected_ip != actual["client_ip"]:
            raise ValueError("background client mapping/order differs from access log")
    if "192.0.2.135" in {row["client_ip"] for row in access_rows}:
        raise ValueError("background container address appears in evidence")

    source_uas = Counter(row["ua"] for row in source)
    if max(source_uas.values()) / len(source) > 0.20:
        raise ValueError("a background User-Agent exceeds 20%")
    client_counts = Counter(row["client_ip"] for row in actual_background)
    if len(client_counts) <= 300:
        raise ValueError("background has 300 or fewer distinct client addresses")
    if max(client_counts.values()) / len(actual_background) > 0.05:
        raise ValueError("a background client address exceeds 5% of requests")

    source_counts = json.loads((replay / "background.json").read_text(encoding="utf-8"))["counts"]
    visitor_lines = 0
    visitor_success = 0
    scanner_lines = 0
    status_mix: dict[str, Counter[int]] = {"visitor": Counter(), "scanner": Counter()}
    for item, actual in zip(source, actual_background, strict=True):
        scanner = item["status"] == "404" or bool(SCANNER_UA.search(item["ua"]))
        group = "scanner" if scanner else "visitor"
        status_mix[group][actual["status"]] += 1
        if scanner:
            scanner_lines += 1
        else:
            visitor_lines += 1
            visitor_success += int(200 <= actual["status"] < 400)
    if visitor_lines == 0 or visitor_success / visitor_lines < 0.80:
        raise ValueError("fewer than 80% of visitor responses were 2xx/3xx")
    if scanner_lines == 0 or scanner_lines != source_counts["scanner"]:
        raise ValueError("source scanner lines were not retained in the replay")

    mapped_attacker_lines = [step["line_no"] for step in steps]
    if mapped_attacker_lines:
        fractions = [line / len(access_rows) for line in mapped_attacker_lines]
        if min(fractions) < 0.30 or max(fractions) > 0.70:
            raise ValueError("attacker lines fall outside the 30-70% interval")

    current = collect.read_manifest(evidence / "manifest.tsv")
    baseline = collect.read_manifest(evidence / "baseline.tsv")
    for path in (evidence / "webroot").rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(evidence / "webroot").as_posix()
        if not collect.changed_from_baseline(current[rel_path], baseline.get(rel_path)):
            raise ValueError(f"unchanged baseline file is stored in snapshot: {rel_path}")
    collect.scan_defanged_snapshot(evidence / "webroot", current, baseline)
    size_bytes = sum(path.stat().st_size for path in scenario.rglob("*") if path.is_file())
    if size_bytes >= 5_000_000:
        raise ValueError("scenario folder is not under 5 MB")
    attacker_roles = {"webshell", "webshell_agent", "attacker_file", "shell"}
    if records.get("root_cause_step") is None and any(
        item.get("role") in attacker_roles for item in truth["files"]
    ):
        raise ValueError("no-compromise scenario has attacker files or a root cause")

    return {
        "scenario": scenario_id,
        "schema": "PASS",
        "ground_truth_regeneration": "PASS",
        "access_rows": len(access_rows),
        "background_rows": len(actual_background),
        "background_clients": len(client_counts),
        "largest_background_client_share": round(max(client_counts.values()) / len(source), 5),
        "background_user_agents": len(source_uas),
        "largest_user_agent_share": round(max(source_uas.values()) / len(source), 5),
        "visitor_success_share": round(visitor_success / visitor_lines, 5),
        "scanner_rows": scanner_lines,
        "attack_position_range": [
            round(min(mapped_attacker_lines) / len(access_rows), 5),
            round(max(mapped_attacker_lines) / len(access_rows), 5),
        ]
        if mapped_attacker_lines
        else None,
        "defanged_files": len((evidence / "defanged.tsv").read_text(encoding="utf-8").splitlines())
        - 1,
        "scenario_bytes": size_bytes,
        "ground_truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[f"s{n:02}" for n in range(1, 13)])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = check_scenario(args.root.resolve(), args.scenario)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8", newline="\n")
    print(output, end="")


if __name__ == "__main__":
    main()
