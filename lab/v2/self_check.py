"""Run the required per-scenario integrity and diversity checks without analysis."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import re
import tempfile
from collections import Counter
from itertools import pairwise
from pathlib import Path
from typing import Any

try:
    from . import background, collect, label
    from .prepare_background import SCANNER_UA, STATIC_SUFFIX, static_asset
except ImportError:  # direct script execution from lab/v2
    import background
    import collect
    import label
    from prepare_background import SCANNER_UA, STATIC_SUFFIX, static_asset


def activity_ips(truth: dict, access_rows: list[dict]) -> set[str]:
    """Include labelled benign actors without calling them attackers in ground truth."""
    lines = {step["line_no"] for step in truth["steps"]}
    return set(truth["attacker_ips"]) | {
        row["client_ip"] for row in access_rows if row["line_no"] in lines
    }


def timing_checks(access_rows: list[dict], background_rows: list[dict], actors: set[str]) -> dict:
    span = max(r["timestamp"] for r in access_rows) - min(r["timestamp"] for r in access_rows)
    rate = len(access_rows) / span if span else float("inf")
    overall = Counter(int(r["timestamp"]) for r in access_rows)
    busy = Counter(int(r["timestamp"]) for r in background_rows)
    if not 2 <= rate <= 5:
        raise ValueError(f"average requests per second outside 2-5: {rate}")
    if max(busy.values()) > 20:
        raise ValueError("background exceeds 20 requests in a second")
    attacks = [r for r in access_rows if r["client_ip"] in actors]
    attack_span = max(r["timestamp"] for r in attacks) - min(r["timestamp"] for r in attacks)
    if attack_span < 180:
        raise ValueError("multi-step attack spans less than three minutes")
    writes = [r["request"].split()[1] for r in background_rows
              if r["request"].split()[0] in {"POST", "PUT", "PATCH"}]
    static_writes = sum(static_asset(target) for target in writes)
    if static_writes:
        raise ValueError("background writes to static assets")
    return {
        "log_span_seconds": span,
        "average_requests_per_second": round(rate, 5),
        "maximum_background_requests_per_second": max(busy.values()),
        "maximum_overall_requests_per_second": max(overall.values()),
        "attack_span_seconds": attack_span,
        "background_writes_to_static_assets": static_writes,
        "scanner_disguised_api_static_suffix_probes": sum(
            ";" in target and bool(STATIC_SUFFIX.search(target.split("?", 1)[0]))
            for target in writes
        ),
        "top_10_post_targets": Counter(
            r["request"].split()[1] for r in background_rows if r["request"].startswith("POST ")
        ).most_common(10),
    }


def analyst_selection(
    access_rows: list[dict], background_rows: list[dict], actors: set[str], seed: int
) -> dict:
    actor_lines = [row["line_no"] for row in access_rows if row["client_ip"] in actors]
    return {
        "sample_seed": seed,
        "sample_background_line_numbers": sorted(random.Random(seed).sample(
            [row["line_no"] for row in background_rows], 50
        )),
        "attack_window": {"start_line": min(actor_lines), "end_line": max(actor_lines)},
    }


def analyst_proof(path: Path, selection: dict, access_sha256: str) -> dict:
    expected = {**selection, "access_log_sha256": access_sha256}
    if not path.is_file():
        return {"result": "PENDING analyst read before commit", **expected}
    proof = json.loads(path.read_text(encoding="utf-8"))
    if proof.get("result") != "PASS" or any(proof.get(k) != v for k, v in expected.items()):
        raise ValueError("analyst review selection or access-log hash does not match")
    return {"result": "PASS", **expected, "notes": "notes.md"}


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
    opener = gzip.open if (evidence / access_name).suffix == ".gz" else Path.open
    with opener(evidence / access_name, "rt", encoding="utf-8", errors="replace") as stream:
        access_lines = stream.readlines()
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
    expected_client_counts = Counter(expected_background)
    actual_client_counts = Counter(row["client_ip"] for row in actual_background)
    if expected_client_counts != actual_client_counts:
        raise ValueError("background client mapping counts differ from access log")
    if "192.0.2.135" in {row["client_ip"] for row in access_rows}:
        raise ValueError("background container address appears in evidence")

    user_agents: list[str] = []
    request_paths: list[str] = []
    for line_no, line in enumerate(access_lines, 1):
        fields = re.search(
            r'"(?P<request>(?:[^"\\]|\\.)*)" \d{3} \d+ "(?:[^"\\]|\\.)*" '
            r'"(?P<ua>(?:[^"\\]|\\.)*)"$',
            line.rstrip("\r\n"),
        )
        if not fields:
            raise ValueError(f"access line {line_no} has no request or User-Agent field")
        ua = label.unescape_nginx(fields["ua"])
        request = label.unescape_nginx(fields["request"])
        user_agents.append(ua)
        parts = request.split()
        request_paths.append(parts[1].split("?", 1)[0] if len(parts) >= 2 else "")
        if re.search(r"m8|m8v2|crawler", ua, re.I):
            raise ValueError(f"access line {line_no} has a lab-labelled User-Agent")

    background_line_numbers = {row["line_no"] for row in actual_background}
    nested_count = 0
    for line_no, path in enumerate(request_paths, 1):
        if line_no not in background_line_numbers:
            continue
        segments = Counter(part for part in path.split("/") if part)
        if any(count >= 3 for count in segments.values()):
            nested_count += 1
    nested_share = nested_count / len(actual_background)
    if nested_share >= 0.01:
        raise ValueError("1% or more of background paths repeat a segment three times")

    source_uas = Counter(row["ua"] for row in source)
    if max(source_uas.values()) / len(source) > 0.20:
        raise ValueError("a background User-Agent exceeds 20%")
    largest_overall_ua_share = max(Counter(user_agents).values()) / len(user_agents)
    if largest_overall_ua_share > 0.20:
        raise ValueError("an access-log User-Agent exceeds 20%")
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
    if root_step and not 0.30 <= root_step["line_no"] / len(access_rows) <= 0.70:
        raise ValueError("compromise root cause falls outside the 30-70% interval")

    current = collect.read_manifest(evidence / "manifest.tsv")
    baseline = collect.read_manifest(evidence / "baseline.tsv")
    restore_config = json.loads((scenario / "replay" / "restore.json").read_text(encoding="utf-8"))
    snapshot_path_map = restore_config.get("snapshot_path_map", {})
    reverse_path_map = {stored: original for original, stored in snapshot_path_map.items()}
    for path in (evidence / "webroot").rglob("*"):
        if not path.is_file():
            continue
        stored_path = path.relative_to(evidence / "webroot").as_posix()
        rel_path = reverse_path_map.get(stored_path, stored_path)
        if not collect.changed_from_baseline(current[rel_path], baseline.get(rel_path)):
            raise ValueError(f"unchanged baseline file is stored in snapshot: {stored_path}")
    collect.scan_defanged_snapshot(evidence / "webroot", current, baseline, snapshot_path_map)
    size_bytes = sum(path.stat().st_size for path in scenario.rglob("*") if path.is_file())
    if size_bytes >= 5_000_000:
        raise ValueError("scenario folder is not under 5 MB")
    attacker_roles = {"webshell", "webshell_agent", "attacker_file", "shell"}
    if records.get("root_cause_step") is None and any(
        item.get("role") in attacker_roles for item in truth["files"]
    ):
        raise ValueError("no-compromise scenario has attacker files or a root cause")

    round7 = {}
    if restore_config.get("version") == 2:
        try:
            from .validate_evidence import validate
        except ImportError:
            from validate_evidence import validate

        parse_failures = validate(evidence)
        if any(parse_failures):
            raise ValueError("evidence parser reported failures")
        proof = json.loads((replay / "restore-validation.txt").read_text())
        if proof.get("result") != "PASS" or not proof.get("destination_was_empty"):
            raise ValueError("portable restore proof missing or failed")
        clean_image_proof = proof.get("image_removal_proof") == "PASS" or (
            "image_removal_proof" not in proof
            and bool(proof.get("local_app_images_removed_and_absence_verified"))
        )
        if not clean_image_proof and os.environ.get("M8V2_DEFER_IMAGE_PROOF") != "1":
            raise ValueError("clean-image restore proof is pending")
        scan = (replay / "defender-scan.txt").read_text(encoding="utf-8-sig")
        if "detections=0" not in scan or "real_time_protection_enabled=True" not in scan:
            raise ValueError("Defender scan proof missing or failed")
        actors = activity_ips(truth, access_rows)
        round7 = timing_checks(access_rows, actual_background, actors)
        round7["activity_client_ips"] = sorted(actors)
        targets = json.loads((replay / "background.json").read_text())["method_targets_from_crawl"]
        for item, actual in zip(source, actual_background, strict=True):
            scanner = item["status"] == "404" or bool(SCANNER_UA.search(item["ua"]))
            if not scanner and item["method"] in {"POST", "PUT", "PATCH"}:
                if item["target"] not in targets.get(item["method"], []):
                    raise ValueError("visitor write target is not an exact crawled method target")
                if actual["request"].split()[1] != item["target"]:
                    raise ValueError("visitor write target changed between plan and live replay")
        all_actor_lines = [row["line_no"] for row in access_rows
                           if row["client_ip"] in actors]
        if min(all_actor_lines) / len(access_rows) < 0.30 or (
            max(all_actor_lines) / len(access_rows) > 0.70
        ):
            raise ValueError("actor window falls outside the 30-70% interval")
        round7["whole_actor_window_position_range"] = [
            min(all_actor_lines) / len(access_rows), max(all_actor_lines) / len(access_rows)
        ]
        replay_run = json.loads((replay / "background.json").read_text())["replay"]
        if not replay_run.get("uninterrupted") or replay_run.get("resumed") is not False:
            raise ValueError("recording was interrupted or resumed")
        hand = json.loads((replay / "hand-pacing.json").read_text())
        for previous, following in pairwise(hand):
            if following["offset_seconds"] - previous["offset_seconds"] < 2:
                raise ValueError("hand-run actions less than two seconds apart")
        round7.update({
            "parse_failures": dict(zip(
                ("access", "manifest", "error"), parse_failures, strict=True
            )),
            "restore": proof,
            "restore_with_app_images_removed": "PASS" if clean_image_proof else "PENDING",
            "defender_scan": "PASS; detections=0; real-time protection enabled",
            "analyst_read": analyst_proof(
                replay / "analyst-review.json",
                analyst_selection(access_rows, actual_background, actors,
                                  7000 + int(scenario_id[1:])),
                hashlib.sha256((evidence / access_name).read_bytes()).hexdigest(),
            ),
            "replay_started_at_utc": replay_run["started_at_utc"],
            "replay_ended_at_utc": replay_run["ended_at_utc"],
            "uninterrupted_run": "PASS; no part resumed",
            "native_tool_bursts_exempt": [
                event["action"] for event in hand if "native burst" in event["action"]
            ] + (["Weevely internal exchanges within hand-paced agent commands"]
                 if any(event["action"] == "agent_command" for event in hand) else []),
            "hand_action_minimum_spacing_seconds": min(
                (b["offset_seconds"] - a["offset_seconds"]
                 for a, b in pairwise(hand)), default=None
            ),
            "write_candidates_within_5_seconds_of_ctime": {
                item["path"]: sum(
                    row["request"].split()[0] in {"POST", "PUT"}
                    and abs(row["timestamp"] - float(
                        current[item["path"].lstrip("/")].fields[8]
                    )) <= 5
                    for row in access_rows
                ) for item in truth["files"] if item["path"].lstrip("/") in current
            },
        })
    return {
        **round7,
        "scenario": scenario_id,
        "schema": "PASS",
        "ground_truth_regeneration": "PASS",
        "access_rows": len(access_rows),
        "background_rows": len(actual_background),
        "background_clients": len(client_counts),
        "largest_background_client_share": round(max(client_counts.values()) / len(source), 5),
        "background_user_agents": len(source_uas),
        "largest_user_agent_share": round(max(source_uas.values()) / len(source), 5),
        "largest_overall_user_agent_share": round(largest_overall_ua_share, 5),
        "top_user_agent": Counter(user_agents).most_common(1)[0][0],
        "nested_path_share": round(nested_share, 5),
        "request_paths_with_lab_terms": sum(
            bool(re.search(r"m8|m8v2|crawler", path, re.I)) for path in request_paths
        ),
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
