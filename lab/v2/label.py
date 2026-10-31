"""Label access-log requests from replay records and the edge's sidecar log."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

COMBINED = re.compile(
    r'^(?P<client>\S+) \S+ \S+ \[(?P<time>[^]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*"$'
)
SCENARIOS = {f"s{number:02}" for number in range(1, 13)}


def unescape_nginx(value: str) -> str:
    return re.sub(
        r"\\x([0-9a-fA-F]{2})|\\(.)",
        lambda match: chr(int(match.group(1), 16)) if match.group(1) else match.group(2),
        value,
    )


def access_index(path: Path) -> list[dict[str, Any]]:
    rows = []
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, "rt", encoding="utf-8", errors="replace") as source:
        for line_no, line in enumerate(source, 1):
            match = COMBINED.match(line.rstrip("\r\n"))
            if not match:
                raise ValueError(f"{path}:{line_no}: invalid combined access-log row")
            timestamp = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
            rows.append(
                {
                    "line_no": line_no,
                    "timestamp": timestamp.timestamp(),
                    "request": unescape_nginx(match["request"]),
                    "status": int(match["status"]),
                    "client_ip": unescape_nginx(match["client"]),
                }
            )
    return rows


def sidecar_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, "rt", encoding="utf-8", errors="strict") as source:
        for line_no, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                row["sidecar_line"] = line_no
                row["msec"] = float(row["msec"])
                row["status"] = int(row["status"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_no}: invalid sidecar row: {exc}") from exc
            rows.append(row)
    return rows


def join_log_rows(
    sidecar_rows_: list[dict[str, Any]], access_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join same-edge logs in write order, verifying every pair in O(N)."""
    if len(sidecar_rows_) != len(access_rows):
        raise ValueError(
            "sidecar/access log line-count mismatch: "
            f"labels={len(sidecar_rows_)} access={len(access_rows)}"
        )
    joined = []
    for sidecar, access in zip(sidecar_rows_, access_rows, strict=True):
        if (
            access["request"] != sidecar["request"]
            or access["status"] != sidecar["status"]
            or access["client_ip"] != sidecar["client_ip"]
            or abs(access["timestamp"] - sidecar["msec"]) > 1.1
        ):
            raise ValueError(
                f"sidecar line {sidecar['sidecar_line']} does not match access line "
                f"{access['line_no']} by request/status/client/time"
            )
        joined.append({**sidecar, "access_line_no": access["line_no"]})
    return joined


def select_time_window_candidate(
    candidates: list[dict[str, Any]], step_id: str, ordinal: int | None = None
) -> dict[str, Any]:
    """Select a request from a tool window by explicit order when needed."""
    if ordinal is not None:
        if ordinal < 1 or ordinal > len(candidates):
            raise ValueError(
                f"time window for {step_id} has {len(candidates)} requests; "
                f"candidate ordinal {ordinal} is unavailable"
            )
        return candidates[ordinal - 1]
    if len(candidates) != 1:
        raise ValueError(
            f"time window for {step_id} identifies {len(candidates)} requests; "
            "add a request/status discriminator or candidate_ordinal"
        )
    return candidates[0]


def parse_manifest(path: Path) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    columns_seen = False
    with path.open(encoding="utf-8", errors="strict") as manifest:
        for line_number, line in enumerate(manifest, 1):
            line = line.rstrip("\n")
            if line.startswith("#columns="):
                columns_seen = line.split("=", 1)[1] == (
                    "path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256"
                )
                continue
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 11:
                raise ValueError(f"{path}:{line_number}: expected 11 manifest fields")
            rel = os.fsdecode(bytes.fromhex(fields[0]))
            names = (
                "type",
                "size",
                "mode",
                "uid",
                "inode",
                "atime",
                "mtime",
                "ctime",
                "btime",
                "sha256",
            )
            rows[rel] = {"path_hex": fields[0], **dict(zip(names, fields[1:], strict=True))}
    if not columns_seen:
        raise ValueError(f"{path}: not a collect.sh manifest v1")
    return rows


def changed_files(
    records: dict[str, Any], baseline: dict[str, dict[str, str]], current: dict[str, dict[str, str]]
) -> list[dict[str, str]]:
    file_metadata = {item["path"].lstrip("/"): item for item in records.get("files", [])}
    result = []
    for rel_path in sorted(set(baseline) | set(current)):
        old = baseline.get(rel_path)
        new = current.get(rel_path)
        if old is None and new is not None:
            change = "created"
        elif old is not None and new is None:
            change = "deleted"
        elif (
            old is not None
            and new is not None
            and any(
                old[key] != new[key]
                for key in (
                    "type",
                    "size",
                    "mode",
                    "uid",
                    "inode",
                    "mtime",
                    "ctime",
                    "btime",
                    "sha256",
                )
            )
        ):
            change = "modified"
        else:
            continue
        result.append(
            {
                "path": rel_path,
                "sha256": (old if change == "deleted" else new)["sha256"],
                "change": change,
                "role": file_metadata.get(rel_path, {}).get("role", "unclassified_change"),
                **(
                    {"expected_in_report": file_metadata[rel_path]["expected_in_report"]}
                    if "expected_in_report" in file_metadata.get(rel_path, {})
                    else {}
                ),
            }
        )
    return result


def make_ground_truth(
    records: dict[str, Any],
    evidence: Path,
    labels_path: Path,
    scenario_id: str,
) -> dict[str, Any]:
    if scenario_id not in SCENARIOS:
        raise ValueError(f"unexpected scenario id: {scenario_id}")
    access_name = records.get("analysis", {}).get("access_logs", ["access.log"])[0]
    access_rows = access_index(evidence / access_name)
    label_rows = join_log_rows(sidecar_rows(labels_path), access_rows)
    by_step = {str(row["step"]): row for row in label_rows if row.get("step")}
    if len(by_step) != sum(bool(row.get("step")) for row in label_rows):
        raise ValueError("sidecar contains duplicate nonempty step labels")
    steps = []
    root_cause_step = records.get("root_cause_step")
    step_ids = {item["id"] for item in records["steps"]}
    if root_cause_step is not None and root_cause_step not in step_ids:
        raise ValueError("root_cause_step does not identify a replay step")
    for step in records["steps"]:
        step_id = step["id"]
        method = step.get("label_method", "header")
        if method == "header":
            if step_id not in by_step:
                raise ValueError(f"sidecar has no header-labelled request for {step_id}")
            labelled = by_step[step_id]
        elif method == "attacker_ip_time_window":
            start = datetime.fromisoformat(step["started_at"]).timestamp()
            end = datetime.fromisoformat(step["ended_at"]).timestamp()
            candidates = [
                row
                for row in label_rows
                if row["client_ip"] == step["attacker_ip"]
                and start <= row["msec"] <= end
                and ("request" not in step or row["request"] == step["request"])
                and ("status" not in step or row["status"] == int(step["status"]))
            ]
            labelled = select_time_window_candidate(
                candidates, step_id, step.get("candidate_ordinal")
            )
        else:
            raise ValueError(f"unsupported label method {method!r} for step {step_id}")
        steps.append(
            {
                "id": step_id,
                "category": step["category"],
                "mitre": step.get("mitre", []),
                "log_file": records.get("analysis", {}).get("access_logs", ["access.log"])[0],
                "line_no": labelled["access_line_no"],
                "is_root_cause": step_id == root_cause_step,
                **(
                    {"expected_in_timeline": step["expected_in_timeline"]}
                    if "expected_in_timeline" in step
                    else {}
                ),
            }
        )
    current = parse_manifest(evidence / "manifest.tsv")
    baseline = parse_manifest(evidence / "baseline.tsv")
    result = {
        "scenario_id": scenario_id,
        "description": records["description"],
        "attacker_ips": sorted(set(records["attacker_ips"])),
        "steps": steps,
        "files": changed_files(records, baseline, current),
        "root_cause_step": root_cause_step,
        "split": records.get("split", "dev"),
        "expected_rule_ids": sorted(set(records.get("expected_rule_ids", []))),
        "analysis": records.get(
            "analysis",
            {
                "access_logs": ["access.log"],
                "error_logs": ["error.log"],
                "error_log_format": "nginx",
                "error_log_utc_offset": "+0000",
                "manifest": "manifest.tsv",
                "baseline": "baseline.tsv",
                "trusted_proxies": records.get("trusted_proxies", []),
            },
        ),
    }
    if records.get("vulnerable_code"):
        result["vulnerable_code"] = records["vulnerable_code"]
    return result


def write_ground_truth(records_path: Path, evidence: Path, labels_path: Path, output: Path) -> None:
    records = json.loads(records_path.read_text(encoding="utf-8"))
    scenario_id = records["scenario_id"]
    truth = make_ground_truth(records, evidence, labels_path, scenario_id)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(truth, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"{output}: sha256={hashlib.sha256(output.read_bytes()).hexdigest()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_ground_truth(args.records, args.evidence, args.labels, args.output)


if __name__ == "__main__":
    main()
