"""Score a webforensics report.json against ground_truth.md for the Zenodo 20001206 case.

    python -I score.py RUN_DIR [INCIDENT_IP]

No webroot is in this dataset, so affected_files and accused actors must be 0 (the primary
metric is precision at real scale). Attack attempts should appear as background groups.
"""

import json
import sys
from pathlib import Path


def main() -> int:
    run = Path(sys.argv[1])
    incident_ip = sys.argv[2] if len(sys.argv) > 2 else None
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    res = report["result"]
    summary = [s["key"] for s in report["summary"]]
    compromise = summary[0] not in ("summary.no_compromise",)
    print(f"run: {run.name}")
    print(f"  summary lines: {summary}")
    print(f"  compromise reported: {compromise} (expected: no)")
    print(f"  affected files: {len(res['affected_files'])} (expected 0: no webroot)")
    print(f"  log-only scripts: {list(res.get('log_only_files', []))}")
    accused = res["iocs"]["ips"]
    print(f"  accused attacker IPs: {accused} (false accusations unless labelled)")
    if incident_ip:
        print(f"  incident IP {incident_ip} flagged as actor: {incident_ip in accused}")
    groups = report.get("background", [])
    total = sum(g["count"] for g in groups)
    print(f"  background attack-pattern lines: {total} in {len(groups)} rule groups")
    for g in sorted(groups, key=lambda g: -g["count"])[:12]:
        print(f"    {g['rule_id']:<26} {g['count']:>7}  clients={g['clients']}")
    print(f"  gaps: {[g['kind'] for g in res['gaps']]}")
    print(f"  unexplained changes: {len(res['unexplained_changes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
