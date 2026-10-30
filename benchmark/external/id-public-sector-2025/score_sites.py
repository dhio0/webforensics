"""Aggregate the per-site runs (run 1b) of Organization Y against ground_truth.md.

    python -I score_sites.py RUN_ROOT [INCIDENT_IP]
"""

import json
import sys
from collections import Counter
from pathlib import Path


def main() -> int:
    root = Path(sys.argv[1])
    incident = sys.argv[2] if len(sys.argv) > 2 else None
    rows, accused, groups, log_only, gaps = [], Counter(), Counter(), [], Counter()
    clients = Counter()
    for report_path in sorted(root.glob("*/report.json")):
        site = report_path.parent.name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        res = report["result"]
        first = report["summary"][0]["key"]
        rows.append((site, first, len(res["affected_files"]), list(res["iocs"]["ips"]),
                     list(res.get("log_only_files", [])), res["root_cause"] is not None))
        accused.update({ip: 1 for ip in res["iocs"]["ips"]})
        log_only += [(site, u) for u in res.get("log_only_files", [])]
        for g in report.get("background", []):
            groups[g["rule_id"]] += g["count"]
            for ip, n in g["top_clients"]:
                clients[ip] += n
        gaps.update(g["kind"] for g in res["gaps"])
    print(f"sites analyzed: {len(rows)}")
    compromised = [r for r in rows if r[1] != "summary.no_compromise"]
    print(f"sites with a compromise reported: {len(compromised)}")
    for site, first, files, ips, scripts, root_cause in compromised:
        print(f"  {site}: {first} files={files} ips={ips} log_only={scripts} "
              f"root_cause={root_cause}")
    print(f"affected files total: {sum(r[2] for r in rows)} (expected 0: no webroot)")
    print(f"accused attacker IPs: {sorted(accused)}")
    if incident:
        print(f"incident IP {incident} accused: {incident in accused}; "
              f"in background top clients: {incident in clients}")
    print(f"log-only scripts: {log_only}")
    print(f"background attack-pattern lines: {sum(groups.values())}")
    for rule, n in groups.most_common(15):
        print(f"  {rule:<28} {n:>8}")
    print(f"top background clients: {clients.most_common(5)}")
    print(f"gap kinds over all sites: {dict(gaps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
