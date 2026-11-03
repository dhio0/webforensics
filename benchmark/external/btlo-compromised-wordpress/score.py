"""Score a webforensics report.json against ground_truth.md (pre-registered rules, with the
pinned lines) of the BTLO "Log Analysis - Compromised WordPress" challenge.

    python -I score.py RUN_DIR
"""

import json
import sys
from pathlib import Path

LOG = "access.log"
ATTACKERS = {"119.241.22.121", "103.69.55.212", "168.22.54.119"}
UNSURE = {"110.29.54.120", "197.23.128.35", "197.13.28.35", "103.212.94.19", "116.23.212.69"}
SHELL = "/wp-content/uploads/simple-file-list/fr34k.php"
EVENTS = {
    "E1 WPScan": {1364},
    "E2 sqlmap": {1528},
    "E3 Simple File List upload / rename": {1714, 1716},
    "E4 shell use (first use, last 404)": {1717, 1736},
}
STRICT = {1714, 1716}
SHELL_USE = set(range(1717, 1737))


def lines(citations) -> set[int]:
    return {c["line_no"] for c in citations
            if c["kind"] == "log_line" and c["source"].endswith(LOG) and c["line_no"]}


def main() -> None:
    run = Path(sys.argv[1])
    if not (run / "report.json").exists():
        print(f"run: {run.name}   no report (the tool did not finish)")
        return
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    res = report["result"]
    timeline = set().union(*(lines(e["citations"]) for e in res["timeline"])) \
        if res["timeline"] else set()
    background = {c["example"]["line_no"] for c in [g for g in report.get("background", [])]
                  if c.get("example")}
    print(f"run: {run.name}   timeline rows: {len(res['timeline'])}")

    print("\nEvents (timeline citations; background examples listed apart)")
    found = 0
    for name, wanted in EVENTS.items():
        hit = wanted <= timeline if name.startswith("E4") else bool(wanted & timeline)
        found += hit
        extra = " (only as unrelated activity)" if not hit and wanted & background else ""
        print(f"  {'HIT ' if hit else 'MISS'} {name}{extra}")
    print(f"  event recall {found}/{len(EVENTS)}")

    print("\nScripts seen only in the logs")
    shells = list(res["log_only_files"])
    print(f"  {'HIT ' if SHELL in shells else 'MISS'} {SHELL}")
    print(f"  false scripts: {[s for s in shells if s != SHELL]}")
    gone = any(e["description"]["key"] == "timeline.log_only_file_gone" for e in res["timeline"])
    print(f"  disappearance (404) shown: {gone}")

    ips = set(res["iocs"]["ips"])
    print("\nIPs (IOC list)")
    print(f"  attackers accused: {sorted(ips & ATTACKERS)} of {sorted(ATTACKERS)}")
    print(f"  unsure accused (not scored): {sorted(ips & UNSURE)}")
    print(f"  false accusations: {sorted(ips - ATTACKERS - UNSURE)}")
    affected = [f["path"] for f in res["affected_files"]]
    print(f"  affected files (none expected: no webroot): {affected}")

    print("\nRoot cause")
    root = res["root_cause"]
    if root is None:
        print("  none   strict MISS   lenient MISS")
    else:
        event = next(e for e in res["timeline"] if e["event_id"] == root["event_id"])
        cited = lines(event["citations"])
        strict = bool(cited & STRICT)
        lenient = strict or bool(cited & SHELL_USE) or any(
            "simple-file-list" in (c.get("excerpt") or "") for c in event["citations"])
        print(f"  {event['description']['key']} lines {sorted(cited)} "
              f"vuln {root.get('vuln_class')} confidence {root['confidence']}")
        print(f"  strict {'OK' if strict else 'WRONG'}   lenient {'OK' if lenient else 'WRONG'}")

    no_webroot = any(g["kind"] == "no_baseline" for g in res["gaps"])
    print(f"\nGaps: {sorted({g['kind'] for g in res['gaps']})}  (no-baseline gap: {no_webroot})")


if __name__ == "__main__":
    main()
