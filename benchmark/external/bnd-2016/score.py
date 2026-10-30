"""Score a webforensics report.json against ground_truth.md (pre-registered rules) of the
BND Forensik-Challenge (2016).

    python -I score.py RUN_DIR
"""

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ATTACKER = "192.168.1.11"
WINDOW = timedelta(seconds=120)
EXPLOIT_TIMES = (datetime(2016, 11, 21, 14, 47, 9, tzinfo=UTC),
                 datetime(2016, 11, 22, 8, 48, 56, tzinfo=UTC))
EXPLOIT_WINDOW = (EXPLOIT_TIMES[0], EXPLOIT_TIMES[1])
A1 = (r"^/index\.php", datetime(2016, 11, 24, 8, 28, 13, tzinfo=UTC),
      datetime(2016, 11, 24, 8, 29, 32, tzinfo=UTC))
DEFACED = "index.html"
APP_PAGES = {"originalIndex.php", "index.php"}
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)')


def parse(excerpt):
    m = LINE.match(excerpt or "")
    if not m:
        return None
    when = datetime.strptime(m[2], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    return m[1], when, m[3], m[4]


def ts(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None


def main():
    run = Path(sys.argv[1])
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    res = report["result"]
    cited = [p for e in res["timeline"] for c in e["citations"]
             if c["kind"] == "log_line" if (p := parse(c["excerpt"]))]
    background = [g for g in report.get("background", [])]
    print(f"run: {run.name}   timeline rows: {len(res['timeline'])}")

    a1 = [p for p in cited if p[0] == ATTACKER and re.search(A1[0], p[3])
          and A1[1] - WINDOW <= p[1] <= A1[2] + WINDOW]
    in_background = any(c[0] == ATTACKER for g in background for c in g["top_clients"])
    print("\nEvents")
    print(f"  {'HIT ' if a1 else 'MISS'} A1 probes of /index.php in the timeline ({len(a1)} lines)"
          f"; attacker listed in unrelated-activity groups: {in_background}")

    flagged = {f["path"] for f in res["affected_files"]}
    print("\nFiles")
    print(f"  {'HIT ' if DEFACED in flagged else 'MISS'} defaced index.html flagged")
    print(f"  vulnerable pages flagged as affected (reported, not scored): "
          f"{sorted(flagged & APP_PAGES)}")
    wrong = sorted(flagged - APP_PAGES - {DEFACED})
    print(f"  false accusations {len(wrong)}: {wrong}")
    print(f"  listed for manual review: {list(res['unexplained_changes'])}")

    ips = set(res["iocs"]["ips"])
    print("\nIPs (IOC list)")
    print(f"  accused: {sorted(ips)}   other than attacker: {sorted(ips - {ATTACKER})}")

    print("\nRoot cause")
    rc = res["root_cause"]
    if rc is None:
        print("  none given (preferred to a wrong one: the exploit line was deleted from the log)")
    else:
        event = next(e for e in res["timeline"] if e["event_id"] == rc["event_id"])
        lines = [p for c in event["citations"] if c["kind"] == "log_line"
                 if (p := parse(c["excerpt"]))]
        strict = any(p[0] == ATTACKER and p[3].startswith("/originalIndex.php")
                     and any(abs(p[1] - t) <= WINDOW for t in EXPLOIT_TIMES) for p in lines)
        lenient = any(p[0] == ATTACKER and re.match(r"^/(originalIndex|index)\.php", p[3])
                      for p in lines)
        print(f"  {lines[0][0] if lines else '-'} {lines[0][2] if lines else ''} "
              f"{lines[0][3].split('?')[0] if lines else ''} ({rc['vuln_class']})")
        print(f"  strict {'OK' if strict else 'WRONG'}   lenient {'OK' if lenient else 'WRONG'}")

    compromise = any(r["key"] != "summary.no_compromise" for r in report["summary"][:1])
    print(f"\nCompromise reported in the summary: {compromise}")
    covering = [g for g in res["gaps"] if g.get("start") and (
        ts(g["start"]) <= EXPLOIT_WINDOW[1] and (ts(g["end"]) or EXPLOIT_WINDOW[1])
        >= EXPLOIT_WINDOW[0])]
    print(f"Gap over the exploit window: {'HIT' if covering else 'MISS'} "
          f"{[(g['kind'], g['start'], g['end']) for g in covering]}")
    print(f"Gaps: {[(g['kind'], g['start'], g['end']) for g in res['gaps']]}")


if __name__ == "__main__":
    main()
