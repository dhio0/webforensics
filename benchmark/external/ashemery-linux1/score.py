"""Score a webforensics report.json against ground_truth.md (pre-registered rules) of Ali
Hadi's Linux "Case #1: Compromised Web Server".

    python -I score.py RUN_DIR
"""

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ATTACKER = "192.168.210.131"
WINDOW = timedelta(seconds=120)


def t(text):
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


EVENTS = {  # id: (method or None, path regex, start UTC, end UTC)
    "W1 Drupalgeddon2 POST": (
        "POST", r"^/jabc/",
        t("2019-10-05T11:01:27"), t("2019-10-05T11:01:27")),
    "W3 update.php?cmd= use": (
        "GET", r"^/jabc/scripts/update\.php",
        t("2019-10-05T11:17:48"), t("2019-10-05T11:17:48")),
}
ATTACKER_FILES = {"jabc/scripts/update.php"}
STRICT = EVENTS["W1 Drupalgeddon2 POST"]
LENIENT = (r"^/jabc/", t("2019-10-05T11:00:00"), t("2019-10-05T11:05:00"))
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)')


def parse(excerpt):
    m = LINE.match(excerpt or "")
    if not m:
        return None
    when = datetime.strptime(m[2], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    return m[1], when, m[3], m[4]


def main():
    run = Path(sys.argv[1])
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    res = report["result"]
    rows = []
    for event in res["timeline"]:
        for c in event["citations"]:
            if c["kind"] == "log_line" and (p := parse(c["excerpt"])):
                rows.append((event, p))
    print(f"run: {run.name}   timeline rows: {len(res['timeline'])}")

    print("\nEvents (web logs)")
    hit = 0
    for name, (method, pattern, start, end) in EVENTS.items():
        found = [p for _, p in rows if p[0] == ATTACKER and re.search(pattern, p[3])
                 and (method is None or p[2] == method)
                 and start - WINDOW <= p[1] <= end + WINDOW]
        hit += bool(found)
        print(f"  {'HIT ' if found else 'MISS'} {name}  ({len(found)} cited lines)")
    print(f"  event recall {hit}/{len(EVENTS)}")

    flagged = {f["path"] for f in res["affected_files"]}
    print("\nFiles")
    print(f"  attacker files flagged {len(flagged & ATTACKER_FILES)}/{len(ATTACKER_FILES)}"
          f"  missed: {sorted(ATTACKER_FILES - flagged)}")
    wrong = sorted(flagged - ATTACKER_FILES)
    print(f"  false accusations {len(wrong)}: {wrong}")
    writer = [e for e in res["timeline"] if e["description"]["params"].get("file")
              == "jabc/scripts/update.php" and e["description"]["key"] in (
              "timeline.file_write_request", "timeline.upload_exploit",
              "timeline.write_exploit")]
    print(f"  HTTP writer claimed for update.php (should be none): {len(writer)}")

    ips = set(res["iocs"]["ips"])
    print("\nIPs (IOC list)")
    print(f"  accused: {sorted(ips)}   other than attacker: {sorted(ips - {ATTACKER})}")

    print("\nRoot cause")
    rc = res["root_cause"]
    if rc is None:
        print("  none   strict WRONG   lenient WRONG")
    else:
        event = next(e for e in res["timeline"] if e["event_id"] == rc["event_id"])
        cited = [p for c in event["citations"] if c["kind"] == "log_line"
                 if (p := parse(c["excerpt"]))]
        strict = any(p[0] == ATTACKER and p[2] == STRICT[0] and re.search(STRICT[1], p[3])
                     and abs(p[1] - STRICT[2]) <= WINDOW for p in cited)
        lenient = any(p[0] == ATTACKER and re.search(LENIENT[0], p[3])
                      and LENIENT[1] <= p[1] <= LENIENT[2] for p in cited)
        where = "-"
        if cited:
            method, path, when = cited[0][2], cited[0][3].split("?")[0], cited[0][1]
            where = f"{cited[0][0]} {method} {path} at {when:%Y-%m-%d %H:%M:%S} UTC"
        print(f"  {where} ({rc['vuln_class']}, confidence {rc['confidence']})")
        print(f"  strict {'OK' if strict else 'WRONG'}   lenient {'OK' if lenient else 'WRONG'}")

    print("\nCode (not scored: CVE-2018-7600 is not SQL injection)")
    print(f"  findings: {sorted((c['file'], c['line']) for c in report['code_findings'])}")
    print(f"\nScripts seen only in the logs: {list(res.get('log_only_files', []))}")
    print(f"Unexplained changes (review): {len(res['unexplained_changes'])}")
    print(f"Gaps: {len(res['gaps'])}")


if __name__ == "__main__":
    main()
