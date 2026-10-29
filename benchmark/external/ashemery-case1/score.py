"""Score a webforensics report.json against ground_truth.md (pre-registered rules).

    python -I score.py RUN_DIR

RUN_DIR holds the report.json of one `webforensics analyze` run on the case evidence.
The rules below implement ground_truth.md exactly; they were written before the first run.
"""

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ATTACKER = "192.168.56.102"
WINDOW = timedelta(seconds=120)


def t(text):
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


EVENTS = {  # id: (method or None, path regex, start UTC, end UTC)
    "G1 command injection": (
        "POST", r"^/dvwa/vulnerabilities/exec/",
        t("2015-09-02T09:04:35"), t("2015-09-02T09:04:35")),
    "G2 LFI": (
        None, r"^/dvwa/vulnerabilities/fi/\?page=\.\./",
        t("2015-09-02T09:31:00"), t("2015-09-02T09:43:00")),
    "G3 manual SQLi": (
        None, r"^/dvwa/vulnerabilities/sqli/\?id=a%27",
        t("2015-09-02T10:49:53"), t("2015-09-02T10:49:53")),
    "G4 sqlmap + tmp shell 09-02": (
        None, r"^/(dvwa/vulnerabilities/sqli/|tmp\w+\.php)",
        t("2015-09-02T11:15:40"), t("2015-09-02T11:26:30")),
    "G5 sqlmap + tmp shell 09-03": (
        None, r"^/(dvwa/vulnerabilities/sqli/|tmp\w+\.php)",
        t("2015-09-03T06:50:00"), t("2015-09-03T06:55:00")),
    "G6 phpshell.php": (
        None, r"^/dvwa/(vulnerabilities/upload/|hackable/uploads/phpshell\.php)",
        t("2015-09-03T07:10:15"), t("2015-09-03T07:10:15")),
    "G7 zip / webshell / c99": (
        None, r"^/dvwa/(c99\.php|webshells?\b|hackable/uploads/phpshell\.php)",
        t("2015-09-03T07:14:48"), t("2015-09-03T07:21:28")),
    "G8 phpshell2.php": (
        None, r"^/dvwa/hackable/uploads/phpshell2\.php",
        t("2015-09-03T07:31:30"), t("2015-09-03T07:31:30")),
}
ATTACKER_FILES = {"DVWA/hackable/uploads/phpshell.php", "DVWA/hackable/uploads/phpshell2.php",
                  "DVWA/webshells.zip", "DVWA/webshell.php", "DVWA/c99.php"}
CODE_OK = {("DVWA/vulnerabilities/sqli/source/low.php", 9),
           ("DVWA/vulnerabilities/sqli/source/medium.php", 10),
           ("DVWA/vulnerabilities/sqli/source/high.php", 13)}
ENTRY_POINTS = r"^/dvwa/vulnerabilities/(exec|fi|sqli|upload)/"
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

    print("\nEvents")
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

    ips = set(res["iocs"]["ips"])
    print("\nIPs (IOC list)")
    print(f"  accused: {sorted(ips)}   other than attacker: {sorted(ips - {ATTACKER})}")
    others = sorted({e["actor"] for e in res["timeline"] if e.get("actor")} - {ATTACKER})
    print(f"  other clients appearing in timeline rows: {others}")

    print("\nRoot cause")
    rc = res["root_cause"]
    if rc is None:
        print("  none")
    else:
        event = next(e for e in res["timeline"] if e["event_id"] == rc["event_id"])
        cited = [parse(c["excerpt"]) for c in event["citations"] if c["kind"] == "log_line"]
        cited = [p for p in cited if p]
        g1 = EVENTS["G1 command injection"]
        strict = any(p[0] == ATTACKER and p[2] == "POST" and re.search(g1[1], p[3])
                     and abs(p[1] - g1[2]) <= WINDOW for p in cited)
        lenient = any(p[0] == ATTACKER and re.search(ENTRY_POINTS, p[3]) for p in cited)
        line = next((c["line_no"] for c in event["citations"] if c["kind"] == "log_line"), None)
        where = "-"
        if cited:
            method, path, when = cited[0][2], cited[0][3].split("?")[0], cited[0][1]
            where = f"{method} {path} at {when:%Y-%m-%d %H:%M:%S} UTC"
        print(f"  {where} (access.log:{line}, {rc['vuln_class']}, confidence {rc['confidence']})")
        print(f"  strict {'OK' if strict else 'WRONG'}   lenient {'OK' if lenient else 'WRONG'}")

    print("\nCode")
    found = {(c["file"], c["line"]) for c in report["code_findings"]}
    print(f"  findings: {sorted(found)}   accepted line hit: {bool(found & CODE_OK)}")
    scope = report["code_scope"] or {}
    print(f"  analyzed: {scope.get('analyzed')}   included: {scope.get('included', [])}")
    print(f"\nScripts seen only in the logs: {list(res.get('log_only_files', []))}")
    print(f"Deleted paths reported: {list(res['deleted_paths'])}")
    print(f"Gaps: {len(res['gaps'])}")


if __name__ == "__main__":
    main()
