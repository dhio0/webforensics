"""Record a no-compromise WordPress SQLi and scanner pass for held-out s11."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"


def isolation() -> None:
    from background import target_url

    try:
        target_url("/", "outside-lab")
    except ValueError:
        print("non_allowlisted_service_refused=PASS")
    else:
        raise SystemExit("non_allowlisted_service_refused=FAIL")
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            raise SystemExit("external_address_unreachable=FAIL")
    except OSError:
        print("external_address_unreachable=PASS")


def scan() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(2400):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded pause")

    headers = {"X-Lab-Client-IP": ATTACKER_IP, "User-Agent": "M8-v2-s11-scan"}
    paths = (
        "/wp-login.php",
        "/wp-admin/",
        "/xmlrpc.php",
        "/wp-json/wp/v2/users",
        "/wp-content/plugins/",
        "/.env",
        "/phpmyadmin/",
        "/administrator/",
    )
    session = requests.Session()
    scanner_results = []
    steps = []
    for index, path in enumerate(paths, start=1):
        step_id = f"scanner_probe_{index}"
        response = session.get(
            f"{EDGE}{path}",
            headers={**headers, "X-Lab-Step": step_id},
            timeout=15,
            allow_redirects=False,
        )
        scanner_results.append({"path": path, "status": response.status_code})
        steps.append(
            {
                "id": step_id,
                "category": "scanner_probe",
                "mitre": ["T1595"],
                "label_method": "header",
                "expected_in_timeline": False,
            }
        )

    result = subprocess.run(
        [
            "python",
            "/opt/sqlmap/sqlmap.py",
            "-u",
            f"{EDGE}/?s=m8v2-heldout-search",
            "--batch",
            "--level=1",
            "--risk=1",
            "--technique=BEUSTQ",
            "--threads=1",
            "--retries=0",
            "--timeout=2",
            "--time-sec=1",
            "--flush-session",
            "--headers",
            f"X-Lab-Client-IP: {ATTACKER_IP}\nUser-Agent: M8-v2-s11-sqlmap",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=150,
        check=False,
    )
    output = result.stdout.lower()
    detected = "is vulnerable" in output or "parameter 's' appears to be" in output
    if detected:
        raise RuntimeError("s11 unexpectedly detected an injectable parameter")

    records = {
        "scenario_id": "s11",
        "description": (
            "A pinned sqlmap run and a short scanner pass probe the isolated WordPress site. "
            "No injectable parameter or compromise is found; no files are changed."
        ),
        "attacker_ips": [],
        "root_cause_step": None,
        "steps": steps,
        "files": [
            {
                "path": "/wp-content/uploads/wp-file-manager-pro/fm_backup/index.php",
                "role": "side_effect",
                "expected_in_report": False,
            }
        ],
        "analysis": {
            "access_logs": ["access.log.gz"],
            "error_logs": ["app-error.log"],
            "error_log_format": "apache",
            "error_log_utc_offset": "+0000",
            "manifest": "manifest.tsv",
            "baseline": "baseline.tsv",
            "trusted_proxies": [],
        },
        "split": "heldout",
        "expected_rule_ids": [],
    }
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    Path("/replay/s11-scan.json").write_text(
        json.dumps(
            {
                "sqlmap_commit": "c42ebd7acf47c88b6407995dd9842a2eb5d6534d",
                "sqlmap_exit_code": result.returncode,
                "scanner_results": scanner_results,
                "injection_detected": detected,
                "output_summary": [
                    line.strip() for line in result.stdout.splitlines() if "tested" in line.lower()
                ][-10:],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    continuation.write_text("continue\n", encoding="ascii")
    print(json.dumps({"sqlmap_exit_code": result.returncode, "compromise": False}))


if __name__ == "__main__":
    {"isolation": isolation, "scan": scan}[sys.argv[1]]()
