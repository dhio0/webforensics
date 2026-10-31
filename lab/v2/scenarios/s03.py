"""Prepare and execute the isolated phpMyFAQ SQL-injection scenario."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ATTACKER_IP = "192.0.2.131"


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
    Path("/replay/setup-complete.json").write_text(
        json.dumps(
            {
                "application": "phpMyFAQ 3.2.5",
                "database": "PostgreSQL",
                "admin_created": True,
                "setup_response": install.status_code,
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
    for _ in range(2400):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded attack point")
    raise NotImplementedError("attack capture is being completed")


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
