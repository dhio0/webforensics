"""Small helpers shared by the fixed, localhost-only scenario replays."""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "lab" / "docker-compose.yml"
STEP_DELAY_SECONDS = 2


def compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), *args],
        check=True,
        cwd=ROOT,
    )


def start_fresh_lab() -> None:
    """Remove this compose project's volumes, then start an empty lab state."""
    compose("down", "-v")
    compose("up", "-d", "--build")
    # MySQL's ping healthcheck can pass while initialization is still completing.
    probe = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "exec",
            "-T",
            "php",
            "php",
            "-r",
            "$p=new PDO('mysql:host=mysql;dbname=lab','lab','lab-only-password');",
        ],
        cwd=ROOT,
        capture_output=True,
    )
    for _ in range(30):
        if probe.returncode == 0:
            break
        time.sleep(1)
        probe = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE),
                "exec",
                "-T",
                "php",
                "php",
                "-r",
                "$p=new PDO('mysql:host=mysql;dbname=lab','lab','lab-only-password');",
            ],
            cwd=ROOT,
            capture_output=True,
        )
    else:
        raise RuntimeError("lab MySQL did not become ready for PHP requests")
    compose(
        "exec",
        "-T",
        "nginx",
        "sh",
        "-c",
        "truncate -s 0 /var/log/nginx/access.log /var/log/nginx/error.log && nginx -s reopen",
    )


def collect_baseline(scenario: str) -> None:
    """Save the pristine webroot manifest before a scenario sends any requests."""
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "lab" / "collect_scenario.py"),
            "--scenario",
            scenario,
            "--baseline-only",
        ],
        check=True,
        cwd=ROOT,
    )
