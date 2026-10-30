"""Orchestrate the isolated s01 pilot from the repository host."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "lab" / "v2" / "docker-compose.yml"
ENV_FILE = ROOT / "lab" / "v2" / ".env"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
SCENARIO = "s01"


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE), *args],
        cwd=ROOT,
        env={**os.environ, "SCENARIO": SCENARIO},
        check=check,
        text=True,
    )


def wait_for_edge() -> None:
    for _ in range(90):
        probe = subprocess.run(
            [
                "docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE),
                "exec", "-T", "attacker",
                "python", "-c",
                "import socket; socket.create_connection(('edge', 80), timeout=1).close()",
            ],
            cwd=ROOT,
            env={**os.environ, "SCENARIO": SCENARIO},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(2)
    raise TimeoutError("edge did not become ready within 180 seconds")


def prepare_log_mounts() -> None:
    evidence = ROOT / "benchmark" / "v2" / SCENARIO / "evidence"
    for name in ("access.log", "error.log"):
        path = evidence / name
        if path.is_dir():
            if any(path.iterdir()):
                raise RuntimeError(f"refusing to replace nonempty log mount directory: {path}")
            path.rmdir()
        elif path.exists():
            if path.stat().st_size:
                raise RuntimeError(f"refusing to overwrite nonempty evidence log: {path}")
            path.unlink()
        path.touch()


def main() -> None:
    if not PYTHON.is_file():
        raise SystemExit("repository .venv is missing; run this with the project venv")
    run("config", "--quiet")
    prepare_log_mounts()
    run("build")
    run("up", "-d", "db", "wp", "edge", "attacker", "collector")
    wait_for_edge()

    run("exec", "-T", "wp", "php", "/opt/wp_bootstrap.php")
    run("exec", "-T", "attacker", "python", "/opt/scenarios/s01.py", "isolation")

    run(
        "exec", "-T", "wp", "bash", "-lc",
        "rm -rf /collector-work/baseline /collector-work/final && "
        "bash /opt/collect.sh -w /var/www/html -o /collector-work/baseline",
    )
    run(
        "exec", "-T", "collector", "python", "/opt/v2/collect.py",
        "--webroot", "/app-webroot", "--captured", "/collector-work/baseline",
        "--output", "/capture", "--scenario", SCENARIO,
    )

    run("exec", "-T", "attacker", "python", "/opt/scenarios/s01.py", "attack")
    run("stop", "edge")
    run(
        "exec", "-T", "wp", "bash", "-lc",
        "bash /opt/collect.sh -w /var/www/html -o /collector-work/final",
    )
    run(
        "exec", "-T", "collector", "python", "/opt/v2/collect.py",
        "--webroot", "/app-webroot", "--captured", "/collector-work/final",
        "--output", "/capture", "--scenario", SCENARIO,
        "--baseline-manifest", "/capture/baseline.tsv", "--records", "/replay/records.json",
    )

    evidence = ROOT / "benchmark" / "v2" / SCENARIO / "evidence"
    replay = ROOT / "benchmark" / "v2" / SCENARIO / "replay"
    labels = replay / "labels.log"
    ground_truth = ROOT / "benchmark" / "v2" / SCENARIO / "ground_truth.json"
    run_label = [
        str(PYTHON), str(ROOT / "lab" / "v2" / "label.py"),
        "--records", str(replay / "records.json"),
        "--evidence", str(evidence), "--labels", str(labels), "--output", str(ground_truth),
    ]
    subprocess.run(run_label, cwd=ROOT, check=True)
    subprocess.run(
        [str(PYTHON), str(ROOT / "lab" / "v2" / "validate_evidence.py"), str(evidence)],
        cwd=ROOT,
        check=True,
    )
    run("down")


if __name__ == "__main__":
    main()
