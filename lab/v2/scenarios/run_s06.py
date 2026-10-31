"""Record the isolated DVWA s06 scenario."""

from __future__ import annotations

import gzip
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "lab" / "v2" / "docker-compose.yml"
ENV_FILE = ROOT / "lab" / "v2" / ".env"
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
SCENARIO = "s06"
ATTACK_SEED = 5206


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE), *args],
        cwd=ROOT,
        env={
            **os.environ,
            "SCENARIO": SCENARIO,
            "APP_DATA_VOLUME": "dvwadata",
            "APP_UPSTREAM": "dvwa:80",
        },
        check=check,
        text=True,
    )


def wait_for_edge() -> None:
    for _ in range(90):
        probe = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                str(ENV_FILE),
                "-f",
                str(COMPOSE_FILE),
                "exec",
                "-T",
                "attacker",
                "python",
                "-c",
                "import socket; socket.create_connection(('edge', 80), timeout=1).close()",
            ],
            cwd=ROOT,
            env={
                **os.environ,
                "SCENARIO": SCENARIO,
                "APP_DATA_VOLUME": "dvwadata",
                "APP_UPSTREAM": "dvwa:80",
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(2)
    raise TimeoutError("edge did not become ready within 180 seconds")


def prepare_mounts() -> None:
    evidence = ROOT / "benchmark" / "v2" / SCENARIO / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    for item in evidence.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    access_log = evidence / "access.log"
    access_log.touch()


def docker_log(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ENV_FILE),
            "-f",
            str(COMPOSE_FILE),
            *args,
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "SCENARIO": SCENARIO,
            "APP_DATA_VOLUME": "dvwadata",
            "APP_UPSTREAM": "dvwa:80",
        },
        check=True,
        text=True,
        capture_output=True,
    )


def main() -> None:
    if not PYTHON.is_file():
        raise SystemExit("repository .venv is missing; run this with the project venv")
    run("down", "--volumes")
    run("config", "--quiet")
    prepare_mounts()
    replay = ROOT / "benchmark" / "v2" / SCENARIO / "replay"
    replay.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(PYTHON),
            str(ROOT / "lab" / "v2" / "prepare_zenodo_background.py"),
            "--zenodo-zip",
            str(ROOT / "lab" / "v2" / ".cache" / "zenodo-20001206-organization-x.zip"),
            "--nasa-log",
            str(ROOT / "lab" / "v2" / ".cache" / "NASA_access_log_Jul95.gz"),
            "--output",
            str(replay / "source-background.log.gz"),
            "--report",
            str(replay / "source-preparation.json"),
            "--limit",
            "15000",
        ],
        cwd=ROOT,
        check=True,
    )
    prepared_log = replay / "background.log.gz"
    if prepared_log.is_dir():
        if any(prepared_log.iterdir()):
            raise RuntimeError(f"refusing nonempty background log directory: {prepared_log}")
        prepared_log.rmdir()
    elif prepared_log.exists():
        prepared_log.unlink()
    for name in (
        "labels.log",
        "background-halfway",
        "background-continue",
        "background.done",
        "background-error.json",
        "background-plan.json",
        "background-run.json",
        "records.json",
        "setup-complete.json",
        "sqlmap-result.json",
        "commix-result.json",
        "self-check.txt",
        "defender-scan.txt",
    ):
        (replay / name).unlink(missing_ok=True)

    run("build", "dvwa", "attacker", "collector")
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", "m8v2-dvwa:a1978a2", "--format", "{{.Id}}"],
        text=True,
    ).strip()
    (replay / "restore.json").write_text(
        json.dumps(
            {
                "application": "DVWA",
                "app_type": "dvwa",
                "image": image_id,
                "webroot": "/var/www/html",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    run("up", "-d", "db", "dvwa", "edge", "attacker", "background", "collector")
    wait_for_edge()
    isolation = docker_log(
        "exec", "-T", "attacker", "python", "/opt/scenarios/s06.py", "isolation"
    )
    (replay / "isolation-test.txt").write_text(isolation.stdout, encoding="utf-8")
    run("exec", "-T", "attacker", "python", "/opt/scenarios/s05.py", "setup")
    run(
        "exec",
        "-T",
        "attacker",
        "python",
        "/opt/crawl_app.py",
        "--base",
        "http://dvwa",
        "/replay/app_urls.txt",
    )
    subprocess.run(
        [
            str(PYTHON),
            str(ROOT / "lab" / "v2" / "prepare_background.py"),
            "--source",
            str(replay / "source-background.log.gz"),
            "--urls",
            str(replay / "app_urls.txt"),
            "--output",
            str(replay / "background.log.gz"),
            "--report",
            str(replay / "background-plan.json"),
            "--classes",
            str(replay / "classification.tsv"),
            "--limit",
            "15000",
        ],
        cwd=ROOT,
        check=True,
    )

    run(
        "exec",
        "-T",
        "dvwa",
        "bash",
        "-lc",
        "rm -f /var/www/html/config/config.inc.php.bak && "
        "rm -rf /collector-work/baseline /collector-work/final && "
        "bash /opt/collect.sh -w /var/www/html -o /collector-work/baseline",
    )
    run(
        "exec",
        "-T",
        "collector",
        "python",
        "/opt/v2/collect.py",
        "--webroot",
        "/app-webroot",
        "--captured",
        "/collector-work/baseline",
        "--output",
        "/capture",
        "--scenario",
        SCENARIO,
    )
    run(
        "exec",
        "-T",
        "edge",
        "sh",
        "-c",
        "truncate -s 0 /var/log/v2/access.log /var/log/v2/replay/labels.log",
    )

    attack_fraction = random.Random(ATTACK_SEED).randint(30, 70) / 100
    run(
        "exec",
        "-d",
        "background",
        "python",
        "/opt/v2/background.py",
        "--source",
        "/replay/background.log.gz",
        "--service",
        "dvwa",
        "--pace",
        "0.001",
        "--limit",
        "15000",
        "--seed",
        str(ATTACK_SEED),
        "--ip-map",
        "/replay/ip_map.tsv",
        "--records",
        "/replay/background-run.json",
        "--pause-at",
        str(attack_fraction),
        "--ready-file",
        "/replay/background-halfway",
        "--continue-file",
        "/replay/background-continue",
    )
    run("exec", "-T", "attacker", "python", "/opt/scenarios/s06.py", "attack")
    for _ in range(1200):
        if (replay / "background.done").is_file():
            break
        error_file = replay / "background-error.json"
        if error_file.is_file():
            failure = json.loads(error_file.read_text(encoding="utf-8"))
            raise RuntimeError(
                f"background replay failed ({failure['error_type']}) after "
                f"source line {failure['last_source_line']}"
            )
        time.sleep(0.5)
    else:
        raise TimeoutError("background replay did not finish within ten minutes")

    plan = json.loads((replay / "background-plan.json").read_text(encoding="utf-8"))
    run_data = json.loads((replay / "background-run.json").read_text(encoding="utf-8"))
    plan["replay"] = run_data
    plan["attack_start_seed"] = ATTACK_SEED
    plan["attack_start_fraction"] = attack_fraction
    mapped_addresses = {
        row.split("\t")[1]
        for row in (replay / "ip_map.tsv").read_text(encoding="utf-8").splitlines()[2:]
    }
    sys.path.insert(0, str(ROOT / "lab" / "v2"))
    from background import parse_line

    access_path = ROOT / "benchmark" / "v2" / SCENARIO / "evidence" / "access.log"
    access_rows = [
        line
        for line in access_path.read_text(encoding="utf-8").splitlines()
        if line.split(" ", 1)[0] in mapped_addresses
    ]
    status_mix: dict[str, dict[str, int]] = {group: {} for group in ("visitor", "scanner")}
    with gzip.open(replay / "background.log.gz", "rt", encoding="utf-8") as source:
        for source_line, access_line in zip(source, access_rows, strict=True):
            item = parse_line(source_line, "Mozilla/5.0 background browser")
            match = re.search(r'"[A-Z]+ [^ ]+ HTTP/[0-9.]+" (\d{3}) ', access_line)
            if item is None or match is None:
                raise RuntimeError("background source/access row could not be classified")
            group = "scanner" if item["status"] == "404" or re.search(
                r"bot|crawler|spider|scanner|sqlmap|nikto|nmap|gobuster|dirb|uptime|hetrix",
                item["ua"],
                re.I,
            ) else "visitor"
            code = match.group(1)
            status_mix[group][code] = status_mix[group].get(code, 0) + 1
    plan["status_mix"] = status_mix
    plan["source_preparation"] = json.loads(
        (replay / "source-preparation.json").read_text(encoding="utf-8")
    )
    (replay / "background.json").write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    run("stop", "edge")
    run(
        "exec",
        "-T",
        "dvwa",
        "bash",
        "-lc",
        "bash /opt/collect.sh -w /var/www/html -o /collector-work/final",
    )
    run(
        "exec",
        "-T",
        "collector",
        "python",
        "/opt/v2/collect.py",
        "--webroot",
        "/app-webroot",
        "--captured",
        "/collector-work/final",
        "--output",
        "/capture",
        "--scenario",
        SCENARIO,
        "--baseline-manifest",
        "/capture/baseline.tsv",
        "--records",
        "/replay/records.json",
    )
    evidence = ROOT / "benchmark" / "v2" / SCENARIO / "evidence"
    logs = docker_log("logs", "--no-color", "--no-log-prefix", "dvwa").stdout.splitlines()
    apache_errors = [
        line
        for line in logs
        if re.match(r"^\[[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} ", line) and "][" in line
    ]
    (evidence / "app-error.log").write_text(
        "\n".join(apache_errors) + ("\n" if apache_errors else ""),
        encoding="utf-8",
        newline="\n",
    )
    access_path = evidence / "access.log"
    with (
        access_path.open("rb") as source,
        (evidence / "access.log.gz").open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as packed,
    ):
        packed.writelines(source)
    access_path.unlink()
    labels = replay / "labels.log"
    with (
        labels.open("rb") as source,
        (replay / "labels.log.gz").open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as packed,
    ):
        packed.writelines(source)
    labels.unlink()
    subprocess.run(
        [
            str(PYTHON),
            str(ROOT / "lab" / "v2" / "label.py"),
            "--records",
            str(replay / "records.json"),
            "--evidence",
            str(evidence),
            "--labels",
            str(replay / "labels.log.gz"),
            "--output",
            str(ROOT / "benchmark" / "v2" / SCENARIO / "ground_truth.json"),
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [str(PYTHON), str(ROOT / "lab" / "v2" / "validate_evidence.py"), str(evidence)],
        cwd=ROOT,
        check=True,
    )
    run("down")
    subprocess.run(
        [
            str(PYTHON),
            str(ROOT / "lab" / "v2" / "self_check.py"),
            SCENARIO,
            "--root",
            str(ROOT),
            "--output",
            str(replay / "self-check.txt"),
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / "lab" / "v2" / "defender_scan.ps1"),
            "-ScanPath",
            str(ROOT / "benchmark" / "v2" / SCENARIO),
            "-OutputPath",
            str(replay / "defender-scan.txt"),
        ],
        cwd=ROOT,
        check=True,
    )
    for name in (
        "background-halfway",
        "background-continue",
        "background.done",
        "background-error.json",
        "background-plan.json",
        "background-run.json",
    ):
        (replay / name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
