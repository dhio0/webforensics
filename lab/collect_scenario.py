"""Collect a selected scenario's webroot manifest and nginx logs."""

import argparse
import shutil
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "lab" / "docker-compose.yml"


def _collect_manifest(container_output: str, destination: Path) -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "exec",
            "-T",
            "php",
            "bash",
            "/opt/collect.sh",
            "-w",
            "/var/www/html",
            "-o",
            container_output,
        ],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE),
            "cp",
            f"php:{container_output}/manifest.tsv",
            str(destination),
        ],
        check=True,
        cwd=ROOT,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("a", "b", "d", "e", "f"), default="a")
    parser.add_argument("--baseline-only", action="store_true")
    args = parser.parse_args()
    evidence = ROOT / "benchmark" / "scenarios" / args.scenario / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    collection_id = f"webforensics-scenario-{args.scenario}-{uuid.uuid4().hex}"
    container_output = f"/tmp/{collection_id}"
    manifest_name = "baseline.tsv" if args.baseline_only else "manifest.tsv"
    _collect_manifest(container_output, evidence / manifest_name)

    if args.baseline_only:
        print(
            f"Scenario {args.scenario.upper()} baseline collected into {evidence / manifest_name}"
        )
        return

    access_log = ROOT / "lab" / "logs" / "access.log"
    if not access_log.is_file():
        raise FileNotFoundError(f"nginx access log not found: {access_log}")
    shutil.copy2(access_log, evidence / "access.log")
    error_log = ROOT / "lab" / "logs" / "error.log"
    if error_log.is_file():
        shutil.copy2(error_log, evidence / "error.log")
    print(f"Scenario {args.scenario.upper()} evidence collected into {evidence.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
