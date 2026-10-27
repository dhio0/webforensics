"""Collect Scenario A's webroot manifest and bind-mounted nginx access log."""

import shutil
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "lab" / "docker-compose.yml"
EVIDENCE = ROOT / "benchmark" / "scenarios" / "a" / "evidence"


def main() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    collection_id = f"webforensics-scenario-a-{uuid.uuid4().hex}"
    container_output = f"/tmp/{collection_id}"
    subprocess.run(
        [
            "docker", "compose", "-f", str(COMPOSE), "exec", "-T", "php",
            "bash", "/opt/collect.sh", "-w", "/var/www/html", "-o", container_output,
            "-l", "/var/log/nginx/access.log",
        ],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        [
            "docker", "compose", "-f", str(COMPOSE), "cp",
            f"php:{container_output}/manifest.tsv", str(EVIDENCE / "manifest.tsv"),
        ],
        check=True,
        cwd=ROOT,
    )

    access_log = ROOT / "lab" / "logs" / "access.log"
    if not access_log.is_file():
        raise FileNotFoundError(f"nginx access log not found: {access_log}")
    shutil.copy2(access_log, EVIDENCE / "access.log")
    print(f"Scenario A evidence collected into {EVIDENCE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
