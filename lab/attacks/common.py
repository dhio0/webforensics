"""Small helpers shared by the fixed, localhost-only scenario replays."""

import subprocess
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
    compose(
        "exec", "-T", "nginx", "sh", "-c",
        "truncate -s 0 /var/log/nginx/access.log && nginx -s reopen",
    )
