"""Run an attack independently of the host session and publish only its exit status."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

replay = Path("/replay")
try:
    with Path("/tmp/attack-output.txt").open("w") as output:
        result = subprocess.run(
            [sys.executable, sys.argv[1], sys.argv[2]],
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    status = {"exit_code": result.returncode, "ended_at_utc": datetime.now(UTC).isoformat()}
    name = "attack.done" if result.returncode == 0 else "attack-error.json"
    (replay / name).write_text(json.dumps(status) + "\n", encoding="utf-8")
except BaseException as exc:
    (replay / "attack-error.json").write_text(
        json.dumps({"error_type": type(exc).__name__}) + "\n", encoding="utf-8"
    )
    raise
