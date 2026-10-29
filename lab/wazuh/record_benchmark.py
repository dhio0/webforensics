"""Re-record one benchmark scenario with Wazuh on: file evidence and a Wazuh recording from
the same replay, so both adapters are scored against the same ground truth.

    python lab/wazuh/setup.py up
    python lab/wazuh/record_benchmark.py a        # or b, d, e, f

Writes benchmark/scenarios/<id>/evidence/{access.log, error.log, manifest.tsv,
baseline.tsv (D, E)} and evidence/wazuh/recording.jsonl, then prints every ground-truth
step next to the line it points at, for review. Update ground_truth.json by hand if a line
moved (the replays are scripted, but concurrent requests in D can swap places).
"""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "lab" / "wazuh"
CA = HERE / ".upstream/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem"
LOCATIONS = {"access.log": "/var/log/nginx/access.log", "error.log": "/var/log/nginx/error.log"}


def _env(key: str) -> str:
    for line in (HERE / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip().strip('"')
    raise KeyError(key)


def record(scenario: str) -> None:
    folder = ROOT / "benchmark" / "scenarios" / scenario
    truth = json.loads((folder / "ground_truth.json").read_text(encoding="utf-8"))
    spec = truth.get("analysis", {})
    access = spec.get("access_logs", ["access.log"])
    errors = spec.get("error_logs", [])
    evidence = folder / "evidence"

    since = datetime.now(UTC)
    subprocess.run([sys.executable, str(ROOT / f"lab/attacks/scenario_{scenario}.py")],
                   check=True, cwd=ROOT, env={**os.environ, "WF_LAB_WAZUH": "1"})
    subprocess.run([sys.executable, str(ROOT / "lab/collect_scenario.py"),
                    "--scenario", scenario], check=True, cwd=ROOT)
    if not errors:  # this scenario's analysis does not use the error log
        (evidence / "error.log").unlink(missing_ok=True)

    (evidence / "wazuh").mkdir(exist_ok=True)
    args = ["pull", "--indexer", "https://127.0.0.1:9200", "--ca-cert", str(CA),
            "--tls-server-name", "wazuh.indexer", "--agent", "wf-lab-agent",
            "--since", since.isoformat(),
            "--until", (datetime.now(UTC) + timedelta(seconds=5)).isoformat(),
            "--docroot", "/var/www/html", "--out", str(evidence / "wazuh" / "recording.jsonl")]
    args += [a for name in access for a in ("--access-log", LOCATIONS[name])]
    args += [a for name in errors for a in ("--error-log", LOCATIONS[name])]
    cli = "from webforensics.cli import app; app()"
    subprocess.run([sys.executable, "-c", cli, *args], check=True, cwd=ROOT,
                   env={**os.environ, "WF_WAZUH_USER": "webforensics_reader",
                        "WF_WAZUH_PASSWORD": _env("WAZUH_READER_PASSWORD")})

    lines = {name: (evidence / name).read_text(encoding="utf-8").splitlines()
             for name in {s["log_file"] for s in truth["steps"]}}
    for step in truth["steps"]:
        text = lines[step["log_file"]][step["line_no"] - 1]
        print(f"{step['id']:<34} {step['log_file']}:{step['line_no']:<3} {text[:110]}")


if __name__ == "__main__":
    record(sys.argv[1])
