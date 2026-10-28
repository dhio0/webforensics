"""Small helpers shared by the fixed, localhost-only scenario replays."""

import subprocess
import sys
import time
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "lab" / "docker-compose.yml"
STEP_DELAY_SECONDS = 2


def compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), *args],
        check=True,
        cwd=ROOT,
    )


def _mysql_ready() -> bool:
    result = subprocess.run(
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
    return result.returncode == 0


def start_fresh_lab() -> None:
    """Remove this compose project's volumes, then start an empty lab state."""
    compose("down", "-v")
    compose("up", "-d", "--build")
    # MySQL's ping healthcheck can pass while initialization is still completing.
    for attempt in range(30):
        if _mysql_ready():
            break
        if attempt < 29:
            time.sleep(1)
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


def lab_request(
    opener: request.OpenerDirector,
    path: str,
    client_ip: str,
    *,
    user_agent: str,
    data: bytes | None = None,
    content_type: str | None = None,
    status: int = 200,
) -> bytes:
    """Send one scripted request through the loopback edge and check its status."""
    headers = {"User-Agent": user_agent, "X-Lab-Client-IP": client_ip}
    if content_type:
        headers["Content-Type"] = content_type
    req = request.Request(f"http://127.0.0.1:8081{path}", data=data, headers=headers)
    try:
        with opener.open(req, timeout=10) as response:
            actual_status = response.status
            body = response.read()
    except error.HTTPError as response:
        actual_status = response.code
        body = response.read()
    except error.URLError as exc:
        raise RuntimeError(f"localhost lab request failed for {path}: {exc}") from exc
    if actual_status != status:
        raise RuntimeError(
            f"expected HTTP {status}, received {actual_status} for localhost lab request {path}"
        )
    return body


def multipart_file(
    field: str,
    filename: str,
    content: bytes,
    content_type: str,
    *,
    boundary: str = "----webforensics-lab-multipart",
) -> tuple[bytes, str]:
    """Build one deterministic multipart file request body and its header value."""
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
    ).encode()
    body += content + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


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
