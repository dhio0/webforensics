"""Replay fixed Scenario E upload and simulated timestomp on the loopback edge."""

import subprocess
import time
import urllib.error
import urllib.request

from common import ROOT, STEP_DELAY_SECONDS, collect_baseline, start_fresh_lab

BASE = "http://127.0.0.1:8081"
UA = "webforensics-lab/1.0 scenario-e"
ATTACKER = "192.0.2.31"
MARKER = b"LAB-FORENSICS-MARKER-E-v1\n"


def request(path, ip, *, data=None, content_type=None):
    headers = {"User-Agent": UA, "X-Lab-Client-IP": ip}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"localhost lab request failed for {path}: {exc}") from exc


def run():
    start_fresh_lab()
    collect_baseline("e")
    benign = ("198.51.100.31", "203.0.113.31", "198.51.100.32")
    for index, ip in enumerate(benign):
        request(("/", "/product.php?id=1", "/admin/login.php")[index], ip)
        time.sleep(STEP_DELAY_SECONDS)

    boundary = "----webforensics-lab-scenario-e"
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            'filename="scenario-e-marker.php"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + MARKER
        + f"\r\n--{boundary}--\r\n".encode()
    )
    result = request(
        "/admin/upload.php",
        ATTACKER,
        data=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    if b"/uploads/scenario-e-marker.php" not in result:
        raise RuntimeError("upload response did not confirm marker path")
    time.sleep(STEP_DELAY_SECONDS)
    if request("/uploads/scenario-e-marker.php", ATTACKER) != MARKER:
        raise RuntimeError("marker request did not return expected inert text")
    time.sleep(STEP_DELAY_SECONDS)

    # Simulate anti-forensics in the container, not through an HTTP request.
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(ROOT / "lab" / "docker-compose.yml"),
            "exec",
            "-T",
            "php",
            "touch",
            "-d",
            "2024-01-15 03:00:00",
            "/var/www/html/uploads/scenario-e-marker.php",
        ],
        check=True,
        cwd=ROOT,
    )
    time.sleep(STEP_DELAY_SECONDS)
    for path, ip in (("/", "203.0.113.32"), ("/product.php?id=2", "198.51.100.33")):
        request(path, ip)
        time.sleep(STEP_DELAY_SECONDS)
    print("Scenario E replay complete; timestomp was simulated outside HTTP.")


if __name__ == "__main__":
    run()
