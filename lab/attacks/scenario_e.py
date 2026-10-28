"""Replay fixed Scenario E upload and simulated timestomp on the loopback edge."""

import subprocess
import time
import urllib.request

from common import (
    ROOT,
    STEP_DELAY_SECONDS,
    collect_baseline,
    lab_request,
    multipart_file,
    start_fresh_lab,
)

UA = "webforensics-lab/1.0 scenario-e"
ATTACKER = "192.0.2.31"
MARKER = b"LAB-FORENSICS-MARKER-E-v1\n"


def run() -> None:
    start_fresh_lab()
    collect_baseline("e")
    opener = urllib.request.build_opener()

    benign = (
        ("/", "198.51.100.31"),
        ("/product.php?id=1", "203.0.113.31"),
        ("/admin/login.php", "198.51.100.32"),
    )
    for path, ip in benign:
        lab_request(opener, path, ip, user_agent=UA)
        time.sleep(STEP_DELAY_SECONDS)

    body, content_type = multipart_file(
        "file",
        "scenario-e-marker.php",
        MARKER,
        "application/octet-stream",
        boundary="----webforensics-lab-scenario-e",
    )
    result = lab_request(
        opener,
        "/admin/upload.php",
        ATTACKER,
        user_agent=UA,
        data=body,
        content_type=content_type,
    )
    if b"/uploads/scenario-e-marker.php" not in result:
        raise RuntimeError("upload response did not confirm marker path")
    time.sleep(STEP_DELAY_SECONDS)

    if (
        lab_request(
            opener,
            "/uploads/scenario-e-marker.php",
            ATTACKER,
            user_agent=UA,
        )
        != MARKER
    ):
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
    lab_request(opener, "/", "203.0.113.32", user_agent=UA)
    time.sleep(STEP_DELAY_SECONDS)
    lab_request(opener, "/product.php?id=2", "198.51.100.33", user_agent=UA)
    print("Scenario E replay complete; timestomp was simulated outside HTTP.")


if __name__ == "__main__":
    run()
