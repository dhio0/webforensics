"""Replay fixed busy-site Scenario D traffic on the loopback edge."""

import http.cookiejar
import time
import urllib.error
import urllib.parse
import urllib.request

from common import STEP_DELAY_SECONDS, collect_baseline, start_fresh_lab

BASE = "http://127.0.0.1:8081"
UA = "webforensics-lab/1.0 scenario-d"


def request(opener, path, ip, *, data=None, content_type=None, status=200):
    headers = {"User-Agent": UA, "X-Lab-Client-IP": ip}
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
    collect_baseline("d")

    # Ten ordinary visitors, each with a fixed documentation-range address.
    for i in range(10):
        opener = urllib.request.build_opener()
        page = ("/", "/product.php?id=1", "/product.php?id=2", "/admin/login.php")[i % 4]
        request(opener, page, f"198.51.100.{10 + i}")

    # Two independent scripted bots: two GET SQLi probes apiece and F's GET login bypass.
    bot_one = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    request(bot_one, "/product.php?id=1+OR+1%3D1", "192.0.2.21")
    time.sleep(STEP_DELAY_SECONDS)
    request(bot_one, "/product.php?id=1+UNION+SELECT+1%2C2", "192.0.2.21")
    time.sleep(STEP_DELAY_SECONDS)
    request(
        bot_one,
        "/admin/login.php?"
        + urllib.parse.urlencode({"username": "admin' OR '1'='1' -- ", "password": ""}),
        "192.0.2.21",
    )
    time.sleep(STEP_DELAY_SECONDS)

    bot_two = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    request(bot_two, "/product.php?id=1+OR+1%3D1", "203.0.113.21")
    time.sleep(STEP_DELAY_SECONDS)
    request(bot_two, "/product.php?id=1+UNION+SELECT+1%2C2", "203.0.113.21")
    time.sleep(STEP_DELAY_SECONDS)
    request(
        bot_two,
        "/admin/login.php?"
        + urllib.parse.urlencode({"username": "admin' OR '1'='1' -- ", "password": ""}),
        "203.0.113.21",
    )
    time.sleep(STEP_DELAY_SECONDS)

    # A real administrator uploads a few-byte, valid 1x1 transparent PNG.
    admin = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    request(
        admin,
        "/admin/login.php?"
        + urllib.parse.urlencode({"username": "admin", "password": "lab-only-password"}),
        "198.51.100.50",
    )
    time.sleep(STEP_DELAY_SECONDS)
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000b49444154789c636000020000050001a5f645400000000049454e44ae426082"
    )
    boundary = "----webforensics-lab-scenario-d"
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            'filename="admin-small.png"\r\n'
            "Content-Type: image/png\r\n\r\n"
        ).encode()
        + png
        + f"\r\n--{boundary}--\r\n".encode()
    )
    request(
        admin,
        "/admin/auth_upload.php",
        "198.51.100.50",
        data=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    time.sleep(STEP_DELAY_SECONDS)

    visitor = urllib.request.build_opener()
    request(
        visitor,
        "/comment.php",
        "203.0.113.60",
        data=b"page=1&comment=Nice+site",
        content_type="application/x-www-form-urlencoded",
    )
    time.sleep(STEP_DELAY_SECONDS)

    crawler = urllib.request.build_opener()
    request(crawler, "/", "198.51.100.70")
    request(crawler, "/product.php?id=1", "198.51.100.70")
    request(crawler, "/product.php?id=2", "198.51.100.70")
    print("Scenario D replay complete: benign site traffic and non-compromising probes.")


if __name__ == "__main__":
    run()
