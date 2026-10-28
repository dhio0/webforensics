"""Replay fixed busy-site Scenario D traffic on the loopback edge."""

import http.cookiejar
import time
import urllib.parse
import urllib.request

from common import (
    STEP_DELAY_SECONDS,
    collect_baseline,
    lab_request,
    multipart_file,
    start_fresh_lab,
)

UA = "webforensics-lab/1.0 scenario-d"


def run() -> None:
    start_fresh_lab()
    collect_baseline("d")

    # Ten ordinary visitors browse two fixed pages each.
    visitors = (
        ("198.51.100.10", "/", "/product.php?id=1"),
        ("198.51.100.11", "/", "/product.php?id=2"),
        ("198.51.100.12", "/admin/login.php", "/product.php?id=1"),
        ("198.51.100.13", "/", "/admin/login.php"),
        ("198.51.100.14", "/product.php?id=2", "/"),
        ("198.51.100.15", "/", "/product.php?id=1"),
        ("198.51.100.16", "/admin/login.php", "/product.php?id=2"),
        ("198.51.100.17", "/", "/product.php?id=2"),
        ("198.51.100.18", "/product.php?id=1", "/admin/login.php"),
        ("198.51.100.19", "/", "/product.php?id=1"),
    )
    for ip, first_page, second_page in visitors:
        opener = urllib.request.build_opener()
        lab_request(opener, first_page, ip, user_agent=UA)
        lab_request(opener, second_page, ip, user_agent=UA)
    time.sleep(STEP_DELAY_SECONDS)

    # Two independent scripted bots: two GET SQLi probes apiece and F's GET login bypass.
    bot_one = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    lab_request(bot_one, "/product.php?id=1+OR+1%3D1", "192.0.2.21", user_agent=UA)
    time.sleep(STEP_DELAY_SECONDS)
    lab_request(
        bot_one,
        "/product.php?id=1+UNION+SELECT+1%2C2",
        "192.0.2.21",
        user_agent=UA,
    )
    time.sleep(STEP_DELAY_SECONDS)
    lab_request(
        bot_one,
        "/admin/login.php?"
        + urllib.parse.urlencode({"username": "admin' OR '1'='1' -- ", "password": ""}),
        "192.0.2.21",
        user_agent=UA,
    )
    time.sleep(STEP_DELAY_SECONDS)

    bot_two = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    lab_request(bot_two, "/product.php?id=1+OR+1%3D1", "203.0.113.21", user_agent=UA)
    time.sleep(STEP_DELAY_SECONDS)
    lab_request(
        bot_two,
        "/product.php?id=1+UNION+SELECT+1%2C2",
        "203.0.113.21",
        user_agent=UA,
    )
    time.sleep(STEP_DELAY_SECONDS)
    lab_request(
        bot_two,
        "/admin/login.php?"
        + urllib.parse.urlencode({"username": "admin' OR '1'='1' -- ", "password": ""}),
        "203.0.113.21",
        user_agent=UA,
    )
    time.sleep(STEP_DELAY_SECONDS)

    # A real administrator signs in by POST, then uploads a valid 1x1 transparent PNG.
    admin = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    admin_login = lab_request(
        admin,
        "/admin/login.php",
        "198.51.100.50",
        user_agent=UA,
        data=urllib.parse.urlencode(
            {"username": "admin", "password": "lab-only-password"}
        ).encode(),
        content_type="application/x-www-form-urlencoded",
    )
    if b"Login successful" not in admin_login:
        raise RuntimeError("normal POST administrator login did not succeed")
    time.sleep(STEP_DELAY_SECONDS)

    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000b49444154789c636000020000050001a5f645400000000049454e44ae426082"
    )
    body, content_type = multipart_file(
        "file",
        "admin-small.png",
        png,
        "image/png",
        boundary="----webforensics-lab-scenario-d",
    )
    lab_request(
        admin,
        "/admin/auth_upload.php",
        "198.51.100.50",
        user_agent=UA,
        data=body,
        content_type=content_type,
    )
    time.sleep(STEP_DELAY_SECONDS)

    visitor = urllib.request.build_opener()
    lab_request(
        visitor,
        "/comment.php",
        "203.0.113.60",
        user_agent=UA,
        data=b"page=1&comment=Nice+site",
        content_type="application/x-www-form-urlencoded",
    )
    time.sleep(STEP_DELAY_SECONDS)

    crawler = urllib.request.build_opener()
    lab_request(crawler, "/", "198.51.100.70", user_agent=UA)
    lab_request(crawler, "/product.php?id=1", "198.51.100.70", user_agent=UA)
    lab_request(crawler, "/product.php?id=2", "198.51.100.70", user_agent=UA)
    print("Scenario D replay complete: busy benign traffic and non-compromising probes.")


if __name__ == "__main__":
    run()
