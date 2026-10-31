"""Record the benign WordPress update, media, cache, and catch-all scenario."""

from __future__ import annotations

import argparse
import base64
import html.parser
import json
import os
import socket
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import requests

sys.path.insert(0, "/opt/v2")

EDGE = "http://edge"
ADMIN_USER = os.environ["BENCH_ADMIN_USER"]
ADMIN_PASSWORD = os.environ["BENCH_ADMIN_PASSWORD"]
PLUGIN_NAME = "m8v2-cache-fixture"
PLUGIN_FILE = f"{PLUGIN_NAME}/{PLUGIN_NAME}.php"
CACHE_PATH = "/wp-content/cache/m8v2-s12-page.php"


class UpdateLinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        if "overwrite=update-plugin" in unquote(href):
            self.links.append(href)


class WarmLinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        if "warm=1" in unquote(href) and "_wpnonce=" in unquote(href):
            self.links.append(href)


def isolate() -> None:
    from background import target_url

    try:
        target_url("/", "outside-lab")
    except ValueError:
        print("non_allowlisted_service_refused=PASS")
    else:
        raise SystemExit("non_allowlisted_service_refused=FAIL")
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            raise SystemExit("external_address_unreachable=FAIL")
    except OSError:
        print("external_address_unreachable=PASS")


def perform_benign_activity() -> None:
    ready = Path("/replay/background-halfway")
    continuation = Path("/replay/background-continue")
    for _ in range(2400):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        raise TimeoutError("background replay did not reach its seeded pause")

    records: dict[str, object] = {
        "scenario_id": "s12",
        "description": (
            "An administrator checks core updates, updates a local cache plugin, uploads "
            "media, and warms a benign PHP cache. A scanner receives a catch-all 200; "
            "there is no compromise."
        ),
        "attacker_ips": [],
        "root_cause_step": None,
        "steps": [],
        "files": [
            {
                "path": f"/wp-content/plugins/{PLUGIN_FILE}",
                "role": "benign_plugin_update",
                "expected_in_report": False,
            },
            {"path": CACHE_PATH, "role": "benign_cache_generated", "expected_in_report": False},
            {
                "path": "/wp-content/uploads/",
                "role": "benign_media_upload",
                "expected_in_report": False,
            },
            {
                "path": "/wp-content/uploads/wp-file-manager-pro/fm_backup/index.php",
                "role": "side_effect",
                "expected_in_report": False,
            },
        ],
        "analysis": {
            "access_logs": ["access.log.gz"],
            "error_logs": ["app-error.log"],
            "error_log_format": "apache",
            "error_log_utc_offset": "+0000",
            "manifest": "manifest.tsv",
            "baseline": "baseline.tsv",
            "trusted_proxies": [],
        },
        "split": "dev",
        "expected_rule_ids": [],
    }
    steps: list[dict[str, object]] = []
    session = requests.Session()
    session.get(f"{EDGE}/wp-login.php", headers={"X-Lab-Step": "admin_login_form"}, timeout=15)
    login = session.post(
        f"{EDGE}/wp-login.php",
        data={
            "log": ADMIN_USER,
            "pwd": ADMIN_PASSWORD,
            "wp-submit": "Log In",
            "redirect_to": f"{EDGE}/wp-admin/",
            "testcookie": "1",
        },
        headers={"X-Lab-Step": "admin_login"},
        timeout=15,
        allow_redirects=False,
    )
    if login.status_code != 302:
        raise RuntimeError(f"administrator login returned HTTP {login.status_code}")
    steps.extend(
        [
            {
                "id": "admin_login_form",
                "category": "benign_admin_activity",
                "mitre": [],
                "label_method": "header",
                "expected_in_timeline": False,
            },
            {
                "id": "admin_login",
                "category": "benign_admin_activity",
                "mitre": [],
                "label_method": "header",
                "expected_in_timeline": False,
            },
        ]
    )

    core_page = session.get(
        f"{EDGE}/wp-admin/update-core.php",
        headers={"X-Lab-Step": "core_update_check"},
        timeout=30,
    )
    if core_page.status_code != 200:
        raise RuntimeError(f"WordPress core update page returned HTTP {core_page.status_code}")
    steps.append(
        {
            "id": "core_update_check",
            "category": "benign_core_update_check",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )

    upload_page = session.get(
        f"{EDGE}/wp-admin/plugin-install.php?tab=upload",
        headers={"X-Lab-Step": "plugin_update_form"},
        timeout=15,
    )
    if upload_page.status_code != 200:
        raise RuntimeError(f"plugin update form returned HTTP {upload_page.status_code}")
    import re

    nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', upload_page.text)
    if nonce_match is None:
        raise RuntimeError("WordPress plugin upload form did not contain its nonce")
    steps.append(
        {
            "id": "plugin_update_form",
            "category": "benign_plugin_update",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )

    with tempfile.TemporaryDirectory(prefix="s12-plugin-update-") as temporary:
        package = Path(temporary) / "m8v2-cache-fixture-1.1.zip"
        plugin_source = Path("/opt/scenarios/fixtures/s12-cache-v1.1.php").read_bytes()
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(PLUGIN_FILE, plugin_source)
        with package.open("rb") as archive_file:
            upload = session.post(
                f"{EDGE}/wp-admin/update.php?action=upload-plugin",
                data={"_wpnonce": nonce_match.group(1), "install-plugin-submit": "Install Now"},
                files={"pluginzip": (package.name, archive_file, "application/zip")},
                headers={"X-Lab-Step": "plugin_update_package"},
                timeout=30,
                allow_redirects=False,
            )
    parser = UpdateLinkParser()
    parser.feed(upload.text)
    if upload.status_code != 200 or len(parser.links) != 1:
        raise RuntimeError("WordPress did not offer the local plugin update action")
    steps.append(
        {
            "id": "plugin_update_package",
            "category": "benign_plugin_update",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )
    updated = session.get(
        urljoin(f"{EDGE}/wp-admin/", parser.links[0]),
        headers={"X-Lab-Step": "plugin_update_apply"},
        timeout=30,
        allow_redirects=False,
    )
    if updated.status_code not in (200, 302):
        raise RuntimeError(f"local plugin update returned HTTP {updated.status_code}")
    steps.append(
        {
            "id": "plugin_update_apply",
            "category": "benign_plugin_update",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )

    cache_page = session.get(
        f"{EDGE}/wp-admin/tools.php?page=m8v2-cache-fixture",
        headers={"X-Lab-Step": "cache_warm_form"},
        timeout=15,
    )
    warm_parser = WarmLinkParser()
    warm_parser.feed(cache_page.text)
    if cache_page.status_code != 200 or len(warm_parser.links) != 1:
        raise RuntimeError("updated cache plugin did not provide a nonce-protected warm link")
    steps.append(
        {
            "id": "cache_warm_form",
            "category": "benign_cache_activity",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )
    warmed = session.get(
        urljoin(f"{EDGE}/wp-admin/", warm_parser.links[0]),
        headers={"X-Lab-Step": "cache_generation"},
        timeout=15,
    )
    if warmed.status_code != 200 or "Cache warmed" not in warmed.text:
        raise RuntimeError(f"cache warming returned HTTP {warmed.status_code}")
    steps.append(
        {
            "id": "cache_generation",
            "category": "benign_cache_activity",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )

    media_form = session.get(
        f"{EDGE}/wp-admin/media-new.php",
        headers={"X-Lab-Step": "media_upload_form"},
        timeout=15,
    )
    nonce_match = re.search(r'name="_wpnonce"\s+value="([^"]+)"', media_form.text)
    if nonce_match is None:
        raise RuntimeError("WordPress media form did not contain its upload nonce")
    steps.append(
        {
            "id": "media_upload_form",
            "category": "benign_media_upload",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/7WQAAAAASUVORK5CYII="
    )
    media = session.post(
        f"{EDGE}/wp-admin/async-upload.php",
        params={"action": "upload-attachment"},
        data={"_wpnonce": nonce_match.group(1), "post_id": "1", "type": "image"},
        headers={
            "X-Lab-Step": "media_upload",
        },
        files={"async-upload": ("m8v2-s12-admin-media.png", png, "image/png")},
        timeout=20,
    )
    if media.status_code != 200:
        detail = media.text[:500].replace("\n", " ")
        raise RuntimeError(
            f"benign media upload returned HTTP {media.status_code}: {detail}"
        )
    try:
        media_result = media.json()
        if not media_result.get("success"):
            raise ValueError("WordPress rejected the media upload")
        media_path = urlparse(media_result["data"]["url"]).path
    except (KeyError, TypeError, ValueError) as exc:
        detail = media.text[:500].replace("\n", " ")
        raise RuntimeError(f"could not confirm the benign media upload: {detail}") from exc
    records["files"][2]["path"] = media_path  # type: ignore[index]
    steps.append(
        {
            "id": "media_upload",
            "category": "benign_media_upload",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )

    scanner = session.get(
        f"{EDGE}/m8v2-s12-scanner-catchall-probe",
        headers={
            "X-Lab-Step": "scanner_catchall_probe",
            "User-Agent": "M8v2Scanner/1.0",
        },
        timeout=15,
    )
    if scanner.status_code != 200:
        raise RuntimeError(f"WordPress catch-all probe returned HTTP {scanner.status_code}")
    steps.append(
        {
            "id": "scanner_catchall_probe",
            "category": "benign_scanner_request",
            "mitre": [],
            "label_method": "header",
            "expected_in_timeline": False,
        }
    )

    continuation.write_text("continue\n", encoding="ascii")
    records["steps"] = steps
    Path("/replay/records.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"benign_activity_completed": True, "steps": len(steps)}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("isolation", "benign"))
    args = parser.parse_args()
    if args.action == "isolation":
        isolate()
    else:
        perform_benign_activity()


if __name__ == "__main__":
    main()
