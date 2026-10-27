"""Replay the fixed localhost-only Scenario A request sequence."""

import argparse
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
USER_AGENT = "webforensics-lab/1.0 scenario-a"
MARKER_NAME = "lab-marker.php"
MARKER_CONTENT = b"LAB-FORENSICS-MARKER-v1\n"


def _request(url: str, *, data: bytes | None = None, content_type: str | None = None) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
            if response.status != 200:
                raise RuntimeError(f"unexpected HTTP status {response.status} for {url}")
            return body
    except urllib.error.URLError as exc:
        raise RuntimeError(f"localhost lab request failed for {url}: {exc}") from exc


def _reset_access_log() -> None:
    subprocess.run(
        [
            "docker", "compose", "-f", str(ROOT / "lab" / "docker-compose.yml"),
            "exec", "-T", "nginx", "sh", "-c",
            "truncate -s 0 /var/log/nginx/access.log && nginx -s reopen",
        ],
        check=True,
        cwd=ROOT,
    )


def run(port: int) -> None:
    base_url = f"http://127.0.0.1:{port}"
    _reset_access_log()

    _request(f"{base_url}/")
    _request(f"{base_url}/product.php?id=1")
    _request(f"{base_url}/admin/upload.php")

    sqli = urllib.parse.urlencode({"id": "1 OR 1=1"})
    _request(f"{base_url}/product.php?{sqli}")

    boundary = "----webforensics-lab-scenario-a"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{MARKER_NAME}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + MARKER_CONTENT + f"\r\n--{boundary}--\r\n".encode()
    upload_response = _request(
        f"{base_url}/admin/upload.php",
        data=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )
    if b"/uploads/lab-marker.php" not in upload_response:
        raise RuntimeError("upload response did not confirm the marker path")

    marker_response = _request(f"{base_url}/uploads/{MARKER_NAME}")
    if marker_response != MARKER_CONTENT:
        raise RuntimeError("marker request did not return the expected inert text")
    print("Scenario A replay complete: 6 localhost requests, marker served as plain text.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    run(args.port)


if __name__ == "__main__":
    main()
