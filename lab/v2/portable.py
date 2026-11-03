"""Read immutable public inputs into a content-addressed app file catalog."""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def archive_bytes(spec: dict, cache: Path) -> bytes:
    sha = spec["sha256"]
    if not re.fullmatch(r"[a-f0-9]{64}", sha) or not spec["url"].startswith("https://"):
        raise ValueError("public archives require HTTPS and a SHA-256 pin")
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / (sha + ".zip")
    if path.exists():
        content = path.read_bytes()
    else:
        request = Request(spec["url"], headers={"User-Agent": "benchmark-portable-restore"})
        with urlopen(request, timeout=120) as response:
            content = response.read()
    if hashlib.sha256(content).hexdigest() != sha:
        raise ValueError("public archive failed its SHA-256 pin")
    if not path.exists():
        path.write_bytes(content)
    return content


def public_files(app: str, *, root: Path = ROOT) -> dict[str, bytes]:
    """Index bytes by hash; only manifest paths are materialized by restore."""
    spec = json.loads((root / "lab/v2/portable-inputs.json").read_text())[app]
    files: dict[str, bytes] = {}

    def add(content: bytes) -> None:
        files[hashlib.sha256(content).hexdigest()] = content

    if "image" in spec:
        image = spec["image"]
        if not re.fullmatch(r"[\w./:-]+@sha256:[a-f0-9]{64}", image):
            raise ValueError("base image must be pinned by registry digest")
        subprocess.run(["docker", "pull", image], check=True, stdout=subprocess.DEVNULL)
        container = subprocess.check_output(
            ["docker", "create", "--network", "none", "--entrypoint", "/bin/true", image],
            text=True,
        ).strip()
        try:
            packed = subprocess.check_output(["docker", "cp", f"{container}:{spec['tree']}/.", "-"])
            with tarfile.open(fileobj=io.BytesIO(packed)) as bundle:
                for member in bundle:
                    if member.isfile():
                        with bundle.extractfile(member) as stream:
                            add(stream.read())
        finally:
            subprocess.run(["docker", "rm", "-v", container], check=True, stdout=subprocess.DEVNULL)
    cache = root / "lab/v2/.cache/portable"
    for archive in spec["archives"]:
        content = archive_bytes(archive, cache)
        with zipfile.ZipFile(io.BytesIO(content)) as outer:
            if "nested" in archive:
                inner = outer.read(archive["nested"])
                with zipfile.ZipFile(io.BytesIO(inner)) as bundle:
                    for name in bundle.namelist():
                        if not name.endswith("/"):
                            add(bundle.read(name))
            else:
                for name in outer.namelist():
                    if not name.endswith("/"):
                        add(outer.read(name))
    return files
