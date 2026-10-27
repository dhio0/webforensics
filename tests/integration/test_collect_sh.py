"""Run the real collector on a temp webroot and parse its manifest (Linux/CI only)."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from webforensics.adapters.file_adapter import ManifestFileSource
from webforensics.hashing import sha256_bytes

COLLECT = Path(__file__).parents[2] / "scripts" / "collect.sh"

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("bash") is None,
    reason="collect.sh targets Linux servers",
)


def test_collect_then_parse(tmp_path):
    webroot = tmp_path / "www"
    (webroot / "uploads").mkdir(parents=True)
    (webroot / "index.php").write_bytes(b"<?php echo 'hi'; ?>")
    (webroot / "uploads" / "tab\tname.php").write_bytes(b"x")
    (webroot / "latest").symlink_to("index.php")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "access.log").write_text("line\n")
    out = tmp_path / "case"

    subprocess.run(
        ["bash", str(COLLECT), "-w", str(webroot), "-o", str(out), "-l", str(logs)],
        check=True,
    )

    files = ManifestFileSource(out / "manifest.tsv").load_files()
    assert not files.failures
    by_path = {f.path: f for f in files.files}
    assert set(by_path) == {"index.php", "uploads/tab\tname.php", "latest"}
    assert by_path["index.php"].sha256 == sha256_bytes(b"<?php echo 'hi'; ?>")
    assert by_path["latest"].sha256 == sha256_bytes(b"index.php")
    assert by_path["index.php"].ctime is not None
    assert (out / "webroot.tar").is_file()
    assert (out / "logs" / "access.log").is_file()
    assert "manifest.tsv" in (out / "SHA256SUMS").read_text()


def test_refuses_outdir_inside_webroot(tmp_path):
    webroot = tmp_path / "www"
    webroot.mkdir()
    result = subprocess.run(
        ["bash", str(COLLECT), "-w", str(webroot), "-o", str(webroot / "case")],
        capture_output=True,
    )
    assert result.returncode != 0
