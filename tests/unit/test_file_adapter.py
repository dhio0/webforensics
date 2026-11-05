import os
import sys

import pytest

from tests.conftest import MANIFEST_HEADER, manifest_row
from webforensics.adapters.file_adapter import (
    DirectoryFileSource,
    LogFileSource,
    ManifestFileSource,
    url_paths_for,
)
from webforensics.hashing import sha256_bytes
from webforensics.models import GapKind, TimestampSource


def test_log_source_expands_directory_and_names_relative(fixtures_dir):
    source = LogFileSource([fixtures_dir / "logs"], base_dir=fixtures_dir, glob="*_access.log")
    logs = source.load_logs()
    assert [s.path for s in logs.sources] == ["logs/apache_access.log", "logs/nginx_access.log"]
    assert len(logs.events) == 8
    assert len(logs.failures) == 2
    assert all(e.log_file.startswith("logs/") for e in logs.events)


def test_log_source_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        LogFileSource([tmp_path / "nope.log"]).load_logs()


def test_manifest_source(fixtures_dir, tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "x.php").write_text("<?php // defanged sample ?>")
    source = ManifestFileSource(
        fixtures_dir / "manifests" / "shop.manifest.tsv",
        webroot_dir=tmp_path,
        base_dir=fixtures_dir,
    )
    files = source.load_files()
    by_path = {f.path: f for f in files.files}

    shell = by_path["uploads/x.php"]
    assert shell.timestamp_source is TimestampSource.MANIFEST
    assert shell.url_paths == ("/uploads/x.php",)
    assert shell.source == "manifests/shop.manifest.tsv:14"
    assert shell.collected_at == files.header.collected_at
    # The extracted bytes do not hash to the manifest value, so they are not trusted.
    assert shell.content_ref is None
    mismatch = [f for f in files.failures if f.reason == "content_hash_mismatch"]
    assert len(mismatch) == 1 and mismatch[0].line_no == 14
    assert by_path["index.php"].content_ref is None  # not extracted
    assert by_path["index.php"].url_paths == ("/index.php", "/")
    # Files the manifest lists but the copy lacks are counted, not silent (D101).
    missing = sorted(f.excerpt for f in files.failures if f.reason == "content_missing")
    assert "index.php" in missing and "uploads/x.php" not in missing
    assert len(files.failures) == 3 + len(missing)
    assert files.sources[0].path == "manifests/shop.manifest.tsv"


def test_manifest_source_keeps_content_that_matches_hash(tmp_path):
    content = b"inert sample"
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "a.txt").write_bytes(content)
    manifest = tmp_path / "m.tsv"
    manifest.write_text(
        MANIFEST_HEADER + manifest_row("a.txt", size=len(content), sha256=sha256_bytes(content))
        + "\n", encoding="utf-8")
    files = ManifestFileSource(manifest, webroot_dir=tmp_path / "web").load_files()
    assert files.files[0].content_ref is not None
    assert files.failures == ()


def test_url_paths_with_prefix():
    assert url_paths_for("blog/index.php", "/site/") == ("/site/blog/index.php", "/site/blog/")


def test_directory_source_copy_has_gaps(tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "a.php").write_bytes(b"<?php echo 1; ?>")
    (tmp_path / "index.php").write_bytes(b"hi")

    files = DirectoryFileSource(tmp_path).load_files()
    assert [f.path for f in files.files] == ["index.php", "uploads/a.php"]
    assert files.files[0].sha256 == sha256_bytes(b"hi")
    assert files.files[0].timestamp_source is TimestampSource.COPIED
    assert {g.kind for g in files.gaps} == {
        GapKind.NO_MANIFEST,
        GapKind.UNTRUSTED_FILE_TIMESTAMPS,
    }
    if os.name != "posix":
        assert files.files[0].ctime is None  # Windows st_ctime is not inode change time


def test_directory_source_live_has_only_no_manifest_gap(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    files = DirectoryFileSource(tmp_path, live=True).load_files()
    assert [g.kind for g in files.gaps] == [GapKind.NO_MANIFEST]


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_directory_source_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("s")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)

    files = DirectoryFileSource(root).load_files()
    assert [(f.path, f.file_type.value) for f in files.files] == [("link", "symlink")]
    assert files.files[0].content_ref is None


def _locked(monkeypatch, name):
    """An extracted file the analyst's machine refuses to read (an antivirus lock)."""
    import webforensics.adapters.file_adapter as adapter

    real = adapter.sha256_file

    def sha256_file(path):
        if path.name == name:
            raise OSError(22, "Invalid argument")
        return real(path)

    monkeypatch.setattr(adapter, "sha256_file", sha256_file)


def test_an_unreadable_extracted_file_is_kept_without_content(fixtures_dir, tmp_path,
                                                               monkeypatch):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "x.php").write_text("locked")
    _locked(monkeypatch, "x.php")
    files = ManifestFileSource(fixtures_dir / "manifests" / "shop.manifest.tsv",
                               webroot_dir=tmp_path, base_dir=fixtures_dir).load_files()
    shell = next(f for f in files.files if f.path == "uploads/x.php")
    assert shell.content_ref is None
    assert [f.reason for f in files.failures if f.line_no == 14] == ["content_unreadable"]


def test_an_unreadable_file_in_a_scanned_folder_is_skipped_and_counted(tmp_path, monkeypatch):
    (tmp_path / "a.php").write_text("ok")
    (tmp_path / "b.php").write_text("locked")
    _locked(monkeypatch, "b.php")
    files = DirectoryFileSource(tmp_path).load_files()
    assert [f.path for f in files.files] == ["a.php"]
    assert [f.reason for f in files.failures] == ["content_unreadable"]
