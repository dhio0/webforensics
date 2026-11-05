"""Files the manifest lists but the webroot copy cannot give (D101): an antivirus on the
analyst's machine deleted a webshell, and the report must say so instead of "nothing found"."""

import hashlib

from tests.conftest import MANIFEST_HEADER, manifest_row
from tests.correlate_helpers import numbered
from webforensics.adapters.file_adapter import ManifestFileSource
from webforensics.correlate import correlate
from webforensics.models import EvidenceScope
from webforensics.report.build import evidence_scope, unread_content, unread_warnings

PAGE = b"<html>about us</html>"


def manifest(tmp_path, *rows):
    path = tmp_path / "manifest.tsv"
    path.write_text(MANIFEST_HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def evidence(tmp_path):
    """Five pages present in the copy, two scripts missing from it (not a mostly absent
    copy, which is reported differently)."""
    web = tmp_path / "web"
    web.mkdir()
    digest = hashlib.sha256(PAGE).hexdigest()
    rows = []
    for name in ("about.html", "a.html", "b.html", "c.html", "d.html"):
        (web / name).write_bytes(PAGE)
        rows.append(manifest_row(name, size=len(PAGE), sha256=digest))
    rows += [manifest_row("uploads/shell.php"), manifest_row("lib/old.php")]
    return ManifestFileSource(manifest(tmp_path, *rows), webroot_dir=web).load_files()


def test_a_listed_file_absent_from_the_copy_is_counted(tmp_path):
    files = evidence(tmp_path)
    missing = sorted(f.excerpt for f in files.failures if f.reason == "content_missing")
    assert missing == ["lib/old.php", "uploads/shell.php"]


def test_no_webroot_means_no_content_expected(tmp_path):
    rows = (manifest_row("uploads/shell.php"),)
    files = ManifestFileSource(manifest(tmp_path, *rows)).load_files()
    assert files.failures == ()


def test_an_attacked_unread_script_is_said_first(tmp_path):
    files = evidence(tmp_path)
    logs = numbered((0, "/about.html"), (5, "/uploads/shell.php?cmd=id"))
    result = correlate(logs, files)
    count, code, attacked = unread_content(files, logs, result)
    assert count == 2
    assert attacked == ["uploads/shell.php"]
    assert code[0] == "uploads/shell.php"  # attacked first
    first, later = unread_warnings(evidence_scope(logs, files, result=result))
    assert first is not None and first.key == "summary.content_unread_attacked"
    assert later is None


def test_an_unread_script_nobody_attacked_is_said_in_place(tmp_path):
    files = evidence(tmp_path)
    logs = numbered((0, "/about.html"))
    first, later = unread_warnings(evidence_scope(logs, files, result=correlate(logs, files)))
    assert first is None
    assert later is not None and later.key == "summary.content_unread"


def test_a_mostly_absent_copy_is_called_incomplete():
    scope = EvidenceScope(files=10, unread_files=8, unread_code=("a.php",))
    first, later = unread_warnings(scope)
    assert first is not None and first.key == "summary.webroot_incomplete"
    assert later is None


def test_unread_content_is_not_counted_as_rejected_rows(tmp_path):
    files = evidence(tmp_path)
    scope = evidence_scope(numbered((0, "/")), files)
    assert scope.files_rejected == 0
    assert scope.unread_files == 2
