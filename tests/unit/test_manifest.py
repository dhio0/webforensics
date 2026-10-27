from datetime import UTC, datetime

import pytest

from tests.conftest import MANIFEST_HEADER, manifest_row
from webforensics.models import FileType
from webforensics.parsers.manifest import ManifestError, decode_path, parse_manifest


def _parse(text: str):
    return parse_manifest(text.splitlines(keepends=True), "manifest.tsv")


def test_fixture_manifest(fixtures_dir):
    path = fixtures_dir / "manifests" / "shop.manifest.tsv"
    with path.open(encoding="utf-8") as handle:
        header, entries, failures = parse_manifest(handle, "shop.manifest.tsv")

    assert header.hostname == "shop-web01"
    assert header.collected_at == datetime(2026, 10, 27, 3, 40, tzinfo=UTC)
    assert header.birth_time_supported is False
    assert [e.path for e in entries] == [
        "admin/upload.php", "css/style.css", "index.php", "latest",
        "uploads/.htaccess", "uploads/x.php",
    ]
    assert sorted(f.reason for f in failures) == ["unsafe_or_bad_path", "wrong_field_count"]

    shell = entries[-1]
    assert shell.ctime == datetime(2026, 10, 27, 3, 6, 40, tzinfo=UTC)
    assert shell.mtime == datetime(2026, 1, 1, tzinfo=UTC)  # timestomped in the fixture
    assert shell.btime is None  # 0 means unknown
    assert shell.mode == 0o644
    assert entries[3].file_type is FileType.SYMLINK


def test_hex_path_survives_tabs_and_newlines():
    name = "uploads/evil\tname\n.php"
    _, entries, failures = _parse(MANIFEST_HEADER + manifest_row(name) + "\n")
    assert not failures
    assert entries[0].path == name


def test_invalid_utf8_path_is_kept_visible():
    assert decode_path(b"up/\xff.php".hex()) == "up/\\xff.php"


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (manifest_row("a.php", type_code="d"), "unsupported_type"),
        (manifest_row("a.php", sha256="-"), "missing_or_bad_sha256"),
        (manifest_row("a.php", size="big"), "bad_number"),  # type: ignore[arg-type]
        ("zz\t" + manifest_row("a.php").split("\t", 1)[1], "unsafe_or_bad_path"),
    ],
)
def test_bad_rows_are_counted(row, reason):
    _, entries, failures = _parse(MANIFEST_HEADER + row + "\n")
    assert not entries
    assert failures[0].reason == reason


def test_duplicate_paths_keep_first():
    text = MANIFEST_HEADER + manifest_row("a.php", size=1) + "\n" + manifest_row("a.php") + "\n"
    _, entries, failures = _parse(text)
    assert [e.size for e in entries] == [1]
    assert failures[0].reason == "duplicate_path"


def test_missing_magic_is_fatal():
    with pytest.raises(ManifestError):
        _parse("path\ttype\n")


def test_unexpected_columns_are_fatal():
    with pytest.raises(ManifestError):
        _parse(MANIFEST_HEADER + "#columns=path,type\n")


def test_unknown_header_keys_are_kept():
    header, _, _ = _parse(MANIFEST_HEADER + "#kernel=6.1\n")
    assert header.extra == {"kernel": "6.1"}
