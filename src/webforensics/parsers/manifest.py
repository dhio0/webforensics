"""Parser for the webroot stat manifest written by scripts/collect.sh (format v1).

The format is specified in docs/evidence-format.md. Paths are hex-encoded so that
attacker-chosen file names (tabs, newlines, invalid UTF-8) can't break the format.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from webforensics.models import (
    FileType,
    ManifestHeader,
    ParseFailure,
    check_relative_path,
)

MAGIC = "#webforensics-manifest v1"
COLUMNS = (
    "path_hex", "type", "size", "mode", "uid", "inode",
    "atime", "mtime", "ctime", "btime", "sha256",
)
_TYPES = {"f": FileType.FILE, "l": FileType.SYMLINK}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UNKNOWN = ("", "-", "?")


class ManifestError(ValueError):
    """The manifest as a whole is unusable (wrong magic, version or columns)."""


@dataclass(frozen=True)
class ManifestEntry:
    line_no: int
    path: str
    file_type: FileType
    size: int
    mode: int
    uid: int
    inode: int
    atime: datetime | None
    mtime: datetime | None
    ctime: datetime | None
    btime: datetime | None
    sha256: str


def _epoch(value: str) -> datetime | None:
    if value in _UNKNOWN:
        return None
    return datetime.fromtimestamp(float(value), tz=UTC)


def _birth_epoch(value: str) -> datetime | None:
    # GNU stat prints 0 for an unknown birth time.
    return None if value == "0" else _epoch(value)


def decode_path(path_hex: str) -> str:
    raw = bytes.fromhex(path_hex)
    path = raw.decode("utf-8", "backslashreplace").removeprefix("./")
    return check_relative_path(path)


def _parse_header(lines: list[tuple[int, str]]) -> tuple[ManifestHeader, int]:
    """Return the header and the index of the first data line."""
    if not lines or lines[0][1] != MAGIC:
        raise ManifestError(f"missing magic line {MAGIC!r}")
    fields: dict[str, str] = {}
    index = 1
    while index < len(lines) and lines[index][1].startswith("#"):
        key, _, value = lines[index][1][1:].partition("=")
        fields[key.strip()] = value.strip()
        index += 1

    columns = fields.pop("columns", None)
    if columns is not None and tuple(columns.split(",")) != COLUMNS:
        raise ManifestError(f"unexpected columns: {columns}")
    collected_at = fields.pop("collected_at", None)
    header = ManifestHeader(
        version="1",
        collector=fields.pop("collector", None),
        hostname=fields.pop("hostname", None),
        webroot=fields.pop("webroot", None),
        collected_at=_epoch(collected_at) if collected_at else None,
        utc_offset=fields.pop("utc_offset", None),
        birth_time_supported=fields.pop("birth_time_supported", "0") == "1",
        extra=fields,
    )
    return header, index


def _parse_row(line_no: int, line: str) -> ManifestEntry:
    cells = line.split("\t")
    if len(cells) != len(COLUMNS):
        raise ValueError("wrong_field_count")
    path_hex, type_code, size, mode, uid, inode, atime, mtime, ctime, btime, sha = cells
    try:
        path = decode_path(path_hex)
    except ValueError as exc:
        raise ValueError("unsafe_or_bad_path") from exc
    if type_code not in _TYPES:
        raise ValueError("unsupported_type")
    if not _SHA256_RE.match(sha):
        raise ValueError("missing_or_bad_sha256")
    try:
        return ManifestEntry(
            line_no=line_no,
            path=path,
            file_type=_TYPES[type_code],
            size=int(size),
            mode=int(mode, 8),
            uid=int(uid),
            inode=int(inode),
            atime=_epoch(atime),
            mtime=_epoch(mtime),
            ctime=_epoch(ctime),
            btime=_birth_epoch(btime),
            sha256=sha,
        )
    except ValueError as exc:
        raise ValueError("bad_number") from exc


def parse_manifest(
    lines: Iterable[str], source: str
) -> tuple[ManifestHeader, list[ManifestEntry], list[ParseFailure]]:
    numbered = [
        (line_no, line.rstrip("\r\n"))
        for line_no, line in enumerate(lines, start=1)
        if line.strip()
    ]
    header, first_data = _parse_header(numbered)

    entries: list[ManifestEntry] = []
    failures: list[ParseFailure] = []
    seen: set[str] = set()
    for line_no, line in numbered[first_data:]:
        try:
            entry = _parse_row(line_no, line)
        except ValueError as exc:
            failures.append(
                ParseFailure(source=source, line_no=line_no, reason=str(exc), excerpt=line)
            )
            continue
        if entry.path in seen:
            failures.append(
                ParseFailure(source=source, line_no=line_no, reason="duplicate_path", excerpt=line)
            )
            continue
        seen.add(entry.path)
        entries.append(entry)
    return header, entries, failures
