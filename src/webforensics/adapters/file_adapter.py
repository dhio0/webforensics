"""FileAdapter: evidence from plain files on disk.

- LogFileSource: access logs (optionally .gz rotated).
- ManifestFileSource: webroot evidence from a collect.sh manifest (preferred, D9).
- DirectoryFileSource: fallback that stats a folder directly; timestamps are less
  trustworthy, and the result says so as evidence gaps.
"""

import os
import stat
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from webforensics.hashing import sha256_bytes, sha256_file
from webforensics.models import (
    EvidenceGap,
    FileCollection,
    FileEvidence,
    FileType,
    GapKind,
    LogCollection,
    LogEvent,
    ParseFailure,
    Reason,
    SourceFile,
    TimestampSource,
    stable_id,
)
from webforensics.parsers.access_log import AccessLogFormat, iter_access_log
from webforensics.parsers.manifest import ManifestEntry, parse_manifest

ADAPTER = "file"
INDEX_NAMES = ("index.php", "index.html", "index.htm")


def display_name(path: Path, base_dir: Path | None) -> str:
    """Name used in citations: relative to base_dir when possible, so it is machine-independent."""
    resolved = path.resolve()
    if base_dir is not None:
        try:
            return resolved.relative_to(base_dir.resolve()).as_posix()
        except ValueError:
            pass
    return resolved.as_posix()


def url_paths_for(path: str, url_prefix: str = "/") -> tuple[str, ...]:
    """URLs that serve a webroot-relative file, including `dir/` for index files."""
    url = f"{url_prefix.rstrip('/')}/{path}"
    name = path.rsplit("/", 1)[-1]
    if name in INDEX_NAMES:
        return (url, url[: -len(name)])
    return (url,)


def _source_file(path: Path, base_dir: Path | None) -> SourceFile:
    return SourceFile(
        path=display_name(path, base_dir), sha256=sha256_file(path), size=path.stat().st_size
    )


class LogFileSource:
    def __init__(
        self,
        paths: Sequence[Path],
        fmt: AccessLogFormat = AccessLogFormat.NGINX_COMBINED,
        base_dir: Path | None = None,
        glob: str = "*access*",
    ) -> None:
        self._paths = paths
        self._fmt = fmt
        self._base_dir = base_dir
        self._glob = glob

    def _expand(self) -> list[Path]:
        files: list[Path] = []
        for path in self._paths:
            if path.is_dir():
                files.extend(sorted(p for p in path.glob(self._glob) if p.is_file()))
            elif path.is_file():
                files.append(path)
            else:
                raise FileNotFoundError(f"log path not found: {path}")
        return list(dict.fromkeys(files))

    def load_logs(self) -> LogCollection:
        events: list[LogEvent] = []
        failures: list[ParseFailure] = []
        sources: list[SourceFile] = []
        for path in self._expand():
            source = _source_file(path, self._base_dir)
            sources.append(source)
            for item in iter_access_log(path, source.path, self._fmt, ADAPTER):
                if isinstance(item, LogEvent):
                    events.append(item)
                else:
                    failures.append(item)
        return LogCollection(events=tuple(events), failures=tuple(failures), sources=tuple(sources))


def _content_ref(webroot_dir: Path | None, rel_path: str) -> str | None:
    """Local path to a regular file's content, only if it stays inside the webroot (D15)."""
    if webroot_dir is None:
        return None
    root = webroot_dir.resolve()
    candidate = webroot_dir / rel_path
    if candidate.is_symlink() or not candidate.is_file():
        return None
    try:
        candidate.resolve().relative_to(root)
    except ValueError:
        return None
    return str(candidate)


class ManifestFileSource:
    def __init__(
        self,
        manifest_path: Path,
        webroot_dir: Path | None = None,
        url_prefix: str = "/",
        base_dir: Path | None = None,
    ) -> None:
        self._manifest_path = manifest_path
        self._webroot_dir = webroot_dir
        self._url_prefix = url_prefix
        self._base_dir = base_dir

    def _to_evidence(self, entry: ManifestEntry, source: str, collected_at: datetime | None):
        return FileEvidence(
            evidence_id=stable_id(ADAPTER, "webroot", entry.path),
            adapter=ADAPTER,
            source=f"{source}:{entry.line_no}",
            collected_at=collected_at,
            path=entry.path,
            file_type=entry.file_type,
            url_paths=url_paths_for(entry.path, self._url_prefix),
            sha256=entry.sha256,
            size=entry.size,
            mode=entry.mode,
            uid=entry.uid,
            inode=entry.inode,
            atime=entry.atime,
            mtime=entry.mtime,
            ctime=entry.ctime,
            btime=entry.btime,
            timestamp_source=TimestampSource.MANIFEST,
            content_ref=(
                _content_ref(self._webroot_dir, entry.path)
                if entry.file_type is FileType.FILE
                else None
            ),
        )

    def load_files(self) -> FileCollection:
        source = _source_file(self._manifest_path, self._base_dir)
        with self._manifest_path.open(encoding="utf-8", errors="replace") as handle:
            header, entries, failures = parse_manifest(handle, source.path)
        files = tuple(self._to_evidence(e, source.path, header.collected_at) for e in entries)
        return FileCollection(
            files=files, failures=tuple(failures), header=header, sources=(source,)
        )


def _ts(value: float) -> datetime:
    return datetime.fromtimestamp(value, tz=UTC)


class DirectoryFileSource:
    """Stat a webroot folder directly. Use `live=True` only when running on the server itself."""

    def __init__(self, root: Path, live: bool = False, url_prefix: str = "/") -> None:
        self._root = root
        self._live = live
        self._url_prefix = url_prefix

    def _iter_paths(self) -> list[Path]:
        found: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self._root, followlinks=False):
            for name in dirnames + filenames:
                path = Path(dirpath) / name
                if path.is_symlink() or (name in filenames and path.is_file()):
                    found.append(path)
        return found

    def _to_evidence(self, path: Path) -> FileEvidence:
        # Normalize undecodable names the same way the manifest parser does.
        rel = os.fsencode(path.relative_to(self._root).as_posix()).decode(
            "utf-8", "backslashreplace"
        )
        st = path.lstat()
        is_link = stat.S_ISLNK(st.st_mode)
        digest = sha256_bytes(os.fsencode(os.readlink(path))) if is_link else sha256_file(path)
        posix = os.name == "posix"
        birth = getattr(st, "st_birthtime", None) if posix else st.st_ctime
        return FileEvidence(
            evidence_id=stable_id(ADAPTER, "webroot", rel),
            adapter=ADAPTER,
            source=rel,
            path=rel,
            file_type=FileType.SYMLINK if is_link else FileType.FILE,
            url_paths=url_paths_for(rel, self._url_prefix),
            sha256=digest,
            size=st.st_size,
            mode=stat.S_IMODE(st.st_mode),
            uid=st.st_uid,
            inode=st.st_ino,
            atime=_ts(st.st_atime),
            mtime=_ts(st.st_mtime),
            # On Windows st_ctime is the creation time, not the inode change time.
            ctime=_ts(st.st_ctime) if posix else None,
            btime=_ts(birth) if birth is not None else None,
            timestamp_source=(
                TimestampSource.LIVE_STAT if self._live else TimestampSource.COPIED
            ),
            content_ref=None if is_link else str(path),
        )

    def _gaps(self) -> tuple[EvidenceGap, ...]:
        source = self._root.name or "webroot"
        kinds = [GapKind.NO_MANIFEST]
        if not self._live:
            kinds.append(GapKind.UNTRUSTED_FILE_TIMESTAMPS)
        return tuple(
            EvidenceGap(
                gap_id=stable_id(ADAPTER, "gap", kind.value, source),
                kind=kind,
                source=source,
                detail=Reason(key=f"gap.{kind.value}"),
            )
            for kind in kinds
        )

    def load_files(self) -> FileCollection:
        files = sorted(
            (self._to_evidence(p) for p in self._iter_paths()), key=lambda f: f.path
        )
        return FileCollection(files=tuple(files), gaps=self._gaps())
