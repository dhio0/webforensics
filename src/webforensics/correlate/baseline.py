"""Compare the current webroot against a known-good baseline (by path and SHA-256)."""

from webforensics.models import BaselineStatus, FileCollection, FileEvidence


def _status(file: FileEvidence, known: dict[str, str]) -> BaselineStatus:
    if file.path not in known:
        return BaselineStatus.NEW
    if known[file.path] != file.sha256:
        return BaselineStatus.MODIFIED
    return BaselineStatus.UNCHANGED


def apply_baseline(
    current: FileCollection, baseline: FileCollection
) -> tuple[FileCollection, tuple[str, ...]]:
    """Label each current file new/modified/unchanged; also return paths that were deleted."""
    known = {file.path: file.sha256 for file in baseline.files}
    files = tuple(
        file.model_copy(update={"baseline_status": _status(file, known)}) for file in current.files
    )
    present = {file.path for file in current.files}
    deleted = tuple(sorted(path for path in known if path not in present))
    return current.model_copy(update={"files": files}), deleted
