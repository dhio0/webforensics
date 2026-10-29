"""FIM alerts from a recording -> FileCollection (D76-D78).

All alerts for one path build one FileEvidence, and every alert stays a citation.
- The FIM baseline scan is the known-good state, so `added` means new and `modified`
  means changed (`has_baseline`).
- A deleted file keeps the hash from its last alert: the agent builds `deleted` events
  from its stored entry (create_db.c). A path that was only deleted (never written in the
  window) is listed in `deleted_paths`, like a file missing from a baseline.
- Paths outside the docroot are not webroot files; they become findings to review.
- Content is read only from a `--webroot` copy whose SHA-256 equals the FIM hash (D77).
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from webforensics.adapters.file_adapter import url_paths_for
from webforensics.adapters.wazuh import schema_v4 as schema
from webforensics.adapters.wazuh.recording import RecordedHit, RecordingHeader, Stream
from webforensics.detect import RULESET_VERSION
from webforensics.hashing import sha256_file
from webforensics.models import (
    BaselineStatus,
    Citation,
    CitationKind,
    Confidence,
    EvidenceGap,
    FileCollection,
    FileEvidence,
    FimChange,
    FimEventType,
    FimMode,
    Finding,
    FindingCategory,
    GapKind,
    ParseFailure,
    Reason,
    Severity,
    SourceFile,
    TimestampSource,
    check_relative_path,
    stable_id,
)

ADAPTER = "wazuh"
OUTSIDE_RULE = "FILE-WAZUH-FIM-OUTSIDE-DOCROOT"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PERM = re.compile(r"^[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]$")


@dataclass(frozen=True, slots=True)
class _Alert:
    """One parsed FIM alert, with the raw `syscheck` object for file metadata."""

    hit: RecordedHit
    ts: datetime
    change: FimChange
    syscheck: dict[str, object]


def _int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _perm(value: object) -> int | None:
    """`perm_after` is `rw-r--r--` on Linux; setuid/sticky bits are ignored."""
    text = str(value) if value is not None else ""
    if not _PERM.match(text):
        return None
    bits = 0
    for char in text:
        bits = (bits << 1) | (char not in "-ST")
    return bits


def _citation(hit: RecordedHit, source: str, event: str, path: str, mode: str,
              sha256: str | None) -> Citation:
    rule = hit.source.get("rule")
    rule_id = rule.get("id") if isinstance(rule, dict) else None
    return Citation(
        kind=CitationKind.WAZUH_ALERT, source=source, line_no=hit.line_no, sha256=sha256,
        excerpt=f"Wazuh rule {rule_id or '?'}: {event} {path} ({mode})",
    )


def _parse(hit: RecordedHit, source: str) -> _Alert | ParseFailure:
    syscheck = hit.source.get("syscheck")
    if not isinstance(syscheck, dict) or not isinstance(syscheck.get("path"), str):
        return ParseFailure(source=source, line_no=hit.line_no, reason="wazuh_fim_no_path")
    path = syscheck["path"]
    try:
        ts = schema.alert_time(hit.source)
        event = FimEventType(str(syscheck.get("event")))
        mode = FimMode(str(syscheck.get("mode", FimMode.SCHEDULED.value)))
    except (KeyError, ValueError):
        return ParseFailure(source=source, line_no=hit.line_no, reason="wazuh_fim_bad_alert",
                            excerpt=path)
    raw_hash = syscheck.get("sha256_after")
    sha256 = raw_hash if isinstance(raw_hash, str) and _SHA256.match(raw_hash) else None
    change = FimChange(ts=ts, event=event, mode=mode, sha256=sha256,
                       citation=_citation(hit, source, event.value, path, mode.value, sha256))
    return _Alert(hit, ts, change, syscheck)


def relative_to_docroot(path: str, docroot: str) -> str | None:
    """`/var/www/html/uploads/x.php` -> `uploads/x.php`; None outside the docroot."""
    prefix = docroot.rstrip("/") + "/"
    if not path.startswith(prefix):
        return None
    try:
        return check_relative_path(path[len(prefix):])
    except ValueError:
        return None


def _outside_finding(path: str, alerts: list[_Alert]) -> Finding:
    return Finding(
        finding_id=stable_id(OUTSIDE_RULE, path), rule_id=OUTSIDE_RULE,
        rule_version=RULESET_VERSION, category=FindingCategory.PERSISTENCE,
        subject=stable_id(ADAPTER, "fim", path), severity=Severity.LOW,
        confidence=Confidence.LOW,
        reasons=(Reason(key=f"finding.{OUTSIDE_RULE}",
                        params={"path": path, "events": str(len(alerts))}),),
        citations=tuple(a.change.citation for a in alerts),
    )


def _content_ref(webroot: Path | None, rel: str, sha256: str) -> tuple[str | None, bool]:
    """(path to verified content, whether a copy existed but did not match)."""
    if webroot is None:
        return None, False
    candidate = webroot / rel
    if candidate.is_symlink() or not candidate.is_file():
        return None, False
    try:
        candidate.resolve().relative_to(webroot.resolve())
    except ValueError:
        return None, False
    if sha256_file(candidate) != sha256:
        return None, True
    return str(candidate), False


def _evidence(rel: str, alerts: list[_Alert], source: str, url_prefix: str,
              webroot: Path | None) -> tuple[FileEvidence | None, ParseFailure | None]:
    """None, failure when no alert carries a hash (nothing can identify the content)."""
    with_hash = [a for a in alerts if a.change.sha256]
    if not with_hash:
        return None, ParseFailure(source=source, line_no=alerts[0].hit.line_no,
                                  reason="wazuh_fim_no_hash", excerpt=rel)
    last = with_hash[-1]
    sha256 = str(last.change.sha256)
    first_write = next(a for a in alerts if a.change.event is not FimEventType.DELETED)
    status = (BaselineStatus.NEW if first_write is alerts[0]
              and first_write.change.event is FimEventType.ADDED else BaselineStatus.MODIFIED)
    content, mismatch = _content_ref(webroot, rel, sha256)
    failure = None
    if mismatch:
        failure = ParseFailure(source=source, line_no=last.hit.line_no,
                               reason="content_hash_mismatch",
                               excerpt=f"{rel} fim={sha256[:12]} webroot copy differs")
    meta = last.syscheck
    return FileEvidence(
        evidence_id=stable_id(ADAPTER, "webroot", rel), adapter=ADAPTER,
        source=f"{source}:{alerts[0].hit.line_no}", path=rel,
        url_paths=url_paths_for(rel, url_prefix), sha256=sha256,
        size=_int(meta.get("size_after")) or 0, mode=_perm(meta.get("perm_after")),
        uid=_int(meta.get("uid_after")), inode=_int(meta.get("inode_after")),
        mtime=schema.mtime_after(meta, last.ts), timestamp_source=TimestampSource.WAZUH_FIM,
        baseline_status=status, fim=tuple(a.change for a in alerts), content_ref=content,
    ), failure


def fim_files(header: RecordingHeader, hits: list[RecordedHit], source: SourceFile,
              url_prefix: str = "/", webroot: Path | None = None) -> FileCollection:
    failures: list[ParseFailure] = []
    by_path: dict[str, list[_Alert]] = defaultdict(list)
    for hit in hits:
        if hit.stream is not Stream.FIM:
            continue
        parsed = _parse(hit, source.path)
        if isinstance(parsed, ParseFailure):
            failures.append(parsed)
        else:
            by_path[str(parsed.syscheck["path"])].append(parsed)

    files: list[FileEvidence] = []
    findings: list[Finding] = []
    deleted: list[str] = []
    for path in sorted(by_path):
        alerts = sorted(by_path[path], key=lambda a: (a.ts, a.hit.line_no))
        rel = relative_to_docroot(path, header.docroot)
        if rel is None:
            findings.append(_outside_finding(path, alerts))
            continue
        if all(a.change.event is FimEventType.DELETED for a in alerts):
            deleted.append(rel)
            continue
        evidence, failure = _evidence(rel, alerts, source.path, url_prefix, webroot)
        if failure is not None:
            failures.append(failure)
        if evidence is not None:
            files.append(evidence)

    gaps = ()
    if files and not any(f.content_ref for f in files):
        gaps = (EvidenceGap(gap_id=stable_id(ADAPTER, "gap", GapKind.NO_FILE_CONTENT.value),
                            kind=GapKind.NO_FILE_CONTENT, source=source.path,
                            detail=Reason(key="gap.no_file_content")),)
    return FileCollection(
        files=tuple(files), failures=tuple(failures), gaps=gaps, sources=(source,),
        findings=tuple(findings), has_baseline=True, deleted_paths=tuple(deleted),
    )
