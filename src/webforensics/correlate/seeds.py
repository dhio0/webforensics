"""Which files start a trace.

Strong seeds: a file rule fired, or the baseline says new/modified (executable or
.htaccess). Weak seeds cover the case with no content and no baseline: an executable
written on its own, apart from any deploy batch ("lonely write"). A weak seed only joins
the incident if a request plausibly wrote it or it is a rarely-hit POST target;
otherwise it is listed for manual review (D49).

The same batches catch deploys: a file written together with more than
`lonely_cluster_max` other files is held to the weak-seed standard too, unless its content
alone shows a webshell (D79, widened in D84). Wazuh FIM marks every file a deploy writes as
`added`, and an application install brings files whose path or content looks odd on its
own (code in a folder named `upload`, encoded test data); without this, a deploy or install
would be reported as an attack.
"""

from datetime import datetime, timedelta

from webforensics.correlate.anchor import choose_anchor
from webforensics.correlate.config import CorrelationConfig
from webforensics.detect import RULESET_VERSION
from webforensics.detect.file_rules import JUDOL_RULE, has_executable_extension
from webforensics.models import (
    BaselineStatus,
    Confidence,
    FileEvidence,
    Finding,
    FindingCategory,
    LogEvent,
    Reason,
    Severity,
    TimestampBasis,
    TimestampSource,
    stable_id,
)

LONELY_RULE = "CORR-LONELY-EXEC-WRITE"
RARE_POST_RULE = "CORR-RARE-POST-TARGET"
# Content that is a webshell wherever it came from: such a file is accused even when it
# arrived with a deploy batch.
DECISIVE_RULES = frozenset({"FILE-WEBSHELL-REQUEST-EXEC"})


def _code_like(path: str) -> bool:
    return has_executable_extension(path) or path.rsplit("/", 1)[-1] == ".htaccess"


def is_strong_seed(file: FileEvidence, findings: list[Finding]) -> bool:
    if file.baseline_status is BaselineStatus.UNCHANGED:
        return False  # identical to the known-good copy, so not attacker-written
    if findings:
        return True
    changed = file.baseline_status in (BaselineStatus.NEW, BaselineStatus.MODIFIED)
    return changed and _code_like(file.path)


def _trusted_write_time(file: FileEvidence, config: CorrelationConfig) -> datetime | None:
    anchor = choose_anchor(file, config)
    if anchor is None or anchor.basis is TimestampBasis.MTIME:
        return None  # mtime is kept by deploy tools, so it can't separate batches
    if file.timestamp_source is TimestampSource.COPIED:
        return None
    return anchor.ts


def write_batches(files: list[FileEvidence],
                  config: CorrelationConfig) -> list[list[FileEvidence]]:
    """Files grouped by trusted write time: consecutive times closer than
    `lonely_cluster_gap_s` belong to the same batch (a deploy writes many files at once)."""
    timed = sorted(
        ((ts, f) for f in files if (ts := _trusted_write_time(f, config)) is not None),
        key=lambda item: (item[0], item[1].path),
    )
    gap = timedelta(seconds=config.lonely_cluster_gap_s)
    batches: list[list[FileEvidence]] = []
    last: datetime | None = None
    for ts, file in timed:
        if last is None or ts - last > gap:
            batches.append([])
        batches[-1].append(file)
        last = ts
    return batches


def lonely_writes(files: list[FileEvidence], config: CorrelationConfig) -> set[str]:
    """Code files without a baseline whose write is in a batch of at most
    `lonely_cluster_max` files."""
    return {
        f.path for batch in write_batches(files, config)
        if len(batch) <= config.lonely_cluster_max for f in batch
        if f.baseline_status is BaselineStatus.UNKNOWN and _code_like(f.path)
    }


def decisive(findings: list[Finding]) -> bool:
    """Dense gambling spam counts too (D98): judol kits drop hundreds of pages at once, and
    no deploy writes a page that dense with slot and lottery promotion."""
    return any(f.rule_id in DECISIVE_RULES
               or (f.rule_id == JUDOL_RULE and f.confidence is Confidence.HIGH)
               for f in findings)


def deploy_writes(files: list[FileEvidence], config: CorrelationConfig) -> set[str]:
    """Files written in a batch larger than `lonely_cluster_max` (a deploy or unpack)."""
    return {f.path for batch in write_batches(files, config)
            if len(batch) > config.lonely_cluster_max for f in batch}


def _finding(file: FileEvidence, rule_id: str, category: FindingCategory,
             params: dict[str, str], citations: tuple) -> Finding:
    return Finding(
        finding_id=stable_id(rule_id, file.evidence_id), rule_id=rule_id,
        rule_version=RULESET_VERSION, category=category, subject=file.evidence_id,
        severity=Severity.MEDIUM, confidence=Confidence.LOW,
        reasons=(Reason(key=f"finding.{rule_id}", params=params),),
        citations=citations, mitre=("T1505.003",),
    )


def lonely_finding(file: FileEvidence) -> Finding:
    return _finding(file, LONELY_RULE, FindingCategory.PERSISTENCE, {"path": file.path},
                    (file.citation(),))


def rare_post_finding(file: FileEvidence, hits: list[LogEvent], actors: dict[str, str],
                      since: datetime, config: CorrelationConfig) -> Finding | None:
    """POSTs to a file that almost nobody else requests: typical of a webshell."""
    posts = [e for e in hits if e.method == "POST" and e.ts >= since]
    clients = {actors[e.evidence_id] for e in posts}
    if not posts or len(clients) > config.rare_post_max_clients:
        return None
    if len(hits) > config.rare_hits_max:
        return None
    params = {"posts": str(len(posts)), "clients": str(len(clients)), "hits": str(len(hits))}
    return _finding(file, RARE_POST_RULE, FindingCategory.WEBSHELL, params,
                    (posts[0].citation(), file.citation()))
