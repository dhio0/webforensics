"""Build the language-neutral `Report` from a correlation result (deterministic).

Everything here is a rule over the result: which summary lines apply, which CSIRT
recommendations follow from the root cause, and how unrelated attack noise is grouped.
"""

from collections import Counter, defaultdict

from webforensics.correlate.actors import parse_networks, resolve_actor
from webforensics.correlate.engine import BYPASS_RULE
from webforensics.models import (
    BackgroundGroup,
    CaseInfo,
    CitationKind,
    CorrelationResult,
    EvidenceScope,
    FileCollection,
    Finding,
    GapKind,
    LogCollection,
    Reason,
    Report,
    RunInfo,
    TimelineEvent,
)

TOP_CLIENTS = 5
_TIME_GAPS = (GapKind.NO_LOG_LINES, GapKind.PARSE_ERRORS, GapKind.ROTATION_BOUNDARY)
_WRITE_KINDS = ("timeline.upload_exploit", "timeline.write_exploit",
                "timeline.file_write_request")
_FIX_FOR_VULN = {
    "unrestricted_file_upload": "rec.eradication.fix_upload",
    "sql_injection_auth_bypass": "rec.eradication.fix_sqli_login",
    "sql_injection_file_write": "rec.eradication.fix_sqli_write",
}
LIMITATIONS = ("limit.automated", "limit.post_body", "limit.timestamps",
               "limit.log_tampering", "limit.shared_ip")


def _r(key: str, **params: object) -> Reason:
    return Reason(key=key, params={k: str(v) for k, v in params.items()})


def root_event(result: CorrelationResult) -> TimelineEvent | None:
    if result.root_cause is None:
        return None
    return next(e for e in result.timeline if e.event_id == result.root_cause.event_id)


def background_groups(result: CorrelationResult, logs: LogCollection,
                      trusted_proxies: tuple[str, ...] = ()) -> list[BackgroundGroup]:
    """Unattributed log findings grouped by rule, most frequent first.

    Clients are resolved like the engine does (X-Forwarded-For behind a trusted proxy),
    so a CDN address does not hide how many bots there were.
    """
    proxies = parse_networks(trusted_proxies)
    unattributed = set(result.unattributed_finding_ids)
    events = {e.evidence_id: e for e in logs.events}
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in result.findings:
        if finding.finding_id in unattributed and finding.subject in events:
            by_rule[finding.rule_id].append(finding)
    groups = []
    for rule_id, found in by_rule.items():
        hits = [events[f.subject] for f in found]
        clients = Counter(resolve_actor(e, proxies) for e in hits)
        first = min(hits, key=lambda e: (e.ts, e.log_file, e.line_no))
        groups.append(BackgroundGroup(
            rule_id=rule_id, count=len(hits), clients=len(clients),
            top_clients=tuple(sorted(clients.items(), key=lambda kv: (-kv[1], kv[0]))
                              [:TOP_CLIENTS]),
            first=first.ts, last=max(e.ts for e in hits), example=first.citation(),
        ))
    return sorted(groups, key=lambda g: (-g.count, g.rule_id))


def other_flagged_files(result: CorrelationResult) -> list[str]:
    """Files with findings that are neither in the incident nor already set aside."""
    unattributed = set(result.unattributed_finding_ids)
    known = {f.path for f in result.affected_files} | set(result.unexplained_changes)
    flagged = {f.citations[0].source for f in result.findings
               if f.finding_id in unattributed and f.citations[0].kind is not CitationKind.LOG_LINE
               and f.rule_id.startswith(("FILE-", "CORR-"))}
    return sorted(flagged - known)


def unlinked_bypass_paths(result: CorrelationResult) -> list[str]:
    """Login endpoints where an SQLi bypass looks successful outside the incident (D71)."""
    return sorted({f.reasons[0].params["path"] for f in result.findings
                   if f.rule_id == BYPASS_RULE})


def _actor_span(result: CorrelationResult) -> tuple[str, str] | None:
    times = [e.ts for e in result.timeline if e.actor in result.iocs.ips]
    if not times:
        times = [e.ts for e in result.timeline]
    if not times:
        return None
    return min(times).isoformat(), max(times).isoformat()


def background_requests(result: CorrelationResult, logs: LogCollection) -> int:
    """Distinct requests behind the background groups (one line can match several rules)."""
    unattributed = set(result.unattributed_finding_ids)
    events = {e.evidence_id for e in logs.events}
    return len({f.subject for f in result.findings
                if f.finding_id in unattributed and f.subject in events})


def build_summary(result: CorrelationResult, background_count: int, review: int,
                  background: tuple[BackgroundGroup, ...] = ()) -> list[Reason]:
    lines: list[Reason] = []
    span = _actor_span(result)
    if result.affected_files and span:
        lines.append(_r("summary.compromise_found", files=len(result.affected_files),
                        actors=len(result.iocs.ips), first_at=span[0], last_at=span[1]))
    else:
        lines.append(_r("summary.no_compromise"))
    root = root_event(result)
    if root is not None and result.root_cause is not None:
        lines.append(_r("summary.root_cause", vuln_class=result.root_cause.vuln_class or "",
                        method=root.description.params.get("method", ""),
                        path=root.description.params.get("path", ""), at=root.ts.isoformat(),
                        confidence=result.root_cause.confidence.value))
        if result.root_cause.alternative_event_ids:
            lines.append(_r("summary.alternatives",
                            count=len(result.root_cause.alternative_event_ids)))
    elif result.affected_files:
        lines.append(_r("summary.root_cause_unknown"))
    bypass = next((g for g in background if g.rule_id == BYPASS_RULE), None)
    if bypass is not None:
        lines.append(_r("summary.unlinked_bypass", count=bypass.count, clients=bypass.clients,
                        paths=", ".join(unlinked_bypass_paths(result))))
    weakening = [g for g in result.gaps if g.affects]
    if weakening:
        lines.append(_r("summary.gaps_affect", count=len(weakening)))
    if review:
        lines.append(_r("summary.unexplained", count=review))
    if result.deleted_paths:
        lines.append(_r("summary.deleted", count=len(result.deleted_paths)))
    if background_count:
        lines.append(_r("summary.background", count=background_count))
    return lines


def _eradication(result: CorrelationResult) -> list[Reason]:
    recs: list[Reason] = []
    if result.affected_files:
        recs.append(_r("rec.eradication.remove_files",
                       paths=", ".join(f.path for f in result.affected_files)))
    root = root_event(result)
    vuln = result.root_cause.vuln_class if result.root_cause else None
    fixed: set[tuple[str, str]] = set()

    def fix(key: str, path: str) -> None:
        if (key, path) not in fixed:
            fixed.add((key, path))
            recs.append(_r(key, path=path))

    if root is not None and vuln in _FIX_FOR_VULN:
        fix(_FIX_FOR_VULN[vuln], root.description.params.get("path", ""))
    elif root is not None and root.description.key == "timeline.login_method_unknown":
        fix("rec.eradication.fix_login", root.description.params.get("path", ""))
    elif result.affected_files:
        recs.append(_r("rec.eradication.unknown_entry"))
    for path in unlinked_bypass_paths(result):
        fix("rec.eradication.fix_sqli_login", path)
    # The endpoint that accepted the script is a weakness too, even behind a login.
    for event in result.timeline:
        if event.description.key in _WRITE_KINDS and event.description.params.get(
                "method") in ("POST", "PUT"):
            fix("rec.eradication.fix_upload", event.description.params.get("path", ""))
    return recs


def build_recommendations(result: CorrelationResult, review: int) -> list[Reason]:
    compromised = bool(result.affected_files)
    recs = [_r("rec.containment.preserve")]
    if compromised:
        recs.append(_r("rec.containment.isolate"))
    if result.iocs.ips:
        recs.append(_r("rec.containment.block_ips", ips=", ".join(result.iocs.ips)))
    recs += _eradication(result)
    if compromised:
        recs += [_r("rec.recovery.rotate_credentials"), _r("rec.recovery.restore_clean")]
    bypassed = unlinked_bypass_paths(result)
    if bypassed:
        recs.append(_r("rec.recovery.revoke_sessions", paths=", ".join(bypassed)))
    if review or result.deleted_paths:
        recs.append(_r("rec.recovery.review_unexplained",
                       count=review + len(result.deleted_paths)))
    if result.iocs.urls:
        recs.append(_r("rec.recovery.monitor", urls=", ".join(result.iocs.urls)))
    kinds = {g.kind for g in result.gaps}
    if kinds & set(_TIME_GAPS):
        recs.append(_r("rec.lessons.log_retention"))
    if GapKind.NO_BASELINE in kinds:
        recs.append(_r("rec.lessons.baseline"))
    recs.append(_r("rec.lessons.fim"))
    if any(r.key == "creation.post_body_not_logged"
           for e in result.timeline for r in e.confidence_reasons):
        recs.append(_r("rec.lessons.log_uploads"))
    return recs


def without_noise(result: CorrelationResult, logs: LogCollection) -> CorrelationResult:
    """Drop unattributed log findings: they are summarized in the background groups, and
    keeping one record per bot request made report.json grow with the log (D65)."""
    events = {e.evidence_id for e in logs.events}
    unattributed = set(result.unattributed_finding_ids)
    noise = {f.finding_id for f in result.findings
             if f.finding_id in unattributed and f.subject in events}
    return result.model_copy(update={
        "findings": tuple(f for f in result.findings if f.finding_id not in noise),
        "unattributed_finding_ids": tuple(i for i in result.unattributed_finding_ids
                                          if i not in noise),
    })


def evidence_scope(logs: LogCollection, files: FileCollection,
                   baseline: FileCollection | None = None) -> EvidenceScope:
    times = [e.ts for e in logs.events]
    return EvidenceScope(
        log_first=min(times, default=None), log_last=max(times, default=None),
        log_events=len(logs.events), log_unparsed=len(logs.failures),
        error_events=len(logs.errors), error_unparsed=len(logs.error_failures),
        files=len(files.files), files_rejected=len(files.failures),
        baseline_files=len(baseline.files) if baseline is not None else None,
        collected_at=files.header.collected_at if files.header else None,
    )


def build_report(result: CorrelationResult, logs: LogCollection, case: CaseInfo,
                 run: RunInfo, scope: EvidenceScope | None = None,
                 trusted_proxies: tuple[str, ...] = ()) -> Report:
    background = background_groups(result, logs, trusted_proxies)
    review = len(result.unexplained_changes) + len(other_flagged_files(result))
    return Report(
        case=case, run=run, result=without_noise(result, logs),
        scope=scope or EvidenceScope(),
        summary=tuple(build_summary(result, background_requests(result, logs), review,
                                    tuple(background))),
        background=tuple(background),
        recommendations=tuple(build_recommendations(result, review)),
        limitations=tuple(_r(key) for key in (*LIMITATIONS, "limit.no_code_analysis")),
    )
