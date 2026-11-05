"""Build the language-neutral `Report` from a correlation result (deterministic).

Everything here is a rule over the result: which summary lines apply, which CSIRT
recommendations follow from the root cause, and how unrelated attack noise is grouped.
"""

from collections import Counter, defaultdict

from webforensics.correlate.actors import parse_networks, resolve_actor
from webforensics.correlate.engine import BYPASS_RULE
from webforensics.correlate.panel import PANEL_RULE
from webforensics.detect.file_rules import CLOAKING_RULE, JUDOL_RULE
from webforensics.models import (
    BackgroundGroup,
    CaseInfo,
    CitationKind,
    CodeLocation,
    CodeScope,
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
    close_log_files,
)
from webforensics.report.messages_id import PATH_GROUP, URL_GROUP

TOP_CLIENTS = 5
_TIME_GAPS = (GapKind.NO_LOG_LINES, GapKind.PARSE_ERRORS, GapKind.ROTATION_BOUNDARY)
_WRITE_KINDS = ("timeline.upload_exploit", "timeline.write_exploit",
                "timeline.file_write_request")
# A write after a clean login (D94): the way in is a valid credential, not a flaw.
_AFTER_LOGIN_KINDS = ("timeline.upload_after_login", "timeline.write_after_login")
_FIX_FOR_VULN = {
    "unrestricted_file_upload": "rec.eradication.fix_upload",
    "sql_injection_auth_bypass": "rec.eradication.fix_sqli_login",
    "sql_injection_file_write": "rec.eradication.fix_sqli_write",
    "remote_code_execution": "rec.eradication.patch_rce",
    "sql_injection": "rec.eradication.fix_sqli_write",
    "os_command_injection": "rec.eradication.fix_cmdi",
    "path_traversal": "rec.eradication.fix_traversal",
}
LIMITATIONS = ("limit.automated", "limit.post_body", "limit.timestamps",
               "limit.log_tampering", "limit.shared_ip")


def _r(key: str, **params: object) -> Reason:
    return Reason(key=key, params={k: str(v) for k, v in params.items()})


def _webroot_seen(result: CorrelationResult) -> bool:
    """False when the log-only scripts were found with no webroot evidence at all (D88)."""
    return not any(e.description.key == "timeline.log_only_file_unverified"
                   for e in result.timeline)


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


def panel_leads(result: CorrelationResult) -> tuple[int, int, list[str]]:
    """(site requests, addresses, panel paths) of sites managed through a hosting panel
    by addresses never seen before (D98). A lead, not an accusation."""
    leads = [f for f in result.findings if f.rule_id == PANEL_RULE]
    count = sum(int(f.reasons[0].params["count"]) for f in leads)
    paths = sorted({p for f in leads for p in f.reasons[0].params["paths"].split(", ")})
    return count, len(leads), paths


# A folder with at least this many paths is named once with a count: judol kits drop
# hundreds of pages in one folder, and a list of all of them hides the advice (D98). The
# full list stays in the affected-files section and report.json.
GROUP_MIN = 5


def compact_paths(paths: list[str], template: str) -> str:
    """Paths joined by commas, with large folders as one `template` entry."""
    folders: dict[str, list[str]] = {}
    for path in paths:
        folders.setdefault(path.rsplit("/", 1)[0] + "/" if "/" in path else "", []).append(path)
    parts: list[str] = []
    for folder, inside in folders.items():
        if folder and len(inside) >= GROUP_MIN:
            parts.append(template.format(count=len(inside), folder=folder))
        else:
            parts.extend(inside)
    return ", ".join(parts)


def judol_files(result: CorrelationResult) -> tuple[list[str], list[str]]:
    """(affected files with gambling spam, affected files that cloak) (D98)."""
    rules: dict[str, set[str]] = defaultdict(set)
    for finding in result.findings:
        rules[finding.subject].add(finding.rule_id)
    spam = [f.path for f in result.affected_files if JUDOL_RULE in rules[f.evidence_id]]
    cloak = [f.path for f in result.affected_files if CLOAKING_RULE in rules[f.evidence_id]]
    return spam, cloak


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


# Above this share of unreadable access-log lines, the summary says so first: a wrong
# --log-format or a damaged file must never read as "nothing found" (D96).
UNREADABLE_SHARE = 0.10
UNREADABLE_MIN = 5  # one cut line in a tiny log is not a format problem


def unreadable_warning(logs: LogCollection) -> Reason | None:
    unread, total = len(logs.failures), len(logs.failures) + len(logs.events)
    if not unread:
        return None
    if logs.events and (unread < UNREADABLE_MIN or unread / total <= UNREADABLE_SHARE):
        return None
    key = "summary.log_unreadable" if not logs.events else "summary.log_mostly_unreadable"
    return _r(key, unread=unread, total=total, percent=round(100 * unread / total))


def build_summary(result: CorrelationResult, background_count: int, review: int,
                  background: tuple[BackgroundGroup, ...] = (),
                  unreadable: Reason | None = None) -> list[Reason]:
    lines: list[Reason] = [unreadable] if unreadable is not None else []
    span = _actor_span(result)
    compromised = bool(result.affected_files or result.log_only_files)
    if compromised and span and result.iocs.ips:
        if result.affected_files:
            lines.append(_r("summary.compromise_found", files=len(result.affected_files),
                            actors=len(result.iocs.ips), first_at=span[0], last_at=span[1]))
        else:  # only scripts seen in the logs (D88)
            lines.append(_r("summary.compromise_found_scripts",
                            scripts=len(result.log_only_files), actors=len(result.iocs.ips),
                            first_at=span[0], last_at=span[1]))
    elif compromised:
        # No request ties anyone to the files (e.g. the log was cut): say so (D87).
        lines.append(_r("summary.compromise_found_no_actor", files=len(result.affected_files)))
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
    elif compromised:
        lines.append(_r("summary.root_cause_unknown"))
    if result.log_only_files:
        lines.append(_r("summary.log_only" if _webroot_seen(result)
                        else "summary.log_only_unverified", count=len(result.log_only_files),
                        paths=", ".join(result.log_only_files)))
    bypass = next((g for g in background if g.rule_id == BYPASS_RULE), None)
    if bypass is not None:
        lines.append(_r("summary.unlinked_bypass", count=bypass.count, clients=bypass.clients,
                        paths=", ".join(unlinked_bypass_paths(result))))
    spam, cloak = judol_files(result)
    if spam:
        lines.append(_r("summary.judol", count=len(spam)))
    if cloak:
        lines.append(_r("summary.cloaking", count=len(cloak)))
    sites, clients, panel_paths = panel_leads(result)
    if sites:
        lines.append(_r("summary.panel_new_address", count=sites, clients=clients,
                        paths=", ".join(panel_paths)))
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
                       paths=compact_paths([f.path for f in result.affected_files],
                                           PATH_GROUP)))
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
    elif root is not None and root.description.key in _AFTER_LOGIN_KINDS:
        fix("rec.eradication.reset_credentials", root.description.params.get("login_path", ""))
        fix("rec.eradication.restrict_admin_upload", root.description.params.get("path", ""))
    elif result.affected_files:
        recs.append(_r("rec.eradication.unknown_entry"))
    for path in unlinked_bypass_paths(result):
        fix("rec.eradication.fix_sqli_login", path)
    # The endpoint that accepted the script is a weakness too, even behind a login.
    for event in result.timeline:
        if event.description.key in _WRITE_KINDS and event.description.params.get(
                "method") in ("POST", "PUT"):
            # A writer only inferred for a log-only script may itself be the attacker's
            # script, not a weak upload form (D88).
            inferred = any(r.key == "logonly.write_inferred" for r in event.confidence_reasons)
            fix("rec.eradication.check_inferred_writer" if inferred
                else "rec.eradication.fix_upload", event.description.params.get("path", ""))
    return recs


def build_recommendations(result: CorrelationResult, review: int,
                          fim_in_use: bool = False,
                          code_findings: tuple[CodeLocation, ...] = ()) -> list[Reason]:
    compromised = bool(result.affected_files or result.log_only_files)
    recs = [_r("rec.containment.preserve")]
    if compromised:
        recs.append(_r("rec.containment.isolate"))
    if result.iocs.ips:
        recs.append(_r("rec.containment.block_ips", ips=", ".join(result.iocs.ips)))
    recs += _eradication(result)
    if result.log_only_files:
        key = ("rec.eradication.check_log_only" if _webroot_seen(result)
               else "rec.eradication.check_log_only_unverified")
        recs.append(_r(key, paths=", ".join(result.log_only_files)))
    recs += [_r("rec.eradication.fix_code_line", file=f.file, line=f.line)
             for f in code_findings]
    if compromised:
        recs += [_r("rec.recovery.rotate_credentials"), _r("rec.recovery.restore_clean")]
    bypassed = unlinked_bypass_paths(result)
    if bypassed:
        recs.append(_r("rec.recovery.revoke_sessions", paths=", ".join(bypassed)))
    sites, _, panel_paths = panel_leads(result)
    if sites:
        recs.append(_r("rec.recovery.verify_panel_sites", paths=", ".join(panel_paths)))
    if review or result.deleted_paths:
        recs.append(_r("rec.recovery.review_unexplained",
                       count=review + len(result.deleted_paths)))
    if result.iocs.urls:
        recs.append(_r("rec.recovery.monitor",
                       urls=compact_paths(list(result.iocs.urls), URL_GROUP)))
    spam, cloak = judol_files(result)
    if spam or cloak:
        recs.append(_r("rec.recovery.judol_search_index"))
    if cloak:
        recs.append(_r("rec.recovery.judol_cloaking", paths=", ".join(cloak)))
    kinds = {g.kind for g in result.gaps}
    if kinds & set(_TIME_GAPS):
        recs.append(_r("rec.lessons.log_retention"))
    if GapKind.NO_BASELINE in kinds:
        recs.append(_r("rec.lessons.baseline"))
    if GapKind.PARTIAL_LOG_SOURCE in kinds:
        recs.append(_r("rec.lessons.wazuh_archives"))
    if not fim_in_use:
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
                   baseline: FileCollection | None = None,
                   file_adapter: str = "file") -> EvidenceScope:
    times = [e.ts for e in logs.events]
    return EvidenceScope(
        log_first=min(times, default=None), log_last=max(times, default=None),
        log_events=len(logs.events), log_unparsed=len(logs.failures),
        error_events=len(logs.errors), error_unparsed=len(logs.error_failures),
        files=len(files.files), files_rejected=len(files.failures),
        baseline_files=len(baseline.files) if baseline is not None else None,
        collected_at=files.header.collected_at if files.header else None,
        file_adapter=file_adapter,
    )


def code_limitations(code_scope: CodeScope | None) -> tuple[str, ...]:
    if code_scope is None:
        return ()
    if code_scope.analyzed:
        return ("limit.code_scope",)
    return ("limit.no_code_content",)


def build_report(result: CorrelationResult, logs: LogCollection, case: CaseInfo,
                 run: RunInfo, scope: EvidenceScope | None = None,
                 trusted_proxies: tuple[str, ...] = (),
                 code_findings: tuple[CodeLocation, ...] = (),
                 code_scope: CodeScope | None = None) -> Report:
    try:
        return _build_report(result, logs, case, run, scope, trusted_proxies,
                             code_findings, code_scope)
    finally:
        close_log_files()  # background examples read log lines back (D88)


def _build_report(result: CorrelationResult, logs: LogCollection, case: CaseInfo,
                  run: RunInfo, scope: EvidenceScope | None,
                  trusted_proxies: tuple[str, ...], code_findings: tuple[CodeLocation, ...],
                  code_scope: CodeScope | None) -> Report:
    background = background_groups(result, logs, trusted_proxies)
    review = len(result.unexplained_changes) + len(other_flagged_files(result))
    return Report(
        case=case, run=run, result=without_noise(result, logs),
        scope=scope or EvidenceScope(),
        summary=tuple(build_summary(result, background_requests(result, logs), review,
                                    tuple(background), unreadable_warning(logs))),
        background=tuple(background),
        recommendations=tuple(build_recommendations(
            result, review, fim_in_use=scope is not None and scope.file_adapter == "wazuh",
            code_findings=code_findings)),
        code_findings=code_findings, code_scope=code_scope,
        limitations=tuple(_r(key) for key in (
            *LIMITATIONS, *(("limit.fim_blind_spots",) if scope and scope.file_adapter == "wazuh"
                            else ()), *code_limitations(code_scope))),
    )
