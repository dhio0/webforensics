"""File-first correlation engine (plan §4).

For each suspicious file: anchor time -> requests that hit it -> the request that most
likely wrote it -> the actor's entry point (root cause). Everything is deterministic:
inputs are sorted, ties break on log file and line number, and ids are content hashes.
"""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from urllib.parse import unquote

from webforensics.attack.mitre import tactic_for
from webforensics.correlate import requests as rq
from webforensics.correlate.actors import (
    LoginOutcome,
    login_outcomes,
    parse_networks,
    resolve_actor,
)
from webforensics.correlate.anchor import Anchor, choose_anchor, timestomp_signal
from webforensics.correlate.baseline import apply_baseline
from webforensics.correlate.confidence import cap, lower, rank
from webforensics.correlate.config import CorrelationConfig
from webforensics.correlate.gaps import coverage_gap, make_gap, parse_error_gaps, silence_gaps
from webforensics.correlate.seeds import (
    is_strong_seed,
    lonely_finding,
    lonely_writes,
    rare_post_finding,
)
from webforensics.detect import RULESET_VERSION
from webforensics.detect.file_rules import detect_file
from webforensics.detect.log_rules import detect_requests
from webforensics.models import (
    Citation,
    Confidence,
    CorrelationResult,
    ErrorLogEvent,
    EvidenceGap,
    FileCollection,
    FileEvidence,
    Finding,
    FindingCategory,
    GapKind,
    Iocs,
    LogCollection,
    LogEvent,
    Reason,
    RootCause,
    Severity,
    TimelineEvent,
    TimestampBasis,
    stable_id,
)

TIMESTOMP_RULE = "FILE-ANTIFORENSICS-TIMESTOMP"
# Only these gap kinds describe missing time; the others are listed but do not downgrade.
_TIME_GAPS = (GapKind.NO_LOG_LINES, GapKind.PARSE_ERRORS, GapKind.ROTATION_BOUNDARY)
_LAST = "￿"  # sorts after any log file name
_WRITE_METHODS = ("POST", "PUT", "PATCH")
# Rules that judge only the URL, so they fire for anyone who merely fetches the file.
_URL_ONLY_RULES = frozenset({"LOG-WEBSHELL-UPLOAD-DIR"})


@dataclass
class _Draft:
    """A timeline event under construction; turned into a frozen TimelineEvent at the end."""

    kind: str
    subject: str  # evidence id the event is about
    ts: datetime
    basis: TimestampBasis
    params: dict[str, str]
    citations: list[Citation]
    confidence: Confidence
    order: tuple[str, int, int]  # tie-break for events in the same second
    window: tuple[datetime, datetime]  # time span this conclusion depends on
    technique: str | None = None
    actor: str | None = None
    reasons: list[Reason] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    is_root_cause: bool = False
    # A root-cause claim can be weaker than the event it sits on (see _entry_point).
    root_cap: Confidence = Confidence.HIGH
    root_reasons: list[Reason] = field(default_factory=list)

    @property
    def event_id(self) -> str:
        return stable_id("timeline", self.kind, self.subject)

    def build(self) -> TimelineEvent:
        return TimelineEvent(
            event_id=self.event_id, ts=self.ts, ts_basis=self.basis,
            mitre_tactic=tactic_for(self.technique), mitre_technique=self.technique,
            actor=self.actor, description=Reason(key=f"timeline.{self.kind}", params=self.params),
            citations=tuple(self.citations), confidence=self.confidence,
            confidence_reasons=tuple(self.reasons), finding_ids=tuple(self.finding_ids),
            is_root_cause=self.is_root_cause,
        )


@dataclass(frozen=True)
class _Write:
    """The request believed to have written a file, from the access or the error log."""

    actor: str
    method: str | None
    path: str | None
    ts: datetime
    position: tuple[datetime, str, int]  # requests sorting before this came earlier
    user_agent: str | None
    level: rq.WriteLevel
    findings: tuple[Finding, ...]


@dataclass
class _Chain:
    """Everything traced from one suspicious file."""

    file: FileEvidence
    file_event: _Draft
    findings: list[Finding]
    creation: _Draft | None = None
    write: _Write | None = None
    alternatives: list[_Draft] = field(default_factory=list)
    root: _Draft | None = None  # entry point; may be the creation draft itself
    invocations: list[_Draft] = field(default_factory=list)
    invoker_ips: set[str] = field(default_factory=set)
    # Invokers who did more than fetch the file (POST, or a flagged request like ?cmd=).
    suspect_invokers: set[str] = field(default_factory=set)
    rare_post: Finding | None = None


@lru_cache(maxsize=65536)
def _url_key(path: str) -> str:
    return unquote(path)


class _Index:
    """Log evidence plus the derived lookups the steps need.

    Everything a step asks for (requests to a URL, an actor's requests, requests in a time
    window) is answered from an index built once, so the cost grows with the log size
    plus the number of seeds, not their product (D53).
    """

    def __init__(self, logs: LogCollection, config: CorrelationConfig) -> None:
        self.config = config
        self.events = sorted(logs.events, key=lambda e: (e.ts, e.log_file, e.line_no))
        self.times = [e.ts for e in self.events]
        self.by_id = {e.evidence_id: e for e in self.events}
        self.findings = detect_requests(self.events)
        self.by_subject: dict[str, list[Finding]] = defaultdict(list)
        for finding in self.findings:
            self.by_subject[finding.subject].append(finding)
        proxies = parse_networks(config.trusted_proxies)
        self.actor_of = {e.evidence_id: resolve_actor(e, proxies) for e in self.events}
        self.by_actor: dict[str, list[LogEvent]] = defaultdict(list)
        self.by_url: dict[str, list[LogEvent]] = defaultdict(list)
        for event in self.events:
            self.by_actor[self.actor_of[event.evidence_id]].append(event)
            self.by_url[_url_key(event.path or "")].append(event)
        self.actor_times = {a: [e.ts for e in own] for a, own in self.by_actor.items()}
        self.logins = login_outcomes(self.events, self.actor_of,
                                     frozenset(self.by_subject))
        self.errors = sorted(logs.errors, key=lambda e: (e.ts, e.log_file, e.line_no))
        self.error_times = [e.ts for e in self.errors]
        self.errors_by_ip: dict[str, list[ErrorLogEvent]] = defaultdict(list)
        for err in self.errors:
            if err.client_ip:
                self.errors_by_ip[err.client_ip].append(err)
        self.span = (self.times[0], self.times[-1]) if self.times else None

    def between(self, start: datetime, end: datetime) -> list[LogEvent]:
        """Requests with start <= ts <= end, in log order."""
        return self.events[bisect_left(self.times, start):bisect_right(self.times, end)]

    def errors_between(self, start: datetime, end: datetime) -> list[ErrorLogEvent]:
        return self.errors[bisect_left(self.error_times, start):
                           bisect_right(self.error_times, end)]

    def actor_since(self, actor: str, since: datetime) -> list[LogEvent]:
        own = self.by_actor.get(actor, [])
        return own[bisect_left(self.actor_times.get(actor, []), since):]

    def hits(self, file: FileEvidence) -> list[LogEvent]:
        """Requests to any URL that serves this file, in log order."""
        found = [e for url in file.url_paths for e in self.by_url.get(url, [])]
        return sorted(found, key=lambda e: (e.ts, e.log_file, e.line_no))

    def of(self, event: LogEvent) -> list[Finding]:
        return self.by_subject.get(event.evidence_id, [])

    def actor(self, event: LogEvent) -> str:
        return self.actor_of[event.evidence_id]

    def login_succeeded(self, event: LogEvent) -> bool:
        outcome = self.logins.get(event.evidence_id)
        return outcome is not None and outcome[0] is LoginOutcome.SUCCEEDED

    def login_failed(self, event: LogEvent) -> bool:
        outcome = self.logins.get(event.evidence_id)
        return outcome is not None and outcome[0] is LoginOutcome.FAILED

    def errors_near(self, event: LogEvent) -> list[ErrorLogEvent]:
        """Error-log entries for the same connection, request and second (± skew)."""
        skew = _seconds(self.config.clock_skew_s)
        return [
            err for err in self.errors_by_ip.get(event.client_ip, [])
            if abs(err.ts - event.ts) <= skew
            and (err.path is None or (err.path == event.path and err.method == event.method))
        ]


def _seconds(value: int) -> timedelta:
    return timedelta(seconds=value)


def _log_draft(index: _Index, kind: str, event: LogEvent, confidence: Confidence,
               technique: str | None, **params: str) -> _Draft:
    base = {"method": event.method or "", "path": event.path or "", "status": str(event.status)}
    return _Draft(
        kind=kind, subject=event.evidence_id, ts=event.ts, basis=TimestampBasis.LOG,
        params={**base, **params}, citations=[event.citation()], confidence=confidence,
        order=(event.log_file, event.line_no, 0), window=(event.ts, event.ts),
        technique=technique, actor=index.actor(event),
        finding_ids=[finding.finding_id for finding in index.of(event)],
    )


def _access_write(event: LogEvent, index: _Index) -> _Write:
    findings = index.of(event)
    return _Write(
        actor=index.actor(event), method=event.method, path=event.path, ts=event.ts,
        position=(event.ts, event.log_file, event.line_no), user_agent=event.user_agent,
        level=rq.write_level(event, findings), findings=tuple(findings),
    )


# --- Step 1 helpers -----------------------------------------------------------------


def _timestomp_finding(file: FileEvidence, reason: Reason) -> Finding:
    return Finding(
        finding_id=stable_id(TIMESTOMP_RULE, file.evidence_id), rule_id=TIMESTOMP_RULE,
        rule_version=RULESET_VERSION, category=FindingCategory.ANTI_FORENSICS,
        subject=file.evidence_id, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        reasons=(reason,), citations=(file.citation(),), mitre=("T1070.006",),
    )


# --- Steps 2-4: anchor, invocations, creation ----------------------------------------


def _file_draft(file: FileEvidence, anchor: Anchor, findings: list[Finding],
                config: CorrelationConfig) -> _Draft:
    kind = {TimestampBasis.BTIME: "file_created", TimestampBasis.CTIME: "file_changed"}.get(
        anchor.basis, "file_modified_mtime")
    suspicious = any(f.category in (FindingCategory.WEBSHELL, FindingCategory.PERSISTENCE)
                     for f in findings)
    return _Draft(
        kind=kind, subject=file.evidence_id, ts=anchor.ts, basis=anchor.basis,
        params={"path": file.path, "sha256": file.sha256,
                "baseline_status": file.baseline_status.value},
        citations=[file.citation()], confidence=anchor.max_confidence,
        order=(_LAST, 0, 1),
        window=(anchor.ts - _seconds(config.creation_window_s),
                anchor.ts + _seconds(config.clock_skew_s)),
        technique="T1505.003" if suspicious else None,
        reasons=list(anchor.reasons), finding_ids=[f.finding_id for f in findings],
    )


def _invocations(chain: _Chain, anchor: Anchor, index: _Index) -> None:
    config = index.config
    earliest = anchor.ts - _seconds(config.clock_skew_s)
    hits = index.hits(chain.file)
    before = [e for e in hits if e.ts < earliest and rq.is_success(e)]
    after = [e for e in hits if e.ts >= earliest]
    if before and anchor.basis is TimestampBasis.BTIME:
        # Served successfully before it was born: the anchor or the file history is off.
        chain.file_event.confidence = cap(chain.file_event.confidence, Confidence.MEDIUM)
        chain.file_event.reasons.append(Reason(
            key="file.invoked_before_anchor",
            params={"count": str(len(before)), "first_line": str(before[0].line_no)}))
    chain.file_event.params["invocations"] = str(len(after))
    for event in after[: config.max_invocations]:
        chain.invocations.append(_log_draft(index, "file_invoked", event, Confidence.HIGH,
                                            "T1505.003", file=chain.file.path))
        chain.invoker_ips.add(index.actor(event))
        behaviour = [f for f in index.of(event) if f.rule_id not in _URL_ONLY_RULES]
        if rq.is_success(event) and (event.method in _WRITE_METHODS or behaviour):
            chain.suspect_invokers.add(index.actor(event))
    chain.rare_post = rare_post_finding(chain.file, hits, index.actor_of, earliest, config)
    if chain.rare_post is not None:
        chain.findings.append(chain.rare_post)
        chain.file_event.finding_ids.append(chain.rare_post.finding_id)


def _client_error(event: LogEvent) -> bool:
    """4xx: the app refused the request, so it did not write the file (5xx still might)."""
    return 400 <= event.status < 500


def _candidate_key(event: LogEvent, index: _Index, anchor_ts: datetime, invokers: set[str]):
    """Sorts best first: logged within ±skew of the write, write semantics, success, same
    actor as the file's users, closeness, then log order.

    Closeness comes first because the writing request is logged within seconds of the
    file's birth (nginx at request end, Apache at start of a short request). Without
    it, an admin's photo upload a minute earlier outranks the comment POST that really
    produced a cache file (D54).
    """
    distance = abs((event.ts - anchor_ts).total_seconds())
    tight = distance <= index.config.clock_skew_s
    return (not tight, -rq.write_level(event, index.of(event)), not rq.is_success(event),
            index.actor(event) not in invokers, distance, event.log_file, event.line_no)


def _creation(chain: _Chain, anchor: Anchor, index: _Index) -> None:
    start, end = chain.file_event.window
    candidates = [
        e for e in index.between(start, end)
        if rq.write_level(e, index.of(e)) > rq.WriteLevel.NONE and not _client_error(e)
    ]
    if not candidates:
        if not _creation_from_error_log(chain, anchor, index):
            chain.file_event.reasons.append(Reason(key="creation.no_http_request_found"))
        return

    def key(e: LogEvent):
        return _candidate_key(e, index, anchor.ts, chain.invoker_ips)

    ranked = sorted(candidates, key=key)
    best = ranked[0]
    rivals = [e for e in ranked[1:] if key(e)[:4] == key(best)[:4]]
    write = _access_write(best, index)
    if write.level < rq.WriteLevel.LIKELY:
        # An upload-like request further away stays visible as an alternative.
        rivals += [e for e in ranked[1:] if e not in rivals
                   and rq.write_level(e, index.of(e)) is rq.WriteLevel.LIKELY]

    confidence, reasons = anchor.max_confidence, []
    if rivals:
        confidence = cap(confidence, Confidence.MEDIUM)
        reasons.append(Reason(key="creation.multiple_candidates",
                              params={"count": str(len(ranked))}))
    else:
        reasons.append(Reason(key="creation.single_candidate"))
    if write.actor in chain.invoker_ips:
        reasons.append(Reason(key="creation.same_actor_invoked_file"))
    else:
        confidence = cap(confidence, Confidence.MEDIUM)
        reasons.append(Reason(key="creation.no_invocation_by_actor"))
    if write.level < rq.WriteLevel.LIKELY:
        confidence = cap(confidence, Confidence.MEDIUM)
        reasons.append(Reason(key="creation.endpoint_not_upload_like"))
    if best.method == "POST":
        reasons.append(Reason(key="creation.post_body_not_logged"))

    draft = _log_draft(index, "file_write_request", best, confidence, "T1505.003",
                       file=chain.file.path)
    draft.citations.append(chain.file.citation())
    draft.reasons, draft.window = reasons, chain.file_event.window
    chain.creation, chain.write = draft, write
    # The file event sorts right after the request that wrote it when they share a second.
    chain.file_event.order = (best.log_file, best.line_no, 1)
    for rival in rivals:
        alt = _log_draft(index, "file_write_candidate", rival, Confidence.LOW, "T1505.003",
                         file=chain.file.path)
        alt.window = chain.file_event.window
        alt.reasons.append(Reason(key="creation.alternative_candidate"))
        chain.alternatives.append(alt)


def _creation_from_error_log(chain: _Chain, anchor: Anchor, index: _Index) -> bool:
    """No access-log candidate: an error-log entry for a write request may still exist."""
    start, end = chain.file_event.window
    candidates = [
        err for err in index.errors_between(start, end)
        if err.method in _WRITE_METHODS and err.client_ip
    ]
    if not candidates:
        return False
    best = min(candidates, key=lambda err: (
        -rq.write_level_for(err.method, err.path, []), abs((err.ts - anchor.ts).total_seconds()),
        err.log_file, err.line_no))
    draft = _Draft(
        kind="file_write_request", subject=best.evidence_id, ts=best.ts,
        basis=TimestampBasis.LOG,
        params={"method": best.method or "", "path": best.path or "", "status": "",
                "file": chain.file.path},
        citations=[best.citation(), chain.file.citation()], confidence=Confidence.LOW,
        order=(best.log_file, best.line_no, 0), window=chain.file_event.window,
        technique="T1505.003", actor=best.client_ip,
        reasons=[Reason(key="creation.error_log_only"),
                 Reason(key="error_log.assumed_utc_offset",
                        params={"offset": best.assumed_utc_offset})],
    )
    chain.creation = draft
    chain.write = _Write(
        actor=best.client_ip or "", method=best.method, path=best.path, ts=best.ts,
        position=(best.ts, "", 0), user_agent=None,
        level=rq.write_level_for(best.method, best.path, []), findings=(),
    )
    chain.file_event.order = (best.log_file, best.line_no, 1)
    return True


# --- Step 5: trace back to the entry point --------------------------------------------


def _write_vuln_class(write: _Write) -> str:
    """Name the weakness only when the request itself shows it; otherwise leave it open."""
    if write.level is not rq.WriteLevel.LIKELY:
        return ""
    if rq.has_sqli(list(write.findings)):
        return "sql_injection_file_write"
    if write.method in ("POST", "PUT"):
        return "unrestricted_file_upload"
    return ""


def _actor_history(index: _Index, write: _Write) -> list[LogEvent]:
    since = write.ts - _seconds(index.config.lookback_s)
    history = []
    for e in index.actor_since(write.actor, since):
        if (e.ts, e.log_file, e.line_no) >= write.position:
            break
        if rq.shares_area(e.path, write.path):
            history.append(e)
    return history


def _entry_point(chain: _Chain, index: _Index) -> None:
    creation, write = chain.creation, chain.write
    if creation is None or write is None:
        return
    history = _actor_history(index, write)
    bypass = next((e for e in history if rq.is_login_endpoint(e.path)
                   and rq.has_sqli(index.of(e)) and index.login_succeeded(e)), None)
    login = next((e for e in history if index.login_succeeded(e)), None)
    entry = bypass or login
    if entry is None:
        creation.kind = "upload_exploit" if write.level is rq.WriteLevel.LIKELY else "write_exploit"
        creation.technique = "T1190"
        creation.params["vuln_class"] = _write_vuln_class(write)
        # "No login seen" is evidence of absence: the session may predate the logs.
        creation.root_cap = Confidence.MEDIUM
        creation.root_reasons += [Reason(key="root.write_without_prior_login"),
                                  Reason(key="confidence.no_login_is_absence_of_evidence")]
        chain.root = creation
        return
    outcome_reason = index.logins[entry.evidence_id][1]
    if bypass is not None:
        root = _log_draft(index, "auth_bypass_sqli", bypass,
                          cap(creation.confidence, Confidence.MEDIUM), "T1190",
                          vuln_class="sql_injection_auth_bypass")
        root.reasons += [Reason(key="root.sqli_login_then_write_same_area"), outcome_reason,
                         Reason(key="confidence.session_link_inferred")]
    else:
        root = _log_draft(index, "login_method_unknown", entry, Confidence.LOW, "T1078",
                          vuln_class="")
        root.reasons += [Reason(key="root.login_then_write_same_area"), outcome_reason,
                         Reason(key="confidence.auth_method_not_visible")]
    if entry.user_agent and write.user_agent and entry.user_agent != write.user_agent:
        # Same IP, different client software: could be a tool switch or a shared IP (NAT).
        root.confidence = lower(root.confidence)
        root.reasons.append(Reason(key="actor.user_agent_changed"))
    root.window = (root.ts, creation.window[1])
    chain.root = root


# --- Steps 6-7: context, corroboration and gaps --------------------------------------


def _context_draft(event: LogEvent, index: _Index, first: bool) -> _Draft | None:
    findings = index.of(event)
    if findings:
        top = findings[0]
        kind = "recon" if top.category is FindingCategory.RECON else "exploit_attempt"
        confidence = max((f.confidence for f in findings), key=rank)
        return _log_draft(index, kind, event, confidence, top.mitre[0] if top.mitre else None,
                          rule_id=top.rule_id)
    if index.login_failed(event):
        draft = _log_draft(index, "login_failed", event, Confidence.HIGH, None)
        draft.reasons.append(index.logins[event.evidence_id][1])
        return draft
    if first:
        return _log_draft(index, "actor_first_seen", event, Confidence.HIGH, None)
    return None


def _context(index: _Index, actors: set[str], taken: set[str],
             roots: list[_Draft]) -> list[_Draft]:
    """The implicated actors' first request, failed logins, and other flagged requests."""
    drafts: list[_Draft] = []
    first_root = min((r.ts for r in roots), default=None)
    for actor in sorted(actors):
        own = index.by_actor.get(actor, [])
        if first_root is not None:
            own = index.actor_since(actor, first_root - _seconds(index.config.lookback_s))
        for position, event in enumerate(own):
            if event.evidence_id in taken:
                continue
            draft = _context_draft(event, index, first=position == 0)
            if draft is not None:
                drafts.append(draft)
                taken.add(event.evidence_id)
    return drafts


def _corroborate(drafts: list[_Draft], index: _Index) -> None:
    """Attach matching error-log lines to access-log events as extra citations."""
    for draft in drafts:
        event = index.by_id.get(draft.subject)
        if event is None or draft.basis is not TimestampBasis.LOG:
            continue
        matches = index.errors_near(event)
        if not matches:
            continue
        draft.citations += [err.citation() for err in matches]
        draft.reasons.append(Reason(key="error_log.corroborates", params={
            "lines": ",".join(str(err.line_no) for err in matches),
            "offset": matches[0].assumed_utc_offset}))


def _overlaps(gap: EvidenceGap, window: tuple[datetime, datetime]) -> bool:
    start, end = window
    return (gap.start is None or gap.start < end) and (gap.end is None or gap.end > start)


def _apply_gaps(gaps: list[EvidenceGap], drafts: list[_Draft]) -> list[EvidenceGap]:
    """Downgrade each event once if any time gap overlaps what it depends on."""
    affects: dict[str, list[str]] = defaultdict(list)
    for draft in drafts:
        hit = [g for g in gaps if g.kind in _TIME_GAPS and _overlaps(g, draft.window)]
        for gap in hit:
            affects[gap.gap_id].append(draft.event_id)
            draft.reasons.append(Reason(key="confidence.gap_overlap",
                                        params={"gap_id": gap.gap_id}))
        if hit:
            draft.confidence = lower(draft.confidence)
    return [g.model_copy(update={"affects": tuple(sorted(affects.get(g.gap_id, [])))})
            for g in gaps]


# --- Step 8: assemble ---------------------------------------------------------------


def _trace(file: FileEvidence, findings: list[Finding], index: _Index,
           weak: bool) -> _Chain | None:
    anchor = choose_anchor(file, index.config)
    if anchor is None:
        return None
    chain = _Chain(file=file, file_event=_file_draft(file, anchor, findings, index.config),
                   findings=list(findings))
    if weak:
        chain.file_event.confidence = cap(chain.file_event.confidence, Confidence.MEDIUM)
        chain.file_event.reasons.append(Reason(key="seed.lonely_write"))
    _invocations(chain, anchor, index)
    _creation(chain, anchor, index)
    if chain.creation is not None:
        # A PUT to the file's own URL is the write, not a later use of the file.
        chain.invocations = [d for d in chain.invocations if d.subject != chain.creation.subject]
    _entry_point(chain, index)
    return chain


def _timestomp_draft(file: FileEvidence, finding: Finding, file_event: _Draft) -> _Draft:
    ts = file.ctime or file_event.ts
    return _Draft(
        kind="file_timestomp", subject=file.evidence_id, ts=ts, basis=TimestampBasis.CTIME,
        params={"path": file.path, **finding.reasons[0].params}, citations=[file.citation()],
        confidence=finding.confidence, order=(_LAST, 0, 2), window=(ts, ts),
        technique="T1070.006", finding_ids=[finding.finding_id],
    )


def _iocs(chains: list[_Chain], drafts: list[_Draft], actors: set[str],
          index: _Index) -> Iocs:
    agents = {
        index.by_id[d.subject].user_agent for d in drafts
        if d.subject in index.by_id and d.actor in actors and index.by_id[d.subject].user_agent
    }
    return Iocs(
        ips=tuple(sorted(actors)), user_agents=tuple(sorted(a for a in agents if a)),
        sha256s=tuple(sorted({c.file.sha256 for c in chains})),
        paths=tuple(sorted(c.file.path for c in chains)),
        urls=tuple(sorted({url for c in chains for url in c.file.url_paths})),
    )


def _input_gaps(files: FileCollection, logs: LogCollection, index: _Index,
                baseline_used: bool) -> list[EvidenceGap]:
    gaps = [*files.gaps, *silence_gaps(index.events, index.config), *parse_error_gaps(logs)]
    if not baseline_used:
        gaps.append(make_gap(GapKind.NO_BASELINE, None, None, None, "gap.no_baseline"))
    return gaps


_CONTENT_RULES = ("FILE-WEBSHELL-REQUEST-EXEC", "FILE-WEBSHELL-OBFUSCATION")


def _looks_generated(chain: _Chain, file_findings: list[Finding], stomped: bool,
                     index: _Index) -> bool:
    """A code file the app itself probably wrote (cache, compiled template): flagged only by
    its path, never requested by URL, and not written by an upload-like request.

    Only applies when the logs cover its write time, so missing logs never hide a shell.
    Such files go to `unexplained_changes` for review instead of the incident (D56).
    """
    if stomped or chain.invocations or chain.rare_post is not None:
        return False
    if any(f.rule_id in _CONTENT_RULES for f in file_findings):
        return False
    if chain.write is not None and chain.write.level is rq.WriteLevel.LIKELY:
        return False
    covered = coverage_gap(chain.file_event.ts, chain.file.path, index.span,
                           index.config) is None
    return covered and index.span is not None


def _implicated_actors(chains: list[_Chain], roots: list[_Draft]) -> set[str]:
    actors = {d.actor for d in roots if d.actor}
    actors |= {c.write.actor for c in chains if c.write and c.write.actor}
    # A plain GET to a webshell URL (crawler, curious visitor) stays in the timeline but
    # does not make that client an attacker; using it (POST, ?cmd=) does (D55).
    actors |= {ip for c in chains for ip in c.suspect_invokers
               if any(f.category is FindingCategory.WEBSHELL for f in c.findings)}
    return actors


def _root_cause(roots: list[_Draft], chains: list[_Chain],
                drafts: dict[str, _Draft]) -> RootCause | None:
    if not roots:
        return None
    primary = drafts[roots[0].event_id]  # the copy that is actually in the timeline
    primary.is_root_cause = True
    primary_chain = next(c for c in chains if c.root is roots[0])
    alternatives = [r.event_id for r in roots[1:] if r.event_id != primary.event_id]
    if primary_chain.root is primary_chain.creation:
        alternatives += [a.event_id for a in primary_chain.alternatives]
    return RootCause(
        event_id=primary.event_id, vuln_class=primary.params.get("vuln_class") or None,
        confidence=cap(primary.confidence, primary.root_cap),
        reasons=(*primary.reasons, *primary.root_reasons),
        alternative_event_ids=tuple(dict.fromkeys(alternatives)),
    )


def correlate(logs: LogCollection, files: FileCollection, *,
              baseline: FileCollection | None = None,
              config: CorrelationConfig | None = None) -> CorrelationResult:
    config = config or CorrelationConfig()
    deleted: tuple[str, ...] = ()
    if baseline is not None:
        files, deleted = apply_baseline(files, baseline)
    index = _Index(logs, config)
    gaps = _input_gaps(files, logs, index, baseline is not None)
    lonely = lonely_writes(list(files.files), config)

    findings: list[Finding] = list(index.findings)
    chains: list[_Chain] = []
    extra: list[_Draft] = []
    unexplained: list[str] = []
    for file in sorted(files.files, key=lambda f: f.path):
        file_findings = detect_file(file)
        findings.extend(file_findings)
        strong = is_strong_seed(file, file_findings)
        weak = not strong and file.path in lonely
        if not strong and not weak:
            continue
        own = list(file_findings)
        signal = timestomp_signal(file, config)
        if signal is not None:
            own.append(_timestomp_finding(file, signal))
        if weak:
            own.append(lonely_finding(file))
        chain = _trace(file, own, index, weak)
        if chain is None or (weak and chain.write is None and chain.rare_post is None) or (
                _looks_generated(chain, file_findings, signal is not None, index)):
            if chain is not None or weak:
                unexplained.append(file.path)  # no HTTP link strong enough to accuse
            continue
        chains.append(chain)
        findings.extend(f for f in chain.findings if f not in file_findings)
        if signal is not None:
            stomp = next(f for f in chain.findings if f.rule_id == TIMESTOMP_RULE)
            extra.append(_timestomp_draft(file, stomp, chain.file_event))
        missing = coverage_gap(chain.file_event.ts, file.path, index.span, config)
        if missing is not None:
            gaps.append(missing)

    roots = sorted((c.root for c in chains if c.root), key=lambda d: (d.ts, d.order))
    actors = _implicated_actors(chains, roots)

    drafts: dict[str, _Draft] = {}
    for chain in chains:
        for draft in (chain.root, chain.creation, *chain.alternatives, chain.file_event,
                      *chain.invocations):
            if draft is not None:
                drafts.setdefault(draft.event_id, draft)
    for draft in extra:
        drafts.setdefault(draft.event_id, draft)
    taken = {d.subject for d in drafts.values() if d.basis is TimestampBasis.LOG}
    for draft in _context(index, actors, taken, roots):
        drafts.setdefault(draft.event_id, draft)

    ordered = sorted(drafts.values(), key=lambda d: (d.ts, d.order))
    _corroborate(ordered, index)
    unique = {g.gap_id: g for g in gaps}
    gaps = _apply_gaps([unique[k] for k in sorted(unique)], ordered)
    root_cause = _root_cause(roots, chains, drafts)

    timeline = tuple(d.build() for d in ordered)
    used = {fid for event in timeline for fid in event.finding_ids}
    return CorrelationResult(
        timeline=timeline, root_cause=root_cause, findings=tuple(findings),
        affected_files=tuple(c.file for c in chains), deleted_paths=deleted,
        unexplained_changes=tuple(unexplained),
        gaps=tuple(gaps), iocs=_iocs(chains, ordered, actors, index),
        unattributed_finding_ids=tuple(f.finding_id for f in findings if f.finding_id not in used),
    )
