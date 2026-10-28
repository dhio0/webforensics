"""Core data models shared by adapters, detection, correlation and reporting.

Every model is immutable and JSON-serializable, and every timestamp is timezone-aware
and normalized to UTC (D6). The rationale for each field is in docs/plan.md §3.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

EXCERPT_MAX_CHARS = 300


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def stable_id(*parts: str) -> str:
    """Deterministic short id derived from its parts, stable across runs (D7)."""
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def truncate_excerpt(value: str) -> str:
    if len(value) <= EXCERPT_MAX_CHARS:
        return value
    return value[: EXCERPT_MAX_CHARS - 1] + "…"


def check_relative_path(value: str) -> str:
    """Reject paths that could escape the webroot (D15). Returns the path unchanged."""
    if not value or value.startswith("/") or "\x00" in value:
        raise ValueError(f"not a safe relative path: {value!r}")
    if any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError(f"not a safe relative path: {value!r}")
    return value


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CitationKind(StrEnum):
    LOG_LINE = "log_line"
    FILE = "file"
    WAZUH_ALERT = "wazuh_alert"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TimestampSource(StrEnum):
    """Where file timestamps came from, ordered roughly by trust (D9, D10)."""

    MANIFEST = "manifest"
    LIVE_STAT = "live_stat"
    WAZUH_FIM = "wazuh_fim"
    COPIED = "copied"


class TimestampBasis(StrEnum):
    """What a timeline event's time is based on."""

    LOG = "log"
    CTIME = "ctime"
    BTIME = "btime"
    MTIME = "mtime"
    FIM = "fim"
    INFERRED = "inferred"


class TsSemantics(StrEnum):
    """nginx logs the time a request ends, Apache the time it starts."""

    REQUEST_START = "request_start"
    REQUEST_END = "request_end"


class BaselineStatus(StrEnum):
    NEW = "new"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


class FileType(StrEnum):
    FILE = "file"
    SYMLINK = "symlink"


class FindingCategory(StrEnum):
    RECON = "recon"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_SUCCESS = "exploit_success"
    WEBSHELL = "webshell"
    PERSISTENCE = "persistence"
    ANTI_FORENSICS = "anti_forensics"


class GapKind(StrEnum):
    NO_LOG_LINES = "no_log_lines"
    ROTATION_BOUNDARY = "rotation_boundary"
    PARSE_ERRORS = "parse_errors"
    MISSING_TIMESTAMPS = "missing_timestamps"
    CLOCK_SKEW_SUSPECTED = "clock_skew_suspected"
    NO_BASELINE = "no_baseline"
    POST_BODY_NOT_LOGGED = "post_body_not_logged"
    NO_MANIFEST = "no_manifest"
    UNTRUSTED_FILE_TIMESTAMPS = "untrusted_file_timestamps"


class Reason(_Frozen):
    """A language-neutral message: a catalog key plus parameters, rendered later (D12)."""

    key: str = Field(min_length=1)
    params: dict[str, str] = Field(default_factory=dict)


class Citation(_Frozen):
    """Pointer to the exact piece of evidence that supports a claim (D4)."""

    kind: CitationKind
    source: str = Field(min_length=1)
    line_no: int | None = Field(default=None, ge=1)
    sha256: Sha256Hex | None = None
    excerpt: str = ""

    _truncate = field_validator("excerpt")(truncate_excerpt)

    @model_validator(mode="after")
    def _require_locator(self) -> "Citation":
        if self.kind is CitationKind.LOG_LINE and self.line_no is None:
            raise ValueError("a log_line citation needs line_no")
        if self.kind is CitationKind.FILE and self.sha256 is None:
            raise ValueError("a file citation needs sha256")
        return self


class Evidence(_Frozen):
    evidence_id: str = Field(min_length=1)
    adapter: str = Field(min_length=1)
    source: str = Field(min_length=1)
    collected_at: UtcDatetime | None = None


class FileEvidence(Evidence):
    """A regular file or symlink from the webroot. For symlinks, `sha256` hashes the target path."""

    path: str
    file_type: FileType = FileType.FILE
    url_paths: tuple[str, ...] = ()
    sha256: Sha256Hex
    size: int = Field(ge=0)
    mode: int | None = None
    uid: int | None = None
    inode: int | None = None
    atime: UtcDatetime | None = None
    mtime: UtcDatetime | None = None
    ctime: UtcDatetime | None = None
    btime: UtcDatetime | None = None
    timestamp_source: TimestampSource
    baseline_status: BaselineStatus = BaselineStatus.UNKNOWN
    # Local path to readable content for static analysis. Machine-specific, so it is
    # kept out of serialized output to keep reports deterministic.
    content_ref: str | None = Field(default=None, exclude=True)

    _check_path = field_validator("path")(check_relative_path)

    def citation(self) -> Citation:
        return Citation(
            kind=CitationKind.FILE,
            source=self.path,
            sha256=self.sha256,
            excerpt=f"{self.file_type} {self.size} bytes",
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class LogEvent:
    """One parsed access-log line. `raw` is kept verbatim for citations.

    A slotted dataclass, not a pydantic model: there is one per log line, and a pydantic
    instance costs ~1.3 KB of overhead versus ~80 B here (D52). Only our own parsers
    build these, so the checks in `__post_init__` are enough. Change one with
    `dataclasses.replace`.
    """

    evidence_id: str
    adapter: str
    source: str
    collected_at: datetime | None = None
    log_file: str
    line_no: int
    raw: str
    ts: datetime
    ts_semantics: TsSemantics
    client_ip: str
    remote_user: str | None = None
    request_raw: str
    method: str | None = None
    path: str | None = None
    query: str | None = None
    protocol: str | None = None
    status: int
    bytes_sent: int
    referer: str | None = None
    user_agent: str | None = None
    xff: str | None = None
    vhost: str | None = None
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evidence_id or self.line_no < 1 or self.bytes_sent < 0:
            raise ValueError("log event needs an id, line_no >= 1 and bytes_sent >= 0")
        if self.ts.tzinfo is None:
            raise ValueError("log event timestamp must be timezone-aware")
        if self.ts.utcoffset() != timedelta(0):
            object.__setattr__(self, "ts", self.ts.astimezone(UTC))

    def citation(self) -> Citation:
        return Citation(
            kind=CitationKind.LOG_LINE,
            source=self.log_file,
            line_no=self.line_no,
            excerpt=self.raw,
        )


class ParseFailure(_Frozen):
    """An input line or record that could not be parsed. Counted, never fatal."""

    source: str
    line_no: int | None = Field(default=None, ge=1)
    reason: str
    excerpt: str = ""

    _truncate = field_validator("excerpt")(truncate_excerpt)


class SourceFile(_Frozen):
    """An input file as received, hashed for the report's reproducibility section."""

    path: str
    sha256: Sha256Hex
    size: int = Field(ge=0)


class EvidenceGap(_Frozen):
    gap_id: str
    kind: GapKind
    source: str | None = None
    start: UtcDatetime | None = None
    end: UtcDatetime | None = None
    detail: Reason | None = None
    affects: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _ordered(self) -> "EvidenceGap":
        if self.start and self.end and self.end < self.start:
            raise ValueError("gap end is before start")
        return self


class ErrorLogEvent(Evidence):
    """One parsed web-server error-log entry (nginx or Apache).

    Error logs carry no status code and their timestamps have no UTC offset, so the
    offset used is recorded in `assumed_utc_offset` and they only support conclusions.
    """

    log_file: str
    line_no: int = Field(ge=1)
    raw: str
    ts: UtcDatetime
    assumed_utc_offset: str
    level: str
    client_ip: str | None = None
    method: str | None = None
    path: str | None = None
    message: str = ""

    def citation(self) -> Citation:
        return Citation(
            kind=CitationKind.LOG_LINE, source=self.log_file, line_no=self.line_no,
            excerpt=self.raw,
        )


class LogCollection(_Frozen):
    events: tuple[LogEvent, ...] = ()
    failures: tuple[ParseFailure, ...] = ()
    sources: tuple[SourceFile, ...] = ()
    # Kept apart from access-log data: error logs have multi-line entries (stack traces),
    # so their unparsed lines are normal and must not count as missing access-log time.
    errors: tuple[ErrorLogEvent, ...] = ()
    error_failures: tuple[ParseFailure, ...] = ()

    def merged(self, other: "LogCollection") -> "LogCollection":
        return LogCollection(
            events=self.events + other.events, failures=self.failures + other.failures,
            sources=self.sources + other.sources, errors=self.errors + other.errors,
            error_failures=self.error_failures + other.error_failures,
        )


class ManifestHeader(_Frozen):
    version: str
    collector: str | None = None
    hostname: str | None = None
    webroot: str | None = None
    collected_at: UtcDatetime | None = None
    utc_offset: str | None = None
    birth_time_supported: bool = False
    extra: dict[str, str] = Field(default_factory=dict)


class FileCollection(_Frozen):
    files: tuple[FileEvidence, ...] = ()
    failures: tuple[ParseFailure, ...] = ()
    header: ManifestHeader | None = None
    gaps: tuple[EvidenceGap, ...] = ()
    sources: tuple[SourceFile, ...] = ()


class Finding(_Frozen):
    finding_id: str
    rule_id: str
    rule_version: str
    category: FindingCategory
    subject: str  # evidence_id of the file or request this finding is about
    severity: Severity
    confidence: Confidence
    reasons: tuple[Reason, ...] = ()
    citations: tuple[Citation, ...] = Field(min_length=1)
    mitre: tuple[str, ...] = ()


class TimelineEvent(_Frozen):
    event_id: str
    ts: UtcDatetime
    ts_basis: TimestampBasis
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    actor: str | None = None
    description: Reason
    citations: tuple[Citation, ...] = Field(min_length=1)
    confidence: Confidence
    confidence_reasons: tuple[Reason, ...] = ()
    finding_ids: tuple[str, ...] = ()
    is_root_cause: bool = False


class CodeLocation(_Frozen):
    file: str
    line: int = Field(ge=1)
    snippet: str
    vuln_class: str
    suggested_fix: str | None = None
    confidence: Confidence
    citation: Citation


class RootCause(_Frozen):
    event_id: str
    vuln_class: str | None = None
    confidence: Confidence
    reasons: tuple[Reason, ...] = ()
    alternative_event_ids: tuple[str, ...] = ()


class RunInfo(_Frozen):
    tool_version: str
    ruleset_version: str
    inputs: tuple[SourceFile, ...] = ()
    config_sha256: Sha256Hex | None = None
    generated_at: UtcDatetime


class CaseInfo(_Frozen):
    case_id: str
    title: str
    analyst: str | None = None
    target_host: str | None = None


class Iocs(_Frozen):
    ips: tuple[str, ...] = ()
    user_agents: tuple[str, ...] = ()
    sha256s: tuple[Sha256Hex, ...] = ()
    paths: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()


def _check_sorted(timeline: tuple[TimelineEvent, ...]) -> None:
    times = [event.ts for event in timeline]
    if times != sorted(times):
        raise ValueError("timeline must be sorted by time")


class CorrelationResult(_Frozen):
    """Output of the correlation engine; the report (M4) is rendered from this."""

    timeline: tuple[TimelineEvent, ...] = ()
    root_cause: RootCause | None = None
    findings: tuple[Finding, ...] = ()
    affected_files: tuple[FileEvidence, ...] = ()
    deleted_paths: tuple[str, ...] = ()  # in the baseline but missing now
    # Executable files written apart from any deploy batch, with no HTTP link: review by hand.
    unexplained_changes: tuple[str, ...] = ()
    gaps: tuple[EvidenceGap, ...] = ()
    iocs: Iocs = Iocs()
    unattributed_finding_ids: tuple[str, ...] = ()  # findings not linked to the incident

    @model_validator(mode="after")
    def _consistent(self) -> "CorrelationResult":
        _check_sorted(self.timeline)
        ids = {event.event_id for event in self.timeline}
        if len(ids) != len(self.timeline):
            raise ValueError("duplicate timeline event id")
        if self.root_cause is not None:
            wanted = (self.root_cause.event_id, *self.root_cause.alternative_event_ids)
            if any(event_id not in ids for event_id in wanted):
                raise ValueError("root cause must point at timeline events")
        return self


class Report(_Frozen):
    case: CaseInfo
    run: RunInfo
    summary: tuple[Reason, ...] = ()
    timeline: tuple[TimelineEvent, ...] = ()
    root_cause: RootCause | None = None
    affected_files: tuple[FileEvidence, ...] = ()
    iocs: Iocs = Iocs()
    gaps: tuple[EvidenceGap, ...] = ()
    code_findings: tuple[CodeLocation, ...] = ()
    recommendations: tuple[Reason, ...] = ()
    limitations: tuple[Reason, ...] = ()

    @model_validator(mode="after")
    def _timeline_sorted(self) -> "Report":
        _check_sorted(self.timeline)
        return self
