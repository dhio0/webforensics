"""Core data models shared by adapters, detection, correlation and reporting.

Every model is immutable and JSON-serializable, and every timestamp is timezone-aware
and normalized to UTC (D6). The rationale for each field is in docs/plan.md §3.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, BinaryIO

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


class FimEventType(StrEnum):
    """Wazuh syscheck `event` values (rules 554, 550, 553)."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


class FimMode(StrEnum):
    """How Wazuh FIM noticed the change. Realtime and whodata alert within seconds of the
    write; scheduled scans only every `frequency` seconds (default 12 h)."""

    REALTIME = "realtime"
    WHODATA = "whodata"
    SCHEDULED = "scheduled"


class FindingCategory(StrEnum):
    RECON = "recon"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_SUCCESS = "exploit_success"
    WEBSHELL = "webshell"
    PERSISTENCE = "persistence"
    ANTI_FORENSICS = "anti_forensics"
    DEFACEMENT = "defacement"


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
    # Only part of the access log is available (Wazuh alerts without archives, D74).
    PARTIAL_LOG_SOURCE = "partial_log_source"
    # File hashes and metadata are known, but not the bytes (Wazuh FIM without --webroot, D77).
    NO_FILE_CONTENT = "no_file_content"


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


class FimChange(_Frozen):
    """One Wazuh FIM alert about a file. `ts` is the manager's alert time, an upper bound
    for when the change happened (D76)."""

    ts: UtcDatetime
    event: FimEventType
    mode: FimMode
    sha256: Sha256Hex | None = None
    citation: Citation


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
    # Wazuh FIM alerts for this path, oldest first. Empty for the FileAdapter.
    fim: tuple[FimChange, ...] = ()
    # Local path to readable content for static analysis. Machine-specific, so it is
    # kept out of serialized output to keep reports deterministic.
    content_ref: str | None = Field(default=None, exclude=True)

    _check_path = field_validator("path")(check_relative_path)

    @property
    def deleted(self) -> bool:
        """FIM saw the file deleted last. `sha256` is then its last known hash (D78)."""
        return bool(self.fim) and self.fim[-1].event is FimEventType.DELETED

    @property
    def fim_written(self) -> FimChange | None:
        """The FIM alert for the write that produced the current content: the first add or
        change whose hash is `sha256`, else the first add or change."""
        writes = [c for c in self.fim if c.event is not FimEventType.DELETED]
        return next((c for c in writes if c.sha256 == self.sha256), writes[0] if writes else None)

    def citation(self) -> Citation:
        return Citation(
            kind=CitationKind.FILE,
            source=self.path,
            sha256=self.sha256,
            excerpt=f"{self.file_type} {self.size} bytes",
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class LogEvent:
    """One parsed access-log line. `raw` is the verbatim line, for citations.

    A slotted dataclass, not a pydantic model: there is one per log line, and a pydantic
    instance costs ~1.3 KB of overhead versus ~80 B here (D52). Only our own parsers
    build these, so the checks in `__post_init__` are enough. Change one with
    `dataclasses.replace`.

    The line text is kept in `raw_inline`, or, for a plain (not gzip) log file, read back
    from `raw_file` at byte `raw_offset` when a citation needs it: only a few thousand of
    millions of lines are ever cited, and the text was a quarter of the memory (D88).
    """

    evidence_id: str
    adapter: str
    source: str
    collected_at: datetime | None = None
    log_file: str
    line_no: int
    raw_inline: str | None = None
    raw_file: str | None = None
    raw_offset: int = -1
    ts: datetime
    ts_semantics: TsSemantics
    client_ip: str
    remote_user: str | None = None
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
        if self.raw_inline is None and self.raw_file is None:
            raise ValueError("log event needs its line text or where to read it")

    @property
    def raw(self) -> str:
        if self.raw_inline is not None:
            return self.raw_inline
        return read_log_line(self.raw_file or "", self.raw_offset)

    def citation(self) -> Citation:
        return Citation(
            kind=CitationKind.LOG_LINE,
            source=self.log_file,
            line_no=self.line_no,
            excerpt=self.raw,
        )


_LINE_FILES: dict[str, "BinaryIO"] = {}


def read_log_line(path: str, offset: int) -> str:
    """The line starting at byte `offset` of a plain log file, decoded exactly as the parser
    decodes it. Handles stay open (read-only) until `close_log_files()`."""
    handle = _LINE_FILES.get(path)
    if handle is None:
        handle = _LINE_FILES[path] = open(path, "rb")  # noqa: SIM115
    handle.seek(offset)
    return handle.readline().rstrip(b"\r\n").decode("utf-8", "backslashreplace")


def close_log_files() -> None:
    while _LINE_FILES:
        _LINE_FILES.popitem()[1].close()


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
    # False when the source holds only some requests (Wazuh alerts without archives): then
    # silence between lines is normal and must not be reported as missing log time (D74).
    complete: bool = True
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
            complete=self.complete and other.complete,
        )


class ManifestHeader(_Frozen):
    version: str
    collector: str | None = None
    hostname: str | None = None
    webroot: str | None = None
    collected_at: UtcDatetime | None = None
    utc_offset: str | None = None
    birth_time_supported: bool = False
    # Filesystem type of the webroot (`stat -f -c %T`), e.g. ext2/ext3, xfs, ntfs. On
    # Windows filesystems URLs match file names case-insensitively and every timestamp,
    # birth time included, can be set by a program (D84).
    filesystem: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)


class FileCollection(_Frozen):
    files: tuple[FileEvidence, ...] = ()
    failures: tuple[ParseFailure, ...] = ()
    header: ManifestHeader | None = None
    gaps: tuple[EvidenceGap, ...] = ()
    sources: tuple[SourceFile, ...] = ()
    # Findings the source itself produces, e.g. FIM changes outside the webroot.
    findings: tuple["Finding", ...] = ()
    # True when the source knows which files changed against an earlier state (Wazuh FIM's
    # own baseline scan), so `baseline_status` is meaningful without a baseline manifest.
    has_baseline: bool = False
    # Paths the source saw deleted without a known content to trace (FIM `deleted` only).
    deleted_paths: tuple[str, ...] = ()
    # True when `files` lists the whole webroot (manifest, folder scan), so a URL that no
    # file serves really had no file. Wazuh FIM lists only changed files (D85).
    complete_listing: bool = True


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
    """A vulnerable line in an implicated file (M7). `line` is where request input enters
    the query; `sink_line` is where the query runs."""

    file: str
    line: int = Field(ge=1)
    snippet: str
    vuln_class: str
    suggested_fix: str | None = None
    confidence: Confidence
    citation: Citation
    sink_line: int | None = Field(default=None, ge=1)
    sink: str = ""
    sources: tuple[str, ...] = ()
    # False when the content came from --webroot without an evidence hash to check it against.
    verified: bool = True
    # Why the file was analyzed: "entry" (root cause or an alternative), "write" (its
    # endpoint wrote a file), "sqli_target" (an attacker's SQL injection got a 2xx answer
    # there, D84) or "included" (an implicated file includes it).
    implicated_by: str = "entry"


class CodeScope(_Frozen):
    """Which implicated files the code analysis read, so "nothing found" has a scope."""

    analyzed: tuple[str, ...] = ()
    included: tuple[str, ...] = ()  # analyzed because an implicated file includes them
    unverified: tuple[str, ...] = ()  # analyzed, but content not checked against a hash
    no_content: tuple[str, ...] = ()  # implicated, but no content was available


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
    # In the baseline but missing now, or seen only as a FIM `deleted` alert.
    deleted_paths: tuple[str, ...] = ()
    # Script URLs an attacker used that no file in the evidence serves (D85).
    log_only_files: tuple[str, ...] = ()
    # Code files changed without an HTTP link strong enough to accuse (a lonely write, or
    # a file of a deploy batch): review by hand.
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


class BackgroundGroup(_Frozen):
    """Attack-pattern requests of one rule that are not linked to the incident (e.g. bots).

    Aggregated so a log full of bot traffic gives a short table, not a million rows.
    """

    rule_id: str
    count: int = Field(ge=1)
    clients: int = Field(ge=1)
    top_clients: tuple[tuple[str, int], ...] = ()
    first: UtcDatetime
    last: UtcDatetime
    example: Citation


class EvidenceScope(_Frozen):
    """What was analyzed: a conclusion is only as wide as the evidence behind it."""

    log_first: UtcDatetime | None = None
    log_last: UtcDatetime | None = None
    log_events: int = 0
    log_unparsed: int = 0
    error_events: int = 0
    error_unparsed: int = 0
    files: int = 0
    files_rejected: int = 0
    baseline_files: int | None = None  # None: no baseline given
    file_adapter: str = "file"  # "wazuh": `files` counts FIM-changed files, not the webroot
    collected_at: UtcDatetime | None = None  # from the manifest header
    # Files whose content the webroot copy could not give (missing, unreadable, or a hash
    # other than the manifest's, D101): their content rules did not run.
    unread_files: int = 0
    unread_code: tuple[str, ...] = ()  # code files among them, attacked ones first, capped
    unread_attacked: tuple[str, ...] = ()  # code files whose URL got an attack-pattern request


REPORT_FORMAT = "webforensics-report/1"


class Report(_Frozen):
    """Everything the renderers need, still language-neutral (keys + params, D12)."""

    # Bumped when report.json changes incompatibly, for tools that read it (eval, Wazuh).
    format: str = REPORT_FORMAT
    case: CaseInfo
    scope: EvidenceScope = EvidenceScope()
    run: RunInfo
    result: CorrelationResult
    summary: tuple[Reason, ...] = ()
    background: tuple[BackgroundGroup, ...] = ()
    code_findings: tuple[CodeLocation, ...] = ()
    code_scope: CodeScope | None = None
    recommendations: tuple[Reason, ...] = ()  # keys start with rec.<phase>.
    limitations: tuple[Reason, ...] = ()
