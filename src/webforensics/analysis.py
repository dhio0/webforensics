"""End-to-end analysis: load evidence, correlate, build the report. No I/O beyond reading
the evidence it is given (no network), so the CLI stays a thin wrapper."""

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from webforensics import __version__
from webforensics.adapters.file_adapter import (
    DirectoryFileSource,
    ErrorLogFileSource,
    LogFileSource,
    ManifestFileSource,
)
from webforensics.adapters.wazuh import WazuhRecordingSource
from webforensics.codeloc.locate import review_code
from webforensics.correlate import CorrelationConfig, correlate, for_filesystem
from webforensics.detect import RULESET_VERSION
from webforensics.models import CaseInfo, FileCollection, LogCollection, Report, RunInfo
from webforensics.parsers.access_log import AccessLogFormat
from webforensics.parsers.error_log import ErrorLogFormat
from webforensics.report import build_report
from webforensics.report.build import evidence_scope
from webforensics.report.messages_id import LABELS


@dataclass(frozen=True)
class EvidenceInputs:
    logs: tuple[Path, ...] = ()
    log_format: AccessLogFormat = AccessLogFormat.NGINX_COMBINED
    log_glob: str = "*access*"
    manifest: Path | None = None
    webroot: Path | None = None
    live: bool = False
    url_prefix: str = "/"
    baseline: Path | None = None
    error_logs: tuple[Path, ...] = ()
    error_format: ErrorLogFormat = ErrorLogFormat.NGINX
    error_utc_offset: str = "+0000"
    # Citations and input names are relative to this. None: the evidence's common folder.
    base_dir: Path | None = None
    # A `webforensics pull` recording replaces --log/--manifest (WazuhAdapter, D78).
    # `webroot` then only supplies content, used where its hash matches FIM (D77).
    wazuh_recording: Path | None = None


@dataclass(frozen=True)
class CaseOptions:
    case_id: str | None = None
    title: str = LABELS["title"]
    analyst: str | None = None
    redact_host: bool = False


@dataclass(frozen=True)
class Evidence:
    logs: LogCollection
    files: FileCollection
    baseline: FileCollection | None
    adapter: str = "file"


def evidence_root(inputs: EvidenceInputs) -> Path | None:
    """Deepest folder holding all evidence inputs, so names in the report do not depend on
    where the command runs and never reveal the analyst's own paths (D66)."""
    paths = [*inputs.logs, *inputs.error_logs, inputs.manifest, inputs.baseline,
             inputs.wazuh_recording]
    folders = [p.resolve() if p.is_dir() else p.resolve().parent
               for p in paths if p is not None]
    if not folders:
        return None
    try:
        return Path(os.path.commonpath(folders))
    except ValueError:  # different drives on Windows
        return None


def _load_wazuh(inputs: EvidenceInputs) -> Evidence:
    if inputs.logs or inputs.error_logs or inputs.manifest or inputs.baseline:
        raise ValueError("a Wazuh recording is used alone: leave out --log, --error-log, "
                         "--manifest and --baseline (FIM is the baseline)")
    assert inputs.wazuh_recording is not None
    source = WazuhRecordingSource(
        inputs.wazuh_recording, base_dir=inputs.base_dir or evidence_root(inputs),
        webroot=inputs.webroot, url_prefix=inputs.url_prefix,
        access_format=inputs.log_format, error_format=inputs.error_format,
        error_utc_offset=inputs.error_utc_offset)
    return Evidence(source.load_logs(), source.load_files(), None, adapter="wazuh")


def load_evidence(inputs: EvidenceInputs) -> Evidence:
    """Raises FileNotFoundError, ManifestError or RecordingError on bad inputs."""
    if inputs.wazuh_recording is not None:
        return _load_wazuh(inputs)
    if not inputs.logs:
        raise ValueError("at least one access log is needed")
    if inputs.manifest is None and inputs.webroot is None:
        raise ValueError("a manifest or a webroot is needed")
    base = inputs.base_dir or evidence_root(inputs)
    logs = LogFileSource(list(inputs.logs), inputs.log_format, base_dir=base,
                         glob=inputs.log_glob).load_logs()
    if inputs.error_logs:
        logs = logs.merged(ErrorLogFileSource(
            list(inputs.error_logs), inputs.error_format, inputs.error_utc_offset,
            base_dir=base).load_logs())
    if inputs.manifest is not None:
        files = ManifestFileSource(inputs.manifest, inputs.webroot, inputs.url_prefix,
                                   base_dir=base).load_files()
    else:
        assert inputs.webroot is not None
        files = DirectoryFileSource(inputs.webroot, live=inputs.live,
                                    url_prefix=inputs.url_prefix).load_files()
    baseline = None
    if inputs.baseline is not None:
        baseline = ManifestFileSource(inputs.baseline, None, inputs.url_prefix,
                                      base_dir=base).load_files()
    return Evidence(logs, files, baseline)


def config_sha256(config: CorrelationConfig) -> str:
    blob = json.dumps(asdict(config), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def run_info(evidence: Evidence, config: CorrelationConfig, generated_at: datetime) -> RunInfo:
    sources = [*evidence.logs.sources, *evidence.files.sources]
    if evidence.baseline is not None:
        sources += evidence.baseline.sources
    unique = {(s.path, s.sha256): s for s in sources}
    return RunInfo(tool_version=__version__, ruleset_version=RULESET_VERSION,
                   inputs=tuple(unique[k] for k in sorted(unique)),
                   config_sha256=config_sha256(config), generated_at=generated_at)


def case_info(evidence: Evidence, run: RunInfo, options: CaseOptions) -> CaseInfo:
    """Default case id is derived from the input hashes, so it is stable across runs."""
    digest = hashlib.sha256("".join(s.sha256 for s in run.inputs).encode()).hexdigest()
    host = evidence.files.header.hostname if evidence.files.header else None
    if options.redact_host and host:
        host = LABELS["redacted"]
    return CaseInfo(case_id=options.case_id or f"WF-{digest[:10].upper()}",
                    title=options.title, analyst=options.analyst, target_host=host)


def analyze(inputs: EvidenceInputs, config: CorrelationConfig, generated_at: datetime,
            options: CaseOptions | None = None) -> Report:
    evidence = load_evidence(inputs)
    header = evidence.files.header
    config = for_filesystem(config, header.filesystem if header else None)
    result = correlate(evidence.logs, evidence.files, baseline=evidence.baseline,
                       config=config)
    run = run_info(evidence, config, generated_at)
    case = case_info(evidence, run, options or CaseOptions())
    scope = evidence_scope(evidence.logs, evidence.files, evidence.baseline,
                           file_adapter=evidence.adapter)
    code_findings, code_scope = review_code(result, evidence.files, inputs.webroot,
                                            inputs.url_prefix,
                                            case_insensitive=config.case_insensitive_paths)
    return build_report(result, evidence.logs, case, run, scope, config.trusted_proxies,
                        code_findings=code_findings, code_scope=code_scope)
