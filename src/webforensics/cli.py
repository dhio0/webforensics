"""Command-line interface."""

import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from webforensics import __version__, evaluate
from webforensics.adapters.base import FileEvidenceSource
from webforensics.adapters.file_adapter import (
    DirectoryFileSource,
    LogFileSource,
    ManifestFileSource,
)
from webforensics.analysis import CaseOptions, EvidenceInputs
from webforensics.analysis import analyze as run_analysis
from webforensics.correlate import CorrelationConfig
from webforensics.models import FileCollection, LogCollection, Report
from webforensics.parsers.access_log import AccessLogFormat
from webforensics.parsers.error_log import ErrorLogFormat
from webforensics.parsers.manifest import ManifestError
from webforensics.report import FORMATS, render
from webforensics.report.build import root_event
from webforensics.report.messages_id import LABELS
from webforensics.report.text import parse_display_offset

app = typer.Typer(
    help="Reconstruct how a website was compromised from webroot files and web logs.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"webforensics {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """webforensics: file-first web incident forensics."""


def summarize_logs(logs: LogCollection) -> list[str]:
    lines = [f"Logs: {len(logs.events)} events, {len(logs.failures)} unparsed lines"]
    for source in logs.sources:
        lines.append(f"  {source.path}  sha256={source.sha256[:12]}...  {source.size} bytes")
    if logs.events:
        times = [event.ts for event in logs.events]
        lines.append(f"  time range (UTC): {min(times).isoformat()} .. {max(times).isoformat()}")
    for reason, count in sorted(Counter(f.reason for f in logs.failures).items()):
        lines.append(f"  unparsed[{reason}]: {count}")
    return lines


def summarize_files(files: FileCollection) -> list[str]:
    lines = [f"Files: {len(files.files)} entries, {len(files.failures)} rejected manifest rows"]
    if files.header is not None:
        lines.append(f"  manifest host={files.header.hostname} webroot={files.header.webroot}")
    for kind, count in sorted(Counter(f.file_type.value for f in files.files).items()):
        lines.append(f"  {kind}: {count}")
    for reason, count in sorted(Counter(f.reason for f in files.failures).items()):
        lines.append(f"  rejected[{reason}]: {count}")
    for gap in files.gaps:
        lines.append(f"  evidence gap: {gap.kind.value}")
    return lines


@app.command()
def inspect(
    log: Annotated[
        list[Path] | None,
        typer.Option("--log", "-l", help="Access log file or directory (repeatable)."),
    ] = None,
    log_format: Annotated[
        AccessLogFormat, typer.Option(help="Access log format.")
    ] = AccessLogFormat.NGINX_COMBINED,
    log_glob: Annotated[
        str, typer.Option(help="File pattern used when --log is a directory.")
    ] = "*access*",
    manifest: Annotated[
        Path | None, typer.Option(help="Webroot manifest from collect.sh.")
    ] = None,
    webroot: Annotated[
        Path | None,
        typer.Option(help="Extracted webroot (content for a manifest, or scanned directly)."),
    ] = None,
    live: Annotated[
        bool, typer.Option(help="--webroot is the live server folder, not a copy.")
    ] = False,
    url_prefix: Annotated[str, typer.Option(help="URL path the webroot is served under.")] = "/",
    as_json: Annotated[bool, typer.Option("--json", help="Print parsed evidence as JSON.")] = False,
) -> None:
    """Load evidence and show what was parsed, without analyzing it."""
    base_dir = Path.cwd()
    try:
        logs = (
            LogFileSource(log, log_format, base_dir=base_dir, glob=log_glob).load_logs()
            if log
            else None
        )
        file_source: FileEvidenceSource | None = None
        if manifest is not None:
            file_source = ManifestFileSource(manifest, webroot, url_prefix, base_dir=base_dir)
        elif webroot is not None:
            file_source = DirectoryFileSource(webroot, live=live, url_prefix=url_prefix)
        files = file_source.load_files() if file_source else None
    except (FileNotFoundError, ManifestError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if logs is None and files is None:
        typer.echo("error: give at least --log, --manifest or --webroot", err=True)
        raise typer.Exit(code=2)

    if as_json:
        payload = {
            "logs": logs.model_dump(mode="json") if logs else None,
            "files": files.model_dump(mode="json") if files else None,
        }
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    if logs is not None:
        typer.echo("\n".join(summarize_logs(logs)))
    if files is not None:
        typer.echo("\n".join(summarize_files(files)))


def resolve_generated_at(value: str | None) -> datetime:
    """--generated-at, else SOURCE_DATE_EPOCH (reproducible builds), else now (UTC)."""
    if value:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("--generated-at needs a UTC offset, e.g. 2026-10-28T09:00:00+07:00")
        return parsed.astimezone(UTC)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        return datetime.fromtimestamp(int(epoch), UTC)
    return datetime.now(UTC).replace(microsecond=0)


def _ascii(text: str) -> str:
    """Console output stays ASCII: Windows consoles may not encode evidence characters."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def report_lines(report: Report, written: list[Path]) -> list[str]:
    result = report.result
    lines = [f"Case {report.case.case_id}: {len(result.affected_files)} affected file(s), "
             f"{len(result.timeline)} timeline event(s), {len(result.gaps)} evidence gap(s)"]
    root = root_event(result)
    if root is not None and result.root_cause is not None:
        params = root.description.params
        lines.append(f"Root cause ({result.root_cause.confidence.value}): "
                     f"{result.root_cause.vuln_class or 'unknown class'} via "
                     f"{params.get('method', '')} {params.get('path', '')} "
                     f"at {root.ts.isoformat()}")
    elif result.affected_files:
        lines.append("Root cause: not determined from the evidence")
    if result.iocs.ips:
        lines.append(f"Attacker IPs: {', '.join(result.iocs.ips)}")
    lines += [f"Wrote {path}" for path in written]
    return [_ascii(line) for line in lines]


@app.command()
def analyze(
    log: Annotated[
        list[Path], typer.Option("--log", "-l", help="Access log file or directory (repeatable).")
    ],
    manifest: Annotated[
        Path | None, typer.Option(help="Webroot manifest from collect.sh (recommended).")
    ] = None,
    webroot: Annotated[
        Path | None,
        typer.Option(help="Extracted webroot (content for a manifest, or scanned directly)."),
    ] = None,
    baseline: Annotated[
        Path | None, typer.Option(help="Manifest of a known-good webroot to compare against.")
    ] = None,
    error_log: Annotated[
        list[Path] | None, typer.Option(help="Error log file or directory (repeatable).")
    ] = None,
    error_log_format: Annotated[
        ErrorLogFormat, typer.Option(help="Error log format.")
    ] = ErrorLogFormat.NGINX,
    error_log_utc_offset: Annotated[
        str, typer.Option(help="Server UTC offset for error-log times, e.g. +0700.")
    ] = "+0000",
    log_format: Annotated[
        AccessLogFormat, typer.Option(help="Access log format.")
    ] = AccessLogFormat.NGINX_COMBINED,
    log_glob: Annotated[
        str, typer.Option(help="File pattern used when --log is a directory.")
    ] = "*access*",
    live: Annotated[
        bool, typer.Option(help="--webroot is the live server folder, not a copy.")
    ] = False,
    url_prefix: Annotated[str, typer.Option(help="URL path the webroot is served under.")] = "/",
    trusted_proxy: Annotated[
        list[str] | None,
        typer.Option(help="Reverse proxy IP/CIDR whose X-Forwarded-For is trusted (repeatable)."),
    ] = None,
    creation_window: Annotated[
        int, typer.Option(help="Seconds before a file's birth a request may have written it.")
    ] = CorrelationConfig.creation_window_s,
    clock_skew: Annotated[
        int, typer.Option(help="Allowed clock/log slack in seconds.")
    ] = CorrelationConfig.clock_skew_s,
    out: Annotated[Path, typer.Option(help="Output directory.")] = Path("webforensics-report"),
    fmt: Annotated[
        list[str] | None, typer.Option("--format", help="md, html and/or json (default: all).")
    ] = None,
    case_id: Annotated[str | None, typer.Option(help="Case id (default: from input hashes).")]
    = None,
    title: Annotated[str, typer.Option(help="Report title.")] = LABELS["title"],
    analyst: Annotated[str | None, typer.Option(help="Analyst name for the report.")] = None,
    redact_host: Annotated[
        bool, typer.Option(help="Hide the manifest hostname in the report.")
    ] = False,
    display_offset: Annotated[
        str, typer.Option(help="Time zone for report times: +07:00 WIB, +08:00 WITA, +09:00 WIT.")
    ] = "+07:00",
    generated_at: Annotated[
        str | None,
        typer.Option(help="Report time (ISO 8601 with offset). Default: SOURCE_DATE_EPOCH or now."),
    ] = None,
) -> None:
    """Correlate files and logs, then write the Indonesian incident report."""
    formats = fmt or list(FORMATS)
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown:
        typer.echo(f"error: unknown --format {', '.join(unknown)} (use md, html, json)", err=True)
        raise typer.Exit(code=2)
    try:
        tz = parse_display_offset(display_offset)
        when = resolve_generated_at(generated_at)
        config = CorrelationConfig(
            creation_window_s=creation_window, clock_skew_s=clock_skew,
            trusted_proxies=tuple(trusted_proxy or ()),
        )
        inputs = EvidenceInputs(
            logs=tuple(log), log_format=log_format, log_glob=log_glob, manifest=manifest,
            webroot=webroot, live=live, url_prefix=url_prefix, baseline=baseline,
            error_logs=tuple(error_log or ()), error_format=error_log_format,
            error_utc_offset=error_log_utc_offset,
        )
        report = run_analysis(inputs, config, when, CaseOptions(
            case_id=case_id, title=title, analyst=analyst, redact_host=redact_host))
    except (FileNotFoundError, ManifestError, ValueError) as exc:
        typer.echo(_ascii(f"error: {exc}"), err=True)
        raise typer.Exit(code=2) from exc

    rendered = render(report, tz)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for ext in FORMATS:
        if ext in formats:
            path = out / f"report.{ext}"
            path.write_text(rendered[ext], encoding="utf-8", newline="\n")
            written.append(path)
    typer.echo("\n".join(report_lines(report, written)))


@app.command("eval")
def eval_command(
    benchmark: Annotated[
        Path, typer.Argument(help="Benchmark folder with scenarios/<id>/ground_truth.json.")
    ] = Path("benchmark"),
    scenario: Annotated[
        list[str] | None, typer.Option(help="Only these scenario ids (repeatable).")
    ] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Also write the scores as JSON here.")
    ] = None,
    markdown_out: Annotated[
        Path | None, typer.Option("--markdown", help="Also write the table as Markdown here.")
    ] = None,
    no_runtime: Annotated[
        bool, typer.Option(help="Leave out runtime, so the table is deterministic.")
    ] = False,
) -> None:
    """Score the analyzer against the benchmark ground truth."""
    try:
        folders = evaluate.scenario_folders(benchmark, tuple(scenario or ()))
        scores = [evaluate.evaluate_scenario(folder) for folder in folders]
    except (FileNotFoundError, ManifestError, ValueError, KeyError) as exc:
        typer.echo(_ascii(f"error: {exc}"), err=True)
        raise typer.Exit(code=2) from exc
    table = evaluate.markdown_table(scores, runtime=not no_runtime)
    typer.echo(_ascii(table))
    for line in evaluate.details(scores):
        typer.echo(_ascii(line))
    if markdown_out is not None:
        markdown_out.write_text(table, encoding="utf-8", newline="\n")
    if json_out is not None:
        json_out.write_text(json.dumps(evaluate.to_json(scores), indent=2) + "\n",
                            encoding="utf-8", newline="\n")
