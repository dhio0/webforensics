"""Command-line interface."""

import hashlib
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
from webforensics.adapters.wazuh.client import Credentials, IndexerClient, IndexerError
from webforensics.adapters.wazuh.pull import PullError, PullRequest
from webforensics.adapters.wazuh.pull import pull as run_pull
from webforensics.adapters.wazuh.queue import Agent as WazuhAgent
from webforensics.adapters.wazuh.queue import WritebackError
from webforensics.adapters.wazuh.queue import message as queue_message
from webforensics.adapters.wazuh.queue import send as send_to_queue
from webforensics.adapters.wazuh.writeback import build_events as build_writeback_events
from webforensics.adapters.wazuh.writeback import write_jsonl as write_events_jsonl
from webforensics.analysis import CaseOptions, EvidenceInputs
from webforensics.analysis import analyze as run_analysis
from webforensics.correlate import CorrelationConfig
from webforensics.models import REPORT_FORMAT, FileCollection, LogCollection, Report
from webforensics.parsers.access_log import AccessLogFormat
from webforensics.parsers.error_log import ErrorLogFormat
from webforensics.parsers.manifest import ManifestError
from webforensics.report import FORMATS, render, render_viewer
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
        list[Path] | None,
        typer.Option("--log", "-l", help="Access log file or directory (repeatable)."),
    ] = None,
    wazuh_recording: Annotated[
        Path | None,
        typer.Option(help="Recording from `webforensics pull`, used instead of --log/--manifest."),
    ] = None,
    manifest: Annotated[
        Path | None, typer.Option(help="Webroot manifest from collect.sh (recommended).")
    ] = None,
    webroot: Annotated[
        Path | None,
        typer.Option(help="Extracted webroot (content for a manifest or a Wazuh recording, "
                          "or scanned directly)."),
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
            logs=tuple(log or ()), log_format=log_format, log_glob=log_glob, manifest=manifest,
            webroot=webroot, live=live, url_prefix=url_prefix, baseline=baseline,
            error_logs=tuple(error_log or ()), error_format=error_log_format,
            error_utc_offset=error_log_utc_offset, wazuh_recording=wazuh_recording,
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


def load_report(path: Path) -> Report:
    """Read a report.json written by `analyze`; refuse other formats instead of guessing."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != REPORT_FORMAT:
        found = data.get("format") if isinstance(data, dict) else None
        raise ValueError(f"{path} is not a {REPORT_FORMAT} report (format: {found!r})")
    return Report.model_validate(data)


@app.command()
def view(
    report_json: Annotated[Path, typer.Argument(help="report.json written by `analyze`.")],
    out: Annotated[
        Path | None, typer.Option(help="Output HTML file (default: viewer.html next to it).")
    ] = None,
    display_offset: Annotated[
        str, typer.Option(help="Time zone for times: +07:00 WIB, +08:00 WITA, +09:00 WIT.")
    ] = "+07:00",
) -> None:
    """Write an interactive, offline HTML viewer for a report."""
    try:
        tz = parse_display_offset(display_offset)
        report = load_report(report_json)
    except (OSError, ValueError) as exc:  # pydantic's ValidationError is a ValueError
        typer.echo(_ascii(f"error: {exc}"), err=True)
        raise typer.Exit(code=2) from exc
    target = out or report_json.with_name("viewer.html")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_viewer(report, tz), encoding="utf-8", newline="\n")
    typer.echo(_ascii(f"Wrote {target}"))


@app.command()
def writeback(
    report_json: Annotated[Path, typer.Argument(help="report.json written by `analyze`.")],
    out: Annotated[
        Path | None, typer.Option(help="Also write the events here as JSON lines.")
    ] = None,
    send_to: Annotated[
        Path | None,
        typer.Option("--socket", help="Send to this Wazuh queue socket (on the manager: "
                                      "/var/ossec/queue/sockets/queue)."),
    ] = None,
    agent_id: Annotated[
        str | None, typer.Option(help="File the events under this agent (Wazuh agent id).")
    ] = None,
    agent_name: Annotated[str | None, typer.Option(help="Agent name for --agent-id.")] = None,
    agent_ip: Annotated[str, typer.Option(help="Agent IP for --agent-id.")] = "any",
) -> None:
    """Turn a report's conclusions into Wazuh events (summary, affected files, attacker
    IPs) and send them to the manager's queue, where the webforensics rules raise alerts."""
    if send_to is None and out is None:
        typer.echo("error: give --socket, --out, or both", err=True)
        raise typer.Exit(code=2)
    if (agent_id is None) != (agent_name is None):
        typer.echo("error: --agent-id and --agent-name go together", err=True)
        raise typer.Exit(code=2)
    try:
        raw = report_json.read_bytes()
        events = build_writeback_events(load_report(report_json),
                                        report_sha256=hashlib.sha256(raw).hexdigest())
        agent = WazuhAgent(agent_id, agent_name, agent_ip) if agent_id and agent_name else None
        messages = [queue_message(e, agent) for e in events]
        if out is not None:
            write_events_jsonl(events, out)
            typer.echo(_ascii(f"Wrote {len(events)} event(s) to {out}"))
        if send_to is not None:
            sent = send_to_queue(messages, send_to)
            typer.echo(_ascii(f"Sent {sent} event(s) to {send_to}"))
    except (OSError, ValueError, WritebackError) as exc:
        typer.echo(_ascii(f"error: {exc}"), err=True)
        raise typer.Exit(code=2) from exc


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
    adapter: Annotated[
        list[str] | None,
        typer.Option(help="file and/or wazuh (default: every adapter a scenario has "
                          "evidence for)."),
    ] = None,
    webroot_root: Annotated[
        Path | None,
        typer.Option(help="Folder holding a restored webroot per scenario id "
                          "(benchmark v2: lab/v2/restore_webroot.py)."),
    ] = None,
) -> None:
    """Score the analyzer against the benchmark ground truth."""
    try:
        unknown = sorted(set(adapter or ()) - set(evaluate.ADAPTERS))
        if unknown:
            raise ValueError(f"unknown --adapter {', '.join(unknown)} (use file, wazuh)")
        folders = evaluate.scenario_folders(benchmark, tuple(scenario or ()))
        if webroot_root is not None and not webroot_root.is_dir():
            raise FileNotFoundError(f"--webroot-root is not a folder: {webroot_root}")
        scores = evaluate.evaluate_all(folders, tuple(adapter or evaluate.ADAPTERS),
                                       webroot_root)
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


def _credentials(user: str | None, password_file: Path | None) -> Credentials:
    """User from --user or WF_WAZUH_USER; password from a file or WF_WAZUH_PASSWORD.

    A password option is deliberately missing: command lines end up in shell history.
    """
    name = user or os.environ.get("WF_WAZUH_USER")
    if password_file is not None:
        secret = password_file.read_text(encoding="utf-8").strip()
    else:
        secret = os.environ.get("WF_WAZUH_PASSWORD", "")
    if not name or not secret:
        raise ValueError("indexer credentials missing: set --user (or WF_WAZUH_USER) and "
                         "--password-file (or WF_WAZUH_PASSWORD)")
    return Credentials(name, secret)


def _aware(value: str, option: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"{option} needs a UTC offset, e.g. 2026-10-29T09:00:00+07:00")
    return parsed


@app.command()
def pull(
    indexer: Annotated[str, typer.Option(help="Wazuh indexer URL, e.g. https://127.0.0.1:9200.")],
    agent: Annotated[str, typer.Option(help="Wazuh agent name of the web server.")],
    since: Annotated[str, typer.Option(help="Window start (ISO 8601 with offset).")],
    docroot: Annotated[
        str, typer.Option(help="Webroot path on the web server, e.g. /var/www/html.")
    ],
    access_log: Annotated[
        list[str],
        typer.Option(help="Access log path as Wazuh `location`, e.g. /var/log/nginx/access.log "
                          "(repeatable)."),
    ],
    out: Annotated[Path, typer.Option(help="Recording file to write (JSONL).")],
    until: Annotated[
        str | None, typer.Option(help="Window end (ISO 8601 with offset). Default: now.")
    ] = None,
    error_log: Annotated[
        list[str] | None, typer.Option(help="Error log path as Wazuh `location` (repeatable).")
    ] = None,
    ca_cert: Annotated[
        Path | None, typer.Option(help="CA certificate that signed the indexer certificate.")
    ] = None,
    tls_server_name: Annotated[
        str | None,
        typer.Option(help="Certificate name to verify when it differs from the URL host."),
    ] = None,
    user: Annotated[str | None, typer.Option(help="Indexer user (or WF_WAZUH_USER).")] = None,
    password_file: Annotated[
        Path | None, typer.Option(help="File holding the password (or WF_WAZUH_PASSWORD).")
    ] = None,
    page_size: Annotated[int, typer.Option(min=1, max=10000, help="Hits per page.")] = 1000,
) -> None:
    """Copy Wazuh web logs and FIM alerts into a recording (the only command that uses the
    network). Analyze it offline with `analyze --wazuh-recording`."""
    try:
        client = IndexerClient(indexer, _credentials(user, password_file),
                               ca_file=str(ca_cert) if ca_cert else None,
                               server_name=tls_server_name)
        request = PullRequest(
            agent=agent, since=_aware(since, "--since"),
            until=_aware(until, "--until") if until else datetime.now(UTC),
            docroot=docroot, access_logs=tuple(access_log), error_logs=tuple(error_log or ()),
            page_size=page_size)
        header = run_pull(client, request, out)
    except (OSError, ValueError, IndexerError, PullError) as exc:
        typer.echo(_ascii(f"error: {exc}"), err=True)
        raise typer.Exit(code=2) from exc
    counts = ", ".join(f"{k}={v}" for k, v in sorted(header.counts.items()))
    typer.echo(f"Wrote {out} ({counts}; web events from {header.web_index})")
    if not header.archives:
        typer.echo("warning: no wazuh-archives-4.x-* index; web events come from alerts only, "
                   "so successful uploads are missing (docs/wazuh-notes.md section 3.1)")
