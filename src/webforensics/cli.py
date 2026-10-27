"""Command-line interface."""

import json
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from webforensics import __version__
from webforensics.adapters.base import FileEvidenceSource
from webforensics.adapters.file_adapter import (
    DirectoryFileSource,
    LogFileSource,
    ManifestFileSource,
)
from webforensics.models import FileCollection, LogCollection
from webforensics.parsers.access_log import AccessLogFormat
from webforensics.parsers.manifest import ManifestError

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
    """Load evidence and show what was parsed. No analysis yet (milestone 1)."""
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
