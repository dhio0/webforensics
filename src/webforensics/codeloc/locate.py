"""Choose the files to analyze and turn analyzer results into report findings (M7).

Only implicated code is analyzed: the endpoint of the root cause, its alternatives, and
the endpoints of requests that wrote a file. Content comes from the evidence when it is
hash-checked there (a manifest with its webroot copy). For files the evidence does not
list, such as unchanged files under Wazuh FIM, a given `--webroot` copy is read and the
finding says the content was not checked against a hash.
"""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from webforensics.adapters.file_adapter import INDEX_NAMES
from webforensics.codeloc.php_sqli import SqlInjection, find_sql_injections
from webforensics.correlate.confidence import cap
from webforensics.hashing import sha256_bytes
from webforensics.models import (
    Citation,
    CitationKind,
    CodeLocation,
    CodeScope,
    Confidence,
    CorrelationResult,
    FileCollection,
)

# Timeline kinds whose request is a way in or a write: their endpoint is implicated.
IMPLICATED_KINDS = frozenset({
    "timeline.upload_exploit", "timeline.write_exploit", "timeline.file_write_request",
    "timeline.auth_bypass_sqli", "timeline.login_method_unknown",
})
PHP_SUFFIXES = (".php", ".phtml", ".php5", ".php7", ".inc")
MAX_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class _Source:
    path: str  # webroot-relative
    content: bytes
    sha256: str
    verified: bool


def implicated_urls(result: CorrelationResult) -> list[str]:
    ids = set()
    if result.root_cause is not None:
        ids = {result.root_cause.event_id, *result.root_cause.alternative_event_ids}
    urls = {
        unquote(e.description.params.get("path", "")) for e in result.timeline
        if e.description.params.get("path")
        and (e.event_id in ids or e.description.key in IMPLICATED_KINDS)
    }
    return sorted(u for u in urls if u.startswith("/"))


def _under(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return candidate.is_file() and not candidate.is_symlink()


def _from_webroot(url: str, webroot: Path, url_prefix: str) -> _Source | None:
    prefix = "/" + url_prefix.strip("/") if url_prefix.strip("/") else ""
    if prefix and not url.startswith(prefix + "/"):
        return None
    rel = url[len(prefix):].lstrip("/")
    names = [f"{rel}{name}" for name in INDEX_NAMES] if rel.endswith("/") or not rel else [rel]
    for name in names:
        candidate = webroot / name
        if name and ".." not in name.split("/") and _under(webroot, candidate):
            content = candidate.read_bytes()[:MAX_BYTES]
            return _Source(name, content, sha256_bytes(content), verified=False)
    return None


def _source_for(url: str, files: FileCollection, webroot: Path | None,
                url_prefix: str) -> _Source | None:
    for file in files.files:
        if url in file.url_paths and file.content_ref:
            content = Path(file.content_ref).read_bytes()[:MAX_BYTES]
            return _Source(file.path, content, file.sha256, verified=True)
    if webroot is not None:
        return _from_webroot(url, webroot, url_prefix)
    return None


def _location(source: _Source, found: SqlInjection) -> CodeLocation:
    confidence = found.confidence if source.verified else cap(found.confidence,
                                                              Confidence.MEDIUM)
    return CodeLocation(
        file=source.path, line=found.line, snippet=found.snippet, vuln_class="sql_injection",
        suggested_fix=found.suggested_fix, confidence=confidence,
        citation=Citation(kind=CitationKind.FILE, source=source.path, sha256=source.sha256,
                          excerpt=f"{source.path}:{found.line}: {found.snippet}"),
        sink_line=found.sink_line, sink=found.sink, sources=found.sources,
        verified=source.verified,
    )


def review_code(result: CorrelationResult, files: FileCollection,
                webroot: Path | None = None, url_prefix: str = "/"
                ) -> tuple[tuple[CodeLocation, ...], CodeScope | None]:
    """Findings in the implicated PHP files, and what was (not) analyzed. None: nothing is
    implicated (no compromise was found)."""
    urls = [u for u in implicated_urls(result)
            if u.endswith("/") or u.lower().endswith(PHP_SUFFIXES)]
    if not urls:
        return (), None
    analyzed: dict[str, _Source] = {}
    missing: list[str] = []
    for url in urls:
        source = _source_for(url, files, webroot, url_prefix)
        if source is None:
            missing.append(url.lstrip("/") or url)
        else:
            analyzed.setdefault(source.path, source)
    findings = tuple(_location(source, found) for path, source in sorted(analyzed.items())
                     for found in find_sql_injections(source.content))
    scope = CodeScope(
        analyzed=tuple(sorted(analyzed)),
        unverified=tuple(sorted(p for p, s in analyzed.items() if not s.verified)),
        no_content=tuple(sorted(set(missing))),
    )
    return findings, scope
