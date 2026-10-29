"""Choose the files to analyze and turn analyzer results into report findings (M7).

Only implicated code is analyzed: the endpoint of the root cause, its alternatives, the
endpoints of requests that wrote a file, and endpoints where an attacker's SQL injection
requests got a 2xx answer (D84). Files these endpoints include are analyzed too, one
level deep (`includes.py`). Content comes from the evidence when it is hash-checked there
(a manifest with its webroot copy). For files the evidence does not list, such as
unchanged files under Wazuh FIM, a given `--webroot` copy is read and the finding says the
content was not checked against a hash.
"""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from webforensics.adapters.file_adapter import INDEX_NAMES
from webforensics.codeloc.includes import resolve_includes
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
SQLI_RULE_PREFIX = "LOG-SQLI-"
PHP_SUFFIXES = (".php", ".phtml", ".php5", ".php7", ".inc")
MAX_BYTES = 2 * 1024 * 1024
MAX_WEBROOT_FILES = 50_000


@dataclass(frozen=True)
class _Source:
    path: str  # webroot-relative
    content: bytes
    sha256: str
    verified: bool


def _exploited_sqli(event) -> bool:
    params = event.description.params
    return (event.description.key == "timeline.exploit_attempt"
            and params.get("rule_id", "").startswith(SQLI_RULE_PREFIX)
            and params.get("status", "").startswith("2"))


_PRIORITY = ("entry", "write", "sqli_target")


def implicated_reasons(result: CorrelationResult) -> dict[str, str]:
    """Implicated URL -> why (the strongest reason when there are several)."""
    ids = set()
    if result.root_cause is not None:
        ids = {result.root_cause.event_id, *result.root_cause.alternative_event_ids}
    attackers = set(result.iocs.ips)
    reasons: dict[str, str] = {}
    for e in result.timeline:
        url = unquote(e.description.params.get("path", ""))
        if not url.startswith("/"):
            continue
        if e.event_id in ids:
            why = "entry"
        elif e.description.key in IMPLICATED_KINDS:
            why = "write"
        elif e.actor in attackers and _exploited_sqli(e):
            why = "sqli_target"
        else:
            continue
        if url not in reasons or _PRIORITY.index(why) < _PRIORITY.index(reasons[url]):
            reasons[url] = why
    return dict(sorted(reasons.items()))


def implicated_urls(result: CorrelationResult) -> list[str]:
    return list(implicated_reasons(result))


class _Lookup:
    """Webroot-relative paths and their content, from the evidence or a webroot copy."""

    def __init__(self, files: FileCollection, webroot: Path | None, url_prefix: str,
                 case_insensitive: bool) -> None:
        self.files = files
        self.webroot = webroot
        self.prefix = "/" + url_prefix.strip("/") if url_prefix.strip("/") else ""
        self.ci = case_insensitive
        self._listing: list[str] | None = None

    def fold(self, text: str) -> str:
        return text.casefold() if self.ci else text

    def for_url(self, url: str) -> _Source | None:
        for file in self.files.files:
            if self.fold(url) in {self.fold(u) for u in file.url_paths} and file.content_ref:
                return self._evidence(file.path)
        if self.webroot is None or not self.fold(url).startswith(self.fold(self.prefix + "/")):
            return None
        rel = url[len(self.prefix):].lstrip("/")
        names = [f"{rel}{name}" for name in INDEX_NAMES] if rel.endswith("/") or not rel else [rel]
        return next((s for name in names if (s := self._from_webroot(name))), None)

    def for_path(self, rel: str) -> _Source | None:
        return self._evidence(rel) or self._from_webroot(rel)

    def paths(self) -> list[str]:
        """Every known webroot path: the evidence's files plus the webroot copy."""
        if self._listing is None:
            known = {f.path for f in self.files.files if f.content_ref}
            if self.webroot is not None and self.webroot.is_dir():
                for i, path in enumerate(sorted(self.webroot.rglob("*"))):
                    if i >= MAX_WEBROOT_FILES:
                        break
                    if path.is_file() and not path.is_symlink():
                        known.add(path.relative_to(self.webroot).as_posix())
            self._listing = sorted(known)
        return self._listing

    def _evidence(self, rel: str) -> _Source | None:
        for file in self.files.files:
            if self.fold(file.path) == self.fold(rel) and file.content_ref:
                content = Path(file.content_ref).read_bytes()[:MAX_BYTES]
                return _Source(file.path, content, file.sha256, verified=True)
        return None

    def _from_webroot(self, rel: str) -> _Source | None:
        if self.webroot is None or not rel or ".." in rel.split("/"):
            return None
        candidate = self._resolve(rel)
        if candidate is None:
            return None
        content = candidate.read_bytes()[:MAX_BYTES]
        name = candidate.relative_to(self.webroot).as_posix()
        return _Source(name, content, sha256_bytes(content), verified=False)

    def _resolve(self, rel: str) -> Path | None:
        """The file at `rel`, named as on disk, so the result does not depend on whether
        the analyst's own filesystem ignores case."""
        assert self.webroot is not None
        candidate = self.webroot
        for part in rel.split("/"):
            if not candidate.is_dir():
                return None
            names = {c.name: c for c in candidate.iterdir()}
            match = names.get(part)
            if match is None and self.ci:
                match = next((names[n] for n in sorted(names)
                              if n.casefold() == part.casefold()), None)
            if match is None:
                return None
            candidate = match
        try:
            candidate.resolve().relative_to(self.webroot.resolve())
        except ValueError:
            return None
        return candidate if candidate.is_file() and not candidate.is_symlink() else None


def _location(source: _Source, found: SqlInjection, why: str) -> CodeLocation:
    confidence = found.confidence if source.verified else cap(found.confidence,
                                                              Confidence.MEDIUM)
    return CodeLocation(
        file=source.path, line=found.line, snippet=found.snippet, vuln_class="sql_injection",
        suggested_fix=found.suggested_fix, confidence=confidence,
        citation=Citation(kind=CitationKind.FILE, source=source.path, sha256=source.sha256,
                          excerpt=f"{source.path}:{found.line}: {found.snippet}"),
        sink_line=found.sink_line, sink=found.sink, sources=found.sources,
        verified=source.verified, implicated_by=why,
    )


def review_code(result: CorrelationResult, files: FileCollection,
                webroot: Path | None = None, url_prefix: str = "/",
                case_insensitive: bool = False,
                ) -> tuple[tuple[CodeLocation, ...], CodeScope | None]:
    """Findings in the implicated PHP files and the files they include, and what was (not)
    analyzed. None: nothing is implicated (no compromise was found)."""
    reasons = {u: why for u, why in implicated_reasons(result).items()
               if u.endswith("/") or u.lower().endswith(PHP_SUFFIXES)}
    if not reasons:
        return (), None
    lookup = _Lookup(files, webroot, url_prefix, case_insensitive)
    analyzed: dict[str, _Source] = {}
    why: dict[str, str] = {}
    missing: list[str] = []
    for url, reason in reasons.items():
        source = lookup.for_url(url)
        if source is None:
            missing.append(url.lstrip("/") or url)
            continue
        analyzed.setdefault(source.path, source)
        if source.path not in why or _PRIORITY.index(reason) < _PRIORITY.index(why[source.path]):
            why[source.path] = reason
    included: dict[str, _Source] = {}
    for source in list(analyzed.values()):
        for rel in resolve_includes(source.content, source.path, lookup.paths(),
                                    case_insensitive):
            if rel not in analyzed and (found := lookup.for_path(rel)) is not None:
                included.setdefault(found.path, found)
                why.setdefault(found.path, "included")
    everything = {**included, **analyzed}
    findings = tuple(_location(source, found, why[path])
                     for path, source in sorted(everything.items())
                     for found in find_sql_injections(source.content))
    scope = CodeScope(
        analyzed=tuple(sorted(analyzed)),
        included=tuple(sorted(included)),
        unverified=tuple(sorted(p for p, s in everything.items() if not s.verified)),
        no_content=tuple(sorted(set(missing))),
    )
    return findings, scope
