"""Static, deterministic heuristics for individual file evidence.

Evidence content is read as bytes from ``content_ref`` only and is never imported
or executed. Content rules inspect at most ``MAX_CONTENT_BYTES`` per file (D15).
"""

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from webforensics.detect import RULESET_VERSION, UPLOAD_WRITABLE_DIRS, judol
from webforensics.models import (
    BaselineStatus,
    Confidence,
    FileEvidence,
    Finding,
    FindingCategory,
    Reason,
    Severity,
    stable_id,
    truncate_excerpt,
)

MAX_CONTENT_BYTES = 2 * 1024 * 1024
_EXECUTABLE_EXTENSIONS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".jsp",
    ".jspx", ".asp", ".aspx", ".cgi", ".pl",
}
_WRITABLE_DIRS = frozenset(UPLOAD_WRITABLE_DIRS)
_REQUEST_VAR = r"\$_(?:GET|POST|REQUEST|COOKIE)\b"
_EXEC_CALL = re.compile(
    r"(?<!->)(?<!::)\b(?P<function>eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\((?P<argument>[^;]{0,300})",
    re.IGNORECASE | re.DOTALL,
)
_REQUEST_INPUT = re.compile(_REQUEST_VAR, re.IGNORECASE)
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{100,}(?![A-Za-z0-9+/=_-])")
_ENCODED_CALL = re.compile(r"\b(?:base64_decode|gzinflate|str_rot13)\s*\(", re.IGNORECASE)
_PERSISTENCE_NAMES = {".htaccess", "index.php", "index.html", "index.htm", "index.phtml"}
# Defacement banners (D87): the attacker signs or brags on a public page.
_PAGE_NAMES = {"index.php", "index.html", "index.htm", "index.phtml", "default.htm",
               "default.html", "default.aspx", "home.html"}
_DEFACEMENT = re.compile(
    r"\b(?:hacked|defaced|owned|pwned)\s+by\b|\b(?:has|have|was)\s+been\s+(?:hacked|defaced|"
    r"owned|pwned)\b|\bsite\s+hacked\b|\bhacked\s+site\b|\bdi\s*-?\s*hack\s+oleh\b",
    re.IGNORECASE)


def has_executable_extension(path: str) -> bool:
    """Any extension part counts, not only the last (D94). Apache's `AddHandler` runs
    `shell.php.jpg` as PHP, and trailing dots or spaces (`x.php..`) slip past naive
    upload filters; Windows and some setups drop them when the file is served."""
    name = path.rsplit("/", 1)[-1].casefold().rstrip(". ")
    return any(f".{part}" in _EXECUTABLE_EXTENSIONS for part in name.split(".")[1:])


# `AddType application/x-httpd-php .jpg`, `AddHandler php-script .gif`: other extensions
# made executable. `SetHandler` inside a FilesMatch, or alone, makes every file executable.
_HANDLER_LINE = re.compile(
    r"^\s*Add(?:Type|Handler)\s+(?P<handler>\S*php\S*)\s+(?P<exts>[^\r\n#]+)",
    re.IGNORECASE | re.MULTILINE)
_SET_HANDLER = re.compile(r"^\s*(?:Set|Force)(?:Handler|Type)\s+\S*php\S*", re.IGNORECASE
                          | re.MULTILINE)


_FILES_BLOCK = re.compile(
    r"<Files(?:Match)?\s+(?P<pattern>[^>]*)>(?P<body>.*?)</Files(?:Match)?\s*>",
    re.IGNORECASE | re.DOTALL)
_PATTERN_EXT = re.compile(r"\.\(?(?P<alts>[a-z0-9|]+)", re.IGNORECASE)


def handler_extensions(content: str) -> tuple[frozenset[str], bool]:
    """Extensions an `.htaccess` maps to PHP beyond the usual ones, and whether it makes
    every file in its folder executable (a `SetHandler` outside any `<Files>` block).
    `<FilesMatch "\\.jpg$"> SetHandler ...php` maps that block's extensions."""
    exts: set[str] = set()
    rest = content
    for block in _FILES_BLOCK.finditer(content):
        if _SET_HANDLER.search(block.group("body")):
            exts |= {f".{alt.casefold()}" for m in _PATTERN_EXT.finditer(block.group("pattern"))
                     for alt in m.group("alts").split("|") if alt}
        rest = rest.replace(block.group(0), "")
    exts |= {f".{e.strip().lstrip('.').casefold()}" for m in _HANDLER_LINE.finditer(content)
             for e in m.group("exts").split() if e.strip(".")}
    return frozenset(exts - _EXECUTABLE_EXTENSIONS), bool(_SET_HANDLER.search(rest))


HTACCESS_RULE = "FILE-HTACCESS-PHP-HANDLER"
JUDOL_RULE = "FILE-JUDOL-CONTENT"
CLOAKING_RULE = "FILE-SEO-CLOAKING"
HANDLED_RULE = "FILE-HANDLER-EXEC"


@dataclass(frozen=True)
class HandlerScope:
    """An `.htaccess` that makes more files run as PHP, for its folder and below."""

    htaccess: FileEvidence
    folder: str  # "" for the webroot itself, else "a/b/"
    extensions: frozenset[str]
    every_file: bool


def handler_scopes(files: Iterable[FileEvidence]) -> list[HandlerScope]:
    scopes = []
    for file in files:
        path = file.path.replace("\\", "/")
        if path.rsplit("/", 1)[-1] != ".htaccess" or file.baseline_status is (
                BaselineStatus.UNCHANGED):
            continue
        content = _read_content(file)
        if content is None:
            continue
        exts, every = handler_extensions(content)
        if exts or every:
            folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
            scopes.append(HandlerScope(file, folder, exts, every))
    return scopes


def handled_by(path: str, scopes: list[HandlerScope]) -> HandlerScope | None:
    """The `.htaccess` that makes this non-script file run as PHP, if any."""
    path = path.replace("\\", "/")
    name = path.rsplit("/", 1)[-1]
    if name == ".htaccess" or has_executable_extension(path):
        return None
    suffix = Path(name.casefold()).suffix
    return next((s for s in scopes if path.startswith(s.folder)
                 and (s.every_file or suffix in s.extensions)), None)


def handler_findings(file: FileEvidence, scopes: list[HandlerScope]) -> list[Finding]:
    found = []
    own = next((s for s in scopes if s.htaccess.evidence_id == file.evidence_id), None)
    if own is not None:
        found.append(_finding(
            file, HTACCESS_RULE, FindingCategory.PERSISTENCE, Severity.HIGH, Confidence.MEDIUM,
            f"finding.{HTACCESS_RULE}",
            {"extensions": ", ".join(sorted(own.extensions)) or "*"}, ("T1505.003",)))
    scope = handled_by(file.path, scopes)
    if scope is not None:
        found.append(_finding(
            file, HANDLED_RULE, FindingCategory.WEBSHELL, Severity.HIGH, Confidence.MEDIUM,
            f"finding.{HANDLED_RULE}",
            {"path": truncate_excerpt(file.path), "htaccess": scope.htaccess.path},
            ("T1505.003",)))
    return found


def is_entrypoint_name(path: str) -> bool:
    return path.rsplit("/", 1)[-1].casefold() in _PERSISTENCE_NAMES


def _read_content(file: FileEvidence) -> str | None:
    if file.content_ref is None:
        return None
    try:
        with Path(file.content_ref).open("rb") as content:
            return content.read(MAX_CONTENT_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _finding(file: FileEvidence, rule_id: str, category: FindingCategory,
             severity: Severity, confidence: Confidence, key: str,
             params: dict[str, str], mitre: tuple[str, ...]) -> Finding:
    return Finding(
        finding_id=stable_id(rule_id, file.evidence_id),
        rule_id=rule_id,
        rule_version=RULESET_VERSION,
        category=category,
        subject=file.evidence_id,
        severity=severity,
        confidence=confidence,
        reasons=(Reason(key=f"finding.{rule_id}", params=params),),
        citations=(file.citation(),),
        mitre=mitre,
    )


def detect_file(file: FileEvidence) -> list[Finding]:
    """Return findings in fixed rule order for one file evidence record."""
    findings: list[Finding] = []
    path = file.path.replace("\\", "/")
    parts = [part.casefold() for part in path.split("/")]
    if has_executable_extension(path) and _WRITABLE_DIRS.intersection(parts[:-1]):
        findings.append(_finding(
            file, "FILE-WEBSHELL-WRITABLE-EXEC", FindingCategory.WEBSHELL,
            Severity.HIGH, Confidence.MEDIUM, "finding.FILE-WEBSHELL-WRITABLE-EXEC",
            {"path": truncate_excerpt(file.path)}, ("T1505.003",),
        ))

    content = _read_content(file)
    if content is not None:
        match = next(
            (
                candidate
                for candidate in _EXEC_CALL.finditer(content)
                if _REQUEST_INPUT.search(candidate.group("argument"))
            ),
            None,
        )
        if match:
            findings.append(_finding(
                file, "FILE-WEBSHELL-REQUEST-EXEC", FindingCategory.WEBSHELL,
                Severity.HIGH, Confidence.HIGH, "finding.FILE-WEBSHELL-REQUEST-EXEC",
                {"function": match.group("function").casefold(), "input": "request_variable"},
                ("T1505.003", "T1059"),
            ))

        blobs = [match.group(0) for match in _LONG_TOKEN.finditer(content)]
        entropy_blob = next((blob for blob in blobs if _entropy(blob) >= 4.5), None)
        encoded = _ENCODED_CALL.search(content)
        if entropy_blob or encoded:
            evidence = entropy_blob or encoded.group(0)  # type: ignore[union-attr]
            findings.append(_finding(
                file, "FILE-WEBSHELL-OBFUSCATION", FindingCategory.WEBSHELL,
                Severity.LOW, Confidence.LOW, "finding.FILE-WEBSHELL-OBFUSCATION",
                {"signal": "high_entropy_blob" if entropy_blob else "encoding_function",
                 "length": str(len(evidence))}, ("T1027",),
            ))

        defaced = _DEFACEMENT.search(content) if parts[-1] in _PAGE_NAMES else None
        if defaced:
            findings.append(_finding(
                file, "FILE-DEFACEMENT-PAGE", FindingCategory.DEFACEMENT,
                Severity.HIGH, Confidence.MEDIUM, "finding.FILE-DEFACEMENT-PAGE",
                {"matched": truncate_excerpt(defaced.group(0))}, ("T1491.002",),
            ))

        spam = judol.score(content) if judol.could_be_spam(content.casefold()) else None
        if spam is not None and spam.spam:
            findings.append(_finding(
                file, JUDOL_RULE, FindingCategory.DEFACEMENT, Severity.HIGH,
                Confidence.HIGH if spam.dense else Confidence.MEDIUM, f"finding.{JUDOL_RULE}",
                {"matched": truncate_excerpt(spam.first), "terms": str(len(spam.labels)),
                 "hits": str(spam.hits)}, ("T1491.002",),
            ))
        cloak = judol.cloaking(content) if has_executable_extension(path) else None
        if cloak:
            findings.append(_finding(
                file, CLOAKING_RULE, FindingCategory.DEFACEMENT, Severity.MEDIUM,
                Confidence.LOW, f"finding.{CLOAKING_RULE}",
                {"matched": truncate_excerpt(cloak)}, ("T1491.002",),
            ))

    name = parts[-1]
    changed = file.baseline_status in (BaselineStatus.NEW, BaselineStatus.MODIFIED)
    if name in _PERSISTENCE_NAMES and changed:
        findings.append(_finding(
            file, "FILE-PERSISTENCE-ENTRYPOINT-CHANGE", FindingCategory.PERSISTENCE,
            Severity.LOW, Confidence.LOW, "finding.FILE-PERSISTENCE-ENTRYPOINT-CHANGE",
            {"path": truncate_excerpt(file.path), "status": file.baseline_status.value},
            ("T1505.003",),
        ))
    return findings
