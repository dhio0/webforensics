"""Static, deterministic heuristics for individual file evidence.

Evidence content is read as bytes from ``content_ref`` only and is never imported
or executed. Content rules inspect at most ``MAX_CONTENT_BYTES`` per file (D15).
"""

import math
import re
from pathlib import Path

from webforensics.detect import RULESET_VERSION, UPLOAD_WRITABLE_DIRS
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
    suffix = Path(parts[-1]).suffix.casefold()
    if suffix in _EXECUTABLE_EXTENSIONS and _WRITABLE_DIRS.intersection(parts[:-1]):
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
