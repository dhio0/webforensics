"""Rules that classify single access-log requests.

A rule match means "this request looks like X", never "the attack succeeded": success is
decided later by correlating the request with file evidence (plan §4). Request text is
percent-decoded before matching because attackers encode payloads to dodge naive filters.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from urllib.parse import unquote_plus

from webforensics.detect import RULESET_VERSION, UPLOAD_WRITABLE_DIRS
from webforensics.models import (
    Confidence,
    Finding,
    FindingCategory,
    LogEvent,
    Reason,
    Severity,
    stable_id,
    truncate_excerpt,
)

MATCH_SNIPPET_CHARS = 80
DECODE_PASSES = 2  # double encoding (%2527) is a common filter bypass


class Target(StrEnum):
    REQUEST = "request"  # decoded path + query
    USER_AGENT = "user_agent"
    PATH = "path"
    QUERY = "query"


@dataclass(frozen=True)
class LogRule:
    rule_id: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    mitre: tuple[str, ...]
    target: Target
    pattern: re.Pattern[str]


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


_UPLOAD_DIRS = rf"(?:{'|'.join(re.escape(name) for name in UPLOAD_WRITABLE_DIRS)})"
_EXEC_EXT = r"\.(?:php[0-9]?|phtml|phar|jsp|jspx|aspx?|cgi|pl)"

LOG_RULES: tuple[LogRule, ...] = (
    LogRule(
        "LOG-SQLI-UNION", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH, Confidence.HIGH,
        ("T1190",), Target.REQUEST,
        _rx(r"\bunion(?:\s|/\*.*?\*/|\+)+(?:all(?:\s|/\*.*?\*/)+)?select\b"),
    ),
    LogRule(
        "LOG-SQLI-TAUTOLOGY", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH, Confidence.MEDIUM,
        ("T1190",), Target.REQUEST,
        _rx(r"""(?:['"]\s*|\s)(?:or|and)\s+['"]?(\w+)['"]?\s*=\s*['"]?\1\b"""),
    ),
    LogRule(
        "LOG-SQLI-BLIND", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH, Confidence.HIGH,
        ("T1190",), Target.REQUEST,
        _rx(r"\b(?:sleep|pg_sleep|benchmark|extractvalue|updatexml)\s*\(|waitfor\s+delay\b"),
    ),
    LogRule(
        "LOG-SQLI-SCHEMA", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH, Confidence.HIGH,
        ("T1190",), Target.REQUEST,
        _rx(r"\binformation_schema\b|\binto\s+(?:out|dump)file\b|\bload_file\s*\("),
    ),
    LogRule(
        "LOG-SQLI-QUOTE-COMMENT", FindingCategory.EXPLOIT_ATTEMPT, Severity.MEDIUM,
        Confidence.MEDIUM, ("T1190",), Target.REQUEST,
        _rx(r"""['"]\s*\)?\s*(?:--(?:\s|$)|#|/\*)"""),
    ),
    LogRule(
        "LOG-TRAVERSAL-DOTS", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH, Confidence.MEDIUM,
        ("T1190",), Target.REQUEST,
        _rx(r"(?:\.\.[/\\]){2,}"),
    ),
    LogRule(
        "LOG-TRAVERSAL-SENSITIVE", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH,
        Confidence.HIGH, ("T1190", "T1083"), Target.REQUEST,
        _rx(r"/etc/(?:passwd|shadow)\b|\bwin\.ini\b|\bboot\.ini\b|/proc/self/environ"),
    ),
    # Script injection probes (D87): markup breaking out of an attribute or tag.
    LogRule(
        "LOG-XSS-PROBE", FindingCategory.EXPLOIT_ATTEMPT, Severity.LOW, Confidence.MEDIUM,
        ("T1190",), Target.QUERY,
        _rx(r"<\s*script\b|[\"']\s*>\s*<\s*[a-z/!]|\bjavascript\s*:|\bon(?:error|load|mouseover)\s*="),
    ),
    # Code injection (D86): PHP code or a code-running callback in the request, e.g.
    # Drupalgeddon2's `name[#post_render][]=passthru&name[#markup]=...`.
    LogRule(
        "LOG-RCE-CODE-INJECTION", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH,
        Confidence.MEDIUM, ("T1190", "T1059"), Target.REQUEST,
        _rx(r"\b(?:eval|assert|base64_decode|gzinflate|str_rot13|passthru|shell_exec"
            r"|proc_open|popen|pcntl_exec|call_user_func(?:_array)?|create_function)\s*\("
            r"|\bsystem\s*\(\s*['\"$]|<\?php|\bphp\s+-r\s"
            r"|\[#(?:post_render|pre_render|lazy_builder|access_callback|value_callback)\]"),
    ),
    # OS command injection (D94): a shell separator, then a command that only probes or
    # reads (`;cat /etc/passwd`, `|id`, `$(whoami)`), as commix and manual tests send.
    LogRule(
        "LOG-CMDI-SHELL", FindingCategory.EXPLOIT_ATTEMPT, Severity.HIGH, Confidence.MEDIUM,
        ("T1190", "T1059.004"), Target.QUERY,
        _rx(r"(?:[;|`]|&&|\$\()\s*(?:cat|id|whoami|uname|ls|dir|type|echo|sleep|ping"
            r"|wget|curl|nc|ncat|bash|sh|pwd|hostname|ifconfig|ipconfig|nslookup)\b"),
    ),
    LogRule(
        "LOG-SCANNER-UA", FindingCategory.RECON, Severity.LOW, Confidence.MEDIUM,
        ("T1595.002",), Target.USER_AGENT,
        _rx(r"\b(?:sqlmap|nikto|nmap|acunetix|nessus|wpscan|masscan|dirbuster|gobuster|havij"
            r"|commix|wfuzz|ffuf|nuclei)\b"),
    ),
    LogRule(
        "LOG-WEBSHELL-UPLOAD-DIR", FindingCategory.WEBSHELL, Severity.HIGH, Confidence.MEDIUM,
        ("T1505.003",), Target.PATH,
        _rx(rf"/{_UPLOAD_DIRS}/(?:[^?]*/)?[^/?]+{_EXEC_EXT}$"),
    ),
    LogRule(
        "LOG-WEBSHELL-CMD-PARAM", FindingCategory.WEBSHELL, Severity.MEDIUM, Confidence.LOW,
        ("T1505.003", "T1059"), Target.QUERY,
        _rx(r"(?:^|&)(?:cmd|exec|command|shell)=[^&]+"),
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in LOG_RULES}


@lru_cache(maxsize=65536)
def decode_text(value: str) -> str:
    """Percent-decode (twice), turn `+` into space, drop NULs. Matching is case-insensitive."""
    if "%" in value or "+" in value:
        for _ in range(DECODE_PASSES):
            decoded = unquote_plus(value)
            if decoded == value:
                break
            value = decoded
    return value.replace("\x00", "") if "\x00" in value else value


@lru_cache(maxsize=65536)
def _matches(path: str, query: str, user_agent: str) -> tuple[tuple[LogRule, str], ...]:
    """(rule, matched text) for one request shape. Cached: real logs repeat the same
    request many times, and the result depends only on these three strings."""
    decoded_path, decoded_query = decode_text(path), decode_text(query)
    texts = {
        Target.USER_AGENT: user_agent,
        Target.PATH: decoded_path,
        Target.QUERY: decoded_query,
        Target.REQUEST: f"{decoded_path}?{decoded_query}" if decoded_query else decoded_path,
    }
    found = []
    for rule in LOG_RULES:
        match = rule.pattern.search(texts[rule.target])
        if match:
            found.append((rule, match.group(0)))
    return tuple(found)


def _finding(event: LogEvent, rule: LogRule, matched: str) -> Finding:
    return Finding(
        finding_id=stable_id(rule.rule_id, event.evidence_id),
        rule_id=rule.rule_id,
        rule_version=RULESET_VERSION,
        category=rule.category,
        subject=event.evidence_id,
        severity=rule.severity,
        confidence=rule.confidence,
        reasons=(
            Reason(
                key=f"finding.{rule.rule_id}",
                params={
                    "matched": truncate_excerpt(matched)[:MATCH_SNIPPET_CHARS],
                    "status": str(event.status),
                    "method": event.method or "",
                },
            ),
        ),
        citations=(event.citation(),),
        mitre=rule.mitre,
    )


def detect_request(event: LogEvent) -> list[Finding]:
    shape = _matches(event.path or "", event.query or "", event.user_agent or "")
    return [_finding(event, rule, matched) for rule, matched in shape]


def detect_requests(events: Iterable[LogEvent]) -> list[Finding]:
    """Findings for every event, in log order, rules in declaration order (deterministic)."""
    return [finding for event in events for finding in detect_request(event)]
