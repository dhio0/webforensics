"""Small, explainable predicates about single requests, used by the correlation steps.

Combined logs carry no cookies or session ids, so "this upload needed that login" can
only be inferred from the same client, order in time, and a shared URL area. Every
predicate here is a heuristic and the engine's confidence levels reflect that.
"""

import re
from enum import IntEnum
from posixpath import dirname

from webforensics.models import Finding, LogEvent

_LOGIN_SEGMENT = re.compile(
    r"^(?:log[-_]?in|log[-_]?on|sign[-_]?in|auth|authenticate|wp-login|session)"
    r"(?:\.[a-z0-9]+)?$",
    re.IGNORECASE,
)
_UPLOAD_HINT = re.compile(r"upload|import|attach|media|plugin|theme|file", re.IGNORECASE)
_WRITE_METHODS = {"POST", "PUT", "PATCH"}


class WriteLevel(IntEnum):
    """How plausible it is that a request wrote a file to the webroot."""

    NONE = 0
    POSSIBLE = 1  # a body-carrying request to an endpoint with no upload hint
    LIKELY = 2  # PUT, a POST to an upload-like endpoint, or SQL `INTO OUTFILE`


def is_success(event: LogEvent) -> bool:
    return 200 <= event.status < 400


def is_login_endpoint(path: str | None) -> bool:
    # Only the last segment: `/auth/upload.php` is an upload, not a login.
    last = (path or "").rstrip("/").rsplit("/", 1)[-1]
    return bool(_LOGIN_SEGMENT.match(last))


def is_login_attempt(event: LogEvent) -> bool:
    """A login endpoint that received credentials (not just the form being viewed)."""
    has_input = event.method in _WRITE_METHODS or bool(event.query)
    return is_login_endpoint(event.path) and has_input


def is_failed_login(event: LogEvent) -> bool:
    return is_login_attempt(event) and event.status in (401, 403)


def area(path: str | None) -> str:
    """The URL directory a request lives in, e.g. `/admin/` for `/admin/login.php`."""
    directory = dirname(path or "/")
    return directory.rstrip("/") + "/"


def shares_area(entry_path: str | None, target_path: str | None) -> bool:
    """True if the target is inside the entry point's URL directory."""
    return (target_path or "/").startswith(area(entry_path))


def has_sqli(findings: list[Finding]) -> bool:
    return any(finding.rule_id.startswith("LOG-SQLI-") for finding in findings)


def write_level_for(method: str | None, path: str | None,
                    findings: list[Finding], query: str | None = None) -> WriteLevel:
    """The query string counts too: `POST /wp-admin/update.php?action=upload-plugin` is an
    upload although its path says nothing (D94). A POST to a static asset is never
    upload-like, whatever folder it sits in (a theme's `index.js`)."""
    matched = " ".join(r.params.get("matched", "") for f in findings for r in f.reasons)
    if method == "PUT" or re.search(r"\binto\s+(?:out|dump)file\b", matched, re.I):
        return WriteLevel.LIKELY
    if method not in _WRITE_METHODS:
        return WriteLevel.NONE
    if is_static_asset(path):
        return WriteLevel.POSSIBLE
    hinted = _UPLOAD_HINT.search(path or "") or _UPLOAD_HINT.search(query or "")
    return WriteLevel.LIKELY if hinted else WriteLevel.POSSIBLE


def write_level(event: LogEvent, findings: list[Finding]) -> WriteLevel:
    return write_level_for(event.method, event.path, findings, event.query)


_STATIC = re.compile(r"\.(?:css|js|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot)$", re.I)


def is_static_asset(path: str | None) -> bool:
    """Browsers fetch these after any page, so they say nothing about being logged in."""
    return bool(_STATIC.search(path or ""))
