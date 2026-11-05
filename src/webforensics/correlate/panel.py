"""Sites created through a hosting panel by an address never seen before (D98).

A stolen panel login leaves no attack payload: the attacker uses the panel's own forms to
add gambling sites, as in Organization Y (benchmark/external/id-public-sector-2025). In an
access log that looks like an administrator at work. What can still be said is narrower:
a site or domain was created or changed, and the address that did it had not appeared in
the log before although the log covers the days before. That is a lead to verify with
the account owner, never an accusation: the address is not named as an attacker.

Endpoints (2026-11; POST bodies are not logged, so a form that both creates and edits
counts as "created or changed"). CyberPanel's web UI paths are from Organization Y's log,
its API path from an integrator's documentation; cPanel's from api.docs.cpanel.net and WHM
API 1; DirectAdmin's from its feature notes; aaPanel's only from a copy of its API
document and client libraries, so it is the least certain:
- CyberPanel: `/websites/submitWebsiteCreation`, `/websites/submitDomainCreation`,
  `/dns/zoneCreation` (web UI), `/api/createWebsite` (API).
- cPanel: UAPI `/execute/SubDomain/addsubdomain`, `/execute/AddonDomain/...`;
  WHM `/json-api/createacct`. A `/cpsessNNN` prefix may come first.
- DirectAdmin: `CMD_API_DOMAIN`, `CMD_DOMAIN`, `CMD_API_SUBDOMAIN`, `CMD_SUBDOMAIN`.
- aaPanel: `/site?action=AddSite`.
"""

import re
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta

from webforensics.detect import RULESET_VERSION
from webforensics.models import (
    Confidence,
    Finding,
    FindingCategory,
    LogEvent,
    Reason,
    Severity,
    stable_id,
)

PANEL_RULE = "CORR-PANEL-SITE-NEW-ADDRESS"
_SITE_PATH = re.compile(
    r"/websites/submit(?:Website|Domain)Creation/?$|/dns/zoneCreation/?$"
    r"|/api/createWebsite/?$"
    r"|/execute/(?:SubDomain/addsubdomain|AddonDomain/\w+)$|/json-api/createacct$"
    r"|/CMD_(?:API_)?(?:SUB)?DOMAIN$",
    re.IGNORECASE)
_AAPANEL = re.compile(r"(?:^|&)action=AddSite(?:&|$)", re.IGNORECASE)


def is_site_management(event: LogEvent) -> bool:
    """A panel request that creates (or changes) a site, domain or DNS zone, answered 2xx."""
    if not 200 <= event.status < 300:
        return False
    path = event.path or ""
    if path.rstrip("/") == "/site" and _AAPANEL.search(event.query or ""):
        return True
    if not _SITE_PATH.search(path):
        return False
    # UAPI and WHM calls may be GETs with the arguments in the query; panel forms POST.
    folded = path.casefold()
    return event.method == "POST" or "/execute/" in folded or "/json-api/" in folded


def panel_leads(events: Iterable[LogEvent], actor: Callable[[LogEvent], str],
                span: tuple[datetime, datetime] | None, history: timedelta,
                skip: set[str]) -> list[Finding]:
    """One finding per new address that managed sites. `events` are in time order.

    An address is new when its first request in the log comes after at least `history`
    of log: with less, every address looks new and nothing is said."""
    if span is None:
        return []
    first_seen: dict[str, LogEvent] = {}
    managed: dict[str, list[LogEvent]] = {}
    for event in events:
        who = actor(event)
        first_seen.setdefault(who, event)
        if is_site_management(event):
            managed.setdefault(who, []).append(event)
    found = []
    for who, hits in sorted(managed.items()):
        first = first_seen[who]
        if who in skip or first.ts - span[0] < history:
            continue
        paths = sorted({e.path or "" for e in hits})
        found.append(Finding(
            finding_id=stable_id(PANEL_RULE, hits[0].evidence_id), rule_id=PANEL_RULE,
            rule_version=RULESET_VERSION, category=FindingCategory.PERSISTENCE,
            subject=hits[0].evidence_id, severity=Severity.MEDIUM, confidence=Confidence.LOW,
            reasons=(Reason(key=f"finding.{PANEL_RULE}", params={
                "count": str(len(hits)), "paths": ", ".join(paths),
                "first_seen": first.ts.isoformat(),
                "days": str((first.ts - span[0]).days)}),),
            citations=(hits[0].citation(), first.citation()), mitre=("T1078",),
        ))
    return found
