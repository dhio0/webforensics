"""Who sent a request, and did a login attempt succeed?

Actor: the client IP, or, when that IP is a trusted reverse proxy, the right-most
X-Forwarded-For hop that is not a trusted proxy. Left-most hops are client-controlled
and can be forged, so they are never trusted (D47).

Login outcome: combined logs show only status and size. An attempt counts as failed if
it got 401/403/429, if the same actor retried the same login before using the protected
area, or if its (status, size) equals a known failure on the same endpoint. Anything
else that got 2xx/3xx counts as a success (D48).
"""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Sequence
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from webforensics.correlate import requests as rq
from webforensics.models import LogEvent, Reason

_EXPLICIT_FAILURE = (401, 403, 429)
Network = IPv4Network | IPv6Network


def parse_networks(values: Sequence[str]) -> tuple[Network, ...]:
    return tuple(ip_network(value, strict=False) for value in values)


def is_trusted_proxy(value: str, networks: tuple[Network, ...]) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in networks)


def _valid_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def resolve_actor(event: LogEvent, proxies: tuple[Network, ...]) -> str:
    if not proxies or not event.xff or not is_trusted_proxy(event.client_ip, proxies):
        return event.client_ip
    for hop in reversed([part.strip() for part in event.xff.split(",")]):
        if _valid_ip(hop) and not is_trusted_proxy(hop, proxies):
            return hop
    return event.client_ip


class LoginOutcome(StrEnum):
    FAILED = "failed"
    SUCCEEDED = "succeeded"


def _is_page_view(event: LogEvent) -> bool:
    """A successful non-login, non-static request: evidence the actor got in."""
    return (rq.is_success(event) and not rq.is_login_endpoint(event.path)
            and not rq.is_static_asset(event.path))


def _used_area_between(own: list[LogEvent], views: list[int], start: int, end: int,
                       login_path: str) -> bool:
    """Any page view in the login's area strictly between positions start and end?"""
    first = bisect_right(views, start)
    last = bisect_left(views, end)
    return any(rq.shares_area(login_path, own[i].path) for i in views[first:last])


def _first_pass(own: list[LogEvent], outcomes: dict[str, tuple[LoginOutcome, Reason]],
                pending: list[LogEvent]) -> None:
    """Explicit failures and retries for one actor's time-sorted requests.

    Each attempt's next attempt is looked up per path, and page views by bisection, so a
    brute-force run of N attempts costs O(N log N), not O(N^2).
    """
    views = [i for i, e in enumerate(own) if _is_page_view(e)]
    attempts: dict[str | None, list[int]] = defaultdict(list)
    for i, event in enumerate(own):
        if rq.is_login_attempt(event):
            attempts[event.path].append(i)
    for path, positions in attempts.items():
        for k, i in enumerate(positions):
            event = own[i]
            if event.status in _EXPLICIT_FAILURE:
                outcomes[event.evidence_id] = (LoginOutcome.FAILED, Reason(
                    key="login.failed_status", params={"status": str(event.status)}))
                continue
            retry = positions[k + 1] if k + 1 < len(positions) else None
            if retry is not None and not _used_area_between(own, views, i, retry, path or "/"):
                outcomes[event.evidence_id] = (LoginOutcome.FAILED, Reason(
                    key="login.retried", params={"retry_line": str(own[retry].line_no)}))
                continue
            pending.append(event)


def login_outcomes(events: list[LogEvent], actor_of: dict[str, str],
                   flagged: frozenset[str] = frozenset()
                   ) -> dict[str, tuple[LoginOutcome, Reason]]:
    """Outcome of every login attempt, keyed by evidence id. `events` must be time-sorted.

    `flagged` holds ids of requests that carry an attack pattern. Bots replay the same
    payload whether or not it works, so their "retries" say nothing about what a failure
    page looks like and are kept out of the failure fingerprints.
    """
    by_actor: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        by_actor[actor_of[event.evidence_id]].append(event)

    outcomes: dict[str, tuple[LoginOutcome, Reason]] = {}
    pending: list[LogEvent] = []
    for own in by_actor.values():
        _first_pass(own, outcomes, pending)

    failures = {(e.path, e.status, e.bytes_sent) for e in events
                if outcomes.get(e.evidence_id, (None,))[0] is LoginOutcome.FAILED
                and e.evidence_id not in flagged}
    for event in pending:
        if (event.path, event.status, event.bytes_sent) in failures:
            outcomes[event.evidence_id] = (LoginOutcome.FAILED, Reason(
                key="login.same_response_as_failure"))
        elif rq.is_success(event):
            outcomes[event.evidence_id] = (LoginOutcome.SUCCEEDED, Reason(
                key="login.success_unlike_failures"))
        else:
            outcomes[event.evidence_id] = (LoginOutcome.FAILED, Reason(
                key="login.failed_status", params={"status": str(event.status)}))
    return outcomes
