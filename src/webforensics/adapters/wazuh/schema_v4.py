"""Wazuh 4.x index names, field names and queries, kept in one place (D73).

Verified against Wazuh 4.14.9 (docs/wazuh-notes.md). Wazuh 5.0 renames the indices and
fields, so a 5.x adapter would be a new module next to this one, not an edit of it.
"""

from datetime import datetime

# Explicit "-4.x-" names: on 5.x they match nothing, and the pull stops with a clear error.
ALERTS = "wazuh-alerts-4.x-*"
ARCHIVES = "wazuh-archives-4.x-*"

# Manager processing time with a correct UTC offset (src/analysisd, json_extended.c).
TIMESTAMP = "timestamp"
AGENT_NAME = "agent.name"
LOCATION = "location"
FULL_LOG = "full_log"
SYSCHECK_PATH = "syscheck.path"

# PIT + search_after needs a total order; `_id` breaks ties within one millisecond.
SORT = ({TIMESTAMP: "asc"}, {"_id": "asc"})


def _iso(value: datetime) -> str:
    return value.isoformat()


def _window(agent: str, since: datetime, until: datetime) -> list[dict[str, object]]:
    """Every query is bounded by agent name and time: re-enrolled agents get new IDs, and
    events from earlier runs stay indexed (docs/wazuh-notes.md §10)."""
    return [
        {"term": {AGENT_NAME: agent}},
        {"range": {TIMESTAMP: {"gte": _iso(since), "lte": _iso(until)}}},
    ]


def web_query(agent: str, locations: tuple[str, ...], since: datetime,
              until: datetime) -> dict[str, object]:
    """Web log events: one per line read by logcollector, raw line in `full_log`."""
    return {"bool": {"filter": [*_window(agent, since, until),
                                {"terms": {LOCATION: list(locations)}},
                                {"exists": {"field": FULL_LOG}}]}}


def fim_query(agent: str, since: datetime, until: datetime) -> dict[str, object]:
    """FIM alerts (rules 550, 553, 554 and friends) carry a `syscheck` object."""
    return {"bool": {"filter": [*_window(agent, since, until),
                                {"exists": {"field": SYSCHECK_PATH}}]}}


def alert_time(source: dict[str, object]) -> datetime:
    """`timestamp`, e.g. 2026-10-29T10:40:56.338+0700. Raises KeyError or ValueError."""
    value = datetime.fromisoformat(str(source[TIMESTAMP]))
    if value.tzinfo is None:
        raise ValueError(f"timestamp without UTC offset: {value}")
    return value


def mtime_after(syscheck: dict[str, object], alert_ts: datetime) -> datetime | None:
    """Read `syscheck.mtime_after` in the manager's time zone (D76).

    The manager formats it in its local time with the offset cut off (to_json.c: a 20-byte
    strftime buffer), and the indexer then reads it as UTC. So the raw `_source` string is
    used, never the indexer's parsed value, and the offset comes from the same alert's
    `timestamp`, which the same process wrote in the same time zone. A DST switch between
    the mtime and the alert would shift it by an hour (accepted limitation).
    Confirmed in the lab with a UTC+7 manager (notes §4.3).
    """
    raw = syscheck.get("mtime_after")
    if not raw:
        return None
    try:
        value = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    if value.tzinfo is not None:  # a future fix may add the offset; trust it then
        return value
    return value.replace(tzinfo=alert_ts.tzinfo)
