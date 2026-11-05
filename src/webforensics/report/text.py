"""Turn language-neutral keys and params into Indonesian plain text.

Output is plain text, never markup: the Markdown and HTML renderers escape it. Keeping
one place that formats times and translates codes makes both formats say the same thing.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from webforensics.models import Citation, CitationKind, Reason
from webforensics.report import messages_id as m

_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_TIME_PARAMS = frozenset({"mtime", "btime", "ctime", "fim"})
# C0 controls and DEL would make terminals and some viewers misbehave; show them instead.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class MissingMessageError(KeyError):
    """A key or placeholder has no Indonesian text (only raised in strict mode)."""


def parse_display_offset(value: str) -> timezone:
    match = _OFFSET.match(value.strip())
    if not match:
        raise ValueError(f"offset must look like +07:00, got {value!r}")
    sign, hours, minutes = match.groups()
    delta = timedelta(hours=int(hours), minutes=int(minutes))
    if delta > timedelta(hours=14):
        raise ValueError(f"offset out of range: {value!r}")
    return timezone(-delta if sign == "-" else delta)


def _iso_offset(tz: timezone) -> str:
    delta = tz.utcoffset(None)
    sign = "-" if delta < timedelta(0) else "+"
    minutes = abs(int(delta.total_seconds())) // 60
    return f"{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def offset_label(tz: timezone) -> str:
    """`WIB (UTC+07:00)` for Indonesian zones, otherwise `UTC+05:30`."""
    iso = _iso_offset(tz)
    name = m.ZONE_NAMES.get(iso)
    return f"{name} (UTC{iso})" if name and name != "UTC" else f"UTC{iso}"


def zone_short(tz: timezone) -> str:
    iso = _iso_offset(tz)
    return m.ZONE_NAMES.get(iso) or f"UTC{iso}"


def clean(value: str) -> str:
    """One line of visible text: newlines become spaces, control bytes become \\xNN."""
    value = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return _CONTROL.sub(lambda c: f"\\x{ord(c.group(0)):02x}", value)


class _Params(dict):
    def __init__(self, values: Mapping[str, str], strict: bool, key: str) -> None:
        super().__init__(values)
        self._strict, self._key = strict, key

    def __missing__(self, name: str) -> str:
        if self._strict:
            raise MissingMessageError(f"{self._key}: no value for {{{name}}}")
        return "?"


@dataclass
class Texts:
    """Formats keys, times and citations for one report. `strict` raises on gaps in the
    catalog instead of falling back (used by tests)."""

    tz: timezone = field(default_factory=lambda: timezone(timedelta(hours=7)))
    gap_labels: Mapping[str, str] = field(default_factory=dict)
    strict: bool = False

    @property
    def zone(self) -> str:
        return offset_label(self.tz)

    def time(self, value: datetime | None) -> str:
        if value is None:
            return m.LABELS["not_set"]
        return f"{value.astimezone(self.tz):%Y-%m-%d %H:%M:%S} {zone_short(self.tz)}"

    def label(self, key: str) -> str:
        return m.LABELS[key]

    def confidence(self, value: str) -> str:
        return m.CONFIDENCE.get(value, value)

    def vuln(self, value: str | None) -> str:
        return m.VULN_CLASSES.get(value or "", m.VULN_UNKNOWN)

    def rule(self, rule_id: str) -> str:
        return m.RULE_NAMES.get(rule_id, rule_id)

    def tactic(self, tactic: str | None, technique: str | None) -> str:
        if tactic is None:
            return m.LABELS["not_set"]
        name = m.TACTICS_ID.get(tactic, tactic)
        return f"{name}, {technique}" if technique else name

    def _param(self, name: str, value: str) -> str:
        if name in _TIME_PARAMS or name == "at" or name.endswith("_at"):
            try:
                return self.time(datetime.fromisoformat(value))
            except ValueError:
                return value
        if name == "confidence":
            return self.confidence(value)
        if name == "vuln_class":
            return self.vuln(value)
        if name == "status" and not value:
            return m.LABELS["not_set"]
        return value

    def _derived(self, params: Mapping[str, str]) -> dict[str, str]:
        out = {name: self._param(name, value) for name, value in params.items()}
        if "sha256" in params:
            out["sha256_short"] = params["sha256"][:12] + "…"
        if "rule_id" in params:
            out["rule_name"] = self.rule(params["rule_id"])
        if "gap_id" in params:
            out["gap"] = self.gap_labels.get(params["gap_id"], params["gap_id"])
        return out

    def message(self, reason: Reason) -> str:
        template = m.MESSAGES.get(reason.key)
        if template is None:
            if self.strict:
                raise MissingMessageError(reason.key)
            return clean(f"[{reason.key}] {reason.params}" if reason.params else reason.key)
        return clean(template.format_map(_Params(self._derived(reason.params), self.strict,
                                                 reason.key)))

    def cite(self, citation: Citation) -> str:
        """Short reference, e.g. `access.log:5` or `uploads/x.php @52d31ac74301`.

        Wazuh citations (log lines and FIM alerts) point at a line of the recording."""
        if citation.kind is CitationKind.LOG_LINE or (
                citation.kind is CitationKind.WAZUH_ALERT and citation.line_no is not None):
            return clean(f"{citation.source}:{citation.line_no}")
        if citation.sha256:
            return clean(f"{citation.source} @{citation.sha256[:12]}")
        return clean(citation.source)
