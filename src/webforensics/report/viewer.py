"""Interactive, offline HTML viewer for a report (`webforensics view`).

The static report is for reading and printing; the viewer is for exploring: a per-actor
timeline chart, filters, and a detail panel with the cited evidence of each event.

Design:
- All Indonesian text is produced here, in Python, with the same `Texts` and `Document`
  the static report uses, so both always state the same facts. The page script only
  arranges and filters that text; it never builds markup from it (textContent only).
- The data sits in a `<script type="application/json">` block with `<`, `>` and `&`
  escaped, so evidence strings cannot close the block.
- The CSP allows exactly one script, by its SHA-256, and no network at all.
- Output is deterministic: the same report.json gives the same bytes.
"""

import base64
import hashlib
import json
from datetime import datetime
from importlib import resources
from typing import Any

from webforensics.models import CitationKind, Report, TimelineEvent
from webforensics.report import messages_id as m
from webforensics.report.document import (
    Block,
    Bullets,
    Code,
    Document,
    Fields,
    Heading,
    Para,
    Table,
    _counts,
    _endpoints,
    attack_story,
    build_document,
    shown_gaps,
    timeline_runs,
)
from webforensics.report.text import Texts, clean, zone_short
from webforensics.report.theme import base_css

# Which tab shows which section of the static document. The overview adds the chain and
# the timeline tab is built from the events themselves (D97). Root cause, files, IOCs,
# gaps and actions are drawn from `detail` so they can link into the timeline (D104).
TABS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("overview", ("ringkasan",)),
    ("timeline", ()),
    ("root", ("akar-masalah",)),
    ("files", ("file-terdampak", "tinjau")),
    ("iocs", ("ioc", "latar")),
    ("gaps", ("celah-bukti",)),
    ("actions", ("tindakan", "keterbatasan")),
    ("case", ("kasus", "bukti", "reproduksi")),
)

CATEGORY: dict[str, str] = {
    "timeline.actor_first_seen": "recon",
    "timeline.recon": "recon",
    "timeline.exploit_attempt": "exploit",
    "timeline.auth_bypass_sqli": "exploit",
    "timeline.upload_exploit": "exploit",
    "timeline.write_exploit": "exploit",
    "timeline.rce_exploit": "exploit",
    "timeline.sqli_file_write": "exploit",
    "timeline.login_failed": "login",
    "timeline.login_bruteforce": "login",
    "timeline.login_method_unknown": "login",
    "timeline.login_valid_credentials": "login",
    "timeline.actor_request": "other",
    "timeline.upload_after_login": "exploit",
    "timeline.write_after_login": "exploit",
    "timeline.exploited_endpoint_write": "exploit",
    "timeline.file_side_write": "write",
    "timeline.log_only_file_gone": "file",
    "timeline.file_write_request": "write",
    "timeline.file_write_candidate": "write",
    "timeline.file_deleted_by_command": "write",
    "timeline.file_created": "file",
    "timeline.file_changed": "file",
    "timeline.file_modified_mtime": "file",
    "timeline.file_timestomp": "file",
    "timeline.file_deleted": "file",
    "timeline.log_only_file": "file",
    "timeline.log_only_file_unverified": "file",
    "timeline.file_invoked": "use",
}
CATEGORIES = ("recon", "exploit", "login", "write", "file", "use", "other")
MAX_LANES = 10  # attackers first, then the busiest actors; the rest share one lane
EN_DASH = chr(0x2013)
MONTHS = ("Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des")


def _ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _clock(texts: Texts, value: datetime) -> tuple[str, str]:
    """('29 Okt 2026', '12:19:55') in the report's zone, for the ledger's date rows."""
    local = value.astimezone(texts.tz)
    return f"{local.day} {MONTHS[local.month - 1]} {local.year}", f"{local:%H:%M:%S}"


def _block(block: Block) -> dict[str, Any]:
    if isinstance(block, Para):
        return {"t": "p", "text": block.text}
    if isinstance(block, Bullets):
        return {"t": "ul", "items": list(block.items)}
    if isinstance(block, Table):
        return {"t": "table", "headers": list(block.headers),
                "rows": [[{"text": c.text, "mark": c.mark} for c in row] for row in block.rows],
                "hl": sorted(block.highlight)}
    if isinstance(block, Fields):
        return {"t": "dl", "pairs": [list(p) for p in block.pairs]}
    if isinstance(block, Code):
        return {"t": "code", "lines": list(block.lines)}
    if isinstance(block, Heading):
        return {"t": "h", "text": block.text}
    raise TypeError(f"unknown block {type(block).__name__}")


def _doc(doc: Document) -> list[dict[str, Any]]:
    """Every section of the static report, in order: the tabs show some of them and the
    full report (`#laporan`) shows all of them."""
    return [{"anchor": s.anchor, "title": s.title, "blocks": [_block(b) for b in s.blocks]}
            for s in doc.sections]


def _tabs(doc: Document, counts: dict[str, int]) -> list[dict[str, Any]]:
    present = {s.anchor for s in doc.sections}
    return [{"id": tab, "label": m.VIEWER[f"tab.{tab}"], "count": counts.get(tab, 0),
             "anchors": [a for a in anchors if a in present]} for tab, anchors in TABS]


def _root_detail(report: Report, texts: Texts, numbers: dict[str, int]) -> dict[str, Any] | None:
    """The root cause taken apart: the request, the reasons, and the vulnerable code."""
    result = report.result
    cause = result.root_cause
    if cause is None:
        return None
    by_id = {e.event_id: e for e in result.timeline}
    event = by_id[cause.event_id]
    line = next((c for c in event.citations if c.kind is CitationKind.LOG_LINE), None)
    code = [{
        "file": clean(f.file), "line": f.line, "sinkLine": f.sink_line, "sink": clean(f.sink),
        "sources": [clean(s) for s in f.sources],
        "why": texts.label(f"code.why.{f.implicated_by}"),
        "conf": f.confidence.value, "confLabel": texts.confidence(f.confidence.value),
        "snippet": clean(f.snippet),
        "fix": [clean(x) for x in (f.suggested_fix or "").splitlines()],
        "verified": f.verified, "ref": texts.cite(f.citation),
    } for f in report.code_findings]
    scope = report.code_scope
    return {
        "n": numbers[event.event_id],
        "request": ({"ref": texts.cite(line), "raw": clean(line.excerpt)}
                    if line is not None and line.excerpt else None),
        "refs": [texts.cite(c) for c in event.citations],
        "reasons": list(dict.fromkeys(texts.message(r) for r in cause.reasons)),
        "alts": [{"n": numbers[i], "text": texts.message(by_id[i].description)}
                 for i in cause.alternative_event_ids if i in by_id],
        "code": code,
        "codeNone": bool(scope and scope.analyzed and not report.code_findings),
        "analyzed": [clean(p) for p in scope.analyzed] if scope else [],
        "included": [clean(p) for p in scope.included] if scope else [],
        "noContent": [clean(p) for p in scope.no_content] if scope else [],
    }


def _related(path: str, events: list[dict[str, Any]], cites: list[dict[str, str]]) -> list[int]:
    """Timeline events about one file: they name it or cite it."""
    own = f"{path} @"
    return [e["n"] for e in events
            if path in e["text"] or any(cites[i]["ref"].startswith(own) for i in e["cites"])]


def _files_detail(report: Report, texts: Texts, events: list[dict[str, Any]],
                  cites: list[dict[str, str]]) -> dict[str, Any]:
    result = report.result
    files = []
    for f in result.affected_files:
        own = [x for x in result.findings if x.subject == f.evidence_id]
        files.append({
            "path": clean(f.path), "sha256": f.sha256,
            "size": f"{f.size} {texts.label('bytes')}",
            "status": m.BASELINE_STATUS[f.baseline_status.value],
            "times": [{"name": name, "time": texts.time(value)} for name, value in (
                ("btime", f.btime), ("ctime", f.ctime), ("mtime", f.mtime)) if value],
            "tsSource": m.TIMESTAMP_SOURCE[f.timestamp_source.value],
            "urls": [clean(u) for u in f.url_paths],
            "fim": [f"{m.FIM_EVENTS[c.event.value]} {texts.time(c.ts)} ({c.mode.value}, "
                    f"{texts.cite(c.citation)})" for c in f.fim],
            "findings": [{"text": texts.message(x.reasons[0]) if x.reasons else
                          texts.rule(x.rule_id), "rule": x.rule_id,
                          "conf": x.confidence.value,
                          "confLabel": texts.confidence(x.confidence.value)} for x in own],
            "events": _related(clean(f.path), events, cites),
        })
    log_only: dict[str, Any] | None = None
    if result.log_only_files:
        unverified = any(e.description.key == "timeline.log_only_file_unverified"
                         for e in result.timeline)
        note = "files.log_only_note_unverified" if unverified else "files.log_only_note"
        log_only = {"title": texts.label("files.log_only"), "note": texts.label(note),
                    "items": [{"path": clean(p), "events": _related(clean(p), events, cites)}
                              for p in result.log_only_files]}
    return {"files": files, "logOnly": log_only}


def _iocs_detail(report: Report, texts: Texts) -> list[dict[str, Any]]:
    iocs = report.result.iocs
    groups = (("ips", iocs.ips), ("user_agents", iocs.user_agents), ("sha256s", iocs.sha256s),
              ("paths", iocs.paths), ("urls", iocs.urls))
    return [{"key": key, "label": texts.label(f"ioc.{key}"), "values": [clean(v) for v in values]}
            for key, values in groups if values]


def _gaps_detail(report: Report, texts: Texts, numbers: dict[str, int]) -> dict[str, Any]:
    gaps, labels = report.result.gaps, texts.gap_labels
    shown = set(shown_gaps(gaps))
    rows = []
    for g in sorted(gaps, key=lambda g: int(labels[g.gap_id][1:])):
        if g.gap_id not in shown:
            continue
        detail = texts.message(g.detail) if g.detail else ""
        rows.append({
            "label": labels[g.gap_id], "kind": m.GAP_KINDS.get(g.kind.value, ""),
            "when": (f"{texts.time(g.start)} s.d. {texts.time(g.end)}" if g.start or g.end
                     else ""),
            "from": _ms(g.start) if g.start and g.end else None,
            "to": _ms(g.end) if g.start and g.end else None,
            "detail": detail, "source": clean(g.source) if g.source else "",
            "affects": [numbers[i] for i in g.affects if i in numbers],
        })
    more = len(gaps) - len(shown)
    return {"rows": rows,
            "more": texts.label("gap.more_silences").format(count=more) if more > 0 else ""}


def _actions_detail(report: Report, texts: Texts) -> list[dict[str, Any]]:
    out = []
    for phase, title in m.PHASES.items():
        items = [texts.message(r) for r in report.recommendations
                 if r.key.startswith(f"rec.{phase}.")]
        if items:
            out.append({"phase": phase, "title": title, "items": items})
    return out


class _Citations:
    """Each distinct citation once, referenced by index from the events."""

    def __init__(self, texts: Texts) -> None:
        self.texts, self.rows, self.index = texts, [], {}

    def add(self, event: TimelineEvent) -> list[int]:
        out = []
        for c in event.citations:
            ref = self.texts.cite(c)
            if ref not in self.index:
                self.index[ref] = len(self.rows)
                # Same rule as the report's evidence appendix: a file is identified by its hash.
                excerpt = (f"SHA-256 {c.sha256}" if c.kind is CitationKind.FILE or
                           (c.sha256 and not c.excerpt) else c.excerpt)
                self.rows.append({"ref": ref, "ex": clean(excerpt)})
            out.append(self.index[ref])
        return out


def _lanes(report: Report) -> list[str]:
    """Actor lanes for the chart: attackers, then by event count; '' is file evidence."""
    counts: dict[str, int] = {}
    for e in report.result.timeline:
        counts[e.actor or ""] = counts.get(e.actor or "", 0) + 1
    attackers = [ip for ip in report.result.iocs.ips if ip in counts]
    rest = sorted((a for a in counts if a and a not in attackers), key=lambda a: (-counts[a], a))
    lanes = (attackers + rest)[:MAX_LANES]
    if "" in counts:
        lanes.append("")
    return lanes


def _events(report: Report, texts: Texts, cites: _Citations) -> tuple[list, list]:
    result = report.result
    compromised = bool(result.affected_files or result.log_only_files)
    story = {e.event_id for e in attack_story(result.timeline, result.iocs.ips)} if compromised \
        else set()
    numbers = {e.event_id: i for i, e in enumerate(result.timeline, start=1)}
    runs, events = [], []
    for run in timeline_runs(result.timeline):
        run_id = None
        if len(run) > 1:
            run_id = len(runs)
            text = m.VIEWER["run.summary"].format(
                count=len(run), endpoints=_endpoints(texts, run),
                rules=_counts([texts.rule(e.description.params.get("rule_id", "")) for e in run]))
            runs.append({"first": numbers[run[0].event_id], "last": numbers[run[-1].event_id],
                         "count": len(run), "text": text,
                         "time": f"{texts.time(run[0].ts)} s.d. {texts.time(run[-1].ts)}",
                         "clock": _clock(texts, run[0].ts)[1] + EN_DASH
                         + _clock(texts, run[-1].ts)[1]})
        for e in run:
            text = texts.message(e.description)
            day, clock = _clock(texts, e.ts)
            events.append({
                "n": numbers[e.event_id],
                "time": texts.time(e.ts),
                "day": day,
                "clock": clock,
                "ms": _ms(e.ts),
                "basis": m.TIME_BASIS.get(e.ts_basis.value, ""),
                "phase": texts.tactic(e.mitre_tactic, e.mitre_technique),
                "actor": clean(e.actor) if e.actor else "",
                "text": text,
                "conf": e.confidence.value,
                "confLabel": texts.confidence(e.confidence.value),
                "root": e.is_root_cause,
                "story": e.event_id in story,
                "cat": CATEGORY.get(e.description.key, "other"),
                "cites": cites.add(e),
                "notes": [texts.message(r) for r in e.confidence_reasons],
                "run": run_id,
            })
    return events, runs


def _gap_bands(report: Report, texts: Texts) -> list[dict[str, Any]]:
    keep = set(shown_gaps(report.result.gaps))
    return [{"label": texts.gap_labels.get(g.gap_id, ""), "from": _ms(g.start), "to": _ms(g.end),
             "kind": m.GAP_KINDS.get(g.kind.value, "")}
            for g in report.result.gaps if g.gap_id in keep and g.start and g.end]


def build_view(report: Report, texts: Texts) -> dict[str, Any]:
    """Everything the page shows, as plain text and numbers."""
    doc = build_document(report, texts)
    result = report.result
    cites = _Citations(texts)
    events, runs = _events(report, texts, cites)
    compromised = bool(result.affected_files or result.log_only_files)
    root = None
    if result.root_cause is not None:
        event = next(e for e in events if e["root"])
        root = {"n": event["n"], "text": event["text"], "time": event["time"],
                "day": event["day"], "clock": event["clock"], "actor": event["actor"],
                "vuln": texts.vuln(result.root_cause.vuln_class),
                "vulnKnown": (result.root_cause.vuln_class or "") in m.VULN_CLASSES,
                "conf": result.root_cause.confidence.value,
                "confLabel": texts.confidence(result.root_cause.confidence.value)}
    offset = texts.tz.utcoffset(None)
    numbers = {e.event_id: i for i, e in enumerate(result.timeline, start=1)}
    files = _files_detail(report, texts, events, cites.rows)
    iocs = _iocs_detail(report, texts)
    gaps = _gaps_detail(report, texts, numbers)
    actions = _actions_detail(report, texts)
    counts = {"files": len(files["files"]) + len(result.log_only_files),
              "iocs": sum(len(g["values"]) for g in iocs), "gaps": len(gaps["rows"]),
              "actions": sum(len(a["items"]) for a in actions)}
    return {
        "title": doc.title,
        "subtitle": doc.subtitle,
        "zone": texts.zone,
        "zoneShort": zone_short(texts.tz),
        "caseId": clean(report.case.case_id),
        "generated": texts.time(report.run.generated_at),
        "tool": clean(report.run.tool_version),
        "offsetMin": int(offset.total_seconds() // 60),
        "verdict": {"compromised": compromised, "root": root,
                    "stats": {"events": len(result.timeline),
                              "files": len(result.affected_files) + len(result.log_only_files),
                              "actors": len(result.iocs.ips), "gaps": len(result.gaps)}},
        "events": events,
        "runs": runs,
        "cites": cites.rows,
        "lanes": _lanes(report),
        "attackers": list(result.iocs.ips),
        "gaps": _gap_bands(report, texts),
        "categories": [{"id": c, "label": m.VIEWER[f"cat.{c}"]} for c in CATEGORIES],
        "tabs": _tabs(doc, counts),
        "doc": _doc(doc),
        "detail": {"root": _root_detail(report, texts, numbers), "files": files,
                   "iocs": iocs, "gaps": gaps, "actions": actions},
        "ui": m.VIEWER,
        "labels": {"rootMarker": m.LABELS["root_marker"], "noActor": m.LABELS["actor.none"]},
    }


def _asset(name: str) -> str:
    return resources.files("webforensics.report").joinpath("viewer_assets", name).read_text(
        encoding="utf-8")


def _json_for_html(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render_viewer(report: Report, texts: Texts) -> str:
    view = build_view(report, texts)
    script, style = _asset("viewer.js"), _asset("viewer.css")
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    # The font is embedded as a data: URI (theme.py), so font-src allows data: only.
    csp = (f"default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; "
           "font-src data:; img-src 'none'; connect-src 'none'; form-action 'none'; "
           "base-uri 'none'")
    title = view["title"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="id">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{title}</title>\n<style>{base_css()}\n{style}</style>\n</head>\n<body>\n"
        '<div id="app"></div>\n'
        f'<script type="application/json" id="data">{_json_for_html(view)}</script>\n'
        f"<script>{script}</script>\n</body>\n</html>\n"
    )
