"""The report's content as a format-neutral document of plain-text blocks.

Both renderers serialize this same structure, so Markdown and HTML always contain the
same facts. Every string here is plain text (often attacker-controlled); escaping is the
renderer's job and happens in exactly one function per format.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Literal

from webforensics.correlate.confidence import rank
from webforensics.models import (
    Citation,
    CitationKind,
    EvidenceGap,
    FileEvidence,
    Finding,
    Report,
    TimelineEvent,
)
from webforensics.report import messages_id as m
from webforensics.report.build import other_flagged_files
from webforensics.report.text import Texts, clean

Mark = Literal["high", "medium", "low", "root"]


@dataclass(frozen=True)
class Cell:
    text: str
    mark: Mark | None = None  # rendered as a badge (confidence) or emphasis (root)


@dataclass(frozen=True)
class Para:
    text: str


@dataclass(frozen=True)
class Bullets:
    items: tuple[str, ...]


@dataclass(frozen=True)
class Table:
    headers: tuple[str, ...]
    rows: tuple[tuple[Cell, ...], ...]
    highlight: frozenset[int] = frozenset()  # row indexes to highlight (root cause)


@dataclass(frozen=True)
class Fields:
    pairs: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Code:
    lines: tuple[str, ...]


@dataclass(frozen=True)
class Heading:
    text: str


Block = Para | Bullets | Table | Fields | Code | Heading


@dataclass(frozen=True)
class Section:
    anchor: str
    title: str
    blocks: tuple[Block, ...]


@dataclass(frozen=True)
class Document:
    title: str
    subtitle: str
    sections: tuple[Section, ...]
    lang: str = "id"


def _conf(texts: Texts, value: str) -> Cell:
    mark: Mark | None = value if value in ("high", "medium", "low") else None  # type: ignore[assignment]
    return Cell(texts.confidence(value), mark)


@dataclass
class _Ctx:
    report: Report
    texts: Texts
    numbers: dict[str, int] = field(default_factory=dict)  # timeline event id -> #n
    cited: dict[str, Citation] = field(default_factory=dict)  # short ref -> citation

    def ref(self, citation: Citation) -> str:
        short = self.texts.cite(citation)
        self.cited.setdefault(short, citation)
        return short

    def refs(self, citations: tuple[Citation, ...]) -> str:
        return ", ".join(self.ref(c) for c in citations)

    def number(self, event_id: str) -> str:
        return f"#{self.numbers[event_id]}"


def gap_labels(gaps: tuple[EvidenceGap, ...]) -> dict[str, str]:
    """G1, G2, ... in time order; gaps without a time range (e.g. no baseline) last."""
    ordered = sorted(gaps, key=lambda g: (g.start is None, g.start.isoformat() if g.start
                                          else "", g.kind.value, g.gap_id))
    return {g.gap_id: f"G{i}" for i, g in enumerate(ordered, start=1)}


# --- Sections -----------------------------------------------------------------------------


_STORY_KINDS = frozenset({
    "timeline.auth_bypass_sqli", "timeline.login_method_unknown", "timeline.upload_exploit",
    "timeline.write_exploit", "timeline.file_write_request", "timeline.file_created",
    "timeline.file_changed", "timeline.file_modified_mtime", "timeline.file_timestomp",
    "timeline.sqli_file_write", "timeline.log_only_file", "timeline.file_deleted_by_command",
    "timeline.log_only_file_unverified", "timeline.upload_after_login",
    "timeline.write_after_login", "timeline.login_valid_credentials",
    "timeline.exploited_endpoint_write", "timeline.file_side_write",
})


def attack_story(timeline: tuple[TimelineEvent, ...],
                 attackers: tuple[str, ...]) -> list[TimelineEvent]:
    """The incident's main steps for a non-technical reader: entry, write, file, first use.

    Context (recon, failed logins) and alternative candidates stay in the full timeline;
    only the first use of each file by an implicated actor is kept.
    """
    story, used = [], set()
    for event in timeline:
        if event.is_root_cause or event.description.key in _STORY_KINDS:
            story.append(event)
        elif (event.description.key == "timeline.file_invoked" and event.actor in attackers
              and event.description.params.get("file") not in used):
            used.add(event.description.params.get("file"))
            story.append(event)
    return story


_FILE_KINDS = frozenset({"timeline.file_created", "timeline.file_changed",
                         "timeline.file_modified_mtime"})


def collapse_identical(story: list[TimelineEvent]) -> list[tuple[TimelineEvent, int]]:
    """Consecutive file events with the same kind, time and content shown as one row and a
    count (D98): a judol kit writes hundreds of identical pages in the same second. The
    full timeline still lists each file."""
    rows: list[tuple[TimelineEvent, int]] = []
    for event in story:
        if rows and event.description.key in _FILE_KINDS:
            last, extra = rows[-1]
            digest = event.description.params.get("sha256")
            same = (digest is not None and last.description.key == event.description.key
                    and last.ts == event.ts and last.description.params.get("sha256") == digest)
            if same:
                rows[-1] = (last, extra + 1)
                continue
        rows.append((event, 0))
    return rows


def _summary(ctx: _Ctx) -> Section:
    t = ctx.texts
    blocks: list[Block] = [Bullets(tuple(t.message(r) for r in ctx.report.summary))]
    result = ctx.report.result
    compromised = result.affected_files or result.log_only_files
    story = attack_story(result.timeline, result.iocs.ips) if compromised else []
    if story:
        more = t.label("story.more_identical")
        blocks += [Heading(t.label("story")), Bullets(tuple(
            f"{ctx.number(e.event_id)} {t.time(e.ts)}: {t.message(e.description)}"
            + (" " + more.format(n=extra) if extra else "")
            for e, extra in collapse_identical(story)))]
    return Section("ringkasan", m.LABELS["s.summary"], tuple(blocks))


def _count(t: Texts, value: int, unit: str) -> str:
    return f"{value} {t.label(unit)}"


def _scope(ctx: _Ctx) -> Fields:
    t, s = ctx.texts, ctx.report.scope
    period = (f"{t.time(s.log_first)} s.d. {t.time(s.log_last)}" if s.log_first
              else t.label("scope.no_logs"))
    access = _count(t, s.log_events, "scope.lines")
    if s.log_unparsed:
        access += f", {_count(t, s.log_unparsed, 'scope.unparsed')}"
    pairs = [(t.label("scope.period"), period), (t.label("scope.access"), access)]
    if s.error_events or s.error_unparsed:
        pairs.append((t.label("scope.errors"), _count(t, s.error_events, "scope.entries")))
    wazuh = s.file_adapter == "wazuh"
    files = _count(t, s.files, "scope.fim_files" if wazuh else "scope.files")
    if s.files_rejected:
        files += f", {_count(t, s.files_rejected, 'scope.rejected')}"
    pairs.append((t.label("scope.webroot"), files))
    if s.collected_at:
        pairs.append((t.label("scope.collected_at"), t.time(s.collected_at)))
    baseline = (_count(t, s.baseline_files, "scope.files") if s.baseline_files is not None
                else t.label("scope.fim_baseline") if wazuh else t.label("scope.no_baseline"))
    pairs.append((t.label("scope.baseline"), baseline))
    return Fields(tuple(pairs))


def _case(ctx: _Ctx) -> Section:
    case, t = ctx.report.case, ctx.texts
    host = case.target_host if case.target_host is not None else t.label("not_set")
    return Section("kasus", t.label("s.case"), (
        Fields((
            (t.label("case_id"), clean(case.case_id)),
            (t.label("analyst"), clean(case.analyst) if case.analyst else t.label("not_set")),
            (t.label("host"), clean(host)),
            (t.label("generated_at"), t.time(ctx.report.run.generated_at)),
            (t.label("times_in"), t.zone),
        )),
        Heading(t.label("scope")),
        _scope(ctx),
    ))


def _event_text(ctx: _Ctx, event: TimelineEvent) -> str:
    text = ctx.texts.message(event.description)
    return f"{m.LABELS['root_marker']}: {text}" if event.is_root_cause else text


def _event_conf(ctx: _Ctx, event: TimelineEvent) -> Cell:
    """The root row can be surer that the request happened than that it was the way in."""
    cause = ctx.report.result.root_cause
    cell = _conf(ctx.texts, event.confidence.value)
    if event.is_root_cause and cause is not None and cause.confidence != event.confidence:
        text = m.LABELS["root.conf_note"].format(
            event=cell.text, root=ctx.texts.confidence(cause.confidence.value))
        return Cell(text, _conf(ctx.texts, cause.confidence.value).mark)
    return cell


# Flagged context requests come in bursts (a scanner or sqlmap sends thousands). Each burst
# from one actor is one row; report.json keeps every event.
_REPEATABLE = frozenset({"timeline.recon", "timeline.exploit_attempt"})
MIN_RUN = 3
RUN_BREAK = timedelta(minutes=5)  # a pause this long starts a new burst
TOP_ENDPOINTS = 3


def timeline_runs(timeline: tuple[TimelineEvent, ...]) -> list[list[TimelineEvent]]:
    """Consecutive flagged context requests from one actor without a pause longer than
    RUN_BREAK, grouped when there are MIN_RUN or more; every other event stands alone."""
    runs: list[list[TimelineEvent]] = []
    for event in timeline:
        last = runs[-1][-1] if runs else None
        if (last is not None and _repeatable(event) and _repeatable(last)
                and event.actor == last.actor and event.ts - last.ts <= RUN_BREAK):
            runs[-1].append(event)
        else:
            runs.append([event])
    out: list[list[TimelineEvent]] = []
    for run in runs:
        out += [run] if len(run) >= MIN_RUN else [[e] for e in run]
    return out


def _repeatable(event: TimelineEvent) -> bool:
    return not event.is_root_cause and event.description.key in _REPEATABLE


def _counts(values: list[str]) -> str:
    return ", ".join(f"{value} x{count}" for value, count in
                     sorted(Counter(values).items(), key=lambda kv: (-kv[1], kv[0])))


def _endpoints(t: Texts, run: list[TimelineEvent]) -> str:
    by_endpoint: dict[str, list[str]] = {}
    for e in run:
        p = e.description.params
        by_endpoint.setdefault(f"{p.get('method', '')} {p.get('path', '')}", []).append(
            p.get("status", ""))
    ranked = sorted(by_endpoint.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    parts = [f"{clean(endpoint)} x{len(statuses)} (status {_counts(statuses)})"
             for endpoint, statuses in ranked[:TOP_ENDPOINTS]]
    if len(ranked) > TOP_ENDPOINTS:
        parts.append(t.label("timeline.run_more").format(count=len(ranked) - TOP_ENDPOINTS))
    return "; ".join(parts)


def _run_row(ctx: _Ctx, run: list[TimelineEvent]) -> tuple[Cell, ...]:
    t, first, last = ctx.texts, run[0], run[-1]
    text = t.label("timeline.run").format(
        count=len(run), endpoints=_endpoints(t, run),
        rules=_counts([t.rule(e.description.params.get("rule_id", "")) for e in run]))
    exploit = next((e for e in run if e.description.key == "timeline.exploit_attempt"), first)
    return (
        Cell(f"{ctx.number(first.event_id)} s.d. {ctx.number(last.event_id)}"),
        Cell(f"{t.time(first.ts)} s.d. {t.time(last.ts)}"),
        Cell(m.TIME_BASIS.get(first.ts_basis.value, "")),
        Cell(t.tactic(exploit.mitre_tactic, exploit.mitre_technique)),
        Cell(clean(first.actor) if first.actor else t.label("actor.none")),
        Cell(text), _event_conf(ctx, max(run, key=lambda e: rank(e.confidence))),
        Cell(ctx.refs((first.citations[0], last.citations[0]))),
    )


def _timeline(ctx: _Ctx) -> Section:
    t, timeline = ctx.texts, ctx.report.result.timeline
    rows, highlight, notes = [], set(), []
    for run in timeline_runs(timeline):
        event = run[0]
        n = ctx.number(event.event_id)
        if len(run) > 1:
            rows.append(_run_row(ctx, run))
            continue
        rows.append((
            Cell(n), Cell(t.time(event.ts)), Cell(m.TIME_BASIS.get(event.ts_basis.value, "")),
            Cell(t.tactic(event.mitre_tactic, event.mitre_technique)),
            Cell(clean(event.actor) if event.actor else t.label("actor.none")),
            Cell(_event_text(ctx, event), "root" if event.is_root_cause else None),
            _event_conf(ctx, event), Cell(ctx.refs(event.citations)),
        ))
        if event.is_root_cause:
            highlight.add(len(rows) - 1)
        if event.confidence_reasons:
            reasons = " ".join(t.message(r) for r in event.confidence_reasons)
            notes.append(f"{n}: {reasons}")
    if not rows:
        return Section("kronologi", t.label("s.timeline"), (Para(t.label("review.none")),))
    headers = ("#", t.label("col.time"), t.label("col.basis"), t.label("col.phase"),
               t.label("col.actor"), t.label("col.event"), t.label("col.confidence"),
               t.label("col.evidence"))
    blocks: list[Block] = [Table(headers, tuple(rows), frozenset(highlight))]
    if notes:
        blocks += [Heading(t.label("timeline.notes")), Bullets(tuple(notes))]
    return Section("kronologi", t.label("s.timeline"), tuple(blocks))


def _root(ctx: _Ctx) -> Section:
    t, result = ctx.texts, ctx.report.result
    cause = result.root_cause
    if cause is None:
        return Section("akar-masalah", t.label("s.root"), (Para(t.label("root.none")),))
    by_id = {e.event_id: e for e in result.timeline}
    event = by_id[cause.event_id]
    pairs = [
        (t.label("root.event"), f"{ctx.number(event.event_id)} {t.message(event.description)}"),
        (t.label("root.vuln"), t.vuln(cause.vuln_class)),
        (t.label("root.confidence"), t.confidence(cause.confidence.value)),
        (t.label("col.evidence"), ctx.refs(event.citations)),
    ]
    # The payload (e.g. SQLi in the query string) is only visible in the raw line.
    line = next((c for c in event.citations if c.kind is CitationKind.LOG_LINE), None)
    blocks: list[Block] = [Fields(tuple(pairs))]
    if line is not None and line.excerpt:
        blocks += [Heading(t.label("root.request")), Code((clean(line.excerpt),))]
    blocks += [Heading(t.label("root.why")),
               Bullets(tuple(dict.fromkeys(t.message(r) for r in cause.reasons)))]
    if cause.alternative_event_ids:
        alts = tuple(f"{ctx.number(i)} {t.message(by_id[i].description)} "
                     f"({ctx.refs(by_id[i].citations)})" for i in cause.alternative_event_ids)
        blocks += [Heading(t.label("root.alternatives")), Bullets(alts)]
    blocks += _code_blocks(ctx)
    return Section("akar-masalah", t.label("s.root"), tuple(blocks))


def _code_blocks(ctx: _Ctx) -> list[Block]:
    """The vulnerable lines in the implicated files (M7), or what was analyzed without one."""
    t, report = ctx.texts, ctx.report
    scope = report.code_scope
    if scope is None:
        return []
    blocks: list[Block] = [Heading(t.label("root.code"))]
    for finding in report.code_findings:
        pairs = [
            (t.label("code.location"), clean(f"{finding.file}:{finding.line}")),
            (t.label("code.why"), t.label(f"code.why.{finding.implicated_by}")),
            (t.label("code.confidence"), t.confidence(finding.confidence.value)),
            (t.label("code.sources"), clean(", ".join(finding.sources))),
        ]
        if finding.sink_line is not None:
            pairs.append((t.label("code.sink"),
                          clean(f"{finding.file}:{finding.sink_line} ({finding.sink})")))
        pairs.append((t.label("col.evidence"), ctx.ref(finding.citation)))
        blocks += [Fields(tuple(pairs)), Code((clean(finding.snippet),))]
        if not finding.verified:
            blocks.append(Para(t.label("code.unverified")))
        if finding.suggested_fix:
            blocks += [Para(t.label("code.fix")),
                       Code(tuple(clean(line) for line in finding.suggested_fix.splitlines()))]
    if scope.analyzed and not report.code_findings:
        blocks.append(Para(t.label("code.none")))
    if scope.analyzed:
        pairs = [(t.label("code.analyzed"), clean(", ".join(scope.analyzed)))]
        if scope.included:
            pairs.append((t.label("code.included"), clean(", ".join(scope.included))))
        blocks.append(Fields(tuple(pairs)))
    if scope.no_content:
        blocks += [Para(t.label("code.no_content")),
                   Bullets(tuple(clean(p) for p in scope.no_content))]
    return blocks


def _finding_line(t: Texts, finding: Finding) -> str:
    text = t.message(finding.reasons[0]) if finding.reasons else t.rule(finding.rule_id)
    return (f"{text} ({finding.rule_id}, "
            f"{t.label('confidence')} {t.confidence(finding.confidence.value)})")


def _file_blocks(ctx: _Ctx, file: FileEvidence) -> list[Block]:
    t = ctx.texts
    times = "; ".join(f"{name} {t.time(value)}" for name, value in (
        ("btime", file.btime), ("ctime", file.ctime), ("mtime", file.mtime)) if value)
    own = [f for f in ctx.report.result.findings if f.subject == file.evidence_id]
    blocks: list[Block] = [
        Heading(clean(file.path)),
        Fields((
            (t.label("file.sha256"), file.sha256),
            (t.label("file.size"), f"{file.size} {t.label('bytes')}"),
            (t.label("file.status"), m.BASELINE_STATUS[file.baseline_status.value]),
            (t.label("file.times"), times or t.label("not_set")),
            (t.label("file.ts_source"), m.TIMESTAMP_SOURCE[file.timestamp_source.value]),
            (t.label("file.urls"), clean(", ".join(file.url_paths)) or t.label("not_set")),
            *_fim_history(ctx, file),
        )),
    ]
    ctx.ref(file.citation())
    if own:
        blocks += [Para(t.label("file.findings")),
                   Bullets(tuple(_finding_line(t, f) for f in own))]
    return blocks


def _fim_history(ctx: _Ctx, file: FileEvidence) -> tuple[tuple[str, str], ...]:
    """One entry per FIM alert: what happened, when, how it was seen, and where it is cited."""
    if not file.fim:
        return ()
    t = ctx.texts
    entries = "; ".join(
        f"{m.FIM_EVENTS[c.event.value]} {t.time(c.ts)} ({c.mode.value}, {ctx.ref(c.citation)})"
        for c in file.fim)
    return ((t.label("file.fim"), entries),)


def _files(ctx: _Ctx) -> Section:
    t = ctx.texts
    blocks: list[Block] = []
    for file in ctx.report.result.affected_files:
        blocks += _file_blocks(ctx, file)
    if ctx.report.result.log_only_files:
        unverified = any(e.description.key == "timeline.log_only_file_unverified"
                         for e in ctx.report.result.timeline)
        note = "files.log_only_note_unverified" if unverified else "files.log_only_note"
        blocks += [Heading(t.label("files.log_only")), Para(t.label(note)),
                   Bullets(tuple(clean(u) for u in ctx.report.result.log_only_files))]
    return Section("file-terdampak", t.label("s.files"),
                   tuple(blocks) or (Para(t.label("review.none")),))


def _review(ctx: _Ctx) -> Section:
    t, result = ctx.texts, ctx.report.result
    unexplained = [*result.unexplained_changes, *other_flagged_files(result)]
    blocks: list[Block] = []
    if unexplained:
        blocks += [Para(t.label("review.unexplained")),
                   Bullets(tuple(clean(p) for p in unexplained))]
    if result.deleted_paths:
        blocks += [Para(t.label("review.deleted")),
                   Bullets(tuple(clean(p) for p in result.deleted_paths))]
    return Section("tinjau", t.label("s.review"), tuple(blocks) or (Para(t.label("review.none")),))


def _iocs(ctx: _Ctx) -> Section:
    t, iocs = ctx.texts, ctx.report.result.iocs
    blocks: list[Block] = []
    for key, values in (("ioc.ips", iocs.ips), ("ioc.user_agents", iocs.user_agents),
                        ("ioc.sha256s", iocs.sha256s), ("ioc.paths", iocs.paths),
                        ("ioc.urls", iocs.urls)):
        if values:
            blocks += [Heading(t.label(key)), Code(tuple(clean(v) for v in values))]
    return Section("ioc", t.label("s.iocs"), tuple(blocks) or (Para(t.label("ioc.none")),))


def _gaps(ctx: _Ctx) -> Section:
    t, gaps = ctx.texts, ctx.report.result.gaps
    if not gaps:
        return Section("celah-bukti", t.label("s.gaps"), (Para(t.label("gap.none")),))
    labels = t.gap_labels
    shown = set(shown_gaps(gaps))
    rows = []
    for gap in sorted(gaps, key=lambda g: int(labels[g.gap_id][1:])):
        if gap.gap_id not in shown:
            continue
        when = (f"{t.time(gap.start)} s.d. {t.time(gap.end)}" if gap.start or gap.end
                else t.label("not_set"))
        detail = t.message(gap.detail) if gap.detail else ""
        if gap.source:
            detail = f"{detail} [{clean(gap.source)}]"
        affects = ", ".join(ctx.number(i) for i in gap.affects if i in ctx.numbers)
        rows.append((Cell(labels[gap.gap_id]), Cell(m.GAP_KINDS.get(gap.kind.value, "")),
                     Cell(when), Cell(detail), Cell(affects or t.label("gap.affects_none"))))
    headers = (t.label("gap.id"), t.label("gap.kind"), t.label("gap.when"),
               t.label("gap.detail"), t.label("gap.affects"))
    blocks: list[Block] = [Table(headers, tuple(rows))]
    if len(gaps) > len(shown):
        blocks.append(Para(t.label("gap.more_silences").format(count=len(gaps) - len(shown))))
    return Section("celah-bukti", t.label("s.gaps"), tuple(blocks))


# A sparse log (an admin panel opened now and then) has thousands of quiet periods; one row
# each made a 1 MB report (D88). Shown: gaps that touch a timeline event, every gap that is
# not plain silence, and the longest silences. report.json keeps all of them.
MAX_SILENCE_ROWS = 15


def shown_gaps(gaps: tuple[EvidenceGap, ...]) -> list[str]:
    def silence(g: EvidenceGap) -> bool:
        return g.detail is not None and g.detail.key == "gap.log_silence" and not g.affects

    keep = [g.gap_id for g in gaps if not silence(g)]
    quiet = sorted((g for g in gaps if silence(g) and g.start and g.end),
                   key=lambda g: (-(g.end - g.start).total_seconds(), g.gap_id))
    return keep + [g.gap_id for g in quiet[:MAX_SILENCE_ROWS]]


def _background(ctx: _Ctx) -> Section:
    t, groups = ctx.texts, ctx.report.background
    if not groups:
        return Section("latar", t.label("s.background"), (Para(t.label("bg.none")),))
    rows = tuple((
        Cell(f"{t.rule(g.rule_id)} ({g.rule_id})"), Cell(str(g.count)), Cell(str(g.clients)),
        Cell(clean(", ".join(f"{ip} ({n})" for ip, n in g.top_clients))),
        Cell(f"{t.time(g.first)} s.d. {t.time(g.last)}"), Cell(ctx.ref(g.example)),
    ) for g in groups)
    headers = (t.label("bg.rule"), t.label("bg.count"), t.label("bg.clients"),
               t.label("bg.top"), t.label("bg.range"), t.label("bg.example"))
    return Section("latar", t.label("s.background"),
                   (Para(t.label("bg.note")), Table(headers, rows)))


def _actions(ctx: _Ctx) -> Section:
    t = ctx.texts
    blocks: list[Block] = []
    for phase, title in m.PHASES.items():
        items = tuple(t.message(r) for r in ctx.report.recommendations
                      if r.key.startswith(f"rec.{phase}."))
        if items:
            blocks += [Heading(title), Bullets(items)]
    return Section("tindakan", t.label("s.actions"), tuple(blocks))


def _limits(ctx: _Ctx) -> Section:
    items = tuple(ctx.texts.message(r) for r in ctx.report.limitations)
    return Section("keterbatasan", ctx.texts.label("s.limits"), (Bullets(items),))


def _excerpt(citation: Citation) -> str:
    if citation.kind is CitationKind.FILE:
        return f"SHA-256 {citation.sha256}"  # the full hash identifies the file version
    return clean(citation.excerpt)


def _evidence(ctx: _Ctx) -> Section:
    rows = tuple((Cell(short), Cell(_excerpt(c))) for short, c in ctx.cited.items())
    headers = (ctx.texts.label("ev.ref"), ctx.texts.label("ev.excerpt"))
    return Section("bukti", ctx.texts.label("s.evidence"), (Table(headers, rows),))


def _run(ctx: _Ctx) -> Section:
    t, run = ctx.texts, ctx.report.run
    inputs = tuple((Cell(clean(s.path)), Cell(s.sha256), Cell(f"{s.size} {t.label('bytes')}"))
                   for s in run.inputs)
    return Section("reproduksi", t.label("s.run"), (
        Fields((
            (t.label("run.tool"), clean(run.tool_version)),
            (t.label("run.ruleset"), clean(run.ruleset_version)),
            (t.label("run.config"), run.config_sha256 or t.label("not_set")),
        )),
        Heading(t.label("run.inputs")),
        Table(("File", t.label("file.sha256"), t.label("file.size")), inputs),
        Para(t.label("run.note")),
    ))


def build_document(report: Report, texts: Texts) -> Document:
    ctx = _Ctx(report, texts, {e.event_id: i for i, e in
                               enumerate(report.result.timeline, start=1)})
    # Sections that cite evidence run first so the appendix lists what they referenced.
    body = [_summary(ctx), _case(ctx), _timeline(ctx), _root(ctx), _files(ctx), _review(ctx),
            _iocs(ctx), _gaps(ctx), _background(ctx), _actions(ctx), _limits(ctx)]
    subtitle = f"{clean(report.case.case_id)} · {texts.time(report.run.generated_at)}"
    return Document(clean(report.case.title), subtitle,
                    (*body, _evidence(ctx), _run(ctx)))
