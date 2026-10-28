"""Report builder logic, time formatting, and escaping of attacker-controlled strings."""

import json
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

import pytest

from tests.correlate_helpers import ATTACKER, VISITOR, file_ev, files, load_scenario, numbered
from webforensics.correlate import correlate
from webforensics.models import REPORT_FORMAT, CaseInfo, LogCollection, RunInfo
from webforensics.report import build_report, render
from webforensics.report.build import evidence_scope
from webforensics.report.markdown import _md
from webforensics.report.text import Texts, clean, offset_label, parse_display_offset

RUN = RunInfo(tool_version="t", ruleset_version="r",
              generated_at=datetime(2026, 10, 28, 2, 0, tzinfo=UTC))
CASE = CaseInfo(case_id="WF-TEST", title="Laporan Uji")
WIB = parse_display_offset("+07:00")


def _report(logs, evidence, baseline=None):
    return build_report(correlate(logs, evidence, baseline=baseline), logs, CASE, RUN)


def _keys(reasons):
    return [r.key for r in reasons]


# --- builder ------------------------------------------------------------------------------


def test_scenario_a_recommends_fixing_the_upload_endpoint():
    logs, evidence = load_scenario("a")
    report = _report(logs, evidence)
    recs = {r.key: r.params for r in report.recommendations}
    assert recs["rec.eradication.fix_upload"] == {"path": "/admin/upload.php"}
    assert "rec.eradication.fix_sqli_login" not in recs
    assert recs["rec.containment.block_ips"] == {"ips": "172.19.0.1"}
    assert _keys(report.summary)[:2] == ["summary.compromise_found", "summary.root_cause"]
    assert report.summary[1].params["vuln_class"] == "unrestricted_file_upload"


def test_scenario_f_fixes_the_login_first_and_the_upload_behind_it():
    logs, evidence = load_scenario("f")
    recs = [r for r in _report(logs, evidence).recommendations
            if r.key.startswith("rec.eradication.fix")]
    assert [(r.key, r.params["path"]) for r in recs] == [
        ("rec.eradication.fix_sqli_login", "/admin/login.php"),
        ("rec.eradication.fix_upload", "/admin/auth_upload.php"),
    ]


def test_recommendations_follow_csirt_phase_order():
    logs, evidence = load_scenario("f")
    phases = [r.key.split(".")[1] for r in _report(logs, evidence).recommendations]
    order = ["containment", "eradication", "recovery", "lessons"]
    assert phases == sorted(phases, key=order.index)


def test_no_compromise_says_so_without_claiming_the_server_is_clean():
    logs = numbered((0, "/"), (5, "/p.php?id=1+OR+1%3D1", {"ip": VISITOR}))
    report = _report(logs, files(file_ev("index.php", btime=0, ctime=0, mtime=0)))
    assert _keys(report.summary)[0] == "summary.no_compromise"
    # Nothing was compromised, so there is no entry point to hunt for; the caution lives
    # in the summary and in the review of unexplained changes.
    assert "rec.eradication.unknown_entry" not in _keys(report.recommendations)
    assert "rec.recovery.review_unexplained" in _keys(report.recommendations)
    assert "rec.containment.isolate" not in _keys(report.recommendations)
    md = render(report, WIB)["md"]
    assert "tidak menjamin server bersih" in md


def test_a_successful_looking_sqli_bypass_outside_the_incident_is_reported_not_accused():
    bypass_url = "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+"
    logs = numbered(
        (0, "/admin/login.php", {"ip": VISITOR, "method": "POST", "status": 401, "size": 300}),
        (5, bypass_url, {"ip": "192.0.2.21", "size": 347}),
        (7, bypass_url, {"ip": "192.0.2.22", "size": 347}),  # retried below: it failed
        (9, bypass_url, {"ip": "192.0.2.22", "size": 347}),
    )
    result = correlate(logs, files())
    bypass = [f for f in result.findings if f.rule_id == "CORR-SQLI-LOGIN-BYPASS"]
    # The second bot's last attempt has no retry, so it counts too; its first does not.
    assert [f.citations[0].line_no for f in bypass] == [2, 4]
    assert result.iocs.ips == () and result.root_cause is None
    report = build_report(result, logs, CASE, RUN)
    summary = next(r for r in report.summary if r.key == "summary.unlinked_bypass")
    assert summary.params == {"count": "2", "clients": "2", "paths": "/admin/login.php"}
    recs = {r.key: r.params for r in report.recommendations}
    assert recs["rec.eradication.fix_sqli_login"] == {"path": "/admin/login.php"}
    assert recs["rec.recovery.revoke_sessions"] == {"paths": "/admin/login.php"}
    assert "rec.containment.block_ips" not in recs  # reported, not accused
    # A log finding is not a changed file to review.
    assert "summary.unexplained" not in [r.key for r in report.summary]


def test_the_incidents_own_bypass_is_not_reported_twice():
    logs, evidence = load_scenario("f")
    result = correlate(logs, evidence)
    assert not [f for f in result.findings if f.rule_id == "CORR-SQLI-LOGIN-BYPASS"]


def test_background_groups_count_requests_once_and_rank_clients():
    logs = numbered(
        (0, "/../../etc/passwd", {"ip": VISITOR}),  # matches two traversal rules
        (1, "/p.php?id=1+OR+1%3D1", {"ip": VISITOR}),
        (2, "/p.php?id=2+OR+1%3D1", {"ip": "192.0.2.9"}),
        (3, "/p.php?id=3+OR+1%3D1", {"ip": VISITOR}),
    )
    report = _report(logs, files())
    by_rule = {g.rule_id: g for g in report.background}
    taut = by_rule["LOG-SQLI-TAUTOLOGY"]
    assert (taut.count, taut.clients, taut.top_clients) == (3, 2, ((VISITOR, 2),
                                                                   ("192.0.2.9", 1)))
    assert taut.example.line_no == 2
    background = next(r for r in report.summary if r.key == "summary.background")
    assert background.params["count"] == "4"  # 4 requests, 5 findings
    # The per-request records are summarized, not copied, so report.json stays small.
    assert report.result.findings == () and report.result.unattributed_finding_ids == ()


def test_background_clients_behind_a_trusted_proxy_are_the_forwarded_addresses():
    proxy = "172.30.0.3"
    logs = numbered(*((i, f"/p.php?id={i}+OR+1%3D1", {"ip": proxy, "xff": bot})
                      for i, bot in enumerate(("192.0.2.21", "203.0.113.21", "192.0.2.21"))))
    result = correlate(logs, files())
    taut = build_report(result, logs, CASE, RUN, trusted_proxies=(proxy,)).background[0]
    assert (taut.clients, taut.top_clients) == (2, (("192.0.2.21", 2), ("203.0.113.21", 1)))
    # Without the proxy being trusted, the header is not believed.
    assert build_report(result, logs, CASE, RUN).background[0].top_clients == ((proxy, 3),)


def test_deleted_and_unexplained_files_are_listed_for_review():
    logs = numbered((0, "/"))
    current = files(file_ev("app/new.php", btime=900, ctime=900, mtime=900))
    baseline = files(file_ev("app/gone.php", btime=0, ctime=0, mtime=0))
    report = _report(logs, current, baseline)
    md = render(report, WIB)["md"]
    section = md[md.index("## 6."):md.index("## 7.")]
    assert "app/gone.php" in section
    assert "summary.deleted" in _keys(report.summary)


# --- time and text ---------------------------------------------------------------------------


@pytest.mark.parametrize(("offset", "label", "shown"), [
    ("+07:00", "WIB (UTC+07:00)", "2026-10-28 09:00:00 WIB"),
    ("+0800", "WITA (UTC+08:00)", "2026-10-28 10:00:00 WITA"),
    ("+09:00", "WIT (UTC+09:00)", "2026-10-28 11:00:00 WIT"),
    ("+00:00", "UTC+00:00", "2026-10-28 02:00:00 UTC"),
    ("-03:30", "UTC-03:30", "2026-10-27 22:30:00 UTC-03:30"),
])
def test_report_times_use_the_chosen_zone(offset, label, shown):
    tz = parse_display_offset(offset)
    assert offset_label(tz) == label
    assert Texts(tz=tz).time(RUN.generated_at) == shown


@pytest.mark.parametrize("bad", ["WIB", "+7", "+25:00", "07:00:00"])
def test_bad_offsets_are_rejected(bad):
    with pytest.raises(ValueError):
        parse_display_offset(bad)


def test_clean_makes_control_bytes_visible_and_keeps_one_line():
    assert clean("a\nb\r\nc\x1b[31m\x00") == "a b c\\x1b[31m\\x00"


# --- escaping (the report is an attack surface) --------------------------------------------

EVIL_UA = '<script>alert(1)</script> "><img src=x onerror=alert(2)>'
EVIL_PATH = "/uploads/x.php?a=<svg/onload=alert(3)>|`x`|[c](javascript:alert(4))"
EVIL_FILE = "uploads/<b>x</b>|**y**.php"


def _evil_report():
    logs = numbered(
        (0, "/admin/upload.php", {"method": "POST", "ua": EVIL_UA}),
        (2, EVIL_PATH, {"ua": EVIL_UA + "\x1b[2J"}),
    )
    evidence = files(file_ev(EVIL_FILE, btime=0, ctime=0, mtime=0))
    report = _report(logs, evidence)
    assert report.result.affected_files  # the evil strings really reach the report
    return render(report, WIB)


def test_html_escapes_everything_from_evidence():
    page = _evil_report()["html"]
    lowered = page.lower()
    assert "<script" not in lowered and "<img" not in lowered and "<svg" not in lowered
    assert "<b>" not in lowered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "onerror=alert(2)&gt;" in page  # present only as text
    assert "default-src 'none'" in page  # CSP: no scripts or remote loads even if missed
    assert re.search(r"<a [^>]*href=\"(?!#)", page) is None  # only in-page links


def test_markdown_escapes_html_links_and_table_pipes():
    md = _evil_report()["md"]
    # Outside fenced code (which is literal text by definition) every < is escaped.
    prose = re.sub(r"^(`{3,})\n.*?\n\1$", "", md, flags=re.M | re.S)
    assert "<script>" in md.replace("\\", "") and prose != md
    assert re.search(r"(?<!\\)<", prose) is None
    assert "](javascript" not in md.replace("\\]", "")
    assert "\x1b" not in md and "\\x1b[2J" in md.replace("\\[", "[")
    tables = [block for block in md.split("\n\n") if block.startswith("|")]
    for table in tables:
        widths = {len(re.split(r"(?<!\\)\|", row)) for row in table.splitlines()}
        assert len(widths) == 1, table  # an attacker pipe never adds a column


def test_markdown_code_fence_outgrows_backticks_in_iocs():
    logs = numbered((0, "/admin/upload.php", {"method": "POST", "ua": "a ```` b"}),
                    (2, "/uploads/x.php", {"ua": "a ```` b"}))
    md = render(_report(logs, files(file_ev("uploads/x.php", btime=0, ctime=0, mtime=0))),
                WIB)["md"]
    assert "`````\na ```` b\n`````" in md


def test_md_escape_only_marks_line_start_where_needed():
    assert _md("1. Ringkasan") == "1. Ringkasan"
    assert _md("1. Ringkasan", line_start=True) == "1\\. Ringkasan"
    assert _md("# x", line_start=True) == "\\# x"
    assert _md("a_b*c") == "a\\_b\\*c"


def test_report_without_logs_or_files_still_renders():
    report = build_report(correlate(LogCollection(), files()), LogCollection(), CASE, RUN)
    out = render(report, WIB, strict=True)
    assert "Tidak ditemukan file mencurigakan" in out["md"]
    assert ATTACKER not in out["md"]


# --- structure ---------------------------------------------------------------------------

_VOID = {"meta", "br", "hr", "img", "link", "input"}


class _Nesting(HTMLParser):
    """Fails on any end tag that does not close the innermost open element."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        assert self.stack and self.stack[-1] == tag, (tag, self.stack[-5:])
        self.stack.pop()


@pytest.mark.parametrize("page", ["golden_a", "golden_f", "evil"])
def test_html_is_well_formed(page):
    golden = Path(__file__).parents[1] / "golden"
    html = (_evil_report()["html"] if page == "evil" else
            (golden / f"scenario_{page[-1]}.html").read_text(encoding="utf-8"))
    parser = _Nesting()
    parser.feed(html)
    parser.close()
    assert parser.stack == []
    ids = re.findall(r'id="([^"]+)"', html)
    assert len(ids) == len(set(ids))
    assert set(re.findall(r'href="#([^"]+)"', html)) <= set(ids)


def test_summary_tells_the_attack_story_in_order():
    logs, evidence = load_scenario("f")
    md = render(_report(logs, evidence), WIB)["md"]
    story = md[md.index("### Alur serangan"):md.index("## 2.")]
    steps = [line for line in story.splitlines() if line.startswith("- ")]
    assert [s.split(":", 3)[3].strip()[:20] for s in steps] == [
        "Bypass login dengan ", "Request yang menulis", "File uploads/scenari",
        "File uploads/scenari"]
    assert "Login gagal" not in story  # context stays in the full timeline


def test_root_cause_shows_the_raw_request_with_its_payload():
    logs, evidence = load_scenario("f")
    md = render(_report(logs, evidence), WIB)["md"]
    root = md[md.index("## 4."):md.index("## 5.")]
    assert "### Baris log asli" in root
    assert "username=admin%27+OR+%271%27%3D%271" in root


def test_scope_states_what_was_analyzed():
    logs, evidence = load_scenario("a")
    scope = evidence_scope(logs, evidence)
    report = build_report(correlate(logs, evidence), logs, CASE, RUN, scope)
    md = render(report, WIB)["md"]
    case = md[md.index("### Cakupan bukti"):md.index("## 3.")]
    assert f"{len(logs.events)} baris terbaca" in case
    assert "**Baseline:** tidak ada" in case
    assert scope.baseline_files is None and scope.log_first == logs.events[0].ts


def test_report_json_carries_a_format_version():
    logs, evidence = load_scenario("a")
    data = json.loads(render(_report(logs, evidence), WIB)["json"])
    assert data["format"] == REPORT_FORMAT and next(iter(data)) == "format"
