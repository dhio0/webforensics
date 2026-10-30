"""Every message the code can emit has Indonesian text, with every placeholder filled.

Two layers: a static scan of the source for keys and rule ids (catches a new key even
if no test triggers it), and strict rendering of many real correlation results (catches
a template that names a parameter the engine does not send).
"""

import base64
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.correlate_helpers import (
    ATTACKER,
    SCENARIOS,
    at,
    file_ev,
    files,
    load_scenario,
    numbered,
)
from tests.unit.test_correlate_properties import _random_case
from tests.unit.test_file_rules import _request_exec, _with_content
from tests.unit.test_held_out_lessons import rce_case
from tests.unit.test_logonly import sqlmap_case
from tests.unit.test_scale_lessons import SHELL, brute_force
from tests.unit.test_wazuh_adapter import MARKER_SHA, upload_story
from tests.wazuh_helpers import DOCROOT, fim_hit, recording
from webforensics.adapters.file_adapter import DirectoryFileSource
from webforensics.adapters.wazuh import WazuhRecordingSource
from webforensics.codeloc.locate import review_code
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.detect.log_rules import LOG_RULES
from webforensics.models import (
    CaseInfo,
    EvidenceScope,
    GapKind,
    LogCollection,
    ParseFailure,
    RunInfo,
    TimestampSource,
)
from webforensics.parsers.error_log import ErrorLogFormat, parse_error_line
from webforensics.report import build_report, render
from webforensics.report import messages_id as m
from webforensics.report.text import MissingMessageError, Texts, parse_display_offset

SRC = Path(__file__).parents[2] / "src" / "webforensics"
FAMILIES = ("timeline", "anchor", "creation", "error_log", "file", "seed", "root", "login",
            "actor", "confidence", "timestomp", "gap", "finding", "summary", "rec", "limit")
_KEY = re.compile(r'"((?:' + "|".join(FAMILIES) + r')\.[A-Za-z0-9_.-]+)"')
# Kinds are joined as f"timeline.{kind}" in the engine, so they are scanned separately.
_KIND = re.compile(r'(?:_log_draft\(index, |kind=|kind = |: |else )"([a-z]+_[a-z_]+)"')
# Declared for adapters that are not built yet (Wazuh, rotation detection).
NOT_EMITTED_YET = {"gap.rotation_boundary", "gap.missing_timestamps",
                   "gap.clock_skew_suspected", "gap.post_body_not_logged"}


def _source_keys() -> set[str]:
    keys = set()
    for path in SRC.rglob("*.py"):
        if path.parent.name == "report" and path.name != "build.py":
            continue  # report labels use the same prefixes but live in LABELS
        keys |= set(_KEY.findall(path.read_text(encoding="utf-8")))
    engine = (SRC / "correlate" / "engine.py").read_text(encoding="utf-8")
    kinds = {k for k in _KIND.findall(engine) if not k.startswith(("sql_", "unrestricted"))}
    return keys | {f"timeline.{kind}" for kind in kinds}


def _rule_ids() -> set[str]:
    ids = {rule.rule_id for rule in LOG_RULES}
    for path in SRC.rglob("*.py"):
        ids |= set(re.findall(r'"((?:FILE|CORR)-[A-Z-]+)"', path.read_text(encoding="utf-8")))
    return ids


def test_static_scan_finds_the_engine_keys():
    keys = _source_keys()
    # Guard the scanner itself: if these disappear the regexes are broken.
    assert {"timeline.auth_bypass_sqli", "timeline.file_created", "timeline.upload_exploit",
            "creation.single_candidate", "rec.eradication.fix_upload"} <= keys


def test_every_key_in_the_source_has_indonesian_text():
    missing = sorted(k for k in _source_keys() if k not in m.MESSAGES
                     and not k.startswith("finding."))
    assert missing == []


def test_every_rule_has_a_name_and_a_finding_message():
    rules = _rule_ids()
    assert len(rules) >= 15
    assert sorted(r for r in rules if r not in m.RULE_NAMES) == []
    timestomp = {"FILE-ANTIFORENSICS-TIMESTOMP"}  # its reason is a timestomp.* key
    assert sorted(r for r in rules - timestomp if f"finding.{r}" not in m.MESSAGES) == []


def test_every_gap_kind_has_text():
    for kind in GapKind:
        assert kind.value in m.GAP_KINDS
        assert f"gap.{kind.value}" in m.MESSAGES or kind is GapKind.NO_LOG_LINES


def test_labels_used_by_the_document_exist():
    source = (SRC / "report" / "document.py").read_text(encoding="utf-8")
    used = set(re.findall(r'label\("([a-z_.]+)"\)', source))
    used |= set(re.findall(r'LABELS\["([a-z_.]+)"\]', source))
    assert used and sorted(used - set(m.LABELS)) == []


# --- strict rendering of real results ----------------------------------------------------


BYPASS = "/admin/login.php?u=a%27+OR+%271%27%3D%271+--+"


def _crafted(tmp_path):
    """Inputs that reach the keys random cases rarely hit."""
    yield numbered(  # recon, several SQLi rules, UA switch before the upload
        (0, "/", {"ua": "sqlmap/1.7"}),
        (1, "/p.php?id=1+UNION+SELECT+1", {"ua": "tool-a"}),
        (2, "/p.php?id=sleep(5)", {"ua": "tool-a"}),
        (3, "/p.php?id=1+from+information_schema.tables", {"ua": "tool-a"}),
        (4, "/p.php?id=1%27--+", {"ua": "tool-a"}),
        (5, BYPASS, {"ua": "tool-a"}),
        (10, "/admin/upload.php", {"method": "POST", "ua": "tool-b"}),
        (12, "/uploads/x.php", {"ua": "tool-b"}),
    ), files(file_ev("uploads/x.php", btime=10, ctime=10, mtime=10)), None
    yield numbered((0, "/"), (600, "/lib/x.php", {"method": "POST"}),
                   (700, "/lib/x.php", {"method": "POST"})), files(
        *[file_ev(f"app/f{i}.php", btime=i * 0.5, ctime=i * 0.5, mtime=i * 0.5,
                  content=str(i)) for i in range(6)],
        file_ev("lib/x.php", btime=300, ctime=300, mtime=300)), None
    # ctime-only and copied timestamps, plus unreadable lines
    logs = numbered((0, "/admin/upload.php", {"method": "POST"}), (2, "/uploads/c.php"))
    logs = LogCollection(events=logs.events, failures=(
        ParseFailure(source="access.log", line_no=3, reason="bad"),))
    yield logs, files(file_ev("uploads/c.php", ctime=1, mtime=1),
                      file_ev("uploads/d.php", btime=1, ctime=1, mtime=1,
                              source=TimestampSource.COPIED)), None
    # content rules, and an index.php that is new compared with the baseline
    (tmp_path / "e").mkdir()
    (tmp_path / "g").mkdir()
    born = {"btime": file_ev("x", btime=1).btime}
    shell = _with_content(tmp_path / "e", "uploads/e.php",
                          _request_exec("ex" + "ec", "GE" + "T", "t")).model_copy(update=born)
    blob = base64.b64encode(bytes(range(256))).decode()  # high entropy, inert
    dense = _with_content(tmp_path / "g", "uploads/g.php",
                          "<?php $d = '" + blob + "'; ?>").model_copy(update=born)
    index = file_ev("index.php", btime=1, ctime=1, mtime=1, content="new")
    old_index = file_ev("index.php", btime=0, ctime=0, mtime=0, content="old")
    yield (numbered((1, "/admin/upload.php", {"method": "POST"})), files(shell, dense, index),
           files(old_index))
    # login of unknown method (a retried failure first), corroborated by the error log
    login = numbered(
        (0, "/admin/login.php", {"method": "POST"}),
        (2, "/admin/login.php", {"method": "POST", "size": 500}),
        (4, "/admin/index.php"),
        (8, "/admin/upload.php", {"method": "POST"}),
        (10, "/uploads/k.php"),
    )
    error = parse_error_line(
        f"{at(8):%Y/%m/%d %H:%M:%S} [error] 1#1: *1 demo, client: {ATTACKER}, server: _, "
        'request: "POST /admin/upload.php HTTP/1.1"', "error.log", 1, ErrorLogFormat.NGINX)
    yield (LogCollection(events=login.events, errors=(error,)),
           files(file_ev("uploads/k.php", btime=8, ctime=8, mtime=8)), None)
    # a file written through SQL injection (INTO OUTFILE), and a file deleted since baseline
    outfile = "/p.php?id=1+union+select+1+into+outfile+%27/var/www/uploads/o.php%27"
    yield (numbered((0, outfile)), files(file_ev("uploads/o.php", btime=0, ctime=0, mtime=0)),
           files(file_ev("uploads/o.php", btime=0, ctime=0, mtime=0, content="x"),
                 file_ev("about.php", btime=0, ctime=0, mtime=0)))
    # scripts seen only in the log: written by INTO OUTFILE, used, then deleted (D85)
    yield sqlmap_case(), files(), None
    # a shell written from a code-injection exploit, outside HTTP (D86)
    logs, evidence = rce_case()
    yield logs, files(evidence.files[0].model_copy(update={
        "url_paths": ("/jabc/scripts/update.php",)})), None
    # a defaced index page, and a log that starts days after it changed (D87)
    (tmp_path / "d").mkdir()
    defaced = _with_content(tmp_path / "d", "index.html", "<h1>This site has been hacked</h1>")
    defaced = defaced.model_copy(update={"btime": at(0), "ctime": at(0), "mtime": at(0)})
    yield numbered((3 * 86_400, "/index.html"),
                   (3 * 86_400 + 5, "/s.php?q=%22%3E%3Cx")), files(defaced), None
    # no webroot at all: a shell seen in the log after a brute-force run (D88)
    yield numbered(*brute_force(20), *SHELL), files(), None
    # directory scan without a manifest
    (tmp_path / "web" / "uploads").mkdir(parents=True)
    (tmp_path / "web" / "uploads" / "h.php").write_text("inert")
    yield numbered((1, "/")), DirectoryFileSource(tmp_path / "web").load_files(), None


def _wazuh_cases(tmp_path):
    """FIM-based evidence: realtime, scheduled, deleted, backdated, outside the docroot,
    and alerts-only (no archives)."""
    marker = f"{DOCROOT}/uploads/x.php"
    cases = {
        "realtime_deleted": (upload_story([fim_hit(marker, "deleted", at(120),
                                                    sha256=MARKER_SHA, n=2)]), {}),
        "scheduled": ((upload_story()[0], [fim_hit(marker, "added", at(7200),
                                                   mode="scheduled", mtime=at(60))]), {}),
        "backdated_outside": ((upload_story()[0], [
            fim_hit(marker, "added", at(60.4), sha256=MARKER_SHA, mtime=at(-86400)),
            fim_hit("/etc/cron.d/x", "added", at(5), n=2)]), {}),
        "alerts_only": (upload_story(), {"archives": False}),
        "kit_unpacked": (upload_story([
            fim_hit(f"{DOCROOT}/lib/k{i}.php", "added", at(60.5 + i * 0.1), n=20 + i,
                    sha256=f"{i:064x}") for i in range(3)]), {}),
    }
    for name, ((web, fim), header) in cases.items():
        path = recording(tmp_path / f"{name}.jsonl", web, fim, **header)
        source = WazuhRecordingSource(path, base_dir=tmp_path)
        yield source.load_logs(), source.load_files(), None


def _results(tmp_path):
    """(result, logs, scope, code findings, code scope). Scenarios A and F run the code
    review on their webroot copy (F has a finding, A none); the crafted cases have no
    content, so their review says so."""
    plain = EvidenceScope()
    for name in ("a", "f"):
        logs, evidence = load_scenario(name)
        result = correlate(logs, evidence)
        webroot = SCENARIOS / name / "evidence" / "webroot"
        yield (result, logs, plain, *review_code(result, evidence, webroot))
    # The same evidence as if the webroot were on NTFS (D84).
    logs, evidence = load_scenario("e")
    windows = CorrelationConfig(case_insensitive_paths=True, birth_time_settable=True)
    yield correlate(logs, evidence, config=windows), logs, plain, (), None
    changed = numbered((0, "/admin/upload.php", {"method": "POST"}), (2, "/uploads/c.php"))
    yield (correlate(changed, files(file_ev("uploads/c.php", ctime=1, mtime=1)), config=windows),
           changed, plain, (), None)
    for seed in range(100):
        logs, evidence, config = _random_case(seed)
        yield correlate(logs, evidence, config=config), logs, plain, (), None
    for logs, evidence, baseline in _crafted(tmp_path):
        result = correlate(logs, evidence, baseline=baseline)
        yield (result, logs, plain, *review_code(result, evidence))
    for logs, evidence, baseline in _wazuh_cases(tmp_path):
        yield (correlate(logs, evidence, baseline=baseline), logs,
               EvidenceScope(file_adapter="wazuh"), (), None)


def _emitted(result) -> set[str]:
    keys = set()
    for event in result.timeline:
        keys.add(event.description.key)
        keys |= {r.key for r in event.confidence_reasons}
    keys |= {r.key for r in result.root_cause.reasons} if result.root_cause else set()
    keys |= {g.detail.key for g in result.gaps if g.detail}
    keys |= {r.key for f in result.findings for r in f.reasons}
    return keys


def test_real_results_render_strictly_and_cover_the_catalog(tmp_path):
    run = RunInfo(tool_version="t", ruleset_version="r", generated_at=datetime.now(UTC))
    emitted: set[str] = set()
    for result, logs, scope, code, code_scope in _results(tmp_path):
        emitted |= _emitted(result)
        report = build_report(result, logs, CaseInfo(case_id="c", title="t"), run, scope,
                              code_findings=code, code_scope=code_scope)
        emitted |= {r.key for r in (*report.summary, *report.recommendations,
                                    *report.limitations)}
        render(report, parse_display_offset("+07:00"), strict=True)
    never = sorted(set(m.MESSAGES) - emitted - NOT_EMITTED_YET)
    # Anything listed here is untested text: reach it with an input above.
    assert never == [], " ".join(never)


def test_strict_mode_catches_missing_keys_and_placeholders():
    from webforensics.models import Reason

    texts = Texts(strict=True)
    with pytest.raises(MissingMessageError):
        texts.message(Reason(key="timeline.nope"))
    with pytest.raises(MissingMessageError):
        texts.message(Reason(key="login.failed_status"))  # needs {status}
    lenient = Texts()
    assert lenient.message(Reason(key="timeline.nope")) == "timeline.nope"
    assert lenient.message(Reason(key="login.failed_status")) == "Server membalas ?."
