"""WazuhAdapter: recording -> evidence, and how the core uses FIM evidence (D74-D78)."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from tests.wazuh_helpers import (
    ACCESS,
    DOCROOT,
    ERROR,
    UTC7,
    fim_hit,
    recording,
    recording_lines,
    web_hit,
)
from webforensics.adapters.wazuh import WazuhRecordingSource
from webforensics.adapters.wazuh.recording import (
    RecordingError,
    Stream,
    read_recording,
    write_recording,
)
from webforensics.adapters.wazuh.schema_v4 import mtime_after
from webforensics.correlate import CorrelationConfig, correlate
from webforensics.correlate.anchor import choose_anchor
from webforensics.models import (
    BaselineStatus,
    CitationKind,
    Confidence,
    GapKind,
    TimestampBasis,
)

T0 = datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC)
MARKER = b"<?php echo 'lab marker';\n"
MARKER_SHA = hashlib.sha256(MARKER).hexdigest()


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def line(seconds: float, target: str, method: str = "GET", status: int = 200,
         ip: str = "203.0.113.7") -> str:
    return (f'{ip} - - [{at(seconds):%d/%b/%Y:%H:%M:%S +0000}] "{method} {target} HTTP/1.1" '
            f'{status} 44 "-" "curl/8.0"')


def upload_story(fim_extra: list | None = None) -> tuple[list, list]:
    """A visitor browses, the attacker uploads a script and then calls it."""
    web = [web_hit(line(0, "/", ip="198.51.100.20"), at(1), n=1),
           web_hit(line(60, "/admin/upload.php", "POST"), at(61), n=2),
           web_hit(line(70, "/uploads/x.php?cmd=id"), at(71), n=3)]
    fim = [fim_hit(f"{DOCROOT}/uploads/x.php", "added", at(60.4), sha256=MARKER_SHA, n=1),
           *(fim_extra or [])]
    return web, fim


def source(tmp_path, web, fim, **kwargs):
    path = recording(tmp_path / "rec.jsonl", web, fim, **kwargs.pop("header", {}))
    return WazuhRecordingSource(path, base_dir=tmp_path, **kwargs)


# --- schema ----------------------------------------------------------------------------


def test_mtime_after_is_read_in_the_managers_time_zone():
    # Lab, manager in UTC+7: timestamp 10:40:56.338+0700, mtime_after 10:40:56 (local, no
    # offset). The indexer stores the latter as 10:40:56Z, 7 h late (notes §4.3).
    alert_ts = datetime.fromisoformat("2026-10-29T10:40:56.338+0700")
    value = mtime_after({"mtime_after": "2026-10-29T10:40:56"}, alert_ts)
    assert value is not None
    assert value.astimezone(UTC) == datetime(2026, 10, 29, 3, 40, 56, tzinfo=UTC)
    assert mtime_after({}, alert_ts) is None
    assert mtime_after({"mtime_after": "garbage"}, alert_ts) is None


def test_fim_mtime_is_corrected_end_to_end_for_a_non_utc_manager(tmp_path):
    hit = fim_hit(f"{DOCROOT}/a.php", "added", at(0), sha256=MARKER_SHA, tz=UTC7)
    file = source(tmp_path, [], [hit]).load_files().files[0]
    assert file.mtime == at(0).replace(microsecond=0)


# --- recording -------------------------------------------------------------------------


def test_recording_round_trip_counts_streams_and_leaves_no_side_file(tmp_path):
    web, fim = upload_story()
    path = recording(tmp_path / "rec.jsonl", web, fim)
    header, hits = read_recording(path)
    assert header.counts == {"web": 3, "fim": 1}
    assert [h.line_no for h in hits] == [2, 3, 4, 5]
    assert hits[0].source == web[0]["_source"]  # values unchanged
    assert not (tmp_path / "rec.jsonl.part").exists()


def test_a_failed_pull_leaves_no_recording(tmp_path):
    def broken():
        yield Stream.WEB, upload_story()[0][0]
        raise OSError("connection reset")

    from tests.wazuh_helpers import header
    with pytest.raises(OSError):
        write_recording(tmp_path / "rec.jsonl", header(), broken())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("first_line", ['{"nope": 1}', "not json",
                                        '{"header": {"format": "other/1"}}'])
def test_a_file_that_is_not_a_recording_is_rejected(tmp_path, first_line):
    path = tmp_path / "rec.jsonl"
    path.write_text(first_line + "\n", encoding="utf-8")
    with pytest.raises(RecordingError):
        read_recording(path)


def test_a_corrupt_hit_line_names_its_line_number(tmp_path):
    path = recording(tmp_path / "rec.jsonl", *upload_story())
    path.write_text(path.read_text(encoding="utf-8") + "{broken\n", encoding="utf-8")
    with pytest.raises(RecordingError, match="line 6"):
        read_recording(path)


# --- web logs (D75) --------------------------------------------------------------------


def test_full_log_is_parsed_and_cited_by_recording_line(tmp_path):
    web, fim = upload_story()
    web.append(web_hit("not an access log line", at(80), n=4))
    logs = source(tmp_path, web, fim).load_logs()
    assert [e.line_no for e in logs.events] == [2, 3, 4]
    event = logs.events[1]
    assert (event.method, event.path, event.ts) == ("POST", "/admin/upload.php", at(60))
    assert event.citation().source == "rec.jsonl"
    assert event.raw == web[1]["_source"]["full_log"]
    assert [(f.line_no, f.reason) for f in logs.failures] == [(5, "format_mismatch")]
    assert logs.complete


def test_request_time_comes_from_the_log_line_not_the_manager(tmp_path):
    # The manager processed the line 30 s late; the request time must not move.
    logs = source(tmp_path, [web_hit(line(5, "/"), at(35))], []).load_logs()
    assert logs.events[0].ts == at(5)


def test_error_log_lines_are_parsed_with_the_given_offset(tmp_path):
    raw = (f"{at(60):%Y/%m/%d %H:%M:%S} [error] 7#7: *3 upstream: x, client: 203.0.113.7, "
           'server: _, request: "POST /admin/upload.php HTTP/1.1"')
    src = source(tmp_path, [web_hit(raw, at(61), location=ERROR)], [],
                 header={"error_logs": (ERROR,)})
    logs = src.load_logs()
    assert [(e.line_no, e.method, e.ts) for e in logs.errors] == [(2, "POST", at(60))]


# --- FIM -> files (D76-D78) ------------------------------------------------------------


def test_fim_added_is_a_new_file_with_its_alert_cited(tmp_path):
    files = source(tmp_path, *upload_story()).load_files()
    file = files.files[0]
    assert (file.path, file.sha256, file.baseline_status) == (
        "uploads/x.php", MARKER_SHA, BaselineStatus.NEW)
    assert file.url_paths == ("/uploads/x.php",)
    assert (file.size, file.uid, file.mode, file.inode) == (24, 82, 0o644, 1234)
    assert files.has_baseline
    cited = file.fim[0].citation
    assert (cited.kind, cited.source, cited.line_no) == (CitationKind.WAZUH_ALERT, "rec.jsonl", 5)
    assert "554" in cited.excerpt


def test_realtime_fim_anchors_at_the_alert_capped_at_medium(tmp_path):
    file = source(tmp_path, *upload_story()).load_files().files[0]
    anchor = choose_anchor(file, CorrelationConfig())
    assert anchor is not None
    assert (anchor.ts, anchor.basis, anchor.max_confidence) == (
        at(60.4), TimestampBasis.FIM, Confidence.MEDIUM)


def test_scheduled_fim_falls_back_to_mtime_capped_at_low(tmp_path):
    hit = fim_hit(f"{DOCROOT}/a.php", "added", at(7200), mode="scheduled", mtime=at(60))
    file = source(tmp_path, [], [hit]).load_files().files[0]
    anchor = choose_anchor(file, CorrelationConfig())
    assert anchor is not None
    assert (anchor.ts, anchor.basis, anchor.max_confidence) == (
        at(60), TimestampBasis.MTIME, Confidence.LOW)
    assert anchor.reasons[0].key == "anchor.fim_scheduled"


def test_anchor_is_the_write_that_produced_the_current_content(tmp_path):
    other = "1" * 64
    hits = [fim_hit(f"{DOCROOT}/i.php", "modified", at(10), sha256=other, n=1),
            fim_hit(f"{DOCROOT}/i.php", "modified", at(90), sha256=MARKER_SHA, n=2),
            fim_hit(f"{DOCROOT}/i.php", "modified", at(95), sha256=MARKER_SHA, n=3)]
    file = source(tmp_path, [], hits).load_files().files[0]
    assert file.baseline_status is BaselineStatus.MODIFIED
    assert choose_anchor(file, CorrelationConfig()).ts == at(90)  # type: ignore[union-attr]
    assert len(file.fim) == 3


def test_deleted_file_keeps_its_last_hash_and_shows_the_deletion(tmp_path):
    deleted = fim_hit(f"{DOCROOT}/uploads/x.php", "deleted", at(120), sha256=MARKER_SHA, n=2)
    src = source(tmp_path, *upload_story([deleted]))
    file = src.load_files().files[0]
    assert file.deleted and file.sha256 == MARKER_SHA
    result = correlate(src.load_logs(), src.load_files())
    assert [f.path for f in result.affected_files] == ["uploads/x.php"]
    gone = next(e for e in result.timeline if e.description.key == "timeline.file_deleted")
    assert (gone.ts, gone.ts_basis, gone.mitre_technique) == (
        at(120), TimestampBasis.FIM, "T1070.004")
    assert gone.citations[0].line_no == 6


def test_a_path_that_was_only_deleted_is_listed_not_traced(tmp_path):
    hit = fim_hit(f"{DOCROOT}/old.php", "deleted", at(5))
    files = source(tmp_path, [], [hit]).load_files()
    assert files.files == () and files.deleted_paths == ("old.php",)
    assert correlate(source(tmp_path, [], [hit]).load_logs(), files).deleted_paths == ("old.php",)


def test_changes_outside_the_docroot_become_findings_to_review(tmp_path):
    files = source(tmp_path, [], [fim_hit("/etc/cron.d/x", "added", at(5))]).load_files()
    assert files.files == ()
    assert [f.rule_id for f in files.findings] == ["FILE-WAZUH-FIM-OUTSIDE-DOCROOT"]
    assert files.findings[0].citations[0].kind is CitationKind.WAZUH_ALERT


def test_an_alert_without_any_hash_cannot_identify_content(tmp_path):
    hit = fim_hit(f"{DOCROOT}/a.php", "added", at(5), sha256=None)
    files = source(tmp_path, [], [hit]).load_files()
    assert files.files == ()
    assert [f.reason for f in files.failures] == ["wazuh_fim_no_hash"]


def test_without_a_webroot_the_report_says_content_was_not_analyzed(tmp_path):
    files = source(tmp_path, *upload_story()).load_files()
    assert [g.kind for g in files.gaps] == [GapKind.NO_FILE_CONTENT]
    assert files.files[0].content_ref is None


def test_webroot_content_is_used_only_when_its_hash_matches_fim(tmp_path):
    webroot = tmp_path / "web" / "uploads"
    webroot.mkdir(parents=True)
    (webroot / "x.php").write_bytes(MARKER)
    files = source(tmp_path, *upload_story(), webroot=tmp_path / "web").load_files()
    assert files.files[0].content_ref == str(webroot / "x.php")
    assert files.gaps == ()

    (webroot / "x.php").write_bytes(b"<?php changed since the alert;")
    files = source(tmp_path, *upload_story(), webroot=tmp_path / "web").load_files()
    assert files.files[0].content_ref is None
    assert [f.reason for f in files.failures] == ["content_hash_mismatch"]
    assert [g.kind for g in files.gaps] == [GapKind.NO_FILE_CONTENT]


# --- core behaviour with FIM evidence ----------------------------------------------------


def test_upload_is_traced_from_the_fim_alert_to_the_request(tmp_path):
    src = source(tmp_path, *upload_story())
    result = correlate(src.load_logs(), src.load_files())
    root = next(e for e in result.timeline if e.event_id == result.root_cause.event_id)
    assert (root.description.params["method"], root.description.params["path"]) == (
        "POST", "/admin/upload.php")
    assert root.citations[0].line_no == 3  # the recording line holding the POST
    assert result.iocs.ips == ("203.0.113.7",)
    created = next(e for e in result.timeline if e.description.key == "timeline.file_created")
    assert created.ts_basis is TimestampBasis.FIM
    assert {c.kind for c in created.citations} == {CitationKind.FILE, CitationKind.WAZUH_ALERT}
    assert not any(g.kind is GapKind.NO_BASELINE for g in result.gaps)  # FIM is the baseline


def test_realtime_fim_exposes_a_backdated_mtime(tmp_path):
    hit = fim_hit(f"{DOCROOT}/uploads/x.php", "added", at(60.4), sha256=MARKER_SHA,
                  mtime=at(-86400))
    src = source(tmp_path, upload_story()[0], [hit])
    result = correlate(src.load_logs(), src.load_files())
    stomp = next(f for f in result.findings if f.rule_id == "FILE-ANTIFORENSICS-TIMESTOMP")
    assert stomp.reasons[0].key == "timestomp.mtime_before_fim"


def test_alerts_only_turns_silence_off_and_lowers_confidence(tmp_path):
    web, fim = upload_story()
    full = correlate(*_load(source(tmp_path, web, fim)))
    partial = correlate(*_load(source(tmp_path, web, fim, header={"archives": False})))
    kinds = [g.kind for g in partial.gaps]
    assert GapKind.PARTIAL_LOG_SOURCE in kinds and GapKind.NO_LOG_LINES not in kinds
    order = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    for before, after in zip(full.timeline, partial.timeline, strict=True):
        assert order.index(after.confidence) == max(order.index(before.confidence) - 1, 0)


def _load(src: WazuhRecordingSource):
    return src.load_logs(), src.load_files()


def test_recording_lines_match_citations(tmp_path):
    """A cited line really holds the cited event."""
    src = source(tmp_path, *upload_story())
    result = correlate(src.load_logs(), src.load_files())
    lines = recording_lines(tmp_path / "rec.jsonl")
    for event in result.timeline:
        for citation in event.citations:
            if citation.kind is CitationKind.LOG_LINE:
                assert lines[citation.line_no - 1]["_source"]["full_log"] == citation.excerpt
            if citation.kind is CitationKind.WAZUH_ALERT:
                assert lines[citation.line_no - 1]["_source"]["location"] == "syscheck"
    assert ACCESS in {line["_source"].get("location") for line in lines[1:]}


def _deploy(at_s: float, n0: int = 10) -> list:
    """The lab's startup: the app's files appear within 0.1 s, after the FIM baseline."""
    names = ("index.php", "db.php", "product.php", "admin/login.php", "admin/upload.php")
    return [fim_hit(f"{DOCROOT}/{name}", "added", at(at_s + i * 0.02),
                    sha256=hashlib.sha256(name.encode()).hexdigest(), n=n0 + i)
            for i, name in enumerate(names)]


def test_a_deploy_inside_the_window_is_reviewed_not_accused(tmp_path):
    # Live lab, scenario A: the 8 app files were reported as affected before D79.
    web, fim = upload_story(_deploy(-8))
    result = correlate(*_load(source(tmp_path, web, fim)))
    assert [f.path for f in result.affected_files] == ["uploads/x.php"]
    assert set(result.unexplained_changes) == {
        "index.php", "db.php", "product.php", "admin/login.php", "admin/upload.php"}
    root = next(e for e in result.timeline if e.event_id == result.root_cause.event_id)
    assert root.description.params["path"] == "/admin/upload.php"


def test_a_batch_file_written_by_a_request_still_joins_the_incident(tmp_path):
    # An attacker unpacking a kit writes many files at once; the POST still links them.
    kit = [fim_hit(f"{DOCROOT}/lib/k{i}.php", "added", at(60.5 + i * 0.1),
                   sha256=hashlib.sha256(str(i).encode()).hexdigest(), n=20 + i)
           for i in range(3)]
    result = correlate(*_load(source(tmp_path, *upload_story(kit))))
    assert {"lib/k0.php", "lib/k1.php", "lib/k2.php"} <= {f.path for f in result.affected_files}
    event = next(e for e in result.timeline if e.description.params.get("path") == "lib/k0.php"
                 and e.description.key == "timeline.file_created")
    assert "seed.deploy_batch" in {r.key for r in event.confidence_reasons}


def test_error_log_only_behind_a_proxy_does_not_accuse_the_proxy(tmp_path):
    # Live lab, scenario E without archives: the only web event was the PHP error-log line,
    # whose client is the edge proxy. It was reported as the attacker IP before this fix.
    raw = (f"{at(60):%Y/%m/%d %H:%M:%S} [error] 24#24: *7 FastCGI sent in stderr: "
           '"PHP message: lab upload stored" while reading response header from upstream, '
           'client: 172.30.0.3, server: _, request: "POST /admin/upload.php HTTP/1.0"')
    src = source(tmp_path, [web_hit(raw, at(61), location=ERROR)], upload_story()[1],
                 header={"archives": False, "error_logs": (ERROR,)})
    result = correlate(*_load(src), config=CorrelationConfig(trusted_proxies=("172.30.0.3",)))
    assert result.iocs.ips == ()
    root = next(e for e in result.timeline if e.event_id == result.root_cause.event_id)
    assert root.actor is None and root.confidence is Confidence.LOW
    assert "error_log.client_is_proxy" in {r.key for r in root.confidence_reasons}
