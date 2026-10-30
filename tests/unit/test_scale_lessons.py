"""Behaviours learned from real logs at scale (D88): Zenodo 20001206, two Indonesian
public-sector servers, 7.4 million access-log lines and no webroot. Each test reduces one
lesson to synthetic input."""

from datetime import UTC, datetime

from tests.correlate_helpers import file_ev, files, numbered
from webforensics.correlate import correlate
from webforensics.correlate.actors import Why, login_outcomes
from webforensics.models import CaseInfo, RunInfo
from webforensics.report import build_report, render
from webforensics.report.text import parse_display_offset

SHELL = [(3600, "/wp-admin/33.php?cmd=a", {"size": 700}),
         (3610, "/wp-admin/33.php?cmd=b", {"size": 987})]


def brute_force(n, start=0, step=2):
    return [(start + i * step, "/wp-login.php", {"method": "POST", "status": 401})
            for i in range(n)]


def kinds(result):
    return [e.description.key for e in result.timeline]


def render_md(result, logs):
    run = RunInfo(tool_version="t", ruleset_version="r",
                  generated_at=datetime(2026, 1, 1, tzinfo=UTC))
    report = build_report(result, logs, CaseInfo(case_id="c", title="t"), run)
    return report, render(report, parse_display_offset("+07:00"), strict=True)["md"]


def test_a_brute_force_run_is_one_timeline_event():
    logs = numbered(*brute_force(50), *SHELL)
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert kinds(result).count("timeline.login_bruteforce") == 1
    assert "timeline.login_failed" not in kinds(result)
    burst = next(e for e in result.timeline if e.description.key == "timeline.login_bruteforce")
    assert burst.description.params["count"] == "50"
    assert burst.mitre_technique == "T1110"
    assert [c.line_no for c in burst.citations] == [1, 50]


def test_a_few_failed_logins_stay_individual():
    logs = numbered(*brute_force(3), *SHELL)
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert kinds(result).count("timeline.login_failed") == 3
    assert "timeline.login_bruteforce" not in kinds(result)


def test_a_long_pause_splits_brute_force_runs():
    logs = numbered(*brute_force(10), *brute_force(10, start=7200), *SHELL)
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert kinds(result).count("timeline.login_bruteforce") == 2


def test_login_outcomes_are_light_tuples_with_a_key():
    logs = numbered(*brute_force(2))
    outcomes = login_outcomes(list(logs.events), {e.evidence_id: e.client_ip
                                                  for e in logs.events})
    why = next(iter(outcomes.values()))[1]
    assert isinstance(why, Why) and why.key.startswith("login.")


def test_a_login_post_is_not_named_as_the_writer_of_a_shell():
    logs = numbered((3598, "/wp-login.php", {"method": "POST", "status": 302}), *SHELL)
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert result.log_only_files == ("/wp-admin/33.php",)
    assert "timeline.file_write_request" not in kinds(result)


def test_without_any_webroot_the_report_does_not_claim_the_script_was_deleted():
    logs = numbered(*SHELL)
    result = correlate(logs, files())
    assert "timeline.log_only_file_unverified" in kinds(result)
    assert "timeline.log_only_file" not in kinds(result)
    report, md = render_md(result, logs)
    keys = [r.key for r in (*report.summary, *report.recommendations)]
    assert "summary.compromise_found_scripts" in keys
    assert "summary.log_only_unverified" in keys
    assert "rec.eradication.check_log_only_unverified" in keys
    assert "sudah dihapus" not in md and "0 file mencurigakan" not in md


def test_a_sparse_log_shows_only_the_longest_silences():
    # Bursts of activity (an admin session) with three-hour pauses: one gap per pause.
    bursts = [(k * 10_800 + i, "/") for k in range(40) for i in range(30)]
    logs = numbered(*bursts)
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    silences = [g for g in result.gaps if g.detail and g.detail.key == "gap.log_silence"]
    assert len(silences) > 20
    _, md = render_md(result, logs)
    section = md[md.index("## 8."):md.index("## 9.")]
    assert section.count("| G") <= 15 + 2
    assert "periode log kosong lain" in section


# --- line text is read back from plain files instead of kept in memory -----------------


def test_plain_log_lines_are_read_back_by_offset_and_gzip_lines_are_kept(tmp_path):
    import gzip

    from webforensics.models import close_log_files
    from webforensics.parsers.access_log import AccessLogFormat, iter_access_log

    line1 = '203.0.113.7 - - [27/Oct/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 5 "-" "ua"'
    line2 = ('203.0.113.7 - - [27/Oct/2026:10:00:01 +0000] "GET /b?x=%C3%A9 HTTP/1.1" 200 5 '
             '"-" "u\xe9"')
    plain = tmp_path / "access.log"
    plain.write_bytes((line1 + "\r\n\r\n" + line2 + "\n").encode("utf-8"))
    packed = tmp_path / "access.log.1.gz"
    with gzip.open(packed, "wb") as handle:
        handle.write((line1 + "\n").encode("utf-8"))
    fmt = AccessLogFormat.NGINX_COMBINED
    events = list(iter_access_log(plain, "access.log", fmt))
    assert [e.raw_inline for e in events] == [None, None]
    assert [e.raw for e in events] == [line1, line2]
    assert [e.citation().excerpt for e in events] == [line1, line2]
    assert [e.line_no for e in events] == [1, 3]
    (gz_event,) = list(iter_access_log(packed, "access.log.1.gz", fmt))
    assert gz_event.raw_inline == line1 and gz_event.raw_file is None
    close_log_files()


def test_no_log_file_stays_open_after_correlation(tmp_path):
    from webforensics.adapters.file_adapter import LogFileSource
    from webforensics.parsers.access_log import AccessLogFormat

    log = tmp_path / "access.log"
    log.write_text('203.0.113.7 - - [27/Oct/2026:10:00:00 +0000] "GET /x.php?cmd=a HTTP/1.1" '
                   '200 5 "-" "ua"\n203.0.113.7 - - [27/Oct/2026:10:00:05 +0000] '
                   '"GET /x.php?cmd=b HTTP/1.1" 200 9 "-" "ua"\n', encoding="utf-8")
    logs = LogFileSource([log], AccessLogFormat.NGINX_COMBINED).load_logs()
    result = correlate(logs, files())
    assert result.log_only_files == ("/x.php",)  # its citations were read back
    log.unlink()  # fails on Windows if a handle were still open


# --- several virtual hosts in one run (D89) ---------------------------------------------

SITE_A = {"log_file": "home/a.example/logs/access_log"}
SITE_B = {"log_file": "home/b.example/logs/access_log"}


def test_one_probe_answered_by_two_sites_is_not_a_script():
    logs = numbered((3600, "/1514.php?cmd=a", {"size": 700, **SITE_A}),
                    (3610, "/1514.php?cmd=a", {"size": 987, **SITE_B}))
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert result.log_only_files == ()


def test_a_redirect_is_not_script_output():
    logs = numbered((3600, "/1514.php?cmd=a", {"status": 301, "size": 0}),
                    (3601, "/1514.php?cmd=a", {"size": 987}))
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert result.log_only_files == ()


def test_a_shell_on_one_site_keeps_its_own_uses_and_writer():
    logs = numbered((3590, "/upload.php", {"method": "POST", **SITE_B}),
                    (3595, "/upload.php", {"method": "POST", **SITE_A}),
                    (3600, "/x.php?cmd=a", {"size": 700, **SITE_A}),
                    (3610, "/x.php?cmd=b", {"size": 987, **SITE_A}),
                    (3620, "/x.php", {"size": 5, **SITE_B}))
    result = correlate(logs, files(file_ev("index.php", btime=-99, ctime=-99, mtime=-99)))
    assert result.log_only_files == ("/x.php",)
    cited = {(c.source, c.line_no) for e in result.timeline for c in e.citations
             if e.description.key in ("timeline.log_only_file", "timeline.file_invoked",
                                      "timeline.file_write_request")}
    assert (SITE_A["log_file"], 2) in cited  # the writer on the same site
    assert (SITE_B["log_file"], 1) not in cited
    assert (SITE_B["log_file"], 5) not in cited
