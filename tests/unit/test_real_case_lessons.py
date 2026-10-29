"""Behaviours learned from the first real case, the Ali Hadi "Web Server Case" (D84). Each
test reduces one lesson to synthetic input; the case itself is not redistributable."""

import io
from datetime import UTC, datetime

from tests.correlate_helpers import at, file_ev, files, numbered
from webforensics.codeloc.includes import include_patterns, resolve_includes
from webforensics.correlate import CorrelationConfig, correlate, for_filesystem
from webforensics.correlate.anchor import choose_anchor
from webforensics.models import CaseInfo, RunInfo, TimestampBasis
from webforensics.parsers.manifest import parse_manifest
from webforensics.report import build_report, render
from webforensics.report.document import timeline_runs
from webforensics.report.text import parse_display_offset

WINDOWS = CorrelationConfig(case_insensitive_paths=True, birth_time_settable=True)


# --- the manifest says which filesystem the webroot is on --------------------------------


def test_manifest_records_the_filesystem_and_windows_adjusts_the_config():
    text = ("#webforensics-manifest v1\n#filesystem=ntfs\n"
            "#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n")
    header, _, _ = parse_manifest(io.StringIO(text), "manifest.tsv")
    assert header.filesystem == "ntfs" and "filesystem" not in header.extra
    assert for_filesystem(CorrelationConfig(), "ntfs") == WINDOWS
    assert for_filesystem(CorrelationConfig(), "NTFS").case_insensitive_paths
    assert for_filesystem(CorrelationConfig(), "ext2/ext3") == CorrelationConfig()
    assert for_filesystem(CorrelationConfig(), None) == CorrelationConfig()


# --- NTFS: birth time is settable and survives unpacking ---------------------------------


def unpacked_shell():
    """webshell.php in the case: birth and mtime from the zip (2014), MFT change at unpack."""
    return file_ev("DVWA/webshell.php", btime=-50_000_000, mtime=-50_000_000, ctime=0)


def test_on_linux_a_stomped_file_is_dated_by_its_birth():
    anchor = choose_anchor(unpacked_shell(), CorrelationConfig())
    assert anchor.basis is TimestampBasis.BTIME


def test_on_windows_the_later_mft_change_dates_it_and_confidence_is_capped():
    anchor = choose_anchor(unpacked_shell(), WINDOWS)
    assert (anchor.basis, anchor.ts, anchor.max_confidence.value) == (
        TimestampBasis.CTIME, at(0), "medium")
    assert [r.key for r in anchor.reasons] == ["anchor.ctime_settable"]


# --- an application install is not an attack ---------------------------------------------


def install_batch(extra=()):
    """40 files unpacked in the same seconds, two of them looking odd on their own."""
    batch = [file_ev(f"app/lib/f{i}.php", btime=i * 0.1, ctime=i * 0.1, mtime=-9_000_000,
                     content=str(i)) for i in range(40)]
    batch.append(file_ev("app/vulnerabilities/upload/source/low.php", btime=2, ctime=2,
                         mtime=-9_000_000))
    return files(*batch, *extra)


def test_install_files_flagged_only_by_path_or_old_mtime_go_to_review():
    result = correlate(numbered((0, "/")), install_batch())
    assert result.affected_files == ()
    assert "app/vulnerabilities/upload/source/low.php" in result.unexplained_changes


def test_a_real_webshell_inside_an_install_batch_is_still_accused(tmp_path):
    shell_file = tmp_path / "s.php"
    shell_file.write_text("<?php sys" "tem($_GET['c']);")
    shell = file_ev("app/lib/s.php", btime=1, ctime=1, mtime=1).model_copy(
        update={"content_ref": str(shell_file)})
    result = correlate(numbered((0, "/")), install_batch([shell]))
    assert [f.path for f in result.affected_files] == ["app/lib/s.php"]


# --- Windows URLs ignore case --------------------------------------------------------------


def test_requests_match_a_differently_cased_file_on_windows_only():
    logs = numbered((0, "/dvwa/up/x.php", {"method": "POST"}),
                    (2, "/dvwa/up/x.php?cmd=dir", {"size": 400}),
                    (3, "/dvwa/up/x.php?cmd=whoami", {"size": 30}))
    evidence = files(file_ev("DVWA/up/x.php", btime=0, ctime=0, mtime=0))
    linux = correlate(logs, evidence)
    windows = correlate(logs, evidence, config=WINDOWS)

    def invoked(result):
        return [e.description.params["file"] for e in result.timeline
                if e.description.key == "timeline.file_invoked"]

    # On Linux the URL names another file, which the evidence does not have (D85).
    assert linux.log_only_files == ("/dvwa/up/x.php",)
    assert "DVWA/up/x.php" not in invoked(linux)
    assert windows.log_only_files == ()
    assert "DVWA/up/x.php" in invoked(windows)


# --- sqlmap's scanner user agent does not hide the payload ------------------------------


def test_a_scanner_request_with_an_sqli_payload_is_an_exploit_attempt():
    logs = numbered((0, "/p.php?id=1+UNION+SELECT+1", {"ua": "sqlmap/1.0"}),
                    (5, "/up.php", {"method": "POST"}), (6, "/u/a.php"))
    result = correlate(logs, files(file_ev("u/a.php", btime=5, ctime=5, mtime=5)))
    first = next(e for e in result.timeline if e.citations[0].line_no == 1)
    assert first.description.key == "timeline.exploit_attempt"
    assert first.description.params["rule_id"].startswith("LOG-SQLI-")


# --- bursts are one row in the report, every event stays in the JSON ----------------------


def test_a_burst_of_flagged_requests_is_one_report_row():
    specs = [(i, f"/p.php?id={i}+UNION+SELECT+1") for i in range(50)]
    specs += [(1000, "/up.php", {"method": "POST"}), (1001, "/u/a.php")]
    logs = numbered(*specs)
    result = correlate(logs, files(file_ev("u/a.php", btime=1000, ctime=1000, mtime=1000)))
    runs = timeline_runs(result.timeline)
    assert any(len(run) == 50 for run in runs)
    run = RunInfo(tool_version="t", ruleset_version="r",
                  generated_at=datetime(2026, 1, 1, tzinfo=UTC))
    report = build_report(result, logs, CaseInfo(case_id="c", title="t"), run)
    md = render(report, parse_display_offset("+07:00"), strict=True)["md"]
    assert "Rentetan 50 request" in md
    assert md.count("| Percobaan eksploitasi") == 0
    assert len(report.result.timeline) == len(result.timeline)


def test_a_pause_splits_a_burst():
    specs = [(i, f"/p.php?id={i}+UNION+SELECT+1") for i in range(5)]
    specs += [(3600 + i, f"/p.php?id={i}+UNION+SELECT+1") for i in range(5)]
    specs += [(7200, "/up.php", {"method": "POST"}), (7201, "/u/a.php")]
    result = correlate(numbered(*specs),
                       files(file_ev("u/a.php", btime=7200, ctime=7200, mtime=7200)))
    assert sorted(len(r) for r in timeline_runs(result.timeline) if len(r) > 1) == [5, 5]


# --- includes: the query is often in a file the endpoint includes -------------------------


def test_include_patterns_keep_literal_parts():
    assert include_patterns(b'<?php require_once ROOT."app/source/{$level}";') == [
        "(?:.*/)?app/source/[^/]*"]
    assert include_patterns(b"<?php require 'lib/' . $f . '.inc.php';") == [
        "(?:.*/)?lib/[^/]*\\.inc\\.php"]
    assert include_patterns(b'<?php include __DIR__ . "/z/w.php";') == ["(?:.*/)?z/w\\.php"]


def test_includes_without_a_folder_or_remote_are_skipped():
    for source in (b"<?php include $page;", b"<?php include $p . '.php';",
                   b"<?php include 'http://example.test/x.php';"):
        assert include_patterns(source) == []


def test_resolve_includes_relative_literal_and_pattern():
    paths = ["web/db.php", "web/admin/login.php", "web/app/source/low.php",
             "web/app/source/high.php", "web/app/index.php"]
    assert resolve_includes(b"<?php require '../db.php';", "web/admin/login.php", paths) == [
        "web/db.php"]
    source = b'<?php require ROOT . "app/source/{$level}";'
    assert resolve_includes(source, "web/app/index.php", paths) == [
        "web/app/source/high.php", "web/app/source/low.php"]
    upper = [p.upper() for p in paths]
    assert resolve_includes(source, "WEB/APP/INDEX.PHP", upper) == []
    assert len(resolve_includes(source, "WEB/APP/INDEX.PHP", upper, case_insensitive=True)) == 2


def test_an_include_matching_too_many_files_is_skipped():
    paths = [f"web/mods/m{i}.php" for i in range(11)]
    assert resolve_includes(b'<?php include "mods/$m";', "web/index.php", paths) == []


# --- code review covers attacked SQLi endpoints and what they include ---------------------


def test_review_follows_an_attacked_endpoint_into_its_included_source(tmp_path):
    from webforensics.codeloc.locate import review_code

    root = tmp_path / "web"
    (root / "DVWA" / "sqli" / "source").mkdir(parents=True)
    (root / "DVWA" / "sqli" / "index.php").write_text(
        '<?php\nrequire_once ROOT . "sqli/source/{$level}";\n')
    (root / "DVWA" / "sqli" / "source" / "low.php").write_text(
        "<?php\n$id = $_GET['id'];\n$q = \"SELECT * FROM users WHERE id = '$id'\";\n"
        "mysql_query($q);\n")
    logs = numbered((0, "/dvwa/sqli/?id=1%27+UNION+SELECT+1--+"),
                    (5, "/up.php", {"method": "POST"}), (6, "/u/a.php"))
    result = correlate(logs, files(file_ev("u/a.php", btime=5, ctime=5, mtime=5)),
                       config=WINDOWS)
    found, scope = review_code(result, files(), root, case_insensitive=True)
    assert [(f.file, f.line, f.implicated_by, f.verified) for f in found] == [
        ("DVWA/sqli/source/low.php", 3, "included", False)]
    assert scope.analyzed == ("DVWA/sqli/index.php",)
    assert scope.included == ("DVWA/sqli/source/low.php",)
    # Without the Windows flag the lowercase URL finds nothing on disk.
    assert review_code(result, files(), root)[1].no_content == ("dvwa/sqli/", "up.php")
