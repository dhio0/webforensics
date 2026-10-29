"""Scripts seen only in the logs (D85): the sqlmap pattern from the Ali Hadi case, reduced to
synthetic requests, plus the cases that must stay quiet."""

from tests.correlate_helpers import ATTACKER, VISITOR, file_ev, files, numbered, root_event
from webforensics.correlate import CorrelationConfig, correlate

OUTFILE = ("/app/item.php?id=2%27%20LIMIT%200%2C1%20INTO%20OUTFILE%20%27%2Fsrv%2Fwww%2F"
           "tmpstage.php%27%20LINES%20TERMINATED%20BY%200x3c3f706870")


def sqlmap_case():
    return numbered(
        (0, "/app/item.php?id=1"),
        (10, OUTFILE),
        (10, "/srv/www/tmpstage.php", {"status": 403}),
        (11, "/tmpstage.php"),
        (11, "/tmpstage.php", {"method": "POST"}),
        (11, "/tmpshell.php?cmd=echo%20test", {"size": 36}),
        (20, "/tmpshell.php?cmd=dir", {"size": 853}),
        (30, "/tmpshell.php?cmd=del%20%2FF%20%2FQ%20C%3A%5Csrv%5Cwww%5Ctmpstage.php", {"size": 11}),
        (30, "/tmpshell.php?cmd=del%20%2FF%20%2FQ%20%5Csrv%5Cwww%5Ctmpshell.php", {"size": 11}),
    )


def kinds(result, file):
    return [e.description.key for e in result.timeline if e.description.params.get("file") == file]


def test_deleted_scripts_are_reported_from_the_log_alone():
    result = correlate(sqlmap_case(), files(file_ev("app/item.php", btime=-999)))
    assert result.log_only_files == ("/tmpstage.php", "/tmpshell.php")
    assert result.affected_files == ()
    assert result.iocs.ips == (ATTACKER,)
    assert set(result.iocs.urls) >= {"/tmpstage.php", "/tmpshell.php"}


def test_the_outfile_request_is_the_root_cause():
    result = correlate(sqlmap_case(), files())
    root = root_event(result)
    assert root.description.key == "timeline.sqli_file_write"
    assert root.description.params["vuln_class"] == "sql_injection_file_write"
    assert root.citations[0].line_no == 2
    assert result.root_cause.confidence.value == "medium"


def test_stager_post_wrote_the_second_script_and_cleanup_is_found():
    result = correlate(sqlmap_case(), files())
    shell = kinds(result, "/tmpshell.php")
    assert "timeline.file_write_request" in shell  # the POST to the stager
    assert "timeline.file_deleted_by_command" in shell
    assert "timeline.file_deleted_by_command" in kinds(result, "/tmpstage.php")
    write = next(e for e in result.timeline if e.description.params.get("file") == "/tmpshell.php"
                 and e.description.key == "timeline.file_write_request")
    assert write.citations[0].line_no == 5


def test_a_script_that_exists_in_the_webroot_is_not_log_only():
    logs = numbered((0, "/tools/run.php?cmd=ls"))
    result = correlate(logs, files(file_ev("tools/run.php", btime=-5, ctime=-5, mtime=-5)))
    assert result.log_only_files == ()


def test_a_failed_request_or_a_non_script_url_is_not_a_shell():
    logs = numbered((0, "/gone.php?cmd=ls", {"status": 404}),
                    (1, "/search?cmd=ls"), (2, "/notes.txt?cmd=ls"))
    assert correlate(logs, files()).log_only_files == ()


def test_an_outfile_whose_file_is_never_served_is_not_reported():
    logs = numbered((0, OUTFILE), (1, "/tmpstage.php", {"status": 404}))
    assert correlate(logs, files()).log_only_files == ()


def test_someone_else_fetching_the_name_does_not_confirm_the_write():
    logs = numbered((0, OUTFILE), (1, "/tmpstage.php", {"ip": VISITOR}))
    assert correlate(logs, files()).log_only_files == ()


def test_case_insensitive_webroot_matches_a_differently_cased_url():
    logs = numbered((0, "/Tools/Run.php?cmd=ls", {"size": 120}),
                    (1, "/Tools/Run.php?cmd=id", {"size": 40}))
    found = files(file_ev("tools/run.php", btime=-5, ctime=-5, mtime=-5))
    assert correlate(logs, found).log_only_files == ("/Tools/Run.php",)
    windows = CorrelationConfig(case_insensitive_paths=True, birth_time_settable=True)
    assert correlate(logs, found, config=windows).log_only_files == ()


def test_a_soft_404_answering_every_probe_alike_is_not_a_shell():
    # A site that answers 200 with the same page for any URL: a bot's probes look alike.
    logs = numbered((0, "/shell.php?cmd=id", {"size": 5120}),
                    (1, "/shell.php?cmd=uname", {"size": 5120}),
                    (2, "/x.php?cmd=id", {"size": 900}))
    assert correlate(logs, files()).log_only_files == ()


def test_a_partial_file_listing_cannot_show_a_script_was_gone():
    # Wazuh FIM lists only changed files; an unchanged tool script is not missing.
    partial = files().model_copy(update={"complete_listing": False})
    assert correlate(sqlmap_case(), partial).log_only_files == ()
