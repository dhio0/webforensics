"""Lessons from the dev scenarios of benchmark v2 (D94).

Each test is a small, made-up case of one general rule, not a copy of a scenario: the
query string of an upload, a clean login, a guessed login, extension tricks, an
`.htaccess` handler, a non-code file written by an attacker, an attacked endpoint that
then writes a file, and a script driven through POST bodies that is gone from the webroot.
"""

from pathlib import Path

from tests.correlate_helpers import ATTACKER, VISITOR, at, file_ev, files, numbered, root_event
from webforensics.correlate import correlate
from webforensics.correlate import requests as rq
from webforensics.detect.file_rules import handler_extensions, has_executable_extension
from webforensics.models import BaselineStatus, Confidence, FileCollection, FileEvidence

PLUGIN = "wp-content/plugins/evil/evil.php"


def _keys(result) -> list[str]:
    return [e.description.key for e in result.timeline]


def _line(event) -> int | None:
    return next((c.line_no for c in event.citations if c.line_no is not None), None)


def _new(path: str, seconds: float, content: str = "inert") -> FileEvidence:
    return file_ev(path, btime=seconds, ctime=seconds, mtime=seconds, content=content)


def _baseline() -> FileCollection:
    """A known-good copy that lacks every file the cases add, so they count as new."""
    return files(file_ev("index.php", btime=-999, ctime=-999, mtime=-999))


def _stored(tmp_path: Path, path: str, seconds: float, content: str) -> FileEvidence:
    tmp_path.mkdir(parents=True, exist_ok=True)
    target = tmp_path / path.replace("/", "_")
    target.write_text(content, encoding="utf-8")
    return _new(path, seconds, content).model_copy(update={"content_ref": str(target)})


# --- cases, shared with test_messages ---------------------------------------------------


def clean_login_case():
    """A login with no failed try, the upload form, then a plugin upload."""
    logs = numbered(
        (0, "/wp-login.php"),
        (5, "/wp-login.php", {"method": "POST", "status": 302}),
        (10, "/wp-admin/plugin-install.php?tab=upload"),
        (20, "/wp-admin/update.php?action=upload-plugin", {"method": "POST"}),
        (30, "/wp-content/plugins/evil/evil.php", {"method": "POST"}),
    )
    return logs, files(_new(PLUGIN, 20)), _baseline()


def clean_login_form_post_case():
    """The same, but the writing request has no upload hint (a settings form)."""
    logs = numbered(
        (5, "/admin/login.php", {"method": "POST", "status": 302}),
        (20, "/admin/settings.php", {"method": "POST"}),
        (30, "/admin/cache/x.php", {"method": "POST"}),
    )
    return logs, files(_new("admin/cache/x.php", 20)), _baseline()


def guessed_login_case():
    logs = numbered(
        (0, "/admin/login.php", {"method": "POST", "status": 401}),
        (2, "/admin/login.php", {"method": "POST", "status": 302}),
        (8, "/admin/upload.php", {"method": "POST"}),
    )
    return logs, files(_new("uploads/k.php", 8)), _baseline()


def handler_case(tmp_path: Path):
    """A plugin upload that brings an `.htaccess` running .jpg as PHP, and a .jpg agent."""
    htaccess = _stored(tmp_path, "wp-content/plugins/p/.htaccess", 20,
                       "AddType application/x-httpd-php .jpg\n")
    photo = _new("wp-content/plugins/p/photo.jpg", 20)
    logs = numbered(
        (20, "/wp-admin/update.php?action=upload-plugin", {"method": "POST"}),
        (40, "/wp-content/plugins/p/photo.jpg", {"method": "POST"}),
    )
    return logs, files(htaccess, photo), _baseline()


def side_file_case():
    """A plugin shell, then a request of the attacker in the second a marker appears,
    and a visitor's media upload one second later. In a tie within the same second, a
    visitor's write would explain the file better, and nothing would be linked."""
    logs = numbered(
        (20, "/upload.php", {"method": "POST"}),
        (60, "/wp-admin/plugins.php?action=activate&plugin=evil"),
        (61, "/wp-admin/async-upload.php", {"method": "POST", "ip": VISITOR}),
        (70, "/wp-content/uploads/marker.txt"),
    )
    evidence = files(_new("uploads/shell.php", 20), _new("wp-content/uploads/marker.txt", 60),
                     _new("wp-content/uploads/2026/photo.png", 61))
    return logs, evidence, _baseline()


def cmdi_case():
    """Command injection on an endpoint, then a POST to it that writes a text file."""
    logs = numbered(
        (0, "/exec/?ip=127.0.0.1%3Bcat%20/etc/passwd"),
        (30, "/exec/", {"method": "POST"}),
        (40, "/uploads/out.txt"),
    )
    return logs, files(_new("uploads/out.txt", 30)), _baseline()


def traversal_case():
    logs = numbered(
        (0, "/view.php?f=../../../../etc/hosts"),
        (30, "/view.php", {"method": "POST"}),
    )
    return logs, files(_new("data/notes.txt", 30)), _baseline()


def posted_script_case():
    """An upload, then POSTs to a new script that is not in the webroot, then a 404."""
    logs = numbered(
        (0, "/fm/connector.php?cmd=upload", {"method": "POST"}),
        (30, "/fm/files/a.php", {"method": "POST", "size": 60}),
        (60, "/fm/files/a.php", {"method": "POST", "size": 60}),
        (90, "/fm/files/a.php", {"status": 404}),
    )
    return logs, files(file_ev("fm/connector.php", btime=-999, ctime=-999, mtime=-999)), None


def all_cases(tmp_path: Path):
    yield clean_login_case()
    yield clean_login_form_post_case()
    yield guessed_login_case()
    yield handler_case(tmp_path)
    yield side_file_case()
    yield cmdi_case()
    yield traversal_case()
    yield posted_script_case()
    yield executed_image_case()


# --- tests -----------------------------------------------------------------------------


def test_upload_hint_reads_the_query_string_but_not_static_assets():
    upload = rq.write_level_for("POST", "/wp-admin/update.php", [], "action=upload-plugin")
    assert upload is rq.WriteLevel.LIKELY
    assert rq.write_level_for("POST", "/wp-admin/update.php", []) is rq.WriteLevel.POSSIBLE
    themed = rq.write_level_for("POST", "/wp-content/themes/t/index.js", [])
    assert themed is rq.WriteLevel.POSSIBLE


def test_a_clean_login_is_not_the_way_in_the_upload_is():
    logs, evidence, baseline = clean_login_case()
    result = correlate(logs, evidence, baseline=baseline)
    root = root_event(result)
    assert root.description.key == "timeline.upload_after_login"
    assert _line(root) == 4
    assert result.root_cause.confidence is Confidence.MEDIUM
    assert result.root_cause.vuln_class == "valid_account_abuse"
    keys = _keys(result)
    assert "timeline.login_valid_credentials" in keys
    # The login form (the actor's first request) and the upload form are in the timeline.
    by_line = {_line(e): e.description.key for e in result.timeline}
    assert by_line[1] == "timeline.actor_first_seen"
    assert by_line[3] == "timeline.actor_request"


def test_a_write_without_upload_hint_after_a_clean_login():
    logs, evidence, baseline = clean_login_form_post_case()
    result = correlate(logs, evidence, baseline=baseline)
    assert root_event(result).description.key == "timeline.write_after_login"


def test_a_guessed_login_stays_the_way_in_and_the_write_is_an_alternative():
    logs, evidence, baseline = guessed_login_case()
    result = correlate(logs, evidence, baseline=baseline)
    root = root_event(result)
    assert root.description.key == "timeline.login_method_unknown"
    alternatives = [e for e in result.timeline
                    if e.event_id in result.root_cause.alternative_event_ids]
    assert [_line(e) for e in alternatives] == [3]


def test_any_extension_part_and_trailing_dots_count_as_executable():
    assert has_executable_extension("images/category-1-.php..")
    assert has_executable_extension("uploads/a.php.jpg")
    assert has_executable_extension("uploads/a.PHP ")
    assert not has_executable_extension("js/jquery.min.js")
    assert not has_executable_extension("uploads/report.pdf")
    assert not has_executable_extension(".htaccess")


def test_htaccess_handler_parsing():
    assert handler_extensions("AddType application/x-httpd-php .jpg .gif\n") == (
        frozenset({".jpg", ".gif"}), False)
    assert handler_extensions('<FilesMatch "\\.(jpg|png)$">\n SetHandler '
                              "application/x-httpd-php\n</FilesMatch>\n") == (
        frozenset({".jpg", ".png"}), False)
    assert handler_extensions("SetHandler application/x-httpd-php\n") == (frozenset(), True)
    # Hosting panels map PHP versions to the usual extensions: nothing new is executable.
    assert handler_extensions("AddHandler application/x-httpd-ea-php74 .php .php7 .phtml\n"
                              "<FilesMatch \\.php$>\nSetHandler application/x-httpd-php\n"
                              "</FilesMatch>\n") == (frozenset(), False)


def test_a_file_run_as_php_by_a_new_htaccess_is_a_script(tmp_path):
    logs, evidence, baseline = handler_case(tmp_path)
    result = correlate(logs, evidence, baseline=baseline)
    assert {f.path for f in result.affected_files} == {
        "wp-content/plugins/p/.htaccess", "wp-content/plugins/p/photo.jpg"}
    rules = {f.rule_id for f in result.findings}
    assert {"FILE-HTACCESS-PHP-HANDLER", "FILE-HANDLER-EXEC"} <= rules
    assert "timeline.file_invoked" in _keys(result)


def test_an_unchanged_htaccess_makes_nothing_executable(tmp_path):
    logs, evidence, _ = handler_case(tmp_path)
    result = correlate(logs, evidence, baseline=evidence)
    assert result.affected_files == ()


def test_a_non_code_file_written_in_the_attackers_second_is_affected():
    logs, evidence, baseline = side_file_case()
    result = correlate(logs, evidence, baseline=baseline)
    paths = {f.path for f in result.affected_files}
    assert "wp-content/uploads/marker.txt" in paths
    # The visitor uploading at the same time is not an attacker.
    assert "wp-content/uploads/2026/photo.png" not in paths
    assert result.iocs.ips == (ATTACKER,)
    side = next(e for e in result.timeline if e.description.key == "timeline.file_side_write")
    assert _line(side) == 2


def test_non_code_files_need_a_baseline():
    logs, evidence, _ = side_file_case()
    result = correlate(logs, evidence)
    assert "wp-content/uploads/marker.txt" not in {f.path for f in result.affected_files}


def test_an_attacked_endpoint_that_then_writes_is_the_root_cause():
    logs, evidence, baseline = cmdi_case()
    result = correlate(logs, evidence, baseline=baseline)
    root = root_event(result)
    assert root.description.key == "timeline.exploited_endpoint_write"
    assert _line(root) == 2
    assert result.root_cause.vuln_class == "os_command_injection"
    assert [f.path for f in result.affected_files] == ["uploads/out.txt"]


def test_a_visitor_post_is_not_linked_without_an_attack():
    logs = numbered((30, "/contact.php", {"method": "POST", "ip": VISITOR}))
    result = correlate(logs, files(_new("uploads/out.txt", 30)), baseline=_baseline())
    assert result.affected_files == ()
    assert result.root_cause is None


def test_a_script_uploaded_then_driven_by_posts_and_gone_is_reported():
    logs, evidence, _ = posted_script_case()
    result = correlate(logs, evidence)
    assert result.log_only_files == ("/fm/files/a.php",)
    root = root_event(result)
    assert root.description.key == "timeline.upload_exploit"
    assert _line(root) == 1
    assert "timeline.log_only_file_gone" in _keys(result)


def test_scanner_probes_through_a_shared_proxy_are_not_a_shell():
    """A PHP-CGI probe (payload in the query) answered by a redirect, then the same probe
    to another script answered 200, twice, all from one proxy address."""
    probe = "?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
    logs = numbered(
        (0, "/10.php" + probe, {"method": "POST", "status": 302}),
        (1, "/18.php" + probe, {"method": "POST"}),
        (2, "/18.php" + probe, {"method": "POST"}),
    )
    result = correlate(logs, files(file_ev("index.php", btime=-999)))
    assert result.log_only_files == ()
    assert result.iocs.ips == ()


def test_posts_to_a_missing_script_without_an_upload_are_not_a_shell():
    logs = numbered(
        (30, "/xmlrpc2.php", {"method": "POST"}),
        (60, "/xmlrpc2.php", {"method": "POST"}),
    )
    result = correlate(logs, files(file_ev("index.php", btime=-999)))
    assert result.log_only_files == ()


def test_baseline_status_of_cases_is_new():
    logs, evidence, baseline = clean_login_case()
    result = correlate(logs, evidence, baseline=baseline)
    assert result.affected_files[0].baseline_status is BaselineStatus.NEW
    assert at(20) == result.affected_files[0].ctime


def executed_image_case():
    """An image written by an upload, then POSTed to and answered with a size unlike its
    own: the server runs it. The `.htaccess` that allows it is not in the evidence."""
    logs = numbered(
        (20, "/wp-admin/update.php?action=upload-plugin", {"method": "POST"}),
        (40, "/wp-content/plugins/p/photo.jpg", {"method": "POST", "size": 60}),
    )
    return logs, files(_new("wp-content/plugins/p/photo.jpg", 20)), _baseline()


def test_an_image_answered_like_a_script_is_a_script():
    logs, evidence, baseline = executed_image_case()
    result = correlate(logs, evidence, baseline=baseline)
    assert [f.path for f in result.affected_files] == ["wp-content/plugins/p/photo.jpg"]
    assert "CORR-STATIC-FILE-EXECUTED" in {f.rule_id for f in result.findings}


def test_an_image_served_as_itself_is_not_a_script():
    logs = numbered(
        (20, "/wp-admin/update.php?action=upload-plugin", {"method": "POST"}),
        (40, "/wp-content/plugins/p/photo.jpg", {"method": "POST", "size": 5}),
    )
    result = correlate(logs, files(_new("wp-content/plugins/p/photo.jpg", 20)),
                       baseline=_baseline())
    assert "CORR-STATIC-FILE-EXECUTED" not in {f.rule_id for f in result.findings}


def test_a_file_identical_to_the_baseline_is_not_listed_for_review(tmp_path):
    """An encoded blob in a core file is not news when the file equals the known-good copy."""
    core = _stored(tmp_path, "wp-includes/blob.php", -999,
                   "<?php $x = base64_decode('aGVsbG8='); ?>")
    result = correlate(numbered((0, "/")), files(core), baseline=files(core))
    assert all(f.subject != core.evidence_id for f in result.findings)
    assert result.unexplained_changes == ()
