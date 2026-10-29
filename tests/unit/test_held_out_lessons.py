"""Behaviours learned from the held-out case, Ali Hadi's Linux "Compromised Web Server"
(D86): Drupalgeddon2 in the query string, a webshell written from a root shell (no HTTP
writer), and a VM author's app install next to a phpMyAdmin form POST."""

from tests.correlate_helpers import ATTACKER, VISITOR, file_ev, files, numbered, root_event
from webforensics.correlate import correlate

EXPLOIT = ("/jabc/?q=user/password&name%5b%23post_render%5d%5b%5d=passthru"
           "&name%5b%23markup%5d=php%20-r%20%27eval%28base64_decode%28Lyo8%29%29%3b%27")


def rce_case(**first):
    """Exploit at 0 s, the shell is born at 900 s with no request near it, used at 906 s."""
    return numbered(
        (0, "/jabc/"),
        (1, EXPLOIT, {"method": "POST", **first}),
        (3, EXPLOIT, {"method": "POST"}),
        (906, "/jabc/scripts/update.php?cmd=ls", {"size": 244}),
    ), files(file_ev("uploads/update.php", btime=900, ctime=900, mtime=900))


def test_a_shell_written_outside_http_traces_back_to_the_first_code_injection():
    logs, evidence = rce_case()
    # The URL serves the same file (the test file is under uploads/ for its path finding).
    evidence = files(evidence.files[0].model_copy(update={
        "url_paths": ("/jabc/scripts/update.php",)}))
    result = correlate(logs, evidence)
    root = root_event(result)
    assert root.description.key == "timeline.rce_exploit"
    assert root.description.params["vuln_class"] == "remote_code_execution"
    assert root.citations[0].line_no == 2
    # Capped at medium; the 15-minute log silence in this input lowers it further.
    assert result.root_cause.confidence.value in ("medium", "low")
    assert result.iocs.ips == (ATTACKER,)
    assert not any(e.description.key == "timeline.file_write_request" for e in result.timeline)


def test_a_failed_code_injection_is_not_an_entry_point():
    logs, evidence = rce_case(status=403)
    evidence = files(evidence.files[0].model_copy(update={
        "url_paths": ("/jabc/scripts/update.php",)}))
    logs = numbered((0, "/jabc/"), (1, EXPLOIT, {"method": "POST", "status": 403}),
                    (906, "/jabc/scripts/update.php?cmd=ls", {"size": 244}))
    assert correlate(logs, evidence).root_cause is None


def test_someone_elses_code_injection_does_not_explain_the_shell():
    logs = numbered((1, EXPLOIT, {"method": "POST", "ip": VISITOR}),
                    (906, "/uploads/update.php?cmd=ls", {"size": 244}))
    result = correlate(logs, files(file_ev("uploads/update.php", btime=900, ctime=900,
                                           mtime=900)))
    assert result.root_cause is None
    assert VISITOR not in result.iocs.ips


def test_an_install_batch_next_to_a_form_post_is_not_accused():
    batch = [file_ev(f"docs/lib/f{i}.php", btime=60 + i * 0.01, ctime=70, mtime=-9_000_000,
                     content=str(i)) for i in range(40)]
    batch.append(file_ev("docs/media/data/server_processing.php", btime=60, ctime=70,
                         mtime=-9_000_000))
    logs = numbered((20, "/phpmyadmin/db_create.php", {"method": "POST", "ip": VISITOR}))
    result = correlate(logs, files(*batch))
    assert result.affected_files == ()
    assert result.iocs.ips == ()
    assert "docs/media/data/server_processing.php" in result.unexplained_changes


def test_an_install_batch_with_a_real_upload_is_still_traced():
    batch = [file_ev(f"docs/lib/f{i}.php", btime=60 + i * 0.01, ctime=60 + i * 0.01,
                     mtime=60, content=str(i)) for i in range(40)]
    batch.append(file_ev("uploads/x.php", btime=60, ctime=60, mtime=60))
    logs = numbered((59, "/admin/upload.php", {"method": "POST"}))
    result = correlate(logs, files(*batch))
    assert [f.path for f in result.affected_files] == ["uploads/x.php"]
