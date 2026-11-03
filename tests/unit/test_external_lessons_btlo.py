"""Lessons from the BTLO "Compromised WordPress" log (D95), as small made-up cases."""

from tests.correlate_helpers import VISITOR, file_ev, files, numbered, root_event
from webforensics.correlate import correlate

SHELL = "/wp-content/uploads/list/s.php"
EXPLOIT = "198.51.100.66"


def _line(event):
    return next((c.line_no for c in event.citations if c.line_no is not None), None)


def shell_from_another_address():
    """A scanner uploads through a plugin, then a second address drives the shell through
    POST bodies with changing output, and finally gets a 404."""
    return numbered(
        (0, "/", {"ip": EXPLOIT, "ua": "WPScan v3.8.10"}),
        (50, "/wp-content/plugins/list/ee-file-engine.php", {"method": "POST", "ip": EXPLOIT}),
        (60, SHELL),
        (62, SHELL, {"method": "POST", "size": 1213}),
        (90, SHELL, {"method": "POST", "size": 5436}),
        (120, SHELL, {"status": 404}),
    )


def test_a_shell_driven_from_another_address_is_found_with_its_writer():
    result = correlate(shell_from_another_address(), files(file_ev("index.php", btime=-999)))
    assert result.log_only_files == (SHELL,)
    root = root_event(result)
    assert root.description.key == "timeline.upload_exploit"
    assert _line(root) == 2
    assert set(result.iocs.ips) == {EXPLOIT, "203.0.113.7"}


def test_the_writer_must_have_attacked_before_when_it_is_another_address():
    logs = numbered(
        (50, "/wp-content/plugins/list/ee-file-engine.php", {"method": "POST", "ip": VISITOR}),
        (62, SHELL, {"method": "POST", "size": 1213}),
        (90, SHELL, {"method": "POST", "size": 5436}),
    )
    result = correlate(logs, files(file_ev("index.php", btime=-999)))
    assert result.log_only_files == (SHELL,)
    assert VISITOR not in result.iocs.ips


def test_same_output_size_in_an_upload_folder_is_not_a_shell():
    logs = numbered(
        (62, SHELL, {"method": "POST", "size": 900}),
        (90, SHELL, {"method": "POST", "size": 900}),
    )
    assert correlate(logs, files(file_ev("index.php", btime=-999))).log_only_files == ()
