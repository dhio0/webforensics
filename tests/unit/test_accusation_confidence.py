"""A file's label is the strength of the accusation, not only of its write time (D100)."""

import base64

from tests.correlate_helpers import file_ev, files, numbered
from tests.unit.test_file_rules import _request_exec
from webforensics.correlate import correlate
from webforensics.models import Confidence

# The same fragments as the other tests: Defender blocks reading `system($_GET[...])`.
SHELL = _request_exec("ex" + "ec", "GE" + "T", "t")
# Encoded data: weak evidence alone (real libraries ship it too).
ENCODED = "<?php $d = '" + base64.b64encode(bytes(range(256))).decode() + "'; ?>"
UPLOAD = (59, "/admin/upload.php", {"method": "POST"})


def evidence(tmp_path, path, content):
    target = tmp_path / path.replace("/", "_")
    target.write_text(content, encoding="utf-8")
    # btime: the write time is as sure as it gets, so only the accusation can lower it.
    return file_ev(path, btime=60, ctime=60, mtime=60, content=content).model_copy(
        update={"content_ref": str(target)})


def file_event(result, path):
    return next(e for e in result.timeline if e.description.params.get("path") == path
                and e.description.key == "timeline.file_created")


def keys(event):
    return [r.key for r in event.confidence_reasons]


def test_attacker_code_with_an_upload_is_high(tmp_path):
    logs = numbered(UPLOAD, (70, "/uploads/s.php?t=id"))
    result = correlate(logs, files(evidence(tmp_path, "uploads/s.php", SHELL)))
    event = file_event(result, "uploads/s.php")
    assert event.confidence is Confidence.HIGH
    assert not [k for k in keys(event) if k.startswith("accusation.")]


def test_attacker_code_with_no_request_is_medium(tmp_path):
    logs = numbered((50, "/"), (70, "/about"))  # plain visits, no writer, no gap
    result = correlate(logs, files(evidence(tmp_path, "uploads/s.php", SHELL)))
    event = file_event(result, "uploads/s.php")
    assert event.confidence is Confidence.MEDIUM
    assert "accusation.content_only" in keys(event)


def test_an_inert_upload_is_medium(tmp_path):
    logs = numbered(UPLOAD, (70, "/uploads/m.php"))
    result = correlate(logs, files(evidence(tmp_path, "uploads/m.php", "<?php echo 1; ?>")))
    event = file_event(result, "uploads/m.php")
    assert event.confidence is Confidence.MEDIUM
    assert "accusation.link_only" in keys(event)


def test_encoded_data_alone_is_low(tmp_path):
    logs = numbered((50, "/"), (70, "/about"))
    result = correlate(logs, files(evidence(tmp_path, "lib/data.php", ENCODED)))
    event = file_event(result, "lib/data.php")
    assert event.confidence is Confidence.LOW
    assert "accusation.weak" in keys(event)


def test_the_root_cause_is_never_surer_than_its_file(tmp_path):
    logs = numbered(UPLOAD, (70, "/uploads/m.php"))
    result = correlate(logs, files(evidence(tmp_path, "uploads/m.php", "<?php echo 1; ?>")))
    assert result.root_cause is not None
    assert result.root_cause.confidence is Confidence.MEDIUM
    root = next(e for e in result.timeline if e.is_root_cause)
    assert root.confidence is Confidence.MEDIUM


def test_a_web_shell_with_an_upload_keeps_a_high_root(tmp_path):
    logs = numbered(UPLOAD, (70, "/uploads/s.php?t=id"))
    result = correlate(logs, files(evidence(tmp_path, "uploads/s.php", SHELL)))
    root = next(e for e in result.timeline if e.is_root_cause)
    assert "root.capped_by_file" not in keys(root)
