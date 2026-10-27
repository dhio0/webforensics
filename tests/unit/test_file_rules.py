"""Synthetic, non-functional samples for file detection heuristics."""

import hashlib

from webforensics.detect import RULESET_VERSION
from webforensics.detect.file_rules import MAX_CONTENT_BYTES, detect_file
from webforensics.models import (
    BaselineStatus,
    Confidence,
    FileEvidence,
    FindingCategory,
    Severity,
    TimestampSource,
)


def _file(path: str, content: str | None = None, *, status=BaselineStatus.UNKNOWN,
          size: int | None = None) -> FileEvidence:
    return FileEvidence(
        evidence_id=f"ev-{path}", adapter="file", source=path, path=path,
        sha256=hashlib.sha256((content or "").encode()).hexdigest(),
        size=size if size is not None else len((content or "").encode()),
        timestamp_source=TimestampSource.MANIFEST, baseline_status=status,
        content_ref=None,
    )


def _with_content(tmp_path, path: str, content: str, *, status=BaselineStatus.UNKNOWN):
    target = tmp_path / "evidence.txt"
    target.write_bytes(content.encode())
    return _file(path, content, status=status).model_copy(update={"content_ref": str(target)})


def _ids(evidence):
    return [finding.rule_id for finding in detect_file(evidence)]


def _request_exec(function: str, method: str, key: str) -> str:
    # Assemble inert source text in fragments so the test file itself is not executable code.
    return "<?php " + function + "(" + "$_" + method + "['" + key + "']); ?>"


def test_writable_directory_executable_extension_positives():
    assert "FILE-WEBSHELL-WRITABLE-EXEC" in _ids(_file("uploads/photo.php"))
    assert "FILE-WEBSHELL-WRITABLE-EXEC" in _ids(_file("wp-content/uploads/2026/payload.phtml"))


def test_writable_directory_executable_extension_negatives():
    assert "FILE-WEBSHELL-WRITABLE-EXEC" not in _ids(_file("uploads/photo.jpg"))
    assert "FILE-WEBSHELL-WRITABLE-EXEC" not in _ids(_file("src/controller.php"))


def test_request_input_execution_positives(tmp_path):
    assert "FILE-WEBSHELL-REQUEST-EXEC" in _ids(
        _with_content(tmp_path, "handler.php", _request_exec("ev" + "al", "PO" + "ST", "value"))
    )
    assert "FILE-WEBSHELL-REQUEST-EXEC" in _ids(
        _with_content(tmp_path, "handler.php", _request_exec("ex" + "ec", "GE" + "T", "task"))
    )


def test_request_input_execution_checks_calls_after_benign_call(tmp_path):
    benign = "<?php " + "ass" + "ert('true'); "
    evidence = _with_content(
        tmp_path,
        "handler.php",
        benign + _request_exec("ev" + "al", "PO" + "ST", "value"),
    )

    finding = next(
        finding for finding in detect_file(evidence)
        if finding.rule_id == "FILE-WEBSHELL-REQUEST-EXEC"
    )
    assert finding.reasons[0].params["function"] == "eval"


def test_request_input_execution_negatives(tmp_path):
    cms = "<?php echo htmlspecialchars(" + "$_GE" + "T['title']); ?>"
    constant = "<?php " + "sys" + "tem('status'); ?>"
    assert "FILE-WEBSHELL-REQUEST-EXEC" not in _ids(_with_content(tmp_path, "theme.php", cms))
    assert "FILE-WEBSHELL-REQUEST-EXEC" not in _ids(_with_content(tmp_path, "task.php", constant))


def test_pdo_exec_method_with_request_input_is_not_command_execution(tmp_path):
    method_call = "$db-" + ">ex" + "ec(" + "$_" + "GET['query']);"
    evidence = _with_content(tmp_path, "database.php", "<?php " + method_call + " ?>")

    assert "FILE-WEBSHELL-REQUEST-EXEC" not in _ids(evidence)


def test_obfuscation_signal_positives(tmp_path):
    token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 3
    first = _with_content(tmp_path, "asset.php", f"<?php $data = '{token}'; ?>")
    encoded_call = "base64_" + "decode('short')"
    second = _with_content(tmp_path, "asset.php", "<?php $data = " + encoded_call + "; ?>")
    assert "FILE-WEBSHELL-OBFUSCATION" in _ids(first)
    assert "FILE-WEBSHELL-OBFUSCATION" in _ids(second)
    finding = next(f for f in detect_file(first) if f.rule_id == "FILE-WEBSHELL-OBFUSCATION")
    assert finding.confidence is Confidence.LOW
    assert finding.severity is Severity.LOW


def test_obfuscation_signal_negatives(tmp_path):
    assert "FILE-WEBSHELL-OBFUSCATION" not in _ids(
        _with_content(tmp_path, "theme.php", "<?php echo '<div>Welcome</div>'; ?>")
    )
    assert "FILE-WEBSHELL-OBFUSCATION" not in _ids(
        _with_content(tmp_path, "site.css", "body { color: #123456; background: white; }")
    )


def test_changed_entrypoint_persistence_positives():
    for path in (".htaccess", "public/index.php"):
        assert "FILE-PERSISTENCE-ENTRYPOINT-CHANGE" in _ids(
            _file(path, status=BaselineStatus.NEW)
        )
    assert "FILE-PERSISTENCE-ENTRYPOINT-CHANGE" in _ids(
        _file("public/index.html", status=BaselineStatus.MODIFIED)
    )


def test_changed_entrypoint_persistence_negatives():
    assert "FILE-PERSISTENCE-ENTRYPOINT-CHANGE" not in _ids(
        _file("public/index.php", status=BaselineStatus.UNCHANGED)
    )
    assert "FILE-PERSISTENCE-ENTRYPOINT-CHANGE" not in _ids(
        _file("public/about.php", status=BaselineStatus.NEW)
    )


def test_missing_content_reference_disables_content_rules():
    assert _ids(_file("uploads/sample.php")) == ["FILE-WEBSHELL-WRITABLE-EXEC"]


def test_read_limit_and_invalid_bytes_are_safe(tmp_path):
    target = tmp_path / "large.bin"
    later_text = b"<?php " + b"sys" + b"tem(" + b"$_" + b"GE" + b"T['x']); ?>"
    target.write_bytes(b"\xff" + b"a" * MAX_CONTENT_BYTES + later_text)
    evidence = _file("normal.php", size=MAX_CONTENT_BYTES + 40).model_copy(
        update={"content_ref": str(target)}
    )
    assert "FILE-WEBSHELL-REQUEST-EXEC" not in _ids(evidence)


def test_finding_schema_determinism_and_citation(tmp_path):
    evidence = _with_content(tmp_path, "handler.php", _request_exec("ev" + "al", "PO" + "ST", "x"))
    assert [f.model_dump() for f in detect_file(evidence)] == [
        f.model_dump() for f in detect_file(evidence)
    ]
    finding = detect_file(evidence)[0]
    assert finding.rule_version == RULESET_VERSION
    assert finding.category is FindingCategory.WEBSHELL
    assert finding.citations == (evidence.citation(),)
    assert finding.finding_id
    assert finding.reasons[0].params["function"] == "eval"
