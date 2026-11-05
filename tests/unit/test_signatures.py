"""Known web-shell families recognized by markers only they carry (D102).

Markers are assembled from pieces so that this test file is not itself flagged as a
web shell by an antivirus."""

from tests.correlate_helpers import file_ev, files, numbered
from webforensics.correlate import correlate
from webforensics.detect.file_rules import detect_file
from webforensics.detect.signatures import known_shell
from webforensics.models import Confidence

SAMPLES = {
    "c99": ["$x = '" + "c99" + "shell';", "function " + "c99" + "sh_getupdate() {}"],
    "r57": ["<title>" + "r57" + "shell</title>"],
    "b374k": ["// " + "b37" + "4k 3.2"],
    "wso": ["$a = '" + "Files" + "Man';", "define('" + "wso" + "_version', 2.5);"],
    "alfa": ["@define('" + "ALFA" + "_DATA', 1);", "by " + "Alfa" + "Team"],
    "indoxploit": ["<!-- " + "Indo" + "Xploit -->"],
    "phpspy": ["// " + "php" + "spy 2008"],
    "madspot": ["<h1>" + "Mad" + "Spot</h1>", "<title>" + "Mad" + " Shell</title>"],
}
ORDINARY = [
    "<?php echo 'hello'; ?>",
    "<?php // file manager for admins: $manager = new FileManager(); ?>",
    "<?php $wsoap = new SoapClient($url); ?>",  # 'wso' inside another word
    "<?php $alfa = 1; $beta = 2; ?>",  # alfa alone is not the alfa shell
    "<?php // Notes on c99 (the C standard) and r57 ?>",
]


def test_each_family_is_recognized():
    for family, texts in SAMPLES.items():
        for text in texts:
            found = known_shell(text)
            assert found is not None and found[0] == family, text


def test_ordinary_code_is_not():
    for text in ORDINARY:
        assert known_shell(text) is None, text


def page(tmp_path, name, text, **times):
    path = tmp_path / name.replace("/", "_")
    path.write_text(text, encoding="utf-8")
    return file_ev(name, content=text, **times).model_copy(update={"content_ref": str(path)})


def test_a_known_shell_is_a_high_confidence_finding_in_scripts_only(tmp_path):
    text = "<?php /* " + "b37" + "4k */ ?>"
    finding = next(f for f in detect_file(page(tmp_path, "uploads/x.php", text))
                   if f.rule_id == "FILE-WEBSHELL-KNOWN-SIGNATURE")
    assert finding.confidence is Confidence.HIGH
    assert finding.reasons[0].params["family"] == "b374k"
    # A text file naming the shell (notes, a scanner's word list) is not a script.
    assert not [f for f in detect_file(page(tmp_path, "docs/notes.txt", text))
                if f.rule_id == "FILE-WEBSHELL-KNOWN-SIGNATURE"]


def test_a_known_shell_used_after_an_upload_is_accused_high(tmp_path):
    text = "<?php /* " + "b37" + "4k */ ?>"
    logs = numbered((59, "/admin/upload.php", {"method": "POST"}),
                    (70, "/uploads/x.php", {"method": "POST"}))
    result = correlate(logs, files(page(tmp_path, "uploads/x.php", text,
                                        btime=60, ctime=60, mtime=60)))
    event = next(e for e in result.timeline if e.description.key == "timeline.file_created")
    assert event.confidence is Confidence.HIGH
