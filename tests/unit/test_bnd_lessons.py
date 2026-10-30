"""Behaviours learned from the third case, the BND Forensik-Challenge (D87): a defaced
index page, and an access log the attacker cut so that it starts after the attack."""

from tests.correlate_helpers import file_ev, files, numbered
from webforensics.correlate import correlate
from webforensics.detect.file_rules import detect_file

DEFACED = ("<html><body><h2>This site has been hacked!</h2><h1>Rul0rzZ</h1>"
           "Pay us to get your server back!</body></html>")


def page(tmp_path, name, text, **times):
    path = tmp_path / name.replace("/", "_")
    path.write_text(text)
    return file_ev(name, content=text, **times).model_copy(update={"content_ref": str(path)})


def rules(evidence):
    return [f.rule_id for f in detect_file(evidence)]


def test_a_defaced_index_page_is_flagged(tmp_path):
    assert rules(page(tmp_path, "index.html", DEFACED, btime=0)) == ["FILE-DEFACEMENT-PAGE"]
    assert rules(page(tmp_path, "shop/index.php", "<?php echo 'Hacked by X'; ?>")) == [
        "FILE-DEFACEMENT-PAGE"]


def test_ordinary_pages_and_non_index_files_are_not(tmp_path):
    assert rules(page(tmp_path, "index.html", "<h1>Welcome to our insurance</h1>")) == []
    assert rules(page(tmp_path, "blog/how-we-were-hacked.html",
                      "Our site has been hacked last year; here is what we learned.")) == []
    assert rules(page(tmp_path, "index.html", "Security news: hackers took over a bank.")) == []


def test_a_defacement_is_an_affected_file_with_the_impact_tactic(tmp_path):
    logs = numbered((86_400, "/index.html"))
    result = correlate(logs, files(page(tmp_path, "index.html", DEFACED, btime=0, ctime=0,
                                        mtime=0)))
    assert [f.path for f in result.affected_files] == ["index.html"]
    event = next(e for e in result.timeline if e.description.params.get("path") == "index.html")
    assert (event.mitre_technique, event.mitre_tactic) == ("T1491.002", "Impact")


def test_a_log_that_starts_after_webroot_changes_is_a_gap():
    logs = numbered((3 * 86_400, "/"), (3 * 86_400 + 60, "/index.php"))
    evidence = files(file_ev("insurances/0815", btime=0, ctime=0, mtime=0),
                     file_ev("app.php", btime=86_400, ctime=86_400, mtime=86_400))
    gaps = [g for g in correlate(logs, evidence).gaps
            if g.detail and g.detail.key == "gap.log_starts_after_changes"]
    assert len(gaps) == 1
    assert gaps[0].detail.params["count"] == "2"
    assert (gaps[0].end - gaps[0].start).days == 3


def test_a_deploy_minutes_before_logging_or_an_old_install_is_not():
    logs = numbered((3 * 86_400, "/"))
    recent = files(file_ev("app.php", btime=3 * 86_400 - 300, ctime=3 * 86_400 - 300,
                           mtime=0))
    old = files(file_ev("app.php", btime=-60 * 86_400, ctime=-60 * 86_400, mtime=0))
    for evidence in (recent, old):
        assert not any(g.detail and g.detail.key == "gap.log_starts_after_changes"
                       for g in correlate(logs, evidence).gaps)
