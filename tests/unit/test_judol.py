"""Online gambling (judol) spam pages and search-engine cloaking (D98)."""

from tests.correlate_helpers import file_ev, files, numbered
from webforensics.correlate import correlate
from webforensics.detect import judol
from webforensics.detect.file_rules import detect_file

# A typical judol landing page: several promotion terms, each repeated.
SPAM = (
    "<html><head><title>SLOT GACOR HARI INI - Situs Slot Online Maxwin</title></head><body>"
    + "<h1>Daftar Slot Gacor Gampang Maxwin</h1>"
    + "<p>Situs slot online terpercaya, RTP live tertinggi, scatter hitam, bonus new member "
      "100%, deposit pulsa tanpa potongan, link alternatif resmi. Togel online dan "
      "mahjong ways 2.</p>" * 4
    + "</body></html>"
)
# Light spam: enough for the rule, not dense enough to count as proof in a deploy batch.
LIGHT = ("<p>slot gacor, situs slot, maxwin, rtp live, gacor, maxwin, situs togel, gacor</p>")
# The shape of real news on hacked government sites (D98): a list of injected URLs and
# "situs judi" throughout, but no selling. Three of twelve real articles had this shape.
HACK_REPORT = (
    "<p>Situs judi online menyusup ke situs pemerintah. Berikut daftar situs judi slot "
    "gacor yang ditemukan:</p><ul>"
    + "".join(f"<li>dinas{i}.kab.go.id/wp-content/slot-gacor-maxwin/</li>" for i in range(30))
    + "</ul><p>Kominfo meminta pengelola situs judi diblokir. Situs slot demo dan togel "
      "ikut disebut. Bandar slot memakai situs judi untuk SEO.</p>" * 3
)
# News about gambling, as a ministry or campus site publishes it.
NEWS = (
    "<article><h1>Kominfo Blokir Ribuan Situs Judi Online</h1><p>Kementerian memblokir "
    "situs slot dan situs togel yang marak beriklan. Masyarakat diminta tidak tergiur iklan "
    "slot gacor. Judi online merusak ekonomi keluarga. Pemblokiran situs judi online akan "
    "terus dilakukan.</p></article>"
)
CLOAKER = (
    "<?php\n$ua = strtolower($_SERVER['HTTP_USER_AGENT']);\n"
    "if (strpos($ua, 'googlebot') !== false) {\n"
    "    echo file_get_contents('https://cdn.example.invalid/page.txt');\n"
    "    exit;\n}\ninclude 'index.html';\n"
)
# A legitimate check: the theme hides a banner from bots, nothing is fetched from outside.
BOT_AWARE = (
    "<?php\nif (preg_match('/bot|crawl/i', $_SERVER['HTTP_USER_AGENT'])) { $banner = false; }\n"
    "echo render('home', ['banner' => $banner]);\n"
)


def page(tmp_path, name, text, **times):
    path = tmp_path / name.replace("/", "_")
    path.write_text(text, encoding="utf-8")
    return file_ev(name, content=text, **times).model_copy(update={"content_ref": str(path)})


def rules(evidence):
    return [f.rule_id for f in detect_file(evidence)]


def test_the_score_counts_distinct_terms_and_every_match():
    spam = judol.score(SPAM)
    assert spam.spam and spam.dense
    assert len(spam.labels) >= 8
    assert spam.first.casefold().startswith("slot gacor")
    light = judol.score(LIGHT)
    assert light.spam and not light.dense


SAMPLES = {
    "slot_brand": ["Slot88", "slot online", "SLOT  Gacor"], "gacor": ["gacor"],
    "maxwin": ["maxwin", "MAX WIN"], "situs": ["situs toto", "situs poker"],
    "bandar_agen": ["bandar togel", "agen bola"], "togel": ["TOGEL"],
    "rtp": ["rtp live", "RTP slot"], "scatter": ["scatter hitam"],
    "mahjong": ["mahjong ways"],
    "deposit": ["depo 10k", "deposit pulsa", "deposit 25 ribu"],
    "bonus": ["bonus new member"], "link_alt": ["link alternatif"],
    "daftar": ["daftar slot", "login toto"],
    "provider": ["Pragmatic Play", "gates of olympus", "sbobet", "pg soft"],
}


def test_every_term_matches_its_samples():
    assert set(SAMPLES) == {label for label, _ in judol._TERMS}
    for label, words in SAMPLES.items():
        for word in words:
            assert judol.score(f"<p>{word}.</p>").labels == (label,), word


def test_the_pre_check_never_drops_spam():
    import itertools
    assert set(judol._ANCHORS) == judol.PROMOTION
    promo = [w for label in sorted(judol.PROMOTION) for w in SAMPLES[label]]
    topic = [w for label in SAMPLES if label not in judol.PROMOTION for w in SAMPLES[label]]
    for a, b in itertools.combinations(promo, 2):
        text = f"{a} {b} {topic[0]} " * 4
        if judol.score(text).spam:
            assert judol.could_be_spam(text.casefold()), (a, b)
    assert judol.could_be_spam(SPAM.casefold())
    assert not judol.could_be_spam("<?php wp_login_form(); // see repository docs")


def test_terms_inside_other_words_do_not_count():
    # "megacorporation" holds "gacor", "rtp live" starts "rtp liveness": whole words only.
    text = "megacorporation slotted mahjongways bandarlampung togelia " * 30
    assert judol.score(text).hits == 0


def test_news_about_gambling_is_not_spam():
    news = judol.score(NEWS)
    assert news.labels and not news.spam
    report = judol.score(HACK_REPORT)
    assert report.hits >= 30 and len(report.labels) >= 4
    assert report.promotion == 1 and not report.spam


def test_a_spam_page_anywhere_is_flagged(tmp_path):
    for name in ("index.html", "wp-content/uploads/slot/index.php", "assets/js/info.txt"):
        assert "FILE-JUDOL-CONTENT" in rules(page(tmp_path, name, SPAM))
    finding = next(f for f in detect_file(page(tmp_path, "a.html", SPAM))
                   if f.rule_id == "FILE-JUDOL-CONTENT")
    assert finding.confidence.value == "high"
    assert finding.mitre == ("T1491.002",)


def test_news_and_ordinary_pages_are_not_flagged(tmp_path):
    assert rules(page(tmp_path, "berita/blokir-judol.html", NEWS)) == []
    assert rules(page(tmp_path, "index.html", "<h1>Selamat datang di kampus</h1>")) == []


def test_cloaking_needs_a_bot_check_and_remote_content(tmp_path):
    assert rules(page(tmp_path, "index.php", CLOAKER)) == ["FILE-SEO-CLOAKING"]
    assert rules(page(tmp_path, "theme/header.php", BOT_AWARE)) == []
    # The same code in a text file is not served as a script.
    assert rules(page(tmp_path, "notes.txt", CLOAKER)) == []


def test_dense_spam_dropped_with_many_pages_is_still_accused(tmp_path):
    """Judol kits write hundreds of pages at once; a deploy batch must not hide them."""
    names = [f"slot-gacor/page{i}.html" for i in range(6)]
    evidence = files(*(page(tmp_path, n, SPAM, btime=0, ctime=0, mtime=0) for n in names))
    result = correlate(numbered((3_600, "/")), evidence)
    assert sorted(f.path for f in result.affected_files) == names
    event = next(e for e in result.timeline if e.description.params.get("path") == names[0])
    assert (event.mitre_technique, event.mitre_tactic) == ("T1491.002", "Impact")


def test_light_spam_in_a_deploy_batch_is_only_listed_for_review(tmp_path):
    names = [f"blog/post{i}.html" for i in range(6)]
    evidence = files(*(page(tmp_path, n, LIGHT, btime=0, ctime=0, mtime=0) for n in names))
    result = correlate(numbered((3_600, "/")), evidence)
    assert result.affected_files == ()
    assert sorted(result.unexplained_changes) == names


def test_a_crawler_reading_spam_is_impact_not_a_web_shell(tmp_path):
    names = [f"slot-gacor/page{i}.html" for i in range(6)]
    evidence = files(*(page(tmp_path, n, SPAM, btime=0, ctime=0, mtime=0) for n in names))
    logs = numbered((3_600, "/slot-gacor/page0.html", {"ip": "66.249.66.1", "ua": "Googlebot"}))
    event = next(e for e in correlate(logs, evidence).timeline
                 if e.description.key == "timeline.file_invoked")
    assert (event.mitre_technique, event.mitre_tactic) == ("T1491.002", "Impact")


def test_large_folders_are_named_once_in_advice():
    from webforensics.report.build import compact_paths
    paths = ["index.php", *(f"a/slot/p{i}.html" for i in range(40)), "b/x.php", "b/y.php"]
    text = compact_paths(paths, "{count} in {folder}")
    assert text == "index.php, 40 in a/slot/, b/x.php, b/y.php"


def test_identical_pages_written_together_are_one_story_row(tmp_path):
    from webforensics.report.document import attack_story, collapse_identical
    names = [f"slot-gacor/page{i}.html" for i in range(6)]
    evidence = files(*(page(tmp_path, n, SPAM, btime=0, ctime=0, mtime=0) for n in names),
                     page(tmp_path, "other.html", SPAM + "<!-- v2 -->", btime=0, ctime=0,
                          mtime=0))
    result = correlate(numbered((3_600, "/")), evidence)
    rows = collapse_identical(attack_story(result.timeline, result.iocs.ips))
    counts = sorted(extra for _, extra in rows)
    assert counts == [0, 5]  # six identical pages in one row; the different one apart
