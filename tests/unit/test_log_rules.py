import pytest

from webforensics.detect.log_rules import LOG_RULES, RULES_BY_ID, decode_text, detect_request
from webforensics.models import LogEvent, ParseFailure
from webforensics.parsers.access_log import AccessLogFormat, parse_access_line


def _event(target: str, *, method: str = "GET", ua: str = "Mozilla/5.0", status: int = 200):
    raw = (
        f'192.0.2.1 - - [27/Oct/2026:10:00:00 +0700] "{method} {target} HTTP/1.1" '
        f'{status} 10 "-" "{ua}"'
    )
    event = parse_access_line(raw, "access.log", 1, AccessLogFormat.NGINX_COMBINED)
    assert not isinstance(event, ParseFailure)
    return event


def _rule_ids(event: LogEvent) -> set[str]:
    return {f.rule_id for f in detect_request(event)}


POSITIVE = [
    ("/p.php?id=1%20UNION%20SELECT%201,2,3", "LOG-SQLI-UNION"),
    ("/p.php?id=1+union+all+select+null", "LOG-SQLI-UNION"),
    ("/p.php?id=1/**/UNION/**/SELECT/**/1", "LOG-SQLI-UNION"),
    ("/p.php?id=1%27%20OR%201=1--%20-", "LOG-SQLI-TAUTOLOGY"),
    ("/p.php?id=1%20AND%207=7", "LOG-SQLI-TAUTOLOGY"),
    ("/p.php?u=admin'%20or%20'a'='a", "LOG-SQLI-TAUTOLOGY"),
    ("/p.php?id=1;SELECT%20SLEEP(5)", "LOG-SQLI-BLIND"),
    ("/p.php?id=1;WAITFOR%20DELAY%20'0:0:5'", "LOG-SQLI-BLIND"),
    ("/p.php?id=-1%20union%20select%20table_name%20from%20information_schema.tables",
     "LOG-SQLI-SCHEMA"),
    ("/p.php?id=1%20into%20outfile%20'/var/www/x.php'", "LOG-SQLI-SCHEMA"),
    ("/p.php?id=1%27--%20", "LOG-SQLI-QUOTE-COMMENT"),
    ("/p.php?id=1%2527%2520OR%25201=1", "LOG-SQLI-TAUTOLOGY"),  # double encoded
    ("/view.php?f=../../../../etc/hosts", "LOG-TRAVERSAL-DOTS"),
    ("/view.php?f=..%2f..%2f..%2fvar/www", "LOG-TRAVERSAL-DOTS"),
    ("/view.php?f=/etc/passwd", "LOG-TRAVERSAL-SENSITIVE"),
    ("/view.php?f=C:\\windows\\win.ini", "LOG-TRAVERSAL-SENSITIVE"),
    ("/uploads/x.php", "LOG-WEBSHELL-UPLOAD-DIR"),
    ("/wp-content/uploads/2026/10/a.PHTML", "LOG-WEBSHELL-UPLOAD-DIR"),
    ("/uploads/x.php?cmd=id", "LOG-WEBSHELL-UPLOAD-DIR"),
    ("/a.php?cmd=whoami", "LOG-WEBSHELL-CMD-PARAM"),
    ("/a.php?x=1&exec=ls%20-la", "LOG-WEBSHELL-CMD-PARAM"),
    # Drupalgeddon2 as sent by Metasploit (Ali Hadi's Linux case, D86)
    ("/jabc/?q=user/password&name%5b%23post_render%5d%5b%5d=assert"
     "&name%5b%23markup%5d=eval%28base64_decode%28Lyo8P3Bo", "LOG-RCE-CODE-INJECTION"),
    ("/?q=user/password&name%5b%23post_render%5d%5b%5d=passthru&name%5b%23markup%5d=id",
     "LOG-RCE-CODE-INJECTION"),
    ("/x.php?a=php%20-r%20%27phpinfo();%27", "LOG-RCE-CODE-INJECTION"),
    ("/x.php?c=<?php%20echo%201;?>", "LOG-RCE-CODE-INJECTION"),
    # BND challenge probes (D87)
    ("/index.php?password=%22%3E%3Cxss&file=hack", "LOG-XSS-PROBE"),
    ("/s.php?q=%3Cscript%3Ealert(1)%3C/script%3E", "LOG-XSS-PROBE"),
    ("/s.php?q=x%22%20onerror=alert(1)", "LOG-XSS-PROBE"),
]

NEGATIVE = [
    "/",
    "/index.php?page=2&sort=name",
    "/search.php?q=union+station",  # 'union' without select
    "/search.php?q=select+a+seat",
    "/search.php?q=rock+and+roll",
    "/p.php?id=1%20and%20x=y",  # not a tautology
    "/blog/2026/10/my-post-about-sql",
    "/uploads/photo.jpg",
    "/uploads/",
    "/uploads/report.pdf?download=1",
    "/files/readme.php.txt",
    "/static/../static/app.js",  # a single ../ is common in normalized paths
    "/docs/passwd-policy.html",
    "/api/items?c=3",  # short param names are too common to flag as a shell command
    "/shop.php?cmdline_help=1",
    "/search.php?q=system+design",  # function names as plain words
    "/search.php?q=evaluation+of+assert+statements",
    "/docs/eval.html",
    "/node?q=#markup",  # a fragment-like word, not a render-array key
    "/index.php?password=%22%3Exss&file=hack",  # a quote and > without a tag
    "/s.php?q=a+%3E+b+and+c+%3C+d",  # comparisons in a search
]


@pytest.mark.parametrize(("target", "rule_id"), POSITIVE)
def test_positive(target, rule_id):
    assert rule_id in _rule_ids(_event(target))


@pytest.mark.parametrize("target", NEGATIVE)
def test_negative(target):
    found = _rule_ids(_event(target))
    assert not found, found


def test_every_rule_has_positive_coverage():
    # LOG-SCANNER-UA matches the user agent, so it has its own test below.
    covered = {rule_id for _, rule_id in POSITIVE} | {"LOG-SCANNER-UA"}
    assert covered == {r.rule_id for r in LOG_RULES}


def test_scanner_user_agent():
    assert "LOG-SCANNER-UA" in _rule_ids(_event("/", ua="sqlmap/1.8#stable"))
    assert "LOG-SCANNER-UA" in _rule_ids(_event("/", ua="Mozilla/5.00 (Nikto/2.5.0)"))
    assert "LOG-SCANNER-UA" not in _rule_ids(_event("/", ua="Mozilla/5.0 (X11; Linux)"))


def test_finding_carries_citation_and_status():
    event = _event("/p.php?id=1%20UNION%20SELECT%201", status=200)
    finding = next(f for f in detect_request(event) if f.rule_id == "LOG-SQLI-UNION")
    assert finding.citations == (event.citation(),)
    assert finding.subject == event.evidence_id
    assert finding.reasons[0].params["status"] == "200"
    assert "UNION SELECT" in finding.reasons[0].params["matched"]
    assert finding.mitre == ("T1190",)


def test_detection_is_deterministic():
    event = _event("/p.php?id=1%27%20OR%201=1%20UNION%20SELECT%201--%20")
    first = [f.model_dump() for f in detect_request(event)]
    second = [f.model_dump() for f in detect_request(event)]
    assert first == second
    assert [f["rule_id"] for f in first] == sorted(
        (f["rule_id"] for f in first), key=[r.rule_id for r in LOG_RULES].index
    )


def test_rule_ids_are_unique():
    assert len(RULES_BY_ID) == len(LOG_RULES)


def test_decode_text():
    assert decode_text("a%2520b") == "a b"
    assert decode_text("a+b%00c") == "a bc"
    assert decode_text("%e0%a4") != ""  # invalid UTF-8 doesn't crash
