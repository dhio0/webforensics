"""SQL injection localization in PHP (M7): hand-made fixtures, the lab app, real CVE fixes,
and one test per behaviour that a real case taught us."""

import json
import re
from pathlib import Path

import pytest

from webforensics.codeloc.php_sqli import find_sql_injections
from webforensics.models import Confidence

ROOT = Path(__file__).parents[2]
HANDMADE = ROOT / "tests" / "fixtures" / "php_sqli" / "handmade"
CVE = ROOT / "tests" / "fixtures" / "php_sqli" / "cve"
CASES = json.loads((CVE / "cases.json").read_text(encoding="utf-8"))


def lines(php: str) -> list[int]:
    return [f.line for f in find_sql_injections(php.encode())]


def expected_lines(path: Path) -> set[int]:
    found = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if match := re.search(r"// vuln(?:@(\d+))?", line):
            found.add(int(match[1]) if match[1] else number)
    return found


# --- hand-made fixtures (written by the rule author: necessary, not sufficient) ----------


@pytest.mark.parametrize("path", sorted(HANDMADE.glob("*.php")), ids=lambda p: p.stem)
def test_handmade_fixture(path):
    got = {f.line for f in find_sql_injections(path.read_bytes())}
    if path.name.startswith("limitation_"):
        assert got == set(), "a documented limitation started to work: move it to p*.php"
    else:
        assert got == expected_lines(path)


def test_handmade_set_has_both_kinds():
    names = [p.name for p in HANDMADE.glob("*.php")]
    assert sum(n.startswith("p") for n in names) >= 10
    assert sum(n.startswith("n") for n in names) >= 10


# --- the lab app --------------------------------------------------------------------------


@pytest.mark.parametrize(("page", "expected"), [
    ("admin/login.php", [(13, 14)]), ("product.php", [(4, 5)]), ("product_post.php", [(4, 5)]),
    ("comment.php", []), ("admin/upload.php", []), ("admin/auth_upload.php", []),
    ("index.php", []), ("db.php", []),
])
def test_lab_app(page, expected):
    found = find_sql_injections((ROOT / "lab" / "app" / page).read_bytes())
    assert [(f.line, f.sink_line) for f in found] == expected


def test_lab_login_gets_a_prepared_statement_fix():
    found = find_sql_injections((ROOT / "lab" / "app" / "admin" / "login.php").read_bytes())
    assert found[0].sources == ("$_GET", "$_POST")
    assert found[0].confidence is Confidence.HIGH
    assert found[0].suggested_fix == (
        '$stmt = $pdo->prepare("SELECT id, username FROM users WHERE username = ? '
        'AND password = ?");\n$stmt->execute([$username, $password]);')


# --- real CVE fixes (selection rule and outcomes: tests/fixtures/php_sqli/cve/README.md) --


def _cve_files(case: dict) -> tuple[Path, Path] | None:
    folder = CVE / case["id"] if case["stored"] else CVE / ".cache" / case["id"]
    before, after = folder / "before.php", folder / "after.php"
    return (before, after) if before.is_file() and after.is_file() else None


def _outcome(before: Path, after: Path, case: dict) -> tuple[bool, bool, int]:
    vulnerable = find_sql_injections(before.read_bytes())
    fixed = find_sql_injections(after.read_bytes())
    left = {(f.snippet, f.sink) for f in fixed}
    gone = [f for f in vulnerable if (f.snippet, f.sink) not in left]
    exact = any(f.line in set(case["fix_removed_lines"]) for f in gone)
    return bool(gone), exact, len(fixed)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_cve_case(case):
    files = _cve_files(case)
    if files is None:
        pytest.skip("not redistributable: run scripts/fetch_cve_fixtures.py")
    detected, _, after_findings = _outcome(*files, case)
    assert detected == (case["expected"] == "detected"), case["note"]
    assert after_findings == 0, "a finding remains in the fixed version"


def test_cve_set_is_complete_and_honest():
    assert len(CASES) == 13
    assert {c["expected"] for c in CASES} == {"detected", "missed"}
    assert all(c["category"] for c in CASES if c["expected"] == "missed")
    assert sum(c["stored"] for c in CASES) == 2  # MIT only


# --- behaviours learned from real code ---------------------------------------------------


def test_exclusive_branches_do_not_leak_taint():
    # TorrentPier: a variable tainted in one `case` was reported in a sibling `case`.
    php = """<?php
$id = (int) $_GET['id'];
switch ($_GET['mode']) {
    case 'a':
        $id = $_POST['list'];
        break;
    case 'b':
        mysqli_query($c, "SELECT * FROM t WHERE id = $id");
        break;
}
"""
    assert lines(php) == []


def test_taint_from_any_branch_survives_after_the_branches():
    php = """<?php
if ($x) { $v = $_GET['v']; } else { $v = 'fixed'; }
mysqli_query($c, "SELECT * FROM t WHERE v = '$v'");
"""
    assert lines(php) == [3]


def test_escaping_every_element_in_a_loop_protects_a_quoted_list():
    # AVideo CVE-2026-33352 after the fix.
    php = """<?php
$cats = $_REQUEST['cats'];
foreach ($cats as $key => $value) {
    $cats[$key] = $mysqli->real_escape_string($value);
}
$sql = "SELECT * FROM c WHERE name NOT IN ('" . implode("', '", $cats) . "')";
sqlDAL::readSql($sql);
"""
    assert lines(php) == []
    weak = php.replace("$mysqli->real_escape_string($value)", "str_replace(\"'\", '', $value)")
    assert lines(weak) == [6]


def test_an_application_db_wrapper_is_a_sink_when_given_an_sql_statement():
    # LibreNMS dbFetchRow(), AVideo sqlDAL::readSql().
    php = """<?php
$device = $_POST['device_id'];
$row = dbFetchRow("SELECT * FROM devices WHERE device_id = $device");
$all = sqlDAL::readSql("SELECT * FROM v WHERE id = " . $_GET['id']);
"""
    assert lines(php) == [3, 4]


def test_hashing_or_logging_an_sql_statement_is_not_a_finding():
    php = """<?php
$sql = "SELECT * FROM v WHERE id = " . $_GET['id'];
$key = md5($sql);
error_log($sql);
"""
    assert lines(php) == []


def test_a_non_sql_string_passed_to_any_function_is_not_a_finding():
    assert lines("<?php\nsend_mail('Hello ' . $_POST['name']);\n") == []


def test_null_coalescing_keeps_the_input():
    assert lines("<?php\n$id = $_GET['id'] ?? 0;\nmysql_query(\"DELETE FROM t WHERE id=$id\");\n") \
        == [3]


def test_escaped_value_without_quotes_is_reported_with_lower_confidence():
    php = """<?php
$id = mysqli_real_escape_string($c, $_GET['id']);
mysqli_query($c, "SELECT * FROM t WHERE id = $id");
"""
    found = find_sql_injections(php.encode())
    assert [(f.line, f.confidence, f.escaped) for f in found] == [(3, Confidence.MEDIUM, True)]


@pytest.mark.parametrize(("php", "fix"), [
    ("<?php\n$c = mysqli_connect();\nmysqli_query($c, \"SELECT * FROM t WHERE a = '\" . "
     "$_GET['a'] . \"'\");\n",
     '$stmt = mysqli_prepare($c, "SELECT * FROM t WHERE a = ?");\n'
     'mysqli_stmt_bind_param($stmt, "s", $_GET[\'a\']);\nmysqli_stmt_execute($stmt);'),
    ("<?php\n$db = new mysqli();\n$db->query(\"SELECT * FROM t WHERE a = '{$_GET['a']}'\");\n",
     '$stmt = $db->prepare("SELECT * FROM t WHERE a = ?");\n'
     '$stmt->bind_param("s", $_GET[\'a\']);\n$stmt->execute();'),
    ("<?php\npg_query($pg, \"SELECT * FROM t WHERE a = '\" . $_GET['a'] . \"'\");\n",
     'pg_query_params($pg, "SELECT * FROM t WHERE a = $1", [$_GET[\'a\']]);'),
    ("<?php\n$wpdb->get_row(\"SELECT * FROM t WHERE a = '\" . $_GET['a'] . \"'\");\n",
     '$wpdb->get_row($wpdb->prepare("SELECT * FROM t WHERE a = %s", $_GET[\'a\']));'),
])
def test_suggested_fix_matches_the_database_api(php, fix):
    assert find_sql_injections(php.encode())[0].suggested_fix == fix


def test_unparsable_or_empty_input_gives_no_finding():
    assert lines("") == [] and lines("<?php if (") == [] and lines("not php at all") == []
