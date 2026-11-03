"""Every rule the code can fire has a section in docs/rules.md, and no section names a rule
that no longer exists (D96)."""

import re
from pathlib import Path

from webforensics.detect.log_rules import LOG_RULES

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src" / "webforensics"


def _code_rules() -> set[str]:
    ids = {rule.rule_id for rule in LOG_RULES}
    for path in SRC.rglob("*.py"):
        ids |= set(re.findall(r'"((?:FILE|CORR)-[A-Z-]+)"', path.read_text(encoding="utf-8")))
    return ids


def _documented() -> set[str]:
    text = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    return set(re.findall(r"^### ((?:LOG|FILE|CORR)-[A-Z-]+)$", text, re.MULTILINE))


def test_every_rule_is_documented():
    missing = sorted(_code_rules() - _documented())
    assert missing == [], f"add a section to docs/rules.md for: {missing}"


def test_no_documented_rule_is_stale():
    stale = sorted(_documented() - _code_rules())
    assert stale == [], f"remove or rename in docs/rules.md: {stale}"
