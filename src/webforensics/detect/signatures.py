"""Names and markers that only well-known web shells carry (D102).

Generic code (eval, system, base64) is left to the other rules: a marker here must be
specific to one shell family, so that an ordinary application never contains it. The
family is reported, which also tells the analyst what the shell can do.

Families seen in Indonesian incident guides (b374k, alfa, IndoXploit, Mad) and in the
public cases (c99), plus the long-lived classics (r57, WSO/FilesMan, phpspy).
"""

import re

# (family, pattern). Patterns are matched case-insensitively on the file content.
_FAMILIES: tuple[tuple[str, str], ...] = (
    ("c99", r"\bc99shell\b|\bc99sh_\w+|\bc99_sess_put\b"),
    ("r57", r"\br57shell\b|\br57_\w+\("),
    ("b374k", r"\bb374k\b"),
    ("wso", r"\bwso_version\b|\bWSOsetcookie\b|['\"]FilesMan['\"]"),
    ("alfa", r"\bALFA_DATA\b|\balfa_?team\b|\bAlfa\s?Shell\b"),
    ("indoxploit", r"\bIndoXploit\b"),
    ("phpspy", r"\bphpspy\b"),
    ("madspot", r"\bMadSpot\b|\bMad ?Shell\b"),
)
_PATTERNS = tuple((family, re.compile(rx, re.IGNORECASE)) for family, rx in _FAMILIES)
# Literal text every marker above contains, lowercase. `in` on a string is far cheaper than
# eight case-insensitive patterns, and almost no script holds any of these (D102: 2.5 s
# for the 968 scripts of a WordPress install without this pre-check, 0.1 s with it).
_ANCHORS = ("c99", "r57", "b374k", "wso_version", "wsosetcookie", "filesman", "alfa",
            "indoxploit", "phpspy", "madspot", "madshell", "mad shell")


def known_shell(content: str) -> tuple[str, str] | None:
    """(family, the matched marker) of the first family whose marker the content holds."""
    folded = content.casefold()
    if not any(anchor in folded for anchor in _ANCHORS):
        return None
    for family, pattern in _PATTERNS:
        match = pattern.search(content)
        if match:
            return family, match.group(0)
    return None
