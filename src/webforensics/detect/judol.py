"""Online gambling ("judi online", judol) spam and the cloaking that hides it (D98).

The most common compromise of Indonesian public-sector and campus sites is not a
defacement banner but gambling SEO spam: pages full of slot and lottery promotion,
often shown only to search engines. These rules look for that content in webroot files.

News about gambling uses the topic words too, and often many times: an article on hacked
go.id sites lists dozens of injected URLs (`.../slot-gacor-maxwin/`) and says "situs judi"
throughout. What news does not do is sell: sign up, deposit by phone credit, claim the
new-member bonus, check today's RTP, use the alternative link. So a page counts as spam
only with several different PROMOTION terms on top of the topic words (D98; first
thresholds were tuned on twelve real news pages, three of which they wrongly flagged).
"""

import re
from dataclasses import dataclass

# Terms, each with a stable label. A label counts once however often it matches; `hits`
# counts every match. Matches do not overlap: "slot gacor" is one match (`slot_brand`),
# not also `gacor`. "judi" is in no term: "judi online" and "situs judi" are what news and
# warnings say. Patterns are lowercase and run once over casefolded text, as one
# alternation: separate case-insensitive passes cost ~20x more on a large file.
_TERMS: tuple[tuple[str, str], ...] = (
    # Topic: what the page is about. News uses these as much as spam does.
    ("slot_brand", r"slot\s*(?:online|88|777|gacor|demo|thailand|server|deposit|pulsa|dana"
                   r"|resmi|terpercaya)"),
    ("gacor", r"gacor"),
    ("situs", r"situs\s+(?:slot|togel|toto|bola|casino|poker)"),
    ("bandar_agen", r"(?:bandar|agen)\s+(?:slot|togel|bola|casino|toto)"),
    ("togel", r"togel"),
    ("provider", r"pragmatic\s+play|gates\s+of\s+olympus|sbobet|pg\s+soft"),
    # Promotion: selling to the visitor.
    ("maxwin", r"max\s*win"),
    ("rtp", r"rtp\s+(?:live|slot)"),
    ("scatter", r"scatter\s+hitam"),
    ("mahjong", r"mahjong\s+ways"),
    ("deposit", r"(?:deposit|depo)\s+(?:pulsa|dana|ovo|gopay|\d+\s*(?:k|rb|ribu))"),
    ("bonus", r"bonus\s+new\s+member"),
    ("link_alt", r"link\s+alternatif"),
    ("daftar", r"(?:daftar|login)\s+(?:slot|togel|toto)"),
)
PROMOTION = frozenset({"maxwin", "rtp", "scatter", "mahjong", "deposit", "bonus",
                       "link_alt", "daftar"})
# The lookahead lists every term's first letter, so most positions fail at once.
_FIRST_LETTERS = "abdglmprst"
_PATTERN = re.compile(
    rf"\b(?=[{_FIRST_LETTERS}])(?:"
    + "|".join(f"(?P<{label}>{rx})" for label, rx in _TERMS) + r")\b")

# Spam: at least MIN_PROMOTION different promotion terms, MIN_LABELS terms in all and
# MIN_HITS matches.
MIN_PROMOTION = 2
MIN_LABELS = 3
MIN_HITS = 8
# Dense enough that no deploy or news page writes it: such a file is accused even when it
# arrived together with many other files (judol kits drop hundreds of pages at once).
DENSE_PROMOTION = 3
DENSE_LABELS = 4
DENSE_HITS = 20


@dataclass(frozen=True)
class JudolScore:
    labels: tuple[str, ...]  # sorted, distinct
    hits: int
    first: str  # the first matched text, for the report

    @property
    def promotion(self) -> int:
        return len(PROMOTION.intersection(self.labels))

    @property
    def spam(self) -> bool:
        return (self.promotion >= MIN_PROMOTION and len(self.labels) >= MIN_LABELS
                and self.hits >= MIN_HITS)

    @property
    def dense(self) -> bool:
        return (self.promotion >= DENSE_PROMOTION and len(self.labels) >= DENSE_LABELS
                and self.hits >= DENSE_HITS)


# Literal text every promotion term contains, one group per label. Two promotion labels
# need anchors from two groups, so a file failing this check cannot be spam; `in` on a
# string is ~10x cheaper than the full pattern, and almost every webroot file fails it.
_ANCHORS: dict[str, tuple[str, ...]] = {
    "maxwin": ("max",), "rtp": ("rtp",), "scatter": ("scatter",), "mahjong": ("mahjong",),
    "deposit": ("depo",), "bonus": ("bonus",), "link_alt": ("alternatif",),
    "daftar": ("daftar", "login"),
}


def could_be_spam(folded: str) -> bool:
    """Cheap pre-check on casefolded text: False means `score(...).spam` is False."""
    groups = 0
    for anchors in _ANCHORS.values():
        if any(anchor in folded for anchor in anchors):
            groups += 1
            if groups >= MIN_PROMOTION:
                return True
    return False


def score(content: str) -> JudolScore:
    labels: set[str] = set()
    hits = 0
    first = ""
    for match in _PATTERN.finditer(content.casefold()):
        labels.add(match.lastgroup or "")
        hits += 1
        first = first or match.group(0)
    return JudolScore(tuple(sorted(labels)), hits, first)


# Cloaking: the script branches on the visitor being a search engine (user agent or
# referer) and then serves remote content or redirects. Both halves must be in one file.
_BOT_CHECK = re.compile(
    r"\$_SERVER\s*\[\s*['\"]HTTP_(?:USER_AGENT|REFERER)['\"]\s*\]"
    r"[\s\S]{0,400}?(?:googlebot|google|bingbot|bot|crawl|spider|slurp)",
    re.IGNORECASE)
_REMOTE = re.compile(
    r"\b(?:file_get_contents|curl_init|curl_setopt|fopen|readfile|include|require)"
    r"(?:_once)?\s*\(\s*['\"]https?://"
    r"|\bheader\s*\(\s*['\"]Location\s*:\s*https?://",
    re.IGNORECASE)


def cloaking(content: str) -> str | None:
    """The bot check that starts a cloaking block, or None."""
    check = _BOT_CHECK.search(content)
    if check is None or _REMOTE.search(content) is None:
        return None
    return check.group(0)
