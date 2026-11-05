"""The visual system shared by the static report and the viewer (D103).

Direction "chain of evidence": cool paper, blue-black ink, one steel blue for evidence and
links, a seal red used only for the compromise and the entry point, and an evidence-tag
yellow used only for evidence gaps. Each colour has one meaning.

Type: Plus Jakarta Sans (designed in Indonesia for Jakarta's city identity; SIL Open Font
License, `fonts/OFL.txt`), embedded as a Latin variable WOFF2 so pages stay offline and
self-contained. A monospace face is used only for evidence itself: log lines, hashes,
paths and addresses, never for labels.
"""

import base64
from functools import lru_cache
from importlib import resources

FONT_FILE = "PlusJakartaSans-latin-wght.woff2"

TOKENS = """
:root{
--paper:#eef1f4;--sheet:#f9fafb;--ink:#16202b;--ink-2:#475463;--ink-3:#5d6a78;
--rule:#d3dae1;--rule-2:#b7c2cd;--steel:#3b5b7a;--steel-soft:#dce5ee;
--seal:#b42318;--seal-soft:#f6dedb;--tag:#e9b949;--tag-soft:#faefcf;--tag-ink:#6f5208;
--sans:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--mono:ui-monospace,"Cascadia Mono",Consolas,"SF Mono",Menlo,"Liberation Mono",monospace;
color-scheme:light}
@media (prefers-color-scheme:dark){:root{
--paper:#18222d;--sheet:#1e2a36;--ink:#e3e9ef;--ink-2:#aab7c4;--ink-3:#8593a1;
--rule:#2e3b48;--rule-2:#43525f;--steel:#8fb2d3;--steel-soft:#26384a;
--seal:#f0796b;--seal-soft:#3d211f;--tag:#e9b949;--tag-soft:#3a3118;--tag-ink:#ecc96d;
color-scheme:dark}}
"""


@lru_cache(maxsize=1)
def font_face() -> str:
    """The embedded font as an @font-face rule (a data: URI; no network)."""
    data = resources.files("webforensics.report").joinpath("fonts", FONT_FILE).read_bytes()
    encoded = base64.b64encode(data).decode("ascii")
    return ('@font-face{font-family:"Plus Jakarta Sans";font-style:normal;'
            "font-weight:200 800;font-display:swap;"
            f'src:url(data:font/woff2;base64,{encoded}) format("woff2")}}')


# Evidence must read exactly as written: no ligatures turning "--" into a dash or "->" into
# an arrow in monospace text (Cascadia and others ship them on by default).
EVIDENCE_TEXT = ('code,pre,kbd,samp,.mono,.proof{font-variant-ligatures:none;'
                 'font-feature-settings:"liga" 0,"calt" 0}')


def base_css() -> str:
    return font_face() + TOKENS.strip() + "\n" + EVIDENCE_TEXT
