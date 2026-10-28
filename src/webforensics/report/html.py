"""Serialize a `Document` to one self-contained HTML file.

Safety (the report is an attack surface, plan §6.9):
- every string from the document goes through `_e` (html.escape, quotes included);
- class names and anchors come from fixed tables or a strict pattern, never from evidence;
- no script, no external resources, and a CSP that forbids both, so even a missed
  escape could not run code or call out.
"""

import html
import re

from webforensics.report.document import (
    Block,
    Bullets,
    Cell,
    Code,
    Document,
    Fields,
    Heading,
    Para,
    Table,
)

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'"
_MARK_CLASS = {"high": "c-high", "medium": "c-medium", "low": "c-low", "root": "root"}
_ANCHOR = re.compile(r"^[a-z0-9-]+$")

_STYLE = """
:root{--bg:#fff;--fg:#1d2330;--muted:#5b6475;--line:#d9dde5;--head:#f3f5f8;
--root:#fff4d6;--high:#1f7a3d;--medium:#9a6700;--low:#b42318;--code:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e4e7ec;--muted:#98a2b3;
--line:#2e3440;--head:#1d2129;--root:#3a3115;--high:#6cc58a;--medium:#e3b341;--low:#f97066;
--code:#1d2129}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.7rem;margin:0 0 4px}h2{font-size:1.25rem;margin:36px 0 12px;
padding-bottom:6px;border-bottom:2px solid var(--line)}h3{font-size:1rem;margin:20px 0 8px}
.sub{color:var(--muted);margin:0 0 20px}
nav{border:1px solid var(--line);border-radius:8px;padding:10px 16px;background:var(--head)}
nav ol{margin:0;padding-left:18px;columns:2}nav a{color:inherit}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;
overflow-wrap:anywhere}th{background:var(--head)}tr.root td{background:var(--root)}
td.root{font-weight:600}
.c-high,.c-medium,.c-low{font-weight:600;white-space:nowrap}
.c-high{color:var(--high)}.c-medium{color:var(--medium)}.c-low{color:var(--low)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}
dt{font-weight:600;color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:10px;
overflow-x:auto;font-size:.85rem}
@media (max-width:640px){nav ol{columns:1}dl{grid-template-columns:1fr}}
@media print{nav{display:none}body{font-size:12px}h2{break-after:avoid}}
"""


def _e(text: str) -> str:
    return html.escape(text, quote=True)


def _cell(cell: Cell, tag: str = "td") -> str:
    cls = f' class="{_MARK_CLASS[cell.mark]}"' if cell.mark else ""
    return f"<{tag}{cls}>{_e(cell.text)}</{tag}>"


def _table(block: Table) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in block.headers)
    rows = []
    for i, row in enumerate(block.rows):
        cls = ' class="root"' if i in block.highlight else ""
        rows.append(f"<tr{cls}>" + "".join(_cell(c) for c in row) + "</tr>")
    return (f'<div class="tw"><table><thead><tr>{head}</tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table></div>")


def _block(block: Block) -> str:
    if isinstance(block, Para):
        return f"<p>{_e(block.text)}</p>"
    if isinstance(block, Heading):
        return f"<h3>{_e(block.text)}</h3>"
    if isinstance(block, Bullets):
        return "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in block.items) + "</ul>"
    if isinstance(block, Fields):
        return "<dl>" + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>"
                                for k, v in block.pairs) + "</dl>"
    if isinstance(block, Code):
        return "<pre>" + "\n".join(_e(line) for line in block.lines) + "</pre>"
    if isinstance(block, Table):
        return _table(block)
    raise TypeError(f"unknown block {block!r}")


def _anchor(value: str) -> str:
    if not _ANCHOR.match(value):
        raise ValueError(f"unsafe anchor {value!r}")
    return value


def render_html(doc: Document) -> str:
    toc = "".join(f'<li><a href="#{_anchor(s.anchor)}">{_e(s.title)}</a></li>'
                  for s in doc.sections)
    parts = [
        "<!doctype html>",
        f'<html lang="{_anchor(doc.lang)}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>{_e(doc.title)}</title>",
        f"<style>{_STYLE.strip()}</style>",
        "</head>",
        "<body><main>",
        f"<h1>{_e(doc.title)}</h1>",
        f'<p class="sub">{_e(doc.subtitle)}</p>',
        f"<nav><ol>{toc}</ol></nav>",
    ]
    for section in doc.sections:
        parts.append(f'<section id="{_anchor(section.anchor)}">')
        parts.append(f"<h2>{_e(section.title)}</h2>")
        parts += [_block(block) for block in section.blocks]
        parts.append("</section>")
    parts.append("</main></body></html>")
    return "\n".join(parts) + "\n"
