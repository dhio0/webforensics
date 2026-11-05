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
from webforensics.report.theme import base_css

# The font is embedded as a data: URI (theme.py), so font-src allows data: only.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src 'none'; "
        "form-action 'none'")
_MARK_CLASS = {"high": "c-high", "medium": "c-medium", "low": "c-low", "root": "root"}
_ANCHOR = re.compile(r"^[a-z0-9-]+$")

_STYLE = """
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
font:15px/1.6 var(--sans);font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
main{max-width:1120px;margin:0 auto;padding:40px 32px 72px}
h1{font-size:30px;line-height:1.2;font-weight:700;letter-spacing:-.012em;margin:0 0 6px}
.sub{color:var(--ink-2);margin:0 0 28px}
h2{font-size:20px;line-height:1.3;font-weight:650;margin:48px 0 14px;padding-top:18px;
border-top:1px solid var(--rule-2)}
h3{font-size:15.5px;font-weight:650;margin:24px 0 8px}
p,li{max-width:78ch}ul{padding-left:22px}li{margin:4px 0}
a{color:var(--steel);text-underline-offset:3px}
nav{border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);padding:12px 0}
nav ol{list-style:none;margin:0;padding:0;columns:2;column-gap:40px}
nav li{margin:0;padding:3px 0;break-inside:avoid}nav a{color:var(--ink);text-decoration:none}
nav a:hover{color:var(--steel);text-decoration:underline}
.tw{overflow-x:auto;margin:10px 0 18px}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-weight:600;color:var(--ink-2);font-size:13px;white-space:nowrap;
padding:8px 14px 8px 0;border-bottom:1px solid var(--rule-2);vertical-align:bottom}
td{padding:8px 14px 8px 0;border-bottom:1px solid var(--rule);vertical-align:top;
overflow-wrap:break-word}
td:first-child,th:first-child{padding-left:8px}
tr.root td{background:var(--seal-soft)}tr.root td:first-child{box-shadow:inset 3px 0 0 var(--seal)}
td.root{color:var(--seal);font-weight:650}
.c-high,.c-medium,.c-low{white-space:nowrap;color:var(--ink-2)}
.c-high::before,.c-medium::before,.c-low::before{content:"";display:inline-block;width:16px;
margin-right:7px;vertical-align:4px;border-top:1.5px solid var(--steel)}
.c-high::before{border-top-width:3.5px}.c-low::before{border-top-style:dashed}
dl{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 20px;margin:8px 0 16px}
dt{color:var(--ink-3)}dd{margin:0;overflow-wrap:break-word}
pre{font:12.5px/1.6 var(--mono);background:var(--sheet);border-left:2px solid var(--rule-2);
padding:10px 14px;margin:8px 0 16px;white-space:pre-wrap;overflow-wrap:anywhere}
:focus-visible{outline:2px solid var(--steel);outline-offset:2px}
@media (max-width:700px){main{padding:24px 16px 48px}h1{font-size:24px}nav ol{columns:1}
dl{grid-template-columns:1fr}dt{margin-top:6px}}
@media print{:root{--paper:#fff;--sheet:#f4f6f8}nav{display:none}body{font-size:11.5pt}
main{padding:0;max-width:none}h2{break-after:avoid}tr,pre{break-inside:avoid}}
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
        f"<style>{base_css()}\n{_STYLE.strip()}</style>",
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
