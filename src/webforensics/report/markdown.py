"""Serialize a `Document` to Markdown (CommonMark + GFM tables).

All text goes through `_md`, which backslash-escapes every character with meaning in
Markdown or inline HTML. Attacker strings (paths, user agents, raw log lines) therefore
show up literally: they cannot open a link, an HTML tag, or break a table cell.
"""

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

_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&$])")
# Only meaningful at the start of a line (heading, list item, quote, ordered list).
_LINE_START = re.compile(r"^([#+>=-])")
_ORDERED = re.compile(r"^(\d+)([.)])")  # escape the dot: "1\." (a digit can't be escaped)


def _md(text: str, *, line_start: bool = False) -> str:
    """Escape inline markup; `line_start` also escapes block markers (for text that
    begins a line or a list item)."""
    text = _SPECIAL.sub(r"\\\1", text)
    if line_start:
        text = _ORDERED.sub(r"\1\\\2", _LINE_START.sub(r"\\\1", text))
    return text


def _cell(cell: Cell) -> str:
    text = _md(cell.text)
    return f"**{text}**" if cell.mark == "root" else text


def _fence(lines: tuple[str, ...]) -> list[str]:
    """Fenced block whose fence is longer than any backtick run inside (CommonMark)."""
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence, *lines, fence]


def _block(block: Block) -> list[str]:
    if isinstance(block, Para):
        return [_md(block.text, line_start=True)]
    if isinstance(block, Heading):
        return [f"### {_md(block.text)}"]
    if isinstance(block, Bullets):
        return [f"- {_md(item, line_start=True)}" for item in block.items]
    if isinstance(block, Fields):
        return [f"- **{_md(key)}:** {_md(value)}" for key, value in block.pairs]
    if isinstance(block, Code):
        return _fence(block.lines)
    if isinstance(block, Table):
        lines = ["| " + " | ".join(_md(h) for h in block.headers) + " |",
                 "|" + "---|" * len(block.headers)]
        lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in block.rows]
        return lines
    raise TypeError(f"unknown block {block!r}")


def render_markdown(doc: Document) -> str:
    out = [f"# {_md(doc.title)}", "", f"_{_md(doc.subtitle)}_", ""]
    for section in doc.sections:
        out += [f"## {_md(section.title)}", ""]
        for block in section.blocks:
            out += [*_block(block), ""]
    return "\n".join(out).rstrip("\n") + "\n"
