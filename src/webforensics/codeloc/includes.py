"""Which webroot files an implicated PHP file includes (D84).

Real applications rarely keep the query in the file the URL names: `index.php` often
includes the code that does the work, sometimes through a path built at run time, e.g.
`require ROOT . "vulnerabilities/sqli/source/{$level}.php"`. The code is never run, so
each include becomes a pattern: string parts are kept, everything else (constants,
variables, calls) matches any text. Leading unknown parts match any folder, so the
pattern is matched against the end of webroot paths.

A fully literal path (`include 'db.php'`, `require '../lib/db.php'`) is resolved from the
including file's folder. Any other include is skipped when its pattern names no folder
(`include $page . '.php'` would match every PHP file) or matches more than `MAX_MATCHES`
files. Only the implicated file's own includes are followed (one level).
"""

import posixpath
import re
from collections.abc import Iterable

from tree_sitter import Node

from webforensics.codeloc.php_sqli import _parser

MAX_MATCHES = 10
_INCLUDES = {"include_expression", "include_once_expression", "require_expression",
             "require_once_expression"}
_WILD = None  # a part whose text is unknown before run time


def _parts(node: Node) -> list[str | None]:
    if node.type == "parenthesized_expression":
        inner = [c for c in node.named_children]
        return _parts(inner[0]) if len(inner) == 1 else [_WILD]
    if node.type == "binary_expression" and node.child_by_field_name("operator") is not None \
            and node.child_by_field_name("operator").type == ".":
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None:
            return [_WILD]
        return _parts(left) + _parts(right)
    if node.type in ("string", "encapsed_string"):
        out: list[str | None] = []
        for child in node.named_children:
            if child.type == "string_content":
                out.append((child.text or b"").decode("utf-8", "replace"))
            elif child.type == "escape_sequence":
                out.append(_WILD)
            else:
                out.append(_WILD)
        return out
    return [_WILD]


def _merge(parts: list[str | None]) -> list[str | None]:
    merged: list[str | None] = []
    for part in parts:
        if part == "":
            continue
        if part is _WILD and merged and merged[-1] is _WILD:
            continue
        if isinstance(part, str) and merged and isinstance(merged[-1], str):
            merged[-1] += part
        else:
            merged.append(part)
    return merged


def _pattern(merged: list[str | None]) -> str | None:
    literals = "".join(p for p in merged if isinstance(p, str))
    if "/" not in literals.strip("/") or "://" in literals:
        return None  # no folder to anchor on, or a remote include
    out = ["(?:.*/)?"]  # unknown leading parts (a root constant): any folder
    for i, part in enumerate(merged):
        if part is _WILD:
            if i > 0:
                out.append("[^/]*")
        else:
            text = part.lstrip("/") if i <= 1 else part
            out.append(re.escape(re.sub(r"^(?:\./)+", "", text) if i <= 1 else text))
    return "".join(out)


def _includes(source: bytes) -> list[list[str | None]]:
    tree = _parser().parse(source)
    found: list[list[str | None]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in _INCLUDES and node.named_children:
            parts = _merge(_parts(node.named_children[-1]))
            if parts and parts not in found:
                found.append(parts)
        stack.extend(reversed(node.children))
    return found


def include_patterns(source: bytes) -> list[str]:
    """Regex patterns (full match against a webroot-relative path) for the includes that
    are not plain literal paths."""
    patterns = []
    for parts in _includes(source):
        if not (len(parts) == 1 and isinstance(parts[0], str)):
            pattern = _pattern(parts)
            if pattern is not None and pattern not in patterns:
                patterns.append(pattern)
    return patterns


def resolve_includes(source: bytes, including: str, paths: Iterable[str],
                     case_insensitive: bool = False,
                     suffixes: tuple[str, ...] = (".php", ".inc")) -> list[str]:
    """Webroot paths that the file at `including` includes, sorted. Ambiguous includes
    are skipped."""
    candidates = sorted(p for p in paths if p.lower().endswith(suffixes) and p != including)
    fold = (lambda p: p.casefold()) if case_insensitive else (lambda p: p)
    by_key = {fold(p): p for p in candidates}
    flags = re.IGNORECASE if case_insensitive else 0
    resolved: set[str] = set()
    for parts in _includes(source):
        if len(parts) == 1 and isinstance(parts[0], str):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(including), parts[0]))
            if fold(target) in by_key:
                resolved.add(by_key[fold(target)])
            continue
        pattern = _pattern(parts)
        if pattern is None:
            continue
        regex = re.compile(pattern, flags)
        matches = [p for p in candidates if regex.fullmatch(p)]
        if len(matches) <= MAX_MATCHES:
            resolved.update(matches)
    return sorted(resolved)
