"""Find SQL injection in PHP source: request input that reaches a query string (M7).

Deterministic taint tracking over a tree-sitter syntax tree, one scope at a time (the file's
top level, and each function, method or closure on its own):

- Sources: request superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, a
  few `$_SERVER` keys) and functions that return request data.
- Taint flows through assignment, array access, concatenation, interpolation, `.=`, ternaries
  and string helpers (`trim`, `sprintf`, ...). The result of any other function is clean:
  calls are not followed into other functions or files (a stated limitation).
- Clean again after an int/float cast, `intval`-style functions, a hash, or an early-exit
  guard such as `if (!is_numeric($id)) exit;`.
- Escaping (`mysqli_real_escape_string`, `addslashes`, ...) protects a value only inside
  quotes in the query; escaped but unquoted, as in `id = $id`, it is still injectable.
- Sinks: `mysqli_query`, `mysql_query`, `pg_query`, `->query()`, `->exec()`, `->prepare()`
  and friends. A prepared statement built by concatenation is as vulnerable as `query()`.
  Applications often wrap the driver (`dbFetchRow($sql)`, `sqlDAL::readSql($sql)`), so a
  tainted string that is plainly an SQL statement (starts with SELECT, INSERT, UPDATE, ...)
  is a finding when it is passed to any function or method.

The reported line is where the input enters the query string (the line the fix changes);
the line that runs the query is reported next to it.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from functools import cache

import tree_sitter_php
from tree_sitter import Language, Node, Parser

from webforensics.models import Confidence

MAX_SOURCE_BYTES = 2 * 1024 * 1024

_SUPERGLOBALS = {"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES"}
_SERVER_KEYS = re.compile(r"^(HTTP_\w+|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO)$")
_SOURCE_FUNCTIONS = {"getallheaders", "apache_request_headers", "filter_input",
                     "filter_input_array"}
_INT_FILTERS = {"FILTER_VALIDATE_INT", "FILTER_VALIDATE_FLOAT", "FILTER_SANITIZE_NUMBER_INT",
                "FILTER_SANITIZE_NUMBER_FLOAT", "FILTER_VALIDATE_BOOLEAN", "FILTER_VALIDATE_BOOL"}
_CLEANING = {"intval", "floatval", "doubleval", "boolval", "abs", "round", "floor", "ceil",
             "count", "strlen", "md5", "sha1", "crc32", "hash", "password_hash", "is_numeric",
             "ctype_digit", "ctype_alnum", "in_array", "array_key_exists", "isset", "empty",
             "pg_escape_literal", "pg_escape_identifier"}
_ESCAPING = {"mysqli_real_escape_string", "mysql_real_escape_string", "mysql_escape_string",
             "addslashes", "pg_escape_string", "sqlite_escape_string", "esc_sql",
             "real_escape_string", "escape_string"}
_PASSTHROUGH = {"trim", "ltrim", "rtrim", "strtolower", "strtoupper", "ucfirst", "ucwords",
                "str_replace", "str_ireplace", "preg_replace", "substr", "mb_substr",
                "urldecode", "rawurldecode", "base64_decode", "stripslashes", "htmlspecialchars",
                "htmlentities", "strip_tags", "nl2br", "implode", "join", "str_pad", "strrev",
                "json_encode", "sprintf", "vsprintf", "strval", "html_entity_decode",
                "filter_var", "array_values", "reset", "end", "current"}
_FORMATTING = {"sprintf", "vsprintf"}
_GUARDS = {"is_numeric", "ctype_digit", "is_int", "filter_var", "in_array"}
# Sink function -> index of the query argument (-1: last).
_SINK_FUNCTIONS = {"mysqli_query": 1, "mysqli_real_query": 1, "mysqli_multi_query": 1,
                   "mysqli_prepare": 1, "mysql_query": 0, "mysql_unbuffered_query": 0,
                   "mysql_db_query": 1, "pg_query": -1, "pg_send_query": -1, "pg_prepare": -1,
                   "sqlite_query": 0, "odbc_exec": 1, "db_query": 0}
_SINK_METHODS = {"query", "exec", "prepare", "multi_query", "real_query", "unbuffered_query",
                 "get_results", "get_row", "get_var", "get_col", "querySingle", "rawQuery"}
_SQL_STATEMENT = re.compile(
    r"^\s*\(?\s*(SELECT\b|INSERT\s+INTO\b|UPDATE\s+\S+\s+SET\b|DELETE\s+FROM\b|REPLACE\s+INTO\b"
    r"|WITH\s+\w+\s+AS\b)", re.IGNORECASE)
_CALLS = ("function_call_expression", "member_call_expression", "scoped_call_expression",
          "nullsafe_member_call_expression")
_INT_CASTS = {"int", "integer", "float", "double", "bool", "boolean"}
_LOOPS = {"while_statement", "do_statement", "for_statement", "foreach_statement"}
_BRANCHING = {"if_statement", "switch_statement", "try_statement", *_LOOPS}
# Calls that take a string without running it as SQL (hashing, logging, caching, string and
# array helpers), so an SQL statement passed to them is not a finding.
_NOT_EXECUTING = re.compile(
    r"(log|debug|trace|dump|print|echo|hash|md5|sha1|crc|cache|key|json|serialize|encode"
    r"|decode|escape|quote|lang|translate|^str|^preg_|^array_|^mb_|^is_|^in_array$"
    r"|^explode$|^implode$|^count$|^sprintf$|^printf$|^trigger_error$)", re.IGNORECASE)
_SCOPES = {"function_definition", "method_declaration", "anonymous_function",
           "arrow_function", "anonymous_function_creation_expression"}
_STRINGS = {"encapsed_string", "string", "heredoc", "nowdoc", "heredoc_body", "nowdoc_body"}
_EXITS = {"exit_statement", "return_statement", "throw_expression", "break_statement"}


@cache
def _parser() -> Parser:
    return Parser(Language(tree_sitter_php.language_php()))


@dataclass(frozen=True)
class Taint:
    sources: frozenset[str]
    escaped: bool = False  # every path to here went through an escaping function
    inject_line: int | None = None  # where the input first entered a string literal
    unquoted_escape: bool = False  # escaped, but placed outside quotes in a query string

    def union(self, other: "Taint | None") -> "Taint":
        if other is None:
            return self
        return Taint(self.sources | other.sources, self.escaped and other.escaped,
                     self.inject_line or other.inject_line,
                     self.unquoted_escape or other.unquoted_escape)

    @property
    def dangerous(self) -> bool:
        return not self.escaped or self.unquoted_escape


def _union(a: Taint | None, b: Taint | None) -> Taint | None:
    return b if a is None else a.union(b)


@dataclass(frozen=True)
class SqlInjection:
    line: int  # where request input enters the query string
    sink_line: int  # where the query runs
    sink: str  # e.g. "mysqli_query", "$pdo->query"
    sources: tuple[str, ...]
    escaped: bool  # escaped but unquoted (lower confidence)
    snippet: str
    suggested_fix: str | None
    confidence: Confidence


@dataclass
class _Scope:
    taint: dict[str, Taint] = field(default_factory=dict)
    defs: dict[str, list[Node]] = field(default_factory=dict)  # assignments to each variable
    loop: tuple[str, str] | None = None  # (array, key) of the enclosing `foreach`
    rewritten: set[str] = field(default_factory=set)  # arrays rewritten element by element

    def copy(self) -> "_Scope":
        return _Scope(dict(self.taint), {k: list(v) for k, v in self.defs.items()},
                      self.loop, set(self.rewritten))

    def merge(self, states: list["_Scope"]) -> None:
        """After exclusive paths: tainted if any path left it tainted. For rebuilding the
        query text, keep the longest chain of assignments seen on any path."""
        taint: dict[str, Taint] = {}
        for state in states:
            for name, value in state.taint.items():
                taint[name] = value.union(taint.get(name)) if name in taint else value
        defs: dict[str, list[Node]] = {}
        for state in states:
            for name, chain in state.defs.items():
                if len(chain) > len(defs.get(name, [])):
                    defs[name] = chain
        self.taint, self.defs = taint, defs


class _Analyzer:
    def __init__(self, source: bytes) -> None:
        self.src = source
        self.tree = _parser().parse(source)
        self.lines = source.decode("utf-8", "replace").splitlines()
        self.findings: dict[tuple[int, int], SqlInjection] = {}
        self.api = _api_hint(source)

    # --- helpers ---------------------------------------------------------------------

    def text(self, node: Node | None) -> str:
        return "" if node is None else self.src[node.start_byte:node.end_byte].decode(
            "utf-8", "replace")

    @staticmethod
    def line(node: Node) -> int:
        return node.start_point[0] + 1

    def var_name(self, node: Node | None) -> str | None:
        """`$x` for a variable, the base variable for `$x['a']['b']` or `$x->y`."""
        while node is not None and node.type in ("subscript_expression",
                                                 "member_access_expression"):
            node = node.named_children[0] if node.named_children else None
        if node is not None and node.type == "variable_name":
            return self.text(node)
        return None

    def call_name(self, node: Node) -> str:
        if node.type == "function_call_expression":
            return self.text(node.child_by_field_name("function")).lstrip("\\").lower()
        return self.text(node.child_by_field_name("name"))

    def arguments(self, node: Node) -> list[Node]:
        args = node.child_by_field_name("arguments")
        if args is None:
            return []
        return [a.named_children[0] if a.type == "argument" and a.named_children else a
                for a in args.named_children]

    # --- taint of expressions ----------------------------------------------------------

    def source_label(self, node: Node) -> str | None:
        if node.type == "subscript_expression":
            base = node.named_children[0] if node.named_children else None
            if base is not None and base.type == "variable_name":
                name = self.text(base)[1:]
                if name in _SUPERGLOBALS:
                    return self.text(node)
                if name == "_SERVER":
                    key = self.text(node.named_children[1]).strip("'\"") if len(
                        node.named_children) > 1 else ""
                    return self.text(node) if _SERVER_KEYS.match(key) else None
            return None
        if node.type == "variable_name" and self.text(node)[1:] in _SUPERGLOBALS:
            return self.text(node)
        return None

    def taint(self, node: Node | None, scope: _Scope) -> Taint | None:
        if node is None:
            return None
        label = self.source_label(node)
        if label is not None:
            return Taint(frozenset({label}))
        kind = node.type
        if kind == "variable_name":
            return scope.taint.get(self.text(node))
        if kind in ("subscript_expression", "member_access_expression"):
            base = self.var_name(node)
            return scope.taint.get(base) if base else None
        if kind in ("parenthesized_expression", "argument"):
            return self.taint(node.named_children[0] if node.named_children else None, scope)
        if kind == "cast_expression":
            cast = self.text(node.child_by_field_name("type")).lower()
            return None if cast in _INT_CASTS else self.taint(
                node.child_by_field_name("value"), scope)
        if kind == "conditional_expression":
            # `$a ?: $b` has no body: the condition itself is the value.
            body = node.child_by_field_name("body") or node.child_by_field_name("condition")
            alternative = node.child_by_field_name("alternative")
            return _union(self.taint(body, scope), self.taint(alternative, scope))
        if kind == "binary_expression":
            operator = self.text(node.child_by_field_name("operator"))
            if operator == ".":
                return self.string_taint(node, scope)
            if operator == "??":  # `$_GET['id'] ?? '0'` is the input when it is set
                return _union(self.taint(node.child_by_field_name("left"), scope),
                              self.taint(node.child_by_field_name("right"), scope))
            return None  # arithmetic, comparison and logic give numbers or booleans
        if kind in ("encapsed_string", "heredoc"):
            return self.string_taint(node, scope)
        if kind == "function_call_expression":
            return self.call_taint(node, scope)
        if kind in ("array_creation_expression", "array_element_initializer"):
            result: Taint | None = None
            for child in node.named_children:
                result = _union(result, self.taint(child, scope))
            return result
        if kind == "member_call_expression":
            name = self.call_name(node)
            if name in ("real_escape_string", "escape_string"):
                inner = self.taint(next(iter(self.arguments(node)), None), scope)
                return replace(inner, escaped=True) if inner else None
            return None  # `quote()` adds quotes; other methods are not followed
        return None

    def call_taint(self, node: Node, scope: _Scope) -> Taint | None:
        name = self.call_name(node)
        args = self.arguments(node)
        if name in _SOURCE_FUNCTIONS:
            if name.startswith("filter_input") and any(
                    self.text(a) in _INT_FILTERS for a in args):
                return None
            return Taint(frozenset({self.text(node)}))
        if name == "filter_var" and any(self.text(a) in _INT_FILTERS for a in args):
            return None
        if name in _CLEANING:
            return None
        if name in _ESCAPING:
            target = args[-1] if name.startswith(("mysqli_", "pg_")) and len(args) > 1 else (
                args[0] if args else None)
            inner = self.taint(target, scope)
            return replace(inner, escaped=True) if inner else None
        if name in _FORMATTING:
            return self.format_taint(node, args, scope)
        if name in _PASSTHROUGH:
            result: Taint | None = None
            for arg in args:
                result = _union(result, self.taint(arg, scope))
            return result
        return None  # user and library functions are not followed (stated limitation)

    def format_taint(self, node: Node, args: list[Node], scope: _Scope) -> Taint | None:
        """sprintf("... '%s' ...", $x): placeholders behave like interpolation."""
        result = None
        fmt = self.literal(args[0]) if args else None
        for arg in args[1:]:
            t = self.taint(arg, scope)
            if t is None:
                continue
            quoted = fmt is not None and bool(re.search(r"(['\"])%[sd]\1", fmt))
            t = replace(t, inject_line=t.inject_line or self.line(arg),
                        unquoted_escape=t.unquoted_escape or (t.escaped and not quoted))
            result = _union(result, t)
        return result

    def literal(self, node: Node) -> str | None:
        if node.type not in _STRINGS:
            return None
        if any(c.type not in ("string_content", "string_value", "escape_sequence", '"', "'",
                              "heredoc_start", "heredoc_end", "<<<", "heredoc_body",
                              "nowdoc_body", "nowdoc_string")
               for c in node.children):
            return None
        return "".join(self.text(c) for c in node.children
                       if c.type in ("string_content", "string_value", "escape_sequence",
                                     "nowdoc_string"))

    def parts(self, node: Node) -> Iterator[tuple[str, Node]]:
        """Flatten concatenation and interpolation into ("text"|"expr", node) parts."""
        if node.type == "binary_expression" and self.text(
                node.child_by_field_name("operator")) == ".":
            yield from self.parts(node.child_by_field_name("left"))
            yield from self.parts(node.child_by_field_name("right"))
            return
        if node.type == "parenthesized_expression" and node.named_children:
            yield from self.parts(node.named_children[0])
            return
        if node.type in ("encapsed_string", "heredoc", "heredoc_body"):
            for child in node.named_children:
                if child.type == "heredoc_body":
                    yield from self.parts(child)
                elif child.type in ("string_content", "string_value", "escape_sequence"):
                    yield "text", child
                elif child.type not in ("heredoc_start", "heredoc_end"):
                    yield "expr", child
            return
        if node.type in ("string", "nowdoc"):
            yield "text", node
            return
        yield "expr", node

    def part_text(self, kind: str, node: Node) -> str:
        if kind != "text":
            return ""
        if node.type in ("string", "nowdoc"):
            return self.literal(node) or ""
        return self.text(node)

    def string_taint(self, node: Node, scope: _Scope) -> Taint | None:
        parts = list(self.parts(node))
        texts = [self.part_text(k, n) for k, n in parts]
        result = None
        for i, (kind, part) in enumerate(parts):
            if kind != "expr":
                continue
            t = self.taint(part, scope)
            if t is None:
                continue
            before = next((texts[j] for j in range(i - 1, -1, -1) if parts[j][0] == "text"), "")
            after = next((texts[j] for j in range(i + 1, len(parts)) if parts[j][0] == "text"),
                         "")
            quoted = bool(before) and bool(after) and before[-1] in "'\"" and (
                after[0] == before[-1])
            in_string = any(k == "text" for k, _ in parts)
            t = replace(t, inject_line=t.inject_line or (self.line(part) if in_string else None),
                        unquoted_escape=t.unquoted_escape or (t.escaped and not quoted))
            result = _union(result, t)
        return result

    # --- statements --------------------------------------------------------------------

    def run(self) -> list[SqlInjection]:
        root = self.tree.root_node
        self.walk_scope(root)
        return [self.findings[k] for k in sorted(self.findings)]

    def walk_scope(self, root: Node) -> None:
        scope = _Scope()
        for child in root.children:
            self.walk(child, scope)

    def walk(self, node: Node, scope: _Scope) -> None:
        if node.type in _SCOPES:
            self.walk_scope(node.child_by_field_name("body") or node)
            return
        if node.type == "if_statement" and self.guard(node, scope):
            return
        if node.type in _BRANCHING:
            self.branches(node, scope)
            return
        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            self.walk(node.child_by_field_name("right"), scope)
            self.assign(node, scope)
            return
        for child in node.children:
            self.walk(child, scope)
        if node.type in _CALLS:
            self.check_sink(node, scope)

    def branches(self, node: Node, scope: _Scope) -> None:
        """Paths that exclude each other start from the same state and merge afterwards,
        so a value set in one `case` never leaks into a sibling `case`."""
        kind = node.type
        if kind in _LOOPS:
            self.loop(node, scope)
            return
        heads: list[Node] = []
        paths: list[Node] = []
        exhaustive = False
        if kind == "if_statement":
            heads = [node.child_by_field_name("condition")]
            paths = [node.child_by_field_name("body"), *(
                c for c in node.children if c.type in ("else_if_clause", "else_clause"))]
            exhaustive = any(c.type == "else_clause" for c in node.children)
        elif kind == "switch_statement":
            heads = [node.child_by_field_name("condition")]
            block = node.child_by_field_name("body")
            paths = [c for c in (block.named_children if block else [])
                     if c.type in ("case_statement", "default_statement")]
            exhaustive = any(c.type == "default_statement" for c in paths)
        elif kind == "try_statement":
            paths = [node.child_by_field_name("body"),
                     *(c for c in node.children if c.type == "catch_clause")]
            heads = [c for c in node.children if c.type == "finally_clause"]
        for head in heads:
            if head is not None and head.type != "finally_clause":
                self.walk(head, scope)
        states = []
        for path in paths:
            if path is not None:
                state = scope.copy()
                self.walk(path, state)
                states.append(state)
        if not exhaustive:
            states.append(scope.copy())
        scope.merge(states)
        for head in heads:
            if head is not None and head.type == "finally_clause":
                self.walk(head, scope)

    def loop(self, node: Node, scope: _Scope) -> None:
        """The body may run zero or more times: merge it with the state before the loop.
        An array whose every element the body rewrote takes the body's value instead."""
        state = scope.copy()
        state.rewritten = set()
        if node.type == "foreach_statement":
            self.foreach(node, state)
        else:
            for child in node.children:
                self.walk(child, state)
        rewritten = state.rewritten
        scope.merge([scope.copy(), state])
        for name in rewritten:
            if name in state.taint:
                scope.taint[name] = state.taint[name]
            else:
                scope.taint.pop(name, None)

    def assign(self, node: Node, scope: _Scope) -> None:
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        name = self.var_name(left)
        if name is None:
            return
        value = self.taint(right, scope)
        whole = left is not None and left.type == "variable_name"
        if not whole and self.elementwise(left, scope):
            whole = True  # `$a[$k] = clean($v)` inside `foreach ($a as $k => $v)`
            scope.rewritten.add(name)
        if node.type == "augmented_assignment_expression":
            if value is not None and self.text(node.child_by_field_name("operator")) == ".=":
                value = replace(value, inject_line=value.inject_line or self.line(right))
            value = _union(scope.taint.get(name), value)
            scope.defs.setdefault(name, []).append(right)
            whole = False
        elif whole:
            scope.defs[name] = [right]
        if value is not None:
            scope.taint[name] = value if whole else _union(scope.taint.get(name), value)
        elif whole:
            scope.taint.pop(name, None)  # overwritten with a clean value

    def elementwise(self, left: Node | None, scope: _Scope) -> bool:
        if left is None or left.type != "subscript_expression" or not scope.loop:
            return False
        named = left.named_children
        if len(named) != 2 or named[0].type != "variable_name":
            return False
        array, key = scope.loop
        return self.text(named[0]) == array and self.text(named[1]) == key

    def foreach(self, node: Node, scope: _Scope) -> None:
        """Bind the loop variables, then walk the body in this (copied) state. A body that
        rewrites every element (`$a[$k] = f($v)`) replaces the array's taint after the
        loop instead of merging with it."""
        named = node.named_children
        if not named:
            return
        self.walk(named[0], scope)
        source = self.taint(named[0], scope)
        key_var = None
        for child in named[1:]:
            if child.type == "compound_statement" or child.type == "colon_block":
                break
            if child.type == "pair" and child.named_children:
                key_var = self.text(child.named_children[0])
            for var in self.variables(child):
                if source is not None:
                    scope.taint[var] = source
                else:
                    scope.taint.pop(var, None)
        array = self.text(named[0]) if named[0].type == "variable_name" else None
        outer_loop = scope.loop
        scope.loop = (array, key_var) if array and key_var else None
        body = node.child_by_field_name("body")
        if body is not None:
            self.walk(body, scope)
        scope.loop = outer_loop

    def variables(self, node: Node) -> Iterator[str]:
        if node.type == "variable_name":
            yield self.text(node)
        elif node.type in ("pair", "by_ref"):
            for child in node.named_children:
                yield from self.variables(child)

    def guard(self, node: Node, scope: _Scope) -> bool:
        """`if (!is_numeric($x)) { exit; }`: $x is clean after it. True if handled."""
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if condition is None or body is None or node.child_by_field_name("alternative"):
            return False
        expr = condition.named_children[0] if condition.named_children else None
        if expr is None or expr.type != "unary_op_expression" or not self.text(expr).startswith(
                "!"):
            return False
        call = expr.named_children[0] if expr.named_children else None
        if call is None or call.type != "function_call_expression" or self.call_name(
                call) not in _GUARDS:
            return False
        args = self.arguments(call)
        if self.call_name(call) == "filter_var" and not any(
                self.text(a) in _INT_FILTERS for a in args):
            return False
        if not self.exits(body) or not args:
            return False
        name = self.var_name(args[0])
        if name is not None and args[0].type == "variable_name":
            scope.taint.pop(name, None)
            return True
        return False

    def exits(self, node: Node) -> bool:
        if node.type in _EXITS or (node.type == "function_call_expression" and self.call_name(
                node) in ("die", "exit")):
            return True
        return any(self.exits(child) for child in node.named_children)

    # --- sinks -------------------------------------------------------------------------

    def sink_query(self, node: Node) -> tuple[str, Node | None]:
        args = self.arguments(node)
        if node.type == "function_call_expression":
            name = self.call_name(node)
            if name not in _SINK_FUNCTIONS or not args:
                return "", None
            index = _SINK_FUNCTIONS[name]
            if index >= len(args):
                index = -1
            return name, args[index]
        name = self.call_name(node)
        if name not in _SINK_METHODS or not args:
            return "", None
        return f"{self.text(node.child_by_field_name('object'))}->{name}", args[0]

    def statement_text(self, node: Node, scope: _Scope, depth: int = 0) -> str:
        """Leading literal text of a query string, following this scope's assignments."""
        if depth > 5:
            return ""
        if node.type == "variable_name":
            defs = scope.defs.get(self.text(node), [])
            return self.statement_text(defs[0], scope, depth + 1) if defs else ""
        for kind, part in self.parts(node):
            if kind == "text":
                return self.part_text(kind, part)
            if part.type in _STRINGS or part.type == "variable_name":
                text = self.statement_text(part, scope, depth + 1)
                if text:
                    return text
            return ""
        return ""

    def generic_sink(self, node: Node, scope: _Scope) -> tuple[str, Node | None]:
        """Any call that receives a tainted SQL statement (an application's DB wrapper)."""
        if _NOT_EXECUTING.search(self.call_name(node) if node.type != "scoped_call_expression"
                                 else self.text(node.child_by_field_name("name"))):
            return "", None
        for arg in self.arguments(node):
            t = self.taint(arg, scope)
            if t is not None and t.dangerous and _SQL_STATEMENT.match(
                    self.statement_text(arg, scope)):
                callee = (node.child_by_field_name("function") or node.child_by_field_name(
                    "name"))
                scope_text = node.child_by_field_name("scope") or node.child_by_field_name(
                    "object")
                joiner = "::" if node.type.startswith("scoped") else "->"
                prefix = f"{self.text(scope_text)}{joiner}" if scope_text else ""
                return prefix + self.text(callee), arg
        return "", None

    def check_sink(self, node: Node, scope: _Scope) -> None:
        sink, query = (self.sink_query(node) if node.type in (
            "function_call_expression", "member_call_expression") else ("", None))
        if query is None:
            sink, query = self.generic_sink(node, scope)
        if query is None:
            return
        t = self.taint(query, scope)
        if t is None or not t.dangerous:
            return
        line = t.inject_line or self.line(query)
        key = (line, self.line(node))
        if key in self.findings:
            return
        self.findings[key] = SqlInjection(
            line=line, sink_line=self.line(node), sink=sink,
            sources=tuple(sorted(t.sources)), escaped=t.escaped,
            snippet=self.lines[line - 1].strip() if line <= len(self.lines) else "",
            suggested_fix=self.fix(node, sink, query, scope),
            confidence=Confidence.MEDIUM if t.escaped else Confidence.HIGH,
        )

    # --- suggested fix -------------------------------------------------------------------

    def render(self, node: Node, scope: _Scope, depth: int = 0) -> tuple[str, list[str]] | None:
        """The query text with each tainted value replaced by `?`, and those values in
        order. A variable built in this scope (`=`, then `.=`) is expanded from its
        assignments. None when the query cannot be rebuilt as one string."""
        if depth > 5:
            return None
        defs = scope.defs.get(self.text(node), []) if node.type == "variable_name" else []
        if defs and any(self.has_text(d) for d in defs):
            pieces = [self.render(d, scope, depth + 1) for d in defs]
            if any(p is None for p in pieces):
                return None
            return ("".join(p[0] for p in pieces if p),
                    [v for p in pieces if p for v in p[1]])
        sql, params = "", []
        for kind, part in self.parts(node):
            if kind == "text":
                sql += self.part_text(kind, part)
            elif self.taint(part, scope) is not None:
                sql += "?"
                params.append(self.text(part))
            elif part.type in _STRINGS or (part.type == "variable_name"
                                           and scope.defs.get(self.text(part))):
                inner = self.render(part, scope, depth + 1)
                if inner is None:
                    return None
                sql, params = sql + inner[0], params + inner[1]
            elif part.type in ("variable_name", "subscript_expression"):
                sql += "{" + self.text(part) + "}"  # a clean dynamic part stays as it is
            else:
                return None
        return sql, params

    def has_text(self, node: Node) -> bool:
        return any(kind == "text" for kind, _ in self.parts(node))

    def fix(self, node: Node, sink: str, query: Node, scope: _Scope) -> str | None:
        built = self.render(query, scope)
        if built is None or not built[1] or built[0].strip() == "?":
            return None
        sql, params = re.sub(r"(['\"])\?\1", "?", built[0]), built[1]
        sql = sql.replace("\\", "\\\\").replace('"', '\\"')
        values = ", ".join(params)
        types = "s" * len(params)
        name = sink.rsplit("->", 1)[-1]
        if node.type == "function_call_expression":
            conn = self.text(self.arguments(node)[0]) if len(self.arguments(node)) > 1 else "$db"
            if name.startswith("pg_"):
                numbered = sql
                for i in range(1, len(params) + 1):
                    numbered = numbered.replace("?", f"${i}", 1)
                return f'pg_query_params({conn}, "{numbered}", [{values}]);'
            return (f'$stmt = mysqli_prepare({conn}, "{sql}");\n'
                    f'mysqli_stmt_bind_param($stmt, "{types}", {values});\n'
                    "mysqli_stmt_execute($stmt);")
        obj = sink.rsplit("->", 1)[0]
        if name in ("get_results", "get_row", "get_var", "get_col"):
            placeholders = sql.replace("?", "%s")
            return f'{obj}->{name}({obj}->prepare("{placeholders}", {values}));'
        if self.api == "mysqli":
            return (f'$stmt = {obj}->prepare("{sql}");\n'
                    f'$stmt->bind_param("{types}", {values});\n'
                    "$stmt->execute();")
        return f'$stmt = {obj}->prepare("{sql}");\n$stmt->execute([{values}]);'


def _api_hint(source: bytes) -> str:
    text = source.decode("utf-8", "replace").lower()
    if "new pdo" in text or "pdo::" in text:
        return "pdo"
    if "new mysqli" in text or "mysqli_connect" in text:
        return "mysqli"
    return "pdo"


def find_sql_injections(source: bytes) -> list[SqlInjection]:
    """All request-input-to-query flows in one PHP file, ordered by line."""
    if len(source) > MAX_SOURCE_BYTES:
        source = source[:MAX_SOURCE_BYTES]
    return _Analyzer(source).run()
