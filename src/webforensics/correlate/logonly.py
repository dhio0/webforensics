"""Script files seen only in the logs: used by an attacker, gone from the webroot (D85).

The rest of the engine starts from files on disk, so a webshell the attacker deleted
before the evidence was collected leaves no seed. Its requests stay in the access log,
and two patterns there are clear enough to report it:

- requests with a command parameter (`?cmd=dir`) to a script URL that answer 2xx with
  at least two different response sizes, although no file in the evidence serves that
  URL (a site that answers 200 for any URL returns the same page to a bot's probes, while
  a real shell's output changes with the command);
- a SQL injection with `INTO OUTFILE '<path>'`, followed by a successful request from the
  same client to a URL ending in that file name (the file was written and served).

What wrote a file is the `INTO OUTFILE` request when there is one, else the closest
write-capable request from the same client just before the first use (e.g. a POST to a
stager script). A later command that deletes the file by name is reported as cleanup.
Nothing here is hashed or read, so these files are listed separately from the affected
files and every conclusion about them comes from log lines alone.
"""

import posixpath
import re
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import unquote_plus

from webforensics.correlate import requests as rq
from webforensics.detect.file_rules import has_executable_extension
from webforensics.models import LogEvent

CMD_RULE = "LOG-WEBSHELL-CMD-PARAM"
_OUTFILE = re.compile(r"\binto\s+(?:out|dump)file\s+(['\"])(?P<target>[^'\"]+)\1", re.I)
_DELETE = re.compile(r"(?:^|[\s;&|=])(?:del|erase|rm|unlink|remove-item)\b", re.I)
# How long after an INTO OUTFILE request the written file is looked for.
OUTFILE_FOLLOW = timedelta(minutes=10)


@dataclass
class LogOnlyFile:
    url: str
    actor: str
    uses: list[LogEvent]  # successful requests to the URL by the actor, in log order
    written_by: LogEvent | None = None
    outfile: bool = False  # written_by is a SQL `INTO OUTFILE` request
    deleted_by: LogEvent | None = None
    commands: list[LogEvent] = field(default_factory=list)


def _decoded_query(event: LogEvent) -> str:
    return unquote_plus(event.query or "")


def _name(path: str) -> str:
    return posixpath.basename(path.replace("\\", "/"))


def find_log_only_files(index, served: set[str]) -> list[LogOnlyFile]:
    """`index` is the engine's request index; `served` holds the lookup keys of every URL
    a file in the evidence serves."""
    fold = index.fold
    found: dict[tuple[str, str], LogOnlyFile] = {}

    def record(event: LogEvent) -> LogOnlyFile | None:
        path = event.path or ""
        key = index.url_key(path)
        if (key in served or not has_executable_extension(path)
                or not rq.is_success(event)):
            return None
        actor = index.actor(event)
        shell = found.setdefault((actor, key), LogOnlyFile(url=path, actor=actor, uses=[]))
        if event not in shell.uses:
            shell.uses.append(event)
        return shell

    for event in index.events:  # 1. used with a command parameter
        if (any(f.rule_id == CMD_RULE for f in index.of(event))
                and (shell := record(event)) is not None):
            shell.commands.append(event)

    for event in index.events:  # 2. written by INTO OUTFILE and then served
        if "file" not in (event.query or "").lower():
            continue  # cheap filter: decoding every query of a large log is slow
        match = _OUTFILE.search(_decoded_query(event))
        if match is None:
            continue
        name = fold(_name(match["target"]))
        actor = index.actor(event)
        later = index.actor_since(actor, event.ts)
        follow = next((e for e in later if e.ts - event.ts <= OUTFILE_FOLLOW
                       and e.evidence_id != event.evidence_id
                       and fold(_name(e.path or "")) == name and rq.is_success(e)), None)
        if follow is None or (shell := record(follow)) is None:
            continue
        if shell.written_by is None or not shell.outfile:
            shell.written_by, shell.outfile = event, True

    shells = sorted((s for s in found.values()
                     if s.outfile or len({e.bytes_sent for e in s.commands}) >= 2),
                    key=lambda s: (s.uses[0].ts, s.uses[0].line_no))
    for shell in shells:
        everything = index.by_url.get(index.url_key(shell.url), [])
        shell.uses = sorted({*shell.uses, *(e for e in everything if index.actor(e) == shell.actor
                                            and rq.is_success(e))},
                            key=lambda e: (e.ts, e.log_file, e.line_no))
        if shell.written_by is None:
            shell.written_by = _writer(index, shell)
        shell.deleted_by = _deleter(index, shell)
    return shells


def _writer(index, shell: LogOnlyFile) -> LogEvent | None:
    """The closest write-capable request from the same actor before the first use."""
    first = shell.uses[0]
    start = first.ts - timedelta(seconds=index.config.creation_window_s)
    candidates = [e for e in index.actor_since(shell.actor, start)
                  if (e.ts, e.line_no) <= (first.ts, first.line_no) and e is not first
                  and index.url_key(e.path or "") != index.url_key(shell.url)
                  and rq.is_success(e) and rq.write_level(e, index.of(e)) > rq.WriteLevel.NONE]
    return max(candidates, key=lambda e: (e.ts, e.line_no), default=None)


def _deleter(index, shell: LogOnlyFile) -> LogEvent | None:
    """A command parameter that deletes the file by name, after its first use."""
    name = index.fold(_name(shell.url))
    for event in index.actor_since(shell.actor, shell.uses[0].ts):
        if not any(f.rule_id == CMD_RULE for f in index.of(event)):
            continue
        command = _decoded_query(event)
        if _DELETE.search(command) and name in index.fold(command.replace("\\", "/")):
            return event
    return None
