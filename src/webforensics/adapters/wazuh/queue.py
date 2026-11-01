"""Send events to Wazuh analysisd's queue socket, the way Wazuh's own integrations do.

Checked in `integrations/virustotal.py` at v4.14.9 (docs/wazuh-notes.md section 11):
- a Unix datagram socket at `<ossec dir>/queue/sockets/queue`;
- the message `1:<location>:<json>`; the location is the integration name for the
  manager, or `[<id>] (<name>) <ip>-><integration>` for an agent, with `|` doubled and
  `:` escaped as `|:`.

Standard library only, and Python 3.10 compatible, so it also runs under the Python that
ships with the Wazuh manager.
"""

import json
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INTEGRATION = "webforensics"
DEFAULT_SOCKET = Path("/var/ossec/queue/sockets/queue")
# analysisd reads at most OS_MAXSTR (65536) bytes per message; stay well below it.
MAX_MESSAGE_BYTES = 60000


class WritebackError(RuntimeError):
    """The events could not be sent (no socket, message too large, ...)."""


@dataclass(frozen=True)
class Agent:
    """Where the events are filed in Wazuh: the agent of the compromised web server."""

    id: str
    name: str
    ip: str = "any"


def _escape(location: str) -> str:
    return location.replace("|", "||").replace(":", "|:")


def message(event: dict[str, Any], agent: Agent | None = None) -> str:
    """The queue message for one event."""
    body = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if agent is None or agent.id == "000":
        text = f"1:{INTEGRATION}:{body}"
    else:
        location = _escape(f"[{agent.id}] ({agent.name}) {agent.ip}")
        text = f"1:{location}->{INTEGRATION}:{body}"
    size = len(text.encode("utf-8"))
    if size > MAX_MESSAGE_BYTES:
        raise WritebackError(f"event too large for the Wazuh queue ({size} bytes)")
    return text


def send(messages: list[str], socket_path: Path = DEFAULT_SOCKET) -> int:
    """Send each message as one datagram; returns how many were sent."""
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        raise WritebackError("the Wazuh queue is a Unix socket; run this on the Wazuh manager")
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect(str(socket_path))
            for text in messages:
                sock.send(text.encode("utf-8"))
    except OSError as exc:
        raise WritebackError(f"cannot send to {socket_path}: {exc}") from exc
    return len(messages)
