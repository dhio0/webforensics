"""Live scheduling shared by the background replay and scripted human actions."""

from __future__ import annotations

import json
import random
import time
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path


def scaled_schedule(timestamps: list[float], rate: float = 3.5) -> list[float]:
    """Scale source gaps, then delay bursts to at most 20 in any rolling second."""
    if not 2 <= rate <= 5 or len(timestamps) < 2:
        raise ValueError("need two source timestamps and a rate between 2 and 5")
    gaps = [b - a for a, b in pairwise(timestamps)]
    if min(gaps) < 0 or sum(gaps) <= 0:
        raise ValueError("source timestamps must be ordered and span positive time")
    scale = (len(timestamps) / rate) / sum(gaps)
    result = [0.0]
    for index, gap in enumerate(gaps, 1):
        when = result[-1] + gap * scale
        if index >= 20:
            when = max(when, result[index - 20] + 1.01)
        result.append(when)
    return result


class LiveClock:
    """Reject suspended or severely stalled runs instead of catching up in a burst."""

    def __init__(self) -> None:
        self.origin = time.monotonic()
        self.last_wall = time.time()
        self.last_tick = self.origin

    def wait_until(self, offset: float) -> None:
        while True:
            tick, wall = time.monotonic(), time.time()
            if wall - self.last_wall > 15 or abs(
                (wall - self.last_wall) - (tick - self.last_tick)
            ) > 5:
                raise RuntimeError("recording interrupted or machine suspended; discard run")
            self.last_tick, self.last_wall = tick, wall
            remaining = self.origin + offset - tick
            if remaining <= 0:
                return
            time.sleep(min(remaining, 0.5))


class HandPacer:
    """Space script-level requests and agent commands; subprocess tools stay native."""

    def __init__(self, seed: int, output: Path = Path("/replay/hand-pacing.json")) -> None:
        self.random = random.Random(seed)
        self.output = output
        self.clock = LiveClock()
        self.last: float | None = None
        self.events: list[dict] = []

    def before(self, action: str, *, minimum_span: bool = False) -> None:
        # A completed native tool run can legitimately take minutes. The concurrent
        # background clock detects machine suspension throughout that interval.
        self.clock.last_tick, self.clock.last_wall = time.monotonic(), time.time()
        now = time.monotonic() - self.clock.origin
        deadline = now if self.last is None else self.last + self.random.uniform(45, 60)
        if minimum_span and self.events:
            deadline = max(deadline, self.events[0]["offset_seconds"] + 185)
        self.clock.wait_until(deadline)
        self.last = time.monotonic() - self.clock.origin
        self.events.append({
            "action": action,
            "offset_seconds": self.last,
            "started_at_utc": datetime.now(UTC).isoformat(),
        })
        self.output.write_text(json.dumps(self.events, indent=2) + "\n", encoding="utf-8")


def install_hand_pacing(seed: int, *, scanner: bool = False) -> HandPacer:
    """Install only in an attack process, after setup and its seeded start signal."""
    import subprocess

    import requests

    pacer = HandPacer(seed)
    original_request = requests.Session.request
    original_run = subprocess.run

    def request(session, method, url, **kwargs):
        if not scanner:
            step = (kwargs.get("headers") or {}).get("X-Lab-Step", "form_navigation")
            pacer.before(step)
        elif not pacer.events:
            pacer.before("scanner_sweep (native burst)")
        return original_request(session, method, url, **kwargs)

    def run(args, *positional, **kwargs):
        values = [str(value) for value in args] if not isinstance(args, str) else [args]
        if values[0] == "weevely" and values[1] != "generate":
            pacer.before("agent_command", minimum_span=True)
        else:
            tool = next((name for name in ("sqlmap", "commix", "hydra")
                         if any(name in value for value in values[:2])), None)
            if tool:
                pacer.before(f"{tool} (native burst)", minimum_span=scanner)
        return original_run(args, *positional, **kwargs)

    requests.Session.request = request
    subprocess.run = run
    return pacer
