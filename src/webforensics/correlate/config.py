"""Tunable thresholds for correlation. Defaults are documented in docs/plan.md §4."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationConfig:
    # Requests up to this many seconds before a file's anchor time can have created it.
    creation_window_s: int = 120
    # Allowed clock/log-resolution slack after the anchor (nginx logs at request end).
    clock_skew_s: int = 5
    # How far back from the creating request we look for the actor's entry point.
    lookback_s: int = 24 * 3600
    # mtime older than ctime by more than this is treated as possible timestomping.
    timestomp_min_s: int = 60
    # Log silence is a gap when longer than max(silence_min_s, silence_factor * the median
    # spacing of the `silence_neighbors` intervals on each side), so quiet nights are normal.
    silence_min_s: int = 600
    silence_factor: float = 30.0
    silence_neighbors: int = 25
    # At most this many invocation requests per file go into the timeline.
    max_invocations: int = 20
    # Reverse proxies (IPs or CIDRs) whose X-Forwarded-For header is believed.
    trusted_proxies: tuple[str, ...] = ()
    # Files written within this many seconds of each other form one batch (a deploy).
    lonely_cluster_gap_s: int = 5
    # A code file in a batch this small, without a baseline, is a "lonely write".
    lonely_cluster_max: int = 2
    # A file POSTed to by at most this many clients, and hit at most `rare_hits_max`
    # times in total, is a rarely-hit POST target.
    rare_post_max_clients: int = 2
    rare_hits_max: int = 20
