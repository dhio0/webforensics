"""Build the v2 replay corpus from the MIT Zenodo logs and NASA client identities.

Organization X supplies the request methods, targets, response shapes, and real
User-Agent strings. NASA supplies only distinct source client identities because
Organization X's published log anonymizes almost every client to one address.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from .background import SAFE_METHODS, parse_line
except ImportError:  # direct execution in the attacker image or as a script
    from background import SAFE_METHODS, parse_line

LOG_ENTRY = re.compile(r"/web-access\.log(?:\.\d+)?(?:\.gz)?$")
TIMESTAMP = re.compile(r"^\S+ \S+ \S+ \[([^]]+)\]")
UA_CAP = 0.199
SCANNER_UA = re.compile(
    r"bot|crawler|spider|scanner|sqlmap|nikto|nmap|gobuster|dirb|uptime|hetrix", re.I
)


def _date(raw: str) -> datetime:
    match = TIMESTAMP.match(raw)
    if not match:
        raise ValueError("Zenodo Apache log line is missing its timestamp")
    return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")


def zenodo_rows(archive: Path) -> list[tuple[datetime, str, dict[str, str]]]:
    rows: list[tuple[datetime, str, dict[str, str]]] = []
    with zipfile.ZipFile(archive) as bundle:
        names = sorted(name for name in bundle.namelist() if LOG_ENTRY.search(name))
        if not names:
            raise ValueError("Zenodo archive contains no Organization X access logs")
        for name in names:
            raw = bundle.read(name)
            if name.endswith(".gz"):
                raw = gzip.decompress(raw)
            for line in raw.decode("utf-8", "replace").splitlines():
                row = parse_line(line, "")
                if row is None or row["method"] not in SAFE_METHODS or not row["ua"]:
                    continue
                rows.append((_date(line), line, row))
    rows.sort(key=lambda item: item[0])
    if not rows:
        raise ValueError("Zenodo archive contains no usable Apache access rows")
    return rows


def _evenly_spaced(items: list, count: int) -> list:
    if len(items) < count:
        raise ValueError(f"need {count} usable rows; found {len(items)}")
    return [items[(index * len(items)) // count] for index in range(count)]


def select_zenodo_rows(
    rows: list[tuple[datetime, str, dict[str, str]]], limit: int
) -> list[tuple[datetime, str, dict[str, str]]]:
    """Preserve source order while ensuring no UA exceeds 19.9% of the replay."""
    cap = max(1, math.floor(limit * UA_CAP))
    counts: Counter[str] = Counter()
    capped = []
    for entry in rows:
        ua = entry[2]["ua"]
        if counts[ua] >= cap:
            continue
        counts[ua] += 1
        capped.append(entry)
    return _evenly_spaced(capped, limit)


def nasa_client_ids(path: Path, count: int) -> list[str]:
    """Sample NASA source identities evenly in original trace order."""
    total = 0
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as source:
        for line in source:
            if parse_line(line, "") is not None:
                total += 1
    if total < count:
        raise ValueError(f"need {count} NASA client identities; found {total}")
    targets = {(index * total) // count for index in range(count)}
    selected: list[str] = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as source:
        position = 0
        for line in source:
            row = parse_line(line, "")
            if row is None:
                continue
            if position in targets:
                selected.append(row["ip"])
            position += 1
    if len(selected) != count:
        raise RuntimeError("NASA identity sampling did not produce the requested count")
    return selected


def prepare(archive: Path, nasa: Path, output: Path, report: Path, limit: int) -> dict:
    source_rows = zenodo_rows(archive)
    selected = select_zenodo_rows(source_rows, limit)
    clients = nasa_client_ids(nasa, limit)
    user_agents = Counter(entry[2]["ua"] for entry in selected)
    status_counts = Counter(entry[2]["status"] for entry in selected)
    methods = Counter(entry[2]["method"] for entry in selected)
    scanners = sum(
        int(row["status"] == "404") or bool(SCANNER_UA.search(row["ua"]))
        for _stamp, _line, row in selected
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(output, "wt", encoding="utf-8", compresslevel=9, newline="\n") as target:
        for (_stamp, line, _row), client in zip(selected, clients, strict=True):
            target.write(re.sub(r"^\S+", client, line, count=1) + "\n")
    data = {
        "source_dataset": "Zenodo record 20001206, Organization X, MIT",
        "request_source": archive.name,
        "client_identity_source": nasa.name,
        "client_identity_rule": (
            "NASA source addresses sampled evenly in original order and paired with "
            "Organization X request rows in chronological order; Organization X "
            "anonymizes nearly all client addresses to one value"
        ),
        "source_rows": len(source_rows),
        "selected_rows": limit,
        "distinct_user_agents": len(user_agents),
        "maximum_user_agent_share": max(user_agents.values()) / limit,
        "distinct_client_identities": len(set(clients)),
        "maximum_client_share": max(Counter(clients).values()) / limit,
        "scanner_rows_by_user_agent_or_source_404": scanners,
        "source_status_mix": dict(sorted(status_counts.items())),
        "source_method_mix": dict(sorted(methods.items())),
    }
    if data["maximum_user_agent_share"] > 0.20:
        raise ValueError("selected source has a User-Agent over the 20% limit")
    if data["distinct_client_identities"] <= 300:
        raise ValueError("selected source has 300 or fewer distinct client identities")
    if data["maximum_client_share"] > 0.05:
        raise ValueError("selected client identity exceeds the 5% limit")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zenodo-zip", type=Path, required=True)
    parser.add_argument("--nasa-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=15_000)
    args = parser.parse_args()
    result = prepare(args.zenodo_zip, args.nasa_log, args.output, args.report, args.limit)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
