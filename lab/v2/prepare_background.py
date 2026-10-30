"""Classify source requests and deterministically remap visitors to a crawled app."""

from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import Counter
from pathlib import Path

from background import parse_line

SCANNER_UA = re.compile(r"bot|crawler|spider|scanner|sqlmap|nikto|nmap|gobuster|dirb", re.I)
FALLBACK_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"


def prepare(
    source: Path,
    urls_file: Path,
    output: Path,
    report: Path,
    classes_path: Path,
    limit: int = 15_000,
) -> dict:
    urls = [
        line.strip() for line in urls_file.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not urls:
        raise ValueError("crawl returned no application URLs")
    opener = gzip.open if source.suffix == ".gz" else Path.open
    parsed = []
    with opener(source, "rt", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            row = parse_line(line, FALLBACK_UA)
            if row:
                row["source_line"] = number
                parsed.append(row)
    if not parsed:
        raise ValueError("source log had no parseable requests")
    path_counts = Counter(row["target"].split("?", 1)[0] for row in parsed)
    rank_map = {
        source_path: urls[index % len(urls)]
        for index, (source_path, _count) in enumerate(
            sorted(path_counts.items(), key=lambda pair: (-pair[1], pair[0]))
        )
    }
    classified = []
    for row in parsed:
        scanner = bool(SCANNER_UA.search(row["ua"])) or row["status"] == "404"
        row["class"] = "scanner" if scanner else "visitor"
        if not scanner:
            row["target"] = rank_map[row["target"].split("?", 1)[0]]
        classified.append(row)
    expanded = [classified[index % len(classified)] for index in range(limit)]
    output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(output, "wt", encoding="utf-8", compresslevel=9, newline="\n") as handle:
        for row in expanded:
            handle.write(
                f"{row['ip']} - - [30/Oct/2026:12:00:00 +0000] "
                f'"{row["method"]} {row["target"]} HTTP/1.1" {row["status"]} 0 '
                f'"-" "{row["ua"] or FALLBACK_UA}"\n'
            )
    counts = Counter(row["class"] for row in expanded)
    source_classes = {row["ip"]: row["class"] for row in classified}
    classes_path.write_text(
        "source_identity\ttraffic_class\n"
        + "".join(f"{ip}\t{kind}\n" for ip, kind in sorted(source_classes.items())),
        encoding="utf-8",
    )
    data = {
        "source": source.name,
        "seed": 5031,
        "classification_rule": (
            "scanner UA patterns or any source-side 404; all other lines are visitors"
        ),
        "visitor_remap": (
            "source paths ranked by descending frequency then path, then mapped to the "
            "pre-attack app crawl URL list in that order"
        ),
        "app_urls": urls,
        "source_lines": len(parsed),
        "replay_lines": len(expanded),
        "counts": dict(counts),
        "visitors": {
            "requests": counts["visitor"],
            "source_404s": sum(r["status"] == "404" and r["class"] == "visitor" for r in expanded),
        },
        "scanners": {"requests": counts["scanner"], "retained_source_paths": True},
        "status_note": (
            "scanner source status codes are retained; visitor response mix comes from "
            "the access log after replay"
        ),
    }
    report.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--urls", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--classes", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=15_000)
    args = parser.parse_args()
    print(
        json.dumps(
            prepare(args.source, args.urls, args.output, args.report, args.classes, args.limit),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
