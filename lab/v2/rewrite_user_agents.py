"""Apply deterministic evidence-only User-Agent rewrites after collection."""

from __future__ import annotations

import argparse
import gzip
import re
import tempfile
from pathlib import Path

from label import access_index, join_log_rows, sidecar_rows

UA_FIELD = re.compile(r'"(?P<ua>(?:[^"\\]|\\.)*)"$')


def _read(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, "rt", encoding="utf-8", errors="strict") as source:
        return source.readlines()


def _write(path: Path, lines: list[str]) -> None:
    if path.suffix != ".gz":
        path.write_text("".join(lines), encoding="utf-8", newline="")
        return
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as raw:
        temporary = Path(raw.name)
    try:
        with (
            temporary.open("wb") as raw,
            gzip.GzipFile(filename="", fileobj=raw, mode="wb", compresslevel=9, mtime=0) as packed,
        ):
            packed.writelines(line.encode("utf-8") for line in lines)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def rewrite(scenario: Path, mapping_path: Path, drop: set[str]) -> tuple[int, int]:
    mapping: dict[str, str] = {}
    for line_no, line in enumerate(mapping_path.read_text(encoding="utf-8").splitlines(), 1):
        if line_no == 1 or not line:
            continue
        old, new = line.split("\t", 1)
        mapping[old] = new

    evidence = scenario / "evidence"
    replay = scenario / "replay"
    access_path = evidence / "access.log.gz"
    labels_path = replay / "labels.log.gz"
    access_lines = _read(access_path)
    access_rows = access_index(access_path)
    label_rows = join_log_rows(sidecar_rows(labels_path), access_rows)
    removed_access: set[int] = set()
    rewritten = 0
    output_access: list[str] = []
    for row, line in zip(access_rows, access_lines, strict=True):
        match = UA_FIELD.search(line.rstrip("\r\n"))
        if not match:
            raise ValueError(f"{access_path}:{row['line_no']}: missing User-Agent field")
        old = match.group("ua")
        if old in drop:
            removed_access.add(row["line_no"])
            continue
        new = mapping.get(old, old)
        if new != old:
            line = line[: match.start("ua")] + new + line[match.end("ua") :]
            rewritten += 1
        output_access.append(line)

    output_labels = [
        line
        for row, line in zip(label_rows, _read(labels_path), strict=True)
        if row["access_line_no"] not in removed_access
    ]
    if removed_access:
        _write(labels_path, output_labels)
    if rewritten or removed_access:
        _write(access_path, output_access)

    # Verify the label join against the rewritten access log.
    join_log_rows(sidecar_rows(labels_path), access_index(access_path))
    return rewritten, len(removed_access)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path)
    parser.add_argument("--map", type=Path)
    parser.add_argument("--drop", action="append", default=[])
    args = parser.parse_args()
    mapping_path = args.map or args.scenario / "replay" / "ua_map.tsv"
    rewritten, removed = rewrite(args.scenario, mapping_path, set(args.drop))
    print(f"rewritten_user_agents={rewritten} removed_requests={removed} label_join=PASS")


if __name__ == "__main__":
    main()
