"""Run the project collector inside an app container and export only safe files.

The host must bind the evidence output directory to ``/capture`` and the local
full-evidence folder to ``/full-evidence``. Webroot content is defanged before it
is copied to ``/capture``; the original tar stays in the container until GCM
encryption completes.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

try:
    from .crypto import encrypt_file, key_from_hex
except ImportError:  # direct execution inside the collector container
    from crypto import encrypt_file, key_from_hex

EXECUTABLE_SUFFIXES = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".phar", ".cgi", ".pl",
    ".py", ".sh", ".bash", ".exe", ".dll", ".so", ".com", ".bat", ".cmd",
    ".htaccess", ".user.ini", ".inc", ".pht", ".phps",
}
ARCHIVE_SUFFIXES = {".zip", ".phar"}
PHP_OPENERS = (b"<?", b"<%")
PUBLIC_ARTIFACT_MAX_BYTES = 1_000_000
@dataclass(frozen=True)
class ManifestRow:
    path: str
    kind: str
    fields: tuple[str, ...]
    sha256: str


def read_manifest(path: Path) -> dict[str, ManifestRow]:
    rows = {}
    columns_seen = False
    with path.open(encoding="utf-8", errors="strict") as source:
        for line_number, line in enumerate(source, 1):
            line = line.rstrip("\n")
            if line.startswith("#columns="):
                columns_seen = line.split("=", 1)[1] == (
                    "path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256"
                )
                continue
            if not line or line.startswith("#"):
                continue
            fields = tuple(line.split("\t"))
            if len(fields) != 11:
                raise ValueError(f"{path}:{line_number}: expected 11 manifest fields")
            raw_path = bytes.fromhex(fields[0])
            rel_path = os.fsdecode(raw_path)
            if rel_path.startswith("/") or any(
                part in {"", ".", ".."} for part in rel_path.split("/")
            ):
                raise ValueError(f"{path}:{line_number}: unsafe webroot path")
            rows[rel_path] = ManifestRow(rel_path, fields[1], fields, fields[10])
    if not columns_seen:
        raise ValueError(f"{path}: not a collect.sh manifest v1")
    return rows


def changed_from_baseline(current: ManifestRow, baseline: ManifestRow | None) -> bool:
    if baseline is None:
        return True
    # atime is omitted because reading/hash collection can update it.
    return any(
        current.fields[index] != baseline.fields[index]
        for index in (1, 2, 3, 4, 5, 7, 8, 9, 10)
    )


def roles_from_records(records_path: Path | None) -> dict[str, str]:
    if records_path is None or not records_path.is_file():
        return {}
    data = json.loads(records_path.read_text(encoding="utf-8"))
    return {
        Path(item["path"].lstrip("/")).as_posix(): item.get("role", "unknown")
        for item in data.get("files", [])
    }


def should_defang(path: Path, content: bytes) -> bool:
    suffix = path.suffix.lower()
    special_names = {".htaccess", ".user.ini"}
    return (
        suffix in EXECUTABLE_SUFFIXES
        or path.name.lower() in special_names
        or suffix in ARCHIVE_SUFFIXES
        or any(opener in content for opener in PHP_OPENERS)
        or content.startswith(b"PK\x03\x04")
        or len(content) > PUBLIC_ARTIFACT_MAX_BYTES
    )


def escaped_tsv(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def defang_snapshot(
    webroot: Path,
    current: dict[str, ManifestRow],
    baseline: dict[str, ManifestRow],
    output: Path,
    roles: dict[str, str],
) -> list[str]:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    replaced: list[str] = []
    table = output.parent / "defanged.tsv"
    rows = []
    for rel_path, row in sorted(current.items()):
        source = webroot / rel_path
        destination = output / rel_path
        before = baseline.get(rel_path)
        changed = changed_from_baseline(row, before)
        if not changed:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        if row.kind == "l":
            # Do not export symlinks from the container. New/changed links are represented
            # by an inert stub; unchanged links are omitted from the content snapshot.
            if changed:
                reason = "new or changed symlink"
                destination.write_text(
                    f"DEFANGED {row.sha256} {row.fields[2]}\n", encoding="ascii"
                )
                replaced.append(rel_path)
                rows.append(
                    (rel_path, row.sha256, row.fields[2], roles.get(rel_path, "unknown"), reason)
                )
            continue
        content = source.read_bytes()
        if changed and should_defang(source, content):
            reason = (
                "changed file exceeds public snapshot size limit; full copy remains encrypted"
                if len(content) > PUBLIC_ARTIFACT_MAX_BYTES
                else "new or changed executable, script-tagged, zip, or phar file"
            )
            destination.write_text(
                f"DEFANGED {row.sha256} {row.fields[2]}\n", encoding="ascii", newline="\n"
            )
            replaced.append(rel_path)
            rows.append(
                (
                    rel_path,
                    row.sha256,
                    row.fields[2],
                    roles.get(rel_path, "new_or_modified_artifact"),
                    reason,
                )
            )
        else:
            shutil.copyfile(source, destination)
    with table.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("path\toriginal_sha256\toriginal_size\trole\treason\n")
        for values in rows:
            handle.write("\t".join(escaped_tsv(str(value)) for value in values) + "\n")
    scan_defanged_snapshot(output, current, baseline)
    return replaced


def trim_unchanged_snapshot(
    snapshot: Path,
    current: dict[str, ManifestRow],
    baseline: dict[str, ManifestRow],
) -> int:
    """Remove unchanged baseline files from an older full-tree snapshot."""
    removed = 0
    for path in snapshot.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(snapshot).as_posix()
        row = current.get(rel_path)
        if row is None or not changed_from_baseline(row, baseline.get(rel_path)):
            path.unlink()
            removed += 1
    for directory in sorted(
        (path for path in snapshot.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        with suppress(OSError):
            directory.rmdir()
    return removed


def scan_defanged_snapshot(
    snapshot: Path,
    current: dict[str, ManifestRow],
    baseline: dict[str, ManifestRow],
    snapshot_path_map: dict[str, str] | None = None,
) -> None:
    reverse_path_map = {stored: original for original, stored in (snapshot_path_map or {}).items()}
    for path in snapshot.rglob("*"):
        if not path.is_file():
            continue
        stored_path = path.relative_to(snapshot).as_posix()
        rel_path = reverse_path_map.get(stored_path, stored_path)
        row = current[rel_path]
        if changed_from_baseline(row, baseline.get(rel_path)) and any(
            marker in path.read_bytes() for marker in (b"<?php", b"<?=")
        ):
            raise RuntimeError(f"live PHP opener remains in changed snapshot file: {stored_path}")


def baseline_capture(captured: Path, output: Path) -> None:
    if not (captured / "manifest.tsv").is_file():
        raise FileNotFoundError(f"collect.sh output is missing from {captured}")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(captured / "manifest.tsv", output / "baseline.tsv")


def scenario_capture(
    webroot: Path,
    captured: Path,
    baseline_path: Path,
    output: Path,
    scenario: str,
    records_path: Path | None,
) -> None:
    key = key_from_hex(os.environ.get("BENCHMARK_V2_ENCRYPTION_KEY", ""))
    baseline = read_manifest(baseline_path)
    current_manifest = captured / "manifest.tsv"
    raw_tar = captured / "webroot.tar"
    if not current_manifest.is_file() or not raw_tar.is_file():
        raise FileNotFoundError(f"collect.sh output is incomplete in {captured}")
    current = read_manifest(current_manifest)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(current_manifest, output / "manifest.tsv")
    replaced = defang_snapshot(
        webroot, current, baseline, output / "webroot", roles_from_records(records_path)
    )
    tar_path = captured.parent / f"{scenario}-full-evidence.tar.gz"
    with raw_tar.open("rb") as source, gzip.open(tar_path, "wb", compresslevel=6) as compressed:
        shutil.copyfileobj(source, compressed)
    full_dir = Path(os.environ.get("FULL_EVIDENCE_DIR", "/full-evidence"))
    encrypt_file(tar_path, full_dir / scenario / "full-evidence.tar.gz.enc", key)
    tar_path.unlink()
    print(f"captured={len(current)} defanged={len(replaced)} scenario={scenario}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webroot", type=Path, required=True)
    parser.add_argument("--captured", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--baseline-manifest", type=Path)
    parser.add_argument("--records", type=Path)
    args = parser.parse_args()
    if args.baseline_manifest is None:
        baseline_capture(args.captured, args.output)
        return
    scenario_capture(
        args.webroot,
        args.captured,
        args.baseline_manifest,
        args.output,
        args.scenario,
        args.records,
    )


if __name__ == "__main__":
    main()
