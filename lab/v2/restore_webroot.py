"""Rebuild a complete scenario webroot from pinned public inputs and inert install overlays."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
from pathlib import Path

try:
    from .collect import read_manifest
    from .portable import public_files
except ImportError:
    from collect import read_manifest
    from portable import public_files

ROOT = Path(__file__).resolve().parents[2]


def digest(path: str | Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def is_inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def io_path(path: Path) -> str | Path:
    """Use Win32 extended paths so POSIX artifact names ending in dots survive."""
    if os.name != "nt":
        return path
    value = str(path)
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value.lstrip("\\")
    return "\\\\?\\" + value


def restore(scenario: str, destination: Path) -> int:
    scenario_dir = ROOT / "benchmark" / "v2" / scenario
    metadata = scenario_dir / "replay" / "restore.json"
    if not metadata.is_file():
        raise FileNotFoundError(f"missing pinned image metadata: {metadata}")
    import json

    config = json.loads(metadata.read_text(encoding="utf-8"))
    if config.get("version") != 2:
        raise ValueError("scenario has not yet been re-recorded with portable round-7 inputs")
    dest = destination.resolve()
    if is_inside(dest, ROOT.resolve()):
        raise ValueError("destination must be outside the repository")
    if dest.exists() and any(dest.iterdir()):
        raise ValueError("destination must be empty")
    dest.mkdir(parents=True, exist_ok=True)
    manifest = read_manifest(scenario_dir / "evidence" / "manifest.tsv")
    catalog = public_files(config["app_type"])
    snapshot_path_map = config.get("snapshot_path_map", {})
    allowed_stub = {}
    with (scenario_dir / "evidence" / "defanged.tsv").open(encoding="utf-8") as table:
        next(table, None)
        for line in table:
            fields = line.rstrip("\n").split("\t")
            allowed_stub[fields[0]] = fields[1:3]
    checked = 0
    for rel, row in manifest.items():
        target = dest / Path(rel)
        if row.kind != "f" or not is_inside(target.resolve(), dest):
            raise ValueError(f"unsupported or unsafe manifest path: {rel}")
        content = None
        for folder in ("evidence/webroot", "replay/restore-overlay"):
            source = scenario_dir / folder / snapshot_path_map.get(rel, rel)
            if not is_inside(source.resolve(), scenario_dir.resolve()) or source.is_symlink():
                raise ValueError(f"unsafe restore overlay path: {rel}")
            if os.path.isfile(io_path(source)):
                with open(io_path(source), "rb") as stream:
                    content = stream.read()
                break
        if content is None:
            content = catalog.get(row.sha256)
        if content is None:
            raise ValueError(f"manifest file missing from public inputs and overlay: {rel}")
        if hashlib.sha256(content).hexdigest() != row.sha256:
            expected = f"DEFANGED {row.sha256} {row.fields[2]}\n".encode("ascii")
            if allowed_stub.get(rel) != [row.sha256, row.fields[2]] or content != expected:
                raise ValueError(f"manifest hash mismatch or invalid defanged stub: {rel}")
        os.makedirs(io_path(target.parent), exist_ok=True)
        with open(io_path(target), "wb") as output:
            output.write(content)
        if digest(io_path(target)) != hashlib.sha256(content).hexdigest():
            raise ValueError(f"written file verification failed: {rel}")
        checked += 1
    # Recheck the completed tree: Windows case folding or name normalization must
    # not let a later file silently overwrite an earlier verified manifest entry.
    for rel, row in manifest.items():
        target = dest / Path(rel)
        if digest(io_path(target)) != row.sha256:
            with open(io_path(target), "rb") as source:
                content = source.read()
            if allowed_stub.get(rel) != [row.sha256, row.fields[2]] or content != (
                f"DEFANGED {row.sha256} {row.fields[2]}\n".encode("ascii")
            ):
                raise ValueError(f"completed restore tree hash mismatch for {rel}")
    restored_paths = {
        p.relative_to(dest).as_posix()
        for p in dest.rglob("*")
        if os.path.isfile(io_path(p))
    }
    missing = set(manifest) - restored_paths
    if missing:
        raise ValueError(f"completed restore tree missing exact names: {sorted(missing)[:5]}")
    extras = restored_paths - set(manifest)
    if extras:
        raise ValueError(f"restored image has files outside manifest: {sorted(extras)[:5]}")
    return checked


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.scenario not in {f"s{i:02}" for i in range(1, 13)}:
        parser.error("unknown scenario")
    try:
        count = restore(args.scenario, args.destination)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(f"restored {count} manifest entries to {args.destination.resolve()}")


if __name__ == "__main__":
    main()
