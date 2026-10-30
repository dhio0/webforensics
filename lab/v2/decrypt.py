"""Authenticate and safely extract one encrypted full-evidence webroot."""

from __future__ import annotations

import argparse
import io
import os
import tarfile
from pathlib import Path, PurePosixPath

try:
    from .crypto import decrypt_bytes, key_from_hex
except ImportError:  # direct execution from the lab/v2 directory
    from crypto import decrypt_bytes, key_from_hex

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_FULL_DIR = Path(r"C:\Users\Pongo\Documents\cases\benchmark-v2-full")


def load_local_env(env_path: Path) -> None:
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip())


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def safe_extract(archive_bytes: bytes, destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=False)
    written = 0
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
        for member in archive.getmembers():
            pure = PurePosixPath(member.name)
            parts = tuple(part for part in pure.parts if part not in {"", "."})
            if pure.is_absolute() or any(part == ".." for part in parts):
                raise ValueError(f"unsafe tar member path: {member.name!r}")
            if not parts:
                if member.isdir():
                    continue
                raise ValueError(f"unsafe empty tar member path: {member.name!r}")
            target = destination.joinpath(*parts)
            if not is_within(target, root):
                raise ValueError(f"tar member escapes output directory: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(f"links and special files are refused: {member.name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read tar member: {member.name!r}")
            with stream, target.open("xb") as output:
                while chunk := stream.read(1024 * 1024):
                    output.write(chunk)
            written += 1
    return written


def decrypt_archive(
    encrypted_path: Path,
    destination: Path,
    full_evidence_dir: Path,
    key: bytes,
    repository: Path = REPOSITORY,
) -> int:
    full_root = full_evidence_dir.resolve()
    if not is_within(encrypted_path, full_root):
        raise ValueError("encrypted archive must be inside FULL_EVIDENCE_DIR")
    output = destination.resolve()
    if output == repository.resolve() or is_within(output, repository.resolve()):
        raise ValueError("refusing to extract inside the repository")
    if not is_within(output, full_root):
        raise ValueError("decrypted output must be a folder under FULL_EVIDENCE_DIR")
    plaintext = decrypt_bytes(encrypted_path.read_bytes(), key)
    return safe_extract(plaintext, output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", help="scenario id, for example s01")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--env-file", type=Path, default=Path(__file__).resolve().parent / ".env"
    )
    args = parser.parse_args()
    load_local_env(args.env_file)
    full_dir = Path(os.environ.get("FULL_EVIDENCE_DIR", str(DEFAULT_FULL_DIR))).expanduser()
    encrypted = full_dir / args.scenario / "full-evidence.tar.gz.enc"
    destination = args.output or full_dir / args.scenario / "decrypted"
    try:
        key = key_from_hex(os.environ.get("BENCHMARK_V2_ENCRYPTION_KEY", ""))
        count = decrypt_archive(encrypted, destination, full_dir, key)
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.error(str(exc))
    print(f"authenticated and extracted {count} files to {destination}")


if __name__ == "__main__":
    main()
