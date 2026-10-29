"""Copy folders out of a disk image (E01 or raw) without mounting it, with the original
NTFS timestamps and a SHA-256 for every file.

    python -I scripts/extract_e01.py IMAGE --list
    python -I scripts/extract_e01.py IMAGE OUT_DIR xampp/apache/logs xampp/htdocs ...

Writes OUT_DIR/files/<folder>/... and OUT_DIR/ntfs-listing.csv (path, type, size,
allocated, created, modified, mft_changed, accessed, inode, sha256; times are NTFS
$STANDARD_INFORMATION in UTC). Turn the listing into a webforensics manifest with
scripts/ntfs_listing_to_manifest.py.

Needs `pip install pytsk3 libewf-python` (not project dependencies: used only to prepare
evidence from images). The image is only read. Extracted files may be live malware: keep
them out of the repository and never execute them.
"""

import contextlib
import csv
import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytsk3

try:
    import pyewf
except ImportError:  # raw images do not need it
    pyewf = None


class _EwfImage(pytsk3.Img_Info):
    def __init__(self, handle) -> None:
        self._handle = handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self) -> None:
        self._handle.close()

    def read(self, offset: int, size: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self) -> int:
        return self._handle.get_media_size()


def open_image(path: str) -> pytsk3.Img_Info:
    if path.lower().endswith((".e01", ".ex01")):
        if pyewf is None:
            sys.exit("E01 images need: pip install libewf-python")
        handle = pyewf.handle()
        handle.open(pyewf.glob(str(Path(path).resolve())))  # pyewf wants native separators
        return _EwfImage(handle)
    return pytsk3.Img_Info(path)


def volumes(image: pytsk3.Img_Info) -> list[tuple[int, str]]:
    try:
        table = pytsk3.Volume_Info(image)
    except OSError:
        return [(0, "whole image")]
    block = table.info.block_size
    return [(p.start * block, p.desc.decode(errors="replace")) for p in table
            if p.len > 2048 and b"Unallocated" not in p.desc and b"Primary Table" not in p.desc]


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat() if ts else ""


def _copy(entry, size: int, target: Path) -> str:
    digest = hashlib.sha256()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as out:
        offset = 0
        while offset < size:
            chunk = entry.read_random(offset, min(1 << 20, size - offset))
            if not chunk:
                break
            out.write(chunk)
            digest.update(chunk)
            offset += len(chunk)
    return digest.hexdigest()


def walk(directory, rel: str, out: Path, rows: list[dict]) -> None:
    for entry in directory:
        name = entry.info.name.name.decode(errors="replace")
        meta = entry.info.meta
        if name in (".", "..") or meta is None:
            continue
        path = f"{rel}/{name}"
        is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
        row = {"path": path, "type": "dir" if is_dir else "file", "size": meta.size,
               "allocated": bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC),
               "created": _iso(meta.crtime), "modified": _iso(meta.mtime),
               "mft_changed": _iso(meta.ctime), "accessed": _iso(meta.atime),
               "inode": meta.addr, "sha256": ""}
        rows.append(row)
        if is_dir:
            with contextlib.suppress(OSError):  # unreadable directory: keep going
                walk(entry.as_directory(), path, out, rows)
            continue
        try:
            row["sha256"] = _copy(entry, meta.size, out / path.lstrip("/"))
        except OSError as exc:
            row["sha256"] = f"ERROR {exc}"


def _has(image, offset: int, folder: str) -> bool:
    try:
        pytsk3.FS_Info(image, offset=offset).open_dir("/" + folder)
        return True
    except OSError:
        return False


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    image = open_image(sys.argv[1])
    if sys.argv[2] == "--list":
        for offset, desc in volumes(image):
            try:
                top = [e.info.name.name.decode(errors="replace")
                       for e in pytsk3.FS_Info(image, offset=offset).open_dir("/")]
                print(offset, desc, top)
            except OSError as exc:
                print(offset, desc, "not a filesystem:", exc)
        return 0
    out, folders = Path(sys.argv[2]), sys.argv[3:]
    offset = next((o for o, _ in volumes(image) if _has(image, o, folders[0])), None)
    if offset is None:
        sys.exit(f"no volume has /{folders[0]}")
    fs = pytsk3.FS_Info(image, offset=offset)
    rows: list[dict] = []
    for folder in folders:
        try:
            walk(fs.open_dir("/" + folder), "/" + folder, out / "files", rows)
        except OSError as exc:
            print("missing:", folder, exc)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "ntfs-listing.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(len(rows), "entries,", sum(r["type"] == "file" for r in rows), "files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
