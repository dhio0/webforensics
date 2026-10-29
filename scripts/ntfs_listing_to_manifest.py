"""Turn the listing from scripts/extract_e01.py into a webforensics manifest for one webroot.

    python -I scripts/ntfs_listing_to_manifest.py LISTING.csv WEBROOT_IN_IMAGE OUT.tsv \\
        --hostname NAME --utc-offset -0700

WEBROOT_IN_IMAGE is the webroot's path inside the image, e.g. /xampp/htdocs (in Git Bash
on Windows, set MSYS_NO_PATHCONV=1 so it is not rewritten into a Windows path).

NTFS mapping: mtime = modified, ctime = MFT entry changed, btime = created, atime =
accessed (all $STANDARD_INFORMATION, settable by programs). NTFS has no POSIX mode or
owner, so mode is written as 644 and uid as 0. The header says `#filesystem=ntfs`, which
makes the analysis match URLs case-insensitively and distrust birth times (D84).
"""

import argparse
import csv
import sys
from datetime import datetime


def epoch(text: str) -> str:
    return str(int(datetime.fromisoformat(text).timestamp())) if text else "-"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("listing")
    parser.add_argument("webroot")
    parser.add_argument("out")
    parser.add_argument("--hostname", default="unknown")
    parser.add_argument("--utc-offset", default="+0000", help="server offset, e.g. -0700")
    args = parser.parse_args()
    root = args.webroot.rstrip("/") + "/"
    with open(args.listing, encoding="utf-8") as handle:
        rows = [r for r in csv.DictReader(handle)
                if r["type"] == "file" and r["path"].startswith(root) and len(r["sha256"]) == 64]
    with open(args.out, "w", encoding="utf-8", newline="\n") as out:
        out.write("#webforensics-manifest v1\n#collector=extract_e01.py (pytsk3)\n")
        out.write(f"#hostname={args.hostname}\n#webroot={root}\n#utc_offset={args.utc_offset}\n")
        out.write("#birth_time_supported=1\n#filesystem=ntfs\n")
        out.write("#columns=path_hex,type,size,mode,uid,inode,atime,mtime,ctime,btime,sha256\n")
        for r in rows:
            rel = r["path"][len(root):]
            out.write("\t".join([rel.encode().hex(), "f", r["size"], "644", "0", r["inode"],
                                 epoch(r["accessed"]), epoch(r["modified"]),
                                 epoch(r["mft_changed"]), epoch(r["created"]), r["sha256"]])
                      + "\n")
    print(len(rows), "files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
