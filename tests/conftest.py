from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def manifest_row(
    path: str,
    *,
    type_code: str = "f",
    size: int = 10,
    mode: str = "644",
    uid: int = 33,
    inode: int = 100,
    atime: str = "1793068800",
    mtime: str = "1793068800",
    ctime: str = "1793068800",
    btime: str = "0",
    sha256: str = "a" * 64,
) -> str:
    cells = [path.encode().hex(), type_code, str(size), mode, str(uid), str(inode),
             atime, mtime, ctime, btime, sha256]
    return "\t".join(cells)


MANIFEST_HEADER = "#webforensics-manifest v1\n#collected_at=1793072400\n"
