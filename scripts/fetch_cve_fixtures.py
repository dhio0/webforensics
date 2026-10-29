"""Fetch the CVE fixtures whose license does not allow storing them in this repository.

    python scripts/fetch_cve_fixtures.py

Reads tests/fixtures/php_sqli/cve/cases.json and, for every case not stored in the repo,
writes before.php (parent of the fix commit) and after.php (the fix) into the ignored
tests/fixtures/php_sqli/cve/.cache/<id>/. Uses `git fetch` of single commits (no GitHub API
token needed). This is the only network use, and only when you run this script; the code is
parsed by the tests, never executed.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

CVE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "php_sqli" / "cve"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True).stdout


def fetch(case: dict, work: Path) -> None:
    target = CVE / ".cache" / case["id"]
    if (target / "after.php").is_file():
        return
    repo = work / case["repo"].replace("/", "__")
    if not repo.exists():
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        git(repo, "remote", "add", "origin", f"https://github.com/{case['repo']}.git")
    git(repo, "fetch", "-q", "--depth=2", "--filter=blob:none", "origin", case["commit"])
    target.mkdir(parents=True, exist_ok=True)
    (target / "before.php").write_bytes(git(repo, "show", f"{case['commit']}^:{case['path']}"))
    (target / "after.php").write_bytes(git(repo, "show", f"{case['commit']}:{case['path']}"))


def main() -> int:
    cases = [c for c in json.loads((CVE / "cases.json").read_text(encoding="utf-8"))
             if not c["stored"]]
    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            try:
                fetch(case, Path(tmp))
                print(f"ok      {case['id']}  {case['repo']}  ({case['license']})")
            except subprocess.CalledProcessError as exc:
                print(f"failed  {case['id']}  {exc.stderr.decode(errors='replace')[:120]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
