"""Load a v2 evidence folder with the existing FileAdapter and report parse failures."""

from __future__ import annotations

import argparse
from pathlib import Path

from webforensics.adapters.file_adapter import (
    ErrorLogFileSource,
    LogFileSource,
    ManifestFileSource,
)


def validate(evidence: Path) -> tuple[int, int, int]:
    logs = LogFileSource([evidence / "access.log"]).load_logs()
    manifest = ManifestFileSource(
        evidence / "manifest.tsv", evidence / "webroot"
    ).load_files()
    error_log = evidence / "error.log"
    error_failures = 0
    if error_log.is_file():
        errors = ErrorLogFileSource([error_log], utc_offset="+0000").load_logs()
        error_failures = len(errors.error_failures)
    print(
        f"{evidence}: access events={len(logs.events)} parse_failures={len(logs.failures)}; "
        f"manifest files={len(manifest.files)} parse_failures={len(manifest.failures)}; "
        f"error parse_failures={error_failures}"
    )
    return len(logs.failures), len(manifest.failures), error_failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, nargs="+")
    args = parser.parse_args()
    results = [validate(path) for path in args.evidence]
    if any(any(failure_counts) for failure_counts in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
