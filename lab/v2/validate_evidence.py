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
    defanged_paths = {
        line.split("\t", 1)[0]
        for line in (evidence / "defanged.tsv").read_text(encoding="utf-8").splitlines()[1:]
        if line
    }
    expected_stub_mismatches = [
        failure
        for failure in manifest.failures
        if failure.reason == "content_hash_mismatch"
        and failure.excerpt.split(" manifest=", 1)[0] in defanged_paths
    ]
    manifest_failures = len(manifest.failures) - len(expected_stub_mismatches)
    error_log = evidence / "error.log"
    error_failures = 0
    if error_log.is_file():
        errors = ErrorLogFileSource([error_log], utc_offset="+0000").load_logs()
        error_failures = len(errors.error_failures)
    print(
        f"{evidence}: access events={len(logs.events)} parse_failures={len(logs.failures)}; "
        f"manifest files={len(manifest.files)} parse_failures={manifest_failures}; "
        f"defanged_hash_mismatches={len(expected_stub_mismatches)} (expected); "
        f"error parse_failures={error_failures}"
    )
    return len(logs.failures), manifest_failures, error_failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, nargs="+")
    args = parser.parse_args()
    results = [validate(path) for path in args.evidence]
    if any(any(failure_counts) for failure_counts in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
