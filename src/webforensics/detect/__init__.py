"""Deterministic detection rules (no ML, no network)."""

RULESET_VERSION = "0.1.0"

# Directory names used by both path-based log and file heuristics.
UPLOAD_WRITABLE_DIRS = (
    "upload",
    "uploads",
    "files",
    "images",
    "media",
    "tmp",
    "cache",
    "attachments",
)
