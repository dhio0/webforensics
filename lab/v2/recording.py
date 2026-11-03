"""Host setup for detached round-7 recordings and portable restore metadata."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from .portable import public_files
except ImportError:
    from portable import public_files


def begin_run(replay: Path) -> None:
    import gzip

    try:
        from .background import parse_line
        from .pacing import scaled_schedule
    except ImportError:
        from background import parse_line
        from pacing import scaled_schedule

    with gzip.open(replay / "background.log.gz", "rt", encoding="utf-8") as stream:
        stamps = [datetime.strptime(parse_line(line, "")["timestamp"],
                                    "%d/%b/%Y:%H:%M:%S %z").timestamp() for line in stream]
    schedule = scaled_schedule(stamps)
    now = datetime.now(UTC)
    local_start = (now + timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S WIB")
    status = replay.parents[1] / "STATUS.md"
    with status.open("a", encoding="utf-8", newline="\n") as output:
        output.write(
            f"\n## Active round-7 run: {replay.parent.name}\n\n"
            f"- Started: {now.isoformat()} ({local_start}).\n"
            f"- Expected replay end: {(now + timedelta(seconds=schedule[-1])).isoformat()}.\n"
            "- Background and attack are detached in their isolated containers.\n"
            "- Windows sleep prevention requested. Any interruption invalidates the run.\n"
        )


def prepare_restore(replay: Path, app: str) -> None:
    if os.name == "nt":
        result = ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
        if not result:
            raise OSError("could not keep recording host awake")
    for name in ("attack.done", "attack-error.json", "hand-pacing.json", "analyst-review.json"):
        (replay / name).unlink(missing_ok=True)
    hashes = public_files(app)
    (replay / "public-hashes.json").write_text(json.dumps(sorted(hashes)) + "\n", encoding="utf-8")


def finalize_restore(replay: Path, app: str) -> None:
    path = replay / "restore.json"
    config = json.loads(path.read_text()) if path.exists() else {}
    if "image" in config:
        config["recording_image"] = config.pop("image")
    config.update({"version": 2, "app_type": app, "inputs": "lab/v2/portable-inputs.json"})
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8", newline="\n")
    (replay / "public-hashes.json").unlink(missing_ok=True)
    normalize_replay_metadata(replay)


def normalize_replay_metadata(replay: Path) -> None:
    """Keep host-authored metadata portable; never rewrite recorded logs or captures."""
    for path in replay.iterdir():
        if path.is_file() and path.suffix in {".json", ".tsv", ".txt"}:
            content = path.read_bytes()
            normalized = content.replace(b"\r\n", b"\n")
            if normalized != content:
                path.write_bytes(normalized)


def validate_portable_restore(replay: Path) -> None:
    """Delete lab app images, prove their absence, then restore into a new empty tree."""
    try:
        from .restore_webroot import restore
    except ImportError:
        from restore_webroot import restore

    root = Path(__file__).resolve().parents[2]
    listing = subprocess.check_output(
        ["docker", "image", "ls", "--format", "{{.Repository}} {{.ID}}", "--no-trunc"], text=True
    )
    ids = sorted({line.split()[1] for line in listing.splitlines()
                  if line.split()[0] in {"m8v2-wordpress", "m8v2-phpmyfaq", "m8v2-dvwa"}})
    # Include surviving untagged images from earlier recordings, without pruning
    # any unrelated Docker images or the public immutable bases.
    known = set(ids)
    for metadata in (root / "benchmark/v2").glob("s??/replay/restore.json"):
        config = json.loads(metadata.read_text())
        for key in ("image", "recording_image"):
            image = config.get(key, "")
            if image.startswith("sha256:") and subprocess.run(
                ["docker", "image", "inspect", image],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode == 0:
                known.add(image)
    ids = sorted(known)
    deferred = os.environ.get("M8V2_DEFER_IMAGE_PROOF") == "1"
    if ids and not deferred:
        subprocess.run(["docker", "image", "rm", *ids], check=True, stdout=subprocess.DEVNULL)
    for image_id in ([] if deferred else ids):
        if subprocess.run(["docker", "image", "inspect", image_id],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError("local app image still exists before restore proof")
    env = dict(line.split("=", 1) for line in (root / "lab/v2/.env").read_text().splitlines()
               if "=" in line and not line.startswith("#"))
    destination = Path(env["FULL_EVIDENCE_DIR"]).resolve() / "restore-round7" / (
        replay.parent.name + "-" + uuid.uuid4().hex[:10]
    )
    config = json.loads((replay / "restore.json").read_text())
    recorded_image = config.get("recording_image")
    absent = not recorded_image or subprocess.run(
        ["docker", "image", "inspect", recorded_image],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode != 0
    if not deferred and not absent:
        raise RuntimeError("recorded app image still exists before restore proof")
    count = restore(replay.parent.name, destination)
    proof = {
        "result": "PASS", "manifest_entries_verified": count,
        "destination": str(destination), "destination_was_empty": True,
        "local_app_images_removed_and_absence_verified": ids if not deferred else [],
        "recorded_app_image_absent_before_restore": absent,
        "image_removal_proof": "PENDING concurrent recordings" if deferred else "PASS",
        "completed_at_utc": datetime.now(UTC).isoformat(),
        "inputs": "repository, public digest-pinned base, SHA-256-pinned source archives",
    }
    (replay / "restore-validation.txt").write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
