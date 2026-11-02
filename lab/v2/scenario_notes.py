"""Write current-only notes and check every generated numerical statement."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from . import label, self_check

STORIES = {
    "s01": (
        "WordPress File Manager accepts an unauthenticated upload. The uploaded agent "
        "returns identification results inside the isolated lab. The upload is the root cause. "
        "The plugin backup index is an ordinary side effect excluded from reports.",
        "This tests the exposed connector, not an authenticated installer. The source pins and "
        "vulnerability advisory are in ../SOURCES.md.",
    ),
    "s02": (
        "DVWA requires login before its SQL injection page. The attacker uses the configured "
        "training account, and sqlmap confirms injection without producing a user-table dump. "
        "The later authenticated agent upload is the root cause; an agent identity check "
        "confirms execution.",
        "No credential dump or login obtained through SQL injection is claimed. This training "
        "app makes no separate vulnerability identifier claim. Steps remain listed out of time "
        "order in held-out ground truth; the scorer does not depend on their order.",
    ),
    "s03": (
        "An authenticated phpMyFAQ editor opens Save News. A generic sqlmap check does not "
        "identify the cross-field condition; a targeted database-delay check confirms the "
        "documented SQL injection. The confirmation request is the root cause. No attack "
        "file or operating-system command is involved.",
        "This adapts the planned small app to licensed phpMyFAQ. The runtime tracking file "
        "changes with ordinary traffic and is excluded from reports. A successful HTTP "
        "response alone is not the proof of database injection; the recorded targeted check "
        "supplies that proof. Source pins and the maintainer advisory are in ../SOURCES.md.",
    ),
    "s04": (
        "An authenticated phpMyFAQ editor uploads a category image through the documented "
        "upload flaw. The later file request confirms the fixed text execution check. "
        "The image upload is the root cause. The ordinary tracking file is excluded "
        "from reports.",
        "No operating-system command is claimed. The original uploaded file name ends in "
        "dots; restore.json maps its portable inert snapshot name to the exact manifest "
        "name. Source pins and the maintainer advisory are in ../SOURCES.md.",
    ),
    "s05": (
        "After reconnaissance, the attacker signs in to DVWA and selects its low security "
        "setting. Commix confirms command execution as the web service account. A separately "
        "labelled command-injection request writes a plain-text marker, and a later request "
        "reads it back. The marker write is the root cause.",
        "The marker is inert text; no shell file is claimed. DVWA is a deliberately vulnerable "
        "training app with no separate vulnerability identifier claim. Login and the "
        "unlabelled landing-page navigation are separate requests.",
    ),
    "s06": (
        "The attacker signs in with the DVWA training account and confirms a local-file "
        "read from the isolated container. The successful file read is the root cause "
        "and expected incident step; login stays outside that timeline.",
        "Log or session poisoning and code execution were not verified. No attacker file "
        "or write is claimed. This read-only adaptation uses a training app and makes "
        "no separate vulnerability identifier claim.",
    ),
    "s07": (
        "Hydra guesses the local WordPress administrator password. The attacker then signs "
        "in, uploads and activates a small plugin, and checks its text marker. The plugin "
        "upload is the root cause because it introduces the attacker-controlled plugin; "
        "password guessing establishes access but is not the selected root cause.",
        "The plugin writes only a marker and offers no command channel. The normal "
        "authenticated installer has no vulnerability claim here. The File Manager backup "
        "index is a side effect explicitly excluded from reports. Hydra's native request "
        "burst is separate from the hand-paced login and installer actions.",
    ),
    "s08": (
        "WordPress File Manager accepts an unauthenticated agent upload. The attacker "
        "uses the agent, deletes it, and verifies its absence. The upload is the root cause. "
        "The deleted agent remains an explicit ground-truth file even though neither "
        "baseline nor final webroot contains it.",
        "The deleted agent's ctime is unavailable; its nearby-write count is unavailable "
        "and is not inferred. Its hash comes from transient-file metadata. The File Manager "
        "backup index is a side effect excluded from reports. The final absence check "
        "is evidence of deletion, not a second upload.",
    ),
    "s09": (
        "A WordPress administrator installs a fixture archive containing an agent. The "
        "agent changes its own modification time to an old date. The timestomp request "
        "is the selected root cause because the collected agent ctime links to that "
        "request, rather than to the earlier archive upload.",
        "This is an explicit ground-truth design choice, not a claim that timestamp "
        "manipulation first gained access. It uses the normal authenticated installer "
        "and makes no installer vulnerability claim. The backup index is a side effect "
        "excluded from reports. Ordinary WordPress cron self-requests remain in the log.",
    ),
    "s10": (
        "A WordPress administrator installs a package with handler configuration and an "
        "agent using an image extension. An agent identity check confirms that the server "
        "handles that extension as executable content. The package upload is the root cause.",
        "The installer is the normal authenticated WordPress interface and has no "
        "vulnerability claim here. The actor's image-extension command requests are intended "
        "agent exchanges. Background visitors do not write to static assets. The backup "
        "index is an excluded side effect.",
    ),
    "s11": (
        "A scanner probes WordPress routes and runs sqlmap against the public search "
        "parameter without finding injection. Some known routes answer normally; a "
        "successful response does not establish compromise. Ground truth names the "
        "scanner address as the actor but has no root cause or attacker file.",
        "The scan is not claimed to produce only error responses. The sole changed "
        "backup index is an ordinary File Manager side effect excluded from reports. "
        "This remains a no-compromise scenario.",
    ),
    "s12": (
        "A benign WordPress administrator checks updates, updates a local cache-plugin "
        "fixture, warms its cache, and uploads an image. A catch-all hook also gives the "
        "scanner probe a successful response. There is no attacker file or root cause. "
        "The administrator uses 192.0.2.131, intentionally the same address used by the "
        "attacker elsewhere: benign activity from that address must not be convicted.",
        "The isolated network cannot fetch the official core-update package; only the "
        "local plugin update is claimed. Generated cache, updated plugin and media are "
        "benign changes excluded from reports. The scanner's catch-all response alone "
        "does not establish compromise.",
    ),
}

ORIGINAL = ["10a8298", "ead8215", "4c57176", "c211f41", "a5fda70", "b983dee",
            "a769ddb", "e9b2116", "cd8786e", "a540ea6", "aff8cbf", "7362475"]
ROUND7 = ["e9eec25", "cff2660", "368bd39", "e60a707", "6ed94b6", "22c9a33",
          "be1c149", "1d11e98", "4f190e1", "0fd5bf5", "371d603", "4dfb7ed"]


def render(scenario: Path) -> str:
    sid = scenario.name
    truth = json.loads((scenario / "ground_truth.json").read_text(encoding="utf-8"))
    check = json.loads((scenario / "replay/self-check.txt").read_text(encoding="utf-8"))
    remap = json.loads((scenario / "replay/ip-remap.json").read_text(encoding="utf-8"))
    access = label.access_index(scenario / "evidence/access.log.gz")
    actors = self_check.activity_ips(truth, access)
    actor_rows = [row for row in access if row["client_ip"] in actors]
    selection = check["analyst_read"]
    window = selection["attack_window"]
    story, limits = STORIES[sid]
    text = f"# {sid}: current recording notes\n\n## Story\n\n{story}\n\n"
    text += (
        "## Steps\n\nLabels come from the recorded sidecar and tool windows through label.py. "
        "The table preserves ground-truth order. HTTP status is read from the current log.\n\n"
        "| Step | Access line | HTTP status | Root cause | Expected in timeline |\n"
        "|---|---:|---:|---|---|\n"
    )
    for step in truth["steps"]:
        row = access[step["line_no"] - 1]
        text += (f"| {step['id']} | {step['line_no']} | {row['status']} | "
                 f"{'Yes' if step['is_root_cause'] else 'No'} | "
                 f"{'Yes' if step.get('expected_in_timeline', True) else 'No'} |\n")
    text += "\n## Timing and background\n\n| Measurement | Current value |\n|---|---:|\n"
    metrics = {
        "Replay start, UTC": check["replay_started_at_utc"],
        "Replay end, UTC": check["replay_ended_at_utc"],
        "Access rows": check["access_rows"], "Background rows": check["background_rows"],
        "Background clients": check["background_clients"],
        "Background user agents": check["background_user_agents"],
        "Largest background client fraction": check["largest_background_client_share"],
        "Largest overall user-agent fraction": check["largest_overall_user_agent_share"],
        "Visitor success fraction": check["visitor_success_share"],
        "Scanner rows": check["scanner_rows"],
        "Log span, seconds": check["log_span_seconds"],
        "Average requests per second": check["average_requests_per_second"],
        "Maximum background requests per second": check["maximum_background_requests_per_second"],
        "Maximum overall requests per second": check["maximum_overall_requests_per_second"],
        "Activity span, seconds": check["attack_span_seconds"],
        "Minimum hand-action spacing, seconds": check["hand_action_minimum_spacing_seconds"],
        "Private background client addresses": check["private_background_client_addresses"],
        "Background writes to static assets": check["background_writes_to_static_assets"],
        "Remapped background addresses": remap["addresses_rewritten"],
        "Remapped access rows": remap["rows_rewritten"],
    }
    for key, value in metrics.items():
        text += f"| {key} | {value} |\n"
    text += (
        "\nThe recording was uninterrupted. Hand actions are spaced; native tool handshakes "
        "and probes keep their original speed. Client counts and top shares are unchanged "
        "by the address correction. All non-client log fields and actor lines "
        "are byte-identical.\n\n"
        "## Files and write candidates\n\nCandidate counts include every POST or PUT within "
        "five seconds of the recorded ctime. They describe ambiguity, not attribution.\n\n"
        "| File | Role | Expected in report | Nearby writes |\n|---|---|---|---:|\n"
    )
    for item in truth["files"]:
        candidates = check["write_candidates_within_5_seconds_of_ctime"].get(
            item["path"], "Unavailable; deleted before collection"
        )
        text += (f"| `{item['path']}` | {item['role']} | "
                 f"{'Yes' if item.get('expected_in_report', True) else 'No'} | {candidates} |\n")
    if not truth["files"]:
        text += "| None | None | No | Not applicable |\n"
    text += (
        "\nExecutable artifacts in the public snapshot are inert stubs. Original full captures "
        "remain encrypted outside Git and retain the original client mapping. The webroot, "
        "manifests and restore inputs did not change; the existing portable "
        "restore proof remains valid.\n\n"
        "## Analyst read\n\n"
        f"The completed recording review covers every activity-window row from line "
        f"{window['start_line']} through {window['end_line']} "
        f"({window['end_line'] - window['start_line'] + 1} rows), including "
        f"{len(actor_rows)} actor requests, plus "
        f"{len(selection['sample_background_line_numbers'])} "
        f"background lines selected with seed {selection['sample_seed']}. "
        "The existing review was rebound to the current log only after a full field comparison. "
        "The final review after the fixes is recorded separately in ROUND8.md.\n\n"
        "The review checks methods and routes, authentication, statuses and sizes, timing, "
        "client attribution, scanner probes, native bursts and file changes. Current schema, "
        "file-role, regeneration, parser and private-client checks pass. Existing clean restore "
        "and Defender records pass. No analysis or evaluation was run.\n\n"
        f"Current access-log SHA-256: `{remap['log_sha256_after']}`.\n\n"
        f"Current ground-truth SHA-256: `{check['ground_truth_sha256']}`.\n\n"
        f"## Limits\n\n{limits}\n\n"
        "All scenarios share the same source background slice. Referrers are absent from "
        "every background row; application cron self-requests can have referrers. Scanner "
        "file names and browser version strings retain the source anonymization. Logs are "
        "short, similarly paced, and capped; lab names remain in evidence. See the known "
        "limits in ../README.md.\n\n## History\n\n"
    )
    index = int(sid[1:]) - 1
    sixth = "23b518b" if sid in {"s03", "s04"} else (
        "0595d50" if sid in {"s06", "s11"} else "a519440" if sid == "s01" else "5ff2319"
    )
    text += (
        f"Original recording: `{ORIGINAL[index]}`. Round six: `{sixth}` corrected "
        "labels, crawl handling or user-agent presentation as applicable; `30a9cef` "
        "records that review. Round seven: "
        f"`{ROUND7[index]}` replaced the recording with live pacing and portable restore "
        "proof. Round eight: `76034f5` fixed the backup-index expectation and added "
        "file-role checks; `249452b` corrected background addresses without recording again. "
        "This note replaces superseded measurements.\n"
    )
    assert hashlib.sha256((scenario / "evidence/access.log.gz").read_bytes()).hexdigest() == (
        remap["log_sha256_after"]
    )
    return text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    for scenario in sorted(Path("benchmark/v2").glob("s[0-9][0-9]")):
        path = scenario / "notes.md"
        expected = render(scenario).encode()
        if args.write:
            path.write_bytes(expected)
        assert path.read_bytes() == expected, f"stale note numbers or prose: {scenario.name}"
        print(scenario.name, "current measurements, step lines, statuses and hashes: PASS")


if __name__ == "__main__":
    main()
