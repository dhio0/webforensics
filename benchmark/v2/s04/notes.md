# s04: current recording notes

## Story

An authenticated phpMyFAQ editor uploads a category image through the documented upload flaw. The later file request confirms the fixed text execution check. The image upload is the root cause. The ordinary tracking file is excluded from reports.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 5703 | 200 | No | No |
| category_admin_probe | 5791 | 200 | No | No |
| editor_login | 5855 | 200 | No | Yes |
| category_editor_open | 6250 | 200 | No | Yes |
| category_image_upload | 6685 | 200 | Yes | Yes |
| uploaded_file_execution | 7099 | 200 | No | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T17:34:51.726933+00:00 |
| Replay end, UTC | 2026-11-01T18:47:51.367869+00:00 |
| Access rows | 15006 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04405 |
| Visitor success fraction | 1.0 |
| Scanner rows | 2923 |
| Log span, seconds | 4380.0 |
| Average requests per second | 3.42603 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 249.0 |
| Minimum hand-action spacing, seconds | 46.98106368700019 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `data/tracking01112026` | side_effect | No | 2 |
| `images/category-1-.php..` | attacker_file | Yes | 14 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5703 through 7099 (1397 rows), including 6 actor requests, plus 50 background lines selected with seed 7004. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `6237ecf2861109dd45ed3cfc813576b01160dd4b928b9fe7d137cdfafea3278d`.

Current ground-truth SHA-256: `4461b705fdf37281ea2b268bea257776b3e68f65ac6b44be2a1422e6102e2c2f`.

## Limits

No operating-system command is claimed. The original uploaded file name ends in dots; restore.json maps its portable inert snapshot name to the exact manifest name. Source pins and the maintainer advisory are in ../SOURCES.md.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `c211f41`. Round six: `23b518b` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `e60a707` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. This note replaces superseded measurements.
