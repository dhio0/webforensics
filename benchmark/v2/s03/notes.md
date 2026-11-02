# s03: current recording notes

## Story

An authenticated phpMyFAQ editor opens Save News. A generic sqlmap check does not identify the cross-field condition; a targeted database-delay check confirms the documented SQL injection. The confirmation request is the root cause. No attack file or operating-system command is involved.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 5402 | 200 | No | No |
| news_admin_probe | 5722 | 200 | No | No |
| editor_login | 5823 | 200 | No | Yes |
| news_editor_open | 5868 | 200 | No | Yes |
| save_news_sql_injection | 6831 | 200 | Yes | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T17:34:51.812051+00:00 |
| Replay end, UTC | 2026-11-01T18:47:51.441941+00:00 |
| Access rows | 15023 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.044 |
| Visitor success fraction | 1.0 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.43069 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 260.0 |
| Minimum hand-action spacing, seconds | 47.39234391299999 |
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

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5402 through 6831 (1430 rows), including 23 actor requests, plus 50 background lines selected with seed 7003. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `aef7541b0ec11c684e5f924e344ee3c05c412452713e67ba8b18f74ab666151e`.

Current ground-truth SHA-256: `dd903488e8fc413836a42c621e12b708749da85fb686ce503ff29eef8e945005`.

## Limits

This adapts the planned small app to licensed phpMyFAQ. The runtime tracking file changes with ordinary traffic and is excluded from reports. A successful HTTP response alone is not the proof of database injection; the recorded targeted check supplies that proof. Source pins and the maintainer advisory are in ../SOURCES.md.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `4c57176`. Round six: `23b518b` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `368bd39` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
