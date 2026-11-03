# s11: current recording notes

## Story

A scanner probes WordPress routes and runs sqlmap against the public search parameter without finding injection. Some known routes answer normally; a successful response does not establish compromise. Ground truth names the scanner address as the actor but has no root cause or attacker file.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| scanner_probe_1 | 5553 | 200 | No | No |
| scanner_probe_2 | 5554 | 302 | No | No |
| scanner_probe_3 | 5555 | 405 | No | No |
| scanner_probe_4 | 5556 | 200 | No | No |
| scanner_probe_5 | 5557 | 200 | No | No |
| scanner_probe_6 | 5558 | 404 | No | No |
| scanner_probe_7 | 5559 | 404 | No | No |
| scanner_probe_8 | 5560 | 404 | No | No |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-02T10:08:58.425415+00:00 |
| Replay end, UTC | 2026-11-02T11:21:58.073904+00:00 |
| Access rows | 15105 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04376 |
| Visitor success fraction | 0.99942 |
| Scanner rows | 2923 |
| Log span, seconds | 4380.0 |
| Average requests per second | 3.44863 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 60 |
| Activity span, seconds | 189.0 |
| Minimum hand-action spacing, seconds | 185.0001556719999 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` | side_effect | No | 2 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5553 through 6490 (938 rows), including 104 actor requests, plus 50 background lines selected with seed 7011. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `2b5d1a0e799d65b6f3a4b0aebbd477bd96b676b9955a02ce16bf3b20f24001be`.

Current ground-truth SHA-256: `f93c41e1eacdf7887f4b7199ed6a39e9f7a67534dadb53ec356caccb7ecd7971`.

## Limits

The scan is not claimed to produce only error responses. The sole changed backup index is an ordinary File Manager side effect excluded from reports. This remains a no-compromise scenario.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `aff8cbf`. Round six: `0595d50` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `371d603` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
