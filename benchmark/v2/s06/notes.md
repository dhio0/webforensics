# s06: current recording notes

## Story

The attacker signs in with the DVWA training account and confirms a local-file read from the isolated container. The successful file read is the root cause and expected incident step; login stays outside that timeline.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| training_account_login | 5578 | 302 | No | No |
| lfi_file_read | 6652 | 200 | Yes | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-02T10:08:33.554216+00:00 |
| Replay end, UTC | 2026-11-02T11:21:33.203298+00:00 |
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
| Activity span, seconds | 262.0 |
| Minimum hand-action spacing, seconds | 47.11489080899992 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| None | None | No | Not applicable |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5254 through 6652 (1399 rows), including 6 actor requests, plus 50 background lines selected with seed 7006. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `594a4ac89cb11af16eb35d9d27fc6a3d37927fb15599db573825c4d4f8bf95f4`.

Current ground-truth SHA-256: `2985a2f356736b985aed1e7723eb365294c01c5ae374b03ea920f2a967e90121`.

## Limits

Log or session poisoning and code execution were not verified. No attacker file or write is claimed. This read-only adaptation uses a training app and makes no separate vulnerability identifier claim.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `b983dee`. Round six: `0595d50` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `22c9a33` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
