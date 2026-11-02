# s05: current recording notes

## Story

After reconnaissance, the attacker signs in to DVWA and selects its low security setting. Commix confirms command execution as the web service account. A separately labelled command-injection request writes a plain-text marker, and a later request reads it back. The marker write is the root cause.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 5553 | 302 | No | No |
| login_page_probe | 5759 | 200 | No | No |
| command_module_probe | 5829 | 302 | No | No |
| editor_login | 5911 | 302 | No | Yes |
| security_page_open | 6873 | 200 | No | Yes |
| security_level_set | 7120 | 302 | No | Yes |
| commix_detection | 7310 | 200 | No | No |
| command_injection_file_write | 7390 | 200 | Yes | Yes |
| marker_file_check | 7432 | 200 | No | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T18:51:31.791056+00:00 |
| Replay end, UTC | 2026-11-01T20:04:31.517231+00:00 |
| Access rows | 15021 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04401 |
| Visitor success fraction | 1.0 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.43024 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 21 |
| Activity span, seconds | 447.0 |
| Minimum hand-action spacing, seconds | 45.82664738399944 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `hackable/uploads/m8v2-s05-marker.txt` | attacker_file | Yes | 1 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5553 through 7432 (1880 rows), including 21 actor requests, plus 50 background lines selected with seed 7005. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `a99a7536f13d11078b730650e60c3947b682d7c21e9a32f66662f4934b8e3530`.

Current ground-truth SHA-256: `d7498fa9f09b06d9616eef0e240ac0c6bb9445b19fa8b3f2cea3cecba9776002`.

## Limits

The marker is inert text; no shell file is claimed. DVWA is a deliberately vulnerable training app with no separate vulnerability identifier claim. Login and the unlabelled landing-page navigation are separate requests.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `a5fda70`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `6ed94b6` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
