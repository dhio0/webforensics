# s08: current recording notes

## Story

WordPress File Manager accepts an unauthenticated agent upload. The attacker uses the agent, deletes it, and verifies its absence. The upload is the root cause. The deleted agent remains an explicit ground-truth file even though neither baseline nor final webroot contains it.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 6603 | 200 | No | No |
| plugin_version_check | 7038 | 200 | No | No |
| admin_probe | 7170 | 302 | No | No |
| xmlrpc_probe | 7326 | 405 | No | No |
| unauthenticated_file_upload | 7388 | 200 | Yes | Yes |
| agent_identity | 7475 | 200 | No | Yes |
| agent_working_directory | 7766 | 200 | No | Yes |
| agent_user | 8046 | 200 | No | Yes |
| agent_deleted | 8175 | 200 | No | Yes |
| agent_absent_check | 8244 | 404 | No | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T17:41:45.042248+00:00 |
| Replay end, UTC | 2026-11-01T18:54:44.734768+00:00 |
| Access rows | 15022 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.044 |
| Visitor success fraction | 0.99942 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.43046 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 466.0 |
| Minimum hand-action spacing, seconds | 45.18140206299995 |
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
| `wp-content/plugins/wp-file-manager/lib/files/m8v2-s08-agent.php` | webshell_agent | Yes | Unavailable; deleted before collection |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 6603 through 8244 (1642 rows), including 21 actor requests, plus 50 background lines selected with seed 7008. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `b7693e3b6ab93992ebd8197c64037465ac30655fae5db5ef6fa7c29b52a0d6ae`.

Current ground-truth SHA-256: `2b417bfe1a40e674004320c0812f4cbb28e1830a1adb620d5a5ea0bd8740378a`.

## Limits

The deleted agent's ctime is unavailable; its nearby-write count is unavailable and is not inferred. Its hash comes from transient-file metadata. The File Manager backup index is a side effect excluded from reports. The final absence check is evidence of deletion, not a second upload.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `e9b2116`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `1d11e98` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
