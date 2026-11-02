# s01: current recording notes

## Story

WordPress File Manager accepts an unauthenticated upload. The uploaded agent returns identification results inside the isolated lab. The upload is the root cause. The plugin backup index is an ordinary side effect excluded from reports.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 6153 | 200 | No | No |
| plugin_version_check | 6682 | 200 | No | No |
| admin_probe | 7098 | 302 | No | No |
| xmlrpc_probe | 7276 | 405 | No | No |
| unauthenticated_file_upload | 7372 | 200 | Yes | Yes |
| agent_identity | 7394 | 200 | No | Yes |
| agent_working_directory | 7535 | 200 | No | Yes |
| agent_user | 7886 | 200 | No | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T06:48:41.916394+00:00 |
| Replay end, UTC | 2026-11-01T08:01:41.563419+00:00 |
| Access rows | 15018 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04401 |
| Visitor success fraction | 0.99942 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.42955 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 365.0 |
| Minimum hand-action spacing, seconds | 46.79236560899972 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `wp-content/plugins/wp-file-manager/lib/files/maintenance-agent.php` | webshell_agent | Yes | 1 |
| `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` | side_effect | No | 2 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 6153 through 7888 (1736 rows), including 17 actor requests, plus 50 background lines selected with seed 7001. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `651e953a5e95cd5ab556f98e1409279e439aebee6444a63f48bba0ead8362d26`.

Current ground-truth SHA-256: `1355a7e6ef9d4b41576a9b175625d664bef5f68a28d1369b139486febcbc4971`.

## Limits

This tests the exposed connector, not an authenticated installer. The source pins and vulnerability advisory are in ../SOURCES.md.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `10a8298`. Round six: `a519440` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `e9eec25` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. This note replaces superseded measurements.
