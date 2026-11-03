# s12: current recording notes

## Story

A benign WordPress administrator checks updates, updates a local cache-plugin fixture, warms its cache, and uploads an image. A catch-all hook also gives the scanner probe a successful response. There is no attacker file or root cause. The administrator uses 192.0.2.131, intentionally the same address used by the attacker elsewhere: benign activity from that address must not be convicted.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| admin_login_form | 5254 | 200 | No | No |
| admin_login | 5573 | 302 | No | No |
| core_update_check | 5774 | 200 | No | No |
| plugin_update_form | 5846 | 200 | No | No |
| plugin_update_package | 6060 | 200 | No | No |
| plugin_update_apply | 6678 | 200 | No | No |
| cache_warm_form | 7103 | 200 | No | No |
| cache_generation | 7219 | 200 | No | No |
| media_upload_form | 7371 | 200 | No | No |
| media_upload | 7399 | 200 | No | No |
| scanner_catchall_probe | 7569 | 200 | No | No |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T17:41:45.042248+00:00 |
| Replay end, UTC | 2026-11-01T18:54:44.718261+00:00 |
| Access rows | 15014 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04403 |
| Visitor success fraction | 0.99064 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.42864 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 529.0 |
| Minimum hand-action spacing, seconds | 45.1657805079999 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `wp-content/cache/m8v2-s12-page.php` | benign_cache_generated | No | 3 |
| `wp-content/plugins/m8v2-cache-fixture/m8v2-cache-fixture.php` | benign_plugin_update | No | 6 |
| `wp-content/uploads/2026/11/m8v2-s12-admin-media.png` | benign_media_upload | No | 2 |
| `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` | side_effect | No | 2 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5254 through 7569 (2316 rows), including 11 actor requests, plus 50 background lines selected with seed 7012. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `276c8355de25a0a68c66357cb38710ba9598e3566ce2ee30a660bb9ef5aaa3c2`.

Current ground-truth SHA-256: `3df574a0396581f17713fcf5ebc86d0c39b265ae64ab4c9c618b1c667d817afc`.

## Limits

The isolated network cannot fetch the official core-update package; only the local plugin update is claimed. Generated cache, updated plugin and media are benign changes excluded from reports. The scanner's catch-all response alone does not establish compromise.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `7362475`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `4dfb7ed` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
