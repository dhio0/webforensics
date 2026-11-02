# s07: current recording notes

## Story

Hydra guesses the local WordPress administrator password. The attacker then signs in, uploads and activates a small plugin, and checks its text marker. The plugin upload is the root cause because it introduces the attacker-controlled plugin; password guessing establishes access but is not the selected root cause.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 5852 | 200 | No | No |
| login_page_probe | 6069 | 200 | No | No |
| admin_area_probe | 6659 | 302 | No | No |
| plugin_upload_probe | 7098 | 302 | No | No |
| hydra_valid_login | 7264 | 302 | No | Yes |
| login_form | 7380 | 200 | No | Yes |
| editor_login | 7404 | 302 | No | Yes |
| plugin_upload_form | 7574 | 200 | No | Yes |
| plugin_upload | 7880 | 200 | Yes | Yes |
| plugin_activation | 8180 | 302 | No | Yes |
| marker_check | 8253 | 200 | No | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T17:41:42.134865+00:00 |
| Replay end, UTC | 2026-11-01T18:54:41.834358+00:00 |
| Access rows | 15023 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.044 |
| Visitor success fraction | 0.99942 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.43069 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 571.0 |
| Minimum hand-action spacing, seconds | 46.84100291000004 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `wp-content/plugins/m8v2-maintenance/m8v2-maintenance.php` | malicious_plugin | Yes | 3 |
| `wp-content/uploads/m8v2-s07-marker.txt` | plugin_marker | Yes | 1 |
| `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` | side_effect | No | 2 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 5852 through 8253 (2402 rows), including 20 actor requests, plus 50 background lines selected with seed 7007. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `ceeebe499c897cb20e017d0406f8218e2c46916cdcae97d9ec881523a0dbc228`.

Current ground-truth SHA-256: `98eac551a0af55b4c1b75dbd888e3cb6d4dee4620f2f855c4dc94be3e58fa9df`.

## Limits

The plugin writes only a marker and offers no command channel. The normal authenticated installer has no vulnerability claim here. The File Manager backup index is a side effect explicitly excluded from reports. Hydra's native request burst is separate from the hand-paced login and installer actions.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `a769ddb`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `be1c149` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. This note replaces superseded measurements.
