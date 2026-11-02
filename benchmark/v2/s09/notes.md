# s09: current recording notes

## Story

A WordPress administrator installs a fixture archive containing an agent. The agent changes its own modification time to an old date. The timestomp request is the selected root cause because the collected agent ctime links to that request, rather than to the earlier archive upload.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| administrator_login | 7095 | 302 | No | No |
| plugin_upload_form | 7234 | 200 | No | No |
| agent_upload | 7365 | 200 | No | No |
| agent_timestomp | 7524 | 200 | Yes | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-02T10:08:59.834504+00:00 |
| Replay end, UTC | 2026-11-02T11:21:59.491880+00:00 |
| Access rows | 15017 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04402 |
| Visitor success fraction | 0.99942 |
| Scanner rows | 2923 |
| Log span, seconds | 4379.0 |
| Average requests per second | 3.42932 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 20 |
| Activity span, seconds | 262.0 |
| Minimum hand-action spacing, seconds | 48.6133514600001 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `wp-content/plugins/m8v2-timestomp/m8v2-s09-agent.php` | webshell_agent | Yes | 6 |
| `wp-content/plugins/m8v2-timestomp/m8v2-timestomp.php` | attacker_plugin | Yes | 1 |
| `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` | side_effect | No | 2 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 6604 through 7527 (924 rows), including 14 actor requests, plus 50 background lines selected with seed 7009. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `8731fcd3d044c47f00e6f3a1e8d6aaef54c0022a89a445a3d31f76b2ef02c956`.

Current ground-truth SHA-256: `671cd2a275938df75344de4f54482c78ee51ada24814c417096dc23645cc9484`.

## Limits

This is an explicit ground-truth design choice, not a claim that timestamp manipulation first gained access. It uses the normal authenticated installer and makes no installer vulnerability claim. The backup index is a side effect excluded from reports. Ordinary WordPress cron self-requests remain in the log.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `cd8786e`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `4f190e1` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. This note replaces superseded measurements.
