# s10: current recording notes

## Story

A WordPress administrator installs a package with handler configuration and an agent using an image extension. An agent identity check confirms that the server handles that extension as executable content. The package upload is the root cause.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| site_check | 6452 | 200 | No | No |
| login_page_probe | 6991 | 200 | No | No |
| admin_probe | 7158 | 302 | No | No |
| plugin_upload_probe | 7335 | 302 | No | No |
| login_form | 7388 | 200 | No | Yes |
| editor_login | 7511 | 302 | No | Yes |
| plugin_upload_form | 7824 | 200 | No | Yes |
| persistence_upload | 8076 | 200 | Yes | Yes |
| image_agent_command | 8182 | 200 | No | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-01T17:41:44.076538+00:00 |
| Replay end, UTC | 2026-11-01T18:54:43.764778+00:00 |
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
| Activity span, seconds | 443.0 |
| Minimum hand-action spacing, seconds | 45.12848706700015 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `wp-content/plugins/m8v2-persistence/.htaccess` | persistence_config | Yes | 4 |
| `wp-content/plugins/m8v2-persistence/m8v2-persistence.php` | malicious_plugin | Yes | 4 |
| `wp-content/plugins/m8v2-persistence/m8v2-photo.jpg` | webshell_agent | Yes | 4 |
| `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php` | side_effect | No | 2 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 6452 through 8187 (1736 rows), including 14 actor requests, plus 50 background lines selected with seed 7010. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `bbcc00be2d3947acc03e8f53bd4bd85f093569aba9075ad2577680fd0645c9d4`.

Current ground-truth SHA-256: `7d8775826f346bd2a18a20d2bf8afbcabbe51bf3fdc6c40ea40e8c68a35e1fbc`.

## Limits

The installer is the normal authenticated WordPress interface and has no vulnerability claim here. The actor's image-extension command requests are intended agent exchanges. Background visitors do not write to static assets. The backup index is an excluded side effect.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `a540ea6`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `0fd5bf5` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. This note replaces superseded measurements.
