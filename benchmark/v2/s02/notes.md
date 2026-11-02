# s02: current recording notes

## Story

DVWA requires login before its SQL injection page. The attacker uses the configured training account, and sqlmap confirms injection without producing a user-table dump. The later authenticated agent upload is the root cause; an agent identity check confirms execution.

## Steps

Labels come from the recorded sidecar and tool windows through label.py. The table preserves ground-truth order. HTTP status is read from the current log.

| Step | Access line | HTTP status | Root cause | Expected in timeline |
|---|---:|---:|---|---|
| sqlmap_injection_check | 7517 | 200 | No | Yes |
| administrator_login | 7080 | 302 | No | Yes |
| security_level_low | 7390 | 302 | No | Yes |
| upload_form | 8056 | 200 | No | No |
| agent_upload | 8311 | 200 | Yes | Yes |

## Timing and background

| Measurement | Current value |
|---|---:|
| Replay start, UTC | 2026-11-02T10:08:30.319821+00:00 |
| Replay end, UTC | 2026-11-02T11:21:30.038087+00:00 |
| Access rows | 15249 |
| Background rows | 15000 |
| Background clients | 10384 |
| Background user agents | 903 |
| Largest background client fraction | 0.00973 |
| Largest overall user-agent fraction | 0.04335 |
| Visitor success fraction | 1.0 |
| Scanner rows | 2923 |
| Log span, seconds | 4380.0 |
| Average requests per second | 3.48151 |
| Maximum background requests per second | 20 |
| Maximum overall requests per second | 142 |
| Activity span, seconds | 417.0 |
| Minimum hand-action spacing, seconds | 45.06295758300007 |
| Private background client addresses | 0 |
| Background writes to static assets | 0 |
| Remapped background addresses | 9749 |
| Remapped access rows | 13190 |

The recording was uninterrupted. Hand actions are spaced; native tool handshakes and probes keep their original speed. Client counts and top shares are unchanged by the address correction. All non-client log fields and actor lines are byte-identical.

## Files and write candidates

Candidate counts include every POST or PUT within five seconds of the recorded ctime. They describe ambiguity, not attribution.

| File | Role | Expected in report | Nearby writes |
|---|---|---|---:|
| `hackable/uploads/m8v2-s02-agent.php` | webshell_agent | Yes | 3 |

Executable artifacts in the public snapshot are inert stubs. Original full captures remain encrypted outside Git and retain the original client mapping. The webroot, manifests and restore inputs did not change; the existing portable restore proof remains valid.

## Analyst read

The completed recording review covers every activity-window row from line 6605 through 8408 (1804 rows), including 249 actor requests, plus 50 background lines selected with seed 7002. The existing review was rebound to the current log only after a full field comparison. The final review after the fixes is recorded separately in ROUND8.md.

The review checks methods and routes, authentication, statuses and sizes, timing, client attribution, scanner probes, native bursts and file changes. Current schema, file-role, regeneration, parser and private-client checks pass. Existing clean restore and Defender records pass. No analysis or evaluation was run.

Current access-log SHA-256: `ebb9c26f22dbd9abb99b5bba1a5bf4ba624db6c7d060b93fbe4dd8938ae8599e`.

Current ground-truth SHA-256: `ae3903050ffbd03e7f72fb3dc1b2a897f302b2d06b517b96b9e2f2215d257525`.

## Limits

No credential dump or login obtained through SQL injection is claimed. This training app makes no separate vulnerability identifier claim. Steps remain listed out of time order in held-out ground truth; the scorer does not depend on their order.

All scenarios share the same source background slice. Referrers are absent from every background row; application cron self-requests can have referrers. Scanner file names and browser version strings retain the source anonymization. Logs are short, similarly paced, and capped; lab names remain in evidence. See the known limits in ../README.md.

## History

Original recording: `ead8215`. Round six: `5ff2319` corrected labels, crawl handling or user-agent presentation as applicable; `30a9cef` records that review. Round seven: `cff2660` replaced the recording with live pacing and portable restore proof. Round eight: `76034f5` fixed the backup-index expectation and added file-role checks; `249452b` corrected background addresses without recording again. `abac921` replaced the stale notes with current measurements. This note replaces superseded measurements.
