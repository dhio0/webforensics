# s11 held-out recording notes

The earlier numerical summary below records round 6. The Round 7 analyst read and `replay/self-check.txt` give the current recording measurements and access-log line numbers.

s11 is a no-compromise WordPress 5.5.3 scanner scenario. The pinned sqlmap
source (commit `c42ebd7acf47c88b6407995dd9842a2eb5d6534d`) tested the public
search parameter against the isolated site and exited successfully without
reporting an injectable parameter. Eight marked scanner requests probed login,
admin, XML-RPC, REST, plugin, and common configuration paths. No files were
changed by the scan; WordPress File Manager created an empty backup index as a
side effect, recorded with role `side_effect` and `expected_in_report: false`.

The labels for the eight named requests use unique `X-Lab-Step` headers. Their
lines are 5,851–5,858 in `access.log.gz`. The sqlmap phase is retained in the
access log and summarized in `replay/s11-scan.json`; it did not produce a
separate root-cause step because no compromise occurred. Ground truth therefore
has `root_cause_step: null` and no attacker IPs.

This is an offline adaptation of the originally described failed scan. The
scanner requests receive normal WordPress responses on some known routes
(HTTP 200, 302, and 405) and 404 on absent paths; no claim is made that every
probe failed with 4xx/5xx. Background traffic retains the same 15,000-row
Organization X/NASA pairing used by the development scenarios. There are
10,384 background client identities and 903 User-Agents; visitor success is
96.274%, and all 2,923 scanner rows remain. The eight named scanner requests
span 38.738%–38.784% of 15,104 access rows.

Schema validation, byte-identical ground-truth regeneration, zero-parse-failure
evidence validation, isolation checks, restore of all 2,844 manifest entries,
and Defender scan passed. Defender realtime protection was enabled and found
zero detections. The empty side effect is the sole defanged file.

## Round 7 analyst read

Read every row in the 938-row activity window (lines 5553-6490) using lossless per-second rows and complete request, User-Agent, referrer, status and response-size dictionaries. Verified the cached core-window hash against the final compressed log after approved User-Agent normalization, then read the final normalized User-Agents and all 50 raw background sample lines selected with seed 7011. Checked method/target plausibility, static reads versus accepting write routes, redirects and authentication, timestamps, client attribution, server-error responses, and native tool bursts versus hand pacing.

Read all 938 rows (5553-6490), complete request/UA/status-size dictionaries, including all 104 actor requests, over 189 seconds. Native scanner sweep gives normal login/admin/XML-RPC and missing-path responses; native sqlmap search probes return normal search pages. Ordinary visitor writes use comment/login/lost-password endpoints. No static writes or server-error anomaly found; no compromise inferred from HTTP 200.

The final sample contains ordinary pages, forms, assets, uptime requests, and unchanged scanner probes; no additional recording defect was found. Source browser-version strings rewritten into IP-like numbers by the dataset anonymization are retained. The current measurements, exact write-candidate counts, full-log hash-bound analyst proof, restore proof, and ground-truth SHA-256 are in replay/self-check.txt and replay/analyst-review.json. Earlier numeric summaries above are historical round 6.

| Current labelled step | Access-log line |
|---|---:|
| `scanner_probe_1` | 5553 |
| `scanner_probe_2` | 5554 |
| `scanner_probe_3` | 5555 |
| `scanner_probe_4` | 5556 |
| `scanner_probe_5` | 5557 |
| `scanner_probe_6` | 5558 |
| `scanner_probe_7` | 5559 |
| `scanner_probe_8` | 5560 |
