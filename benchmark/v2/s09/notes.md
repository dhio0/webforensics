# s09 held-out recording notes

The earlier numerical summary below records round 6. The Round 7 analyst read and `replay/self-check.txt` give the current recording measurements and access-log line numbers.

s09 tests timestamp manipulation with WordPress 5.5.3 and the pinned Weevely3
agent. An authenticated administrator installed a local fixture archive with
the agent. The agent's pinned `file_touch` module changed its modification time
to 2001-01-01 and verified that time through the same agent. The module
implementation and supported timestamp inputs are in the [pinned Weevely
source](https://github.com/epinna/weevely3/blob/3d62e889871a62a344365b6a2d02b35c5ac1e946/src/weevely/modules/file/touch.py).

The marked archive upload is line 9,905. The timestamp operation is line 9,912
and is the root-cause step. The administrator login and installer form are at
lines 9,902–9,903. Weevely does not send `X-Lab-Step`, so the timestamp request
was selected by the attacker's IP, the command's recorded UTC time window, its
request path, status, and ordinal. No payload or agent code is reproduced here.

This uses the normal authenticated WordPress plugin installer and therefore
makes no CVE claim. It adapts the planned timestomp technique without a separate
WordPress vulnerability. The collector defanged the plugin PHP, agent PHP, and
empty File Manager backup side effect; the side effect is `expected_in_report:
false`. The scenario has 15,000 background rows and 15,016 access rows total,
10,384 clients and 903 User-Agents, 96.274% visitor success, and all 2,923
scanner rows. Named steps span 65.943%–66.010% of the log.

Schema validation, byte-identical regeneration, zero-parse-failure evidence
validation, self-check, isolation checks, manifest restoration, and Defender
scan passed. Defender realtime protection was enabled and found zero detections.

## Round 7 analyst read

Read every row in the 924-row activity window (lines 6604-7527) using lossless per-second rows and complete request, User-Agent, referrer, status and response-size dictionaries. Verified the cached core-window hash against the final compressed log after approved User-Agent normalization, then read the final normalized User-Agents and all 50 raw background sample lines selected with seed 7009. Checked method/target plausibility, static reads versus accepting write routes, redirects and authentication, timestamps, client attribution, server-error responses, and native tool bursts versus hand pacing.

Read all 924 rows (6604-7527), all 14 raw actor requests, and complete request/UA/referrer/status-size dictionaries over 262 seconds. Authenticated login, normal plugin upload, and two native agent command bursts are coherent. Two WordPress loopback cron POSTs from the app address return HTTP 200 with empty bodies and matching cron referrers. Visitors write only to crawled form endpoints; assets are read. Scanner failures and ordinary WordPress redirects are plausible. No server-error or recording defect found.

The final sample contains ordinary pages, forms, assets, uptime requests, and unchanged scanner probes; no additional recording defect was found. Source browser-version strings rewritten into IP-like numbers by the dataset anonymization are retained. The current measurements, exact write-candidate counts, full-log hash-bound analyst proof, restore proof, and ground-truth SHA-256 are in replay/self-check.txt and replay/analyst-review.json. Earlier numeric summaries above are historical round 6.

| Current labelled step | Access-log line |
|---|---:|
| `administrator_login` | 7095 |
| `plugin_upload_form` | 7234 |
| `agent_upload` | 7365 |
| `agent_timestomp` | 7524 |
