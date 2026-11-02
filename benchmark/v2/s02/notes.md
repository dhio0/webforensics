# s02 held-out recording notes

The earlier numerical summary below records round 6. The Round 7 analyst read and `replay/self-check.txt` give the current recording measurements and access-log line numbers.

s02 is an offline adaptation using the GPL-3.0 DVWA training app at pinned
commit `a1978a2fed195acd093010af6395f86a281537ca`. DVWA's SQL injection module
requires an authenticated session, so the preconfigured local administrator
account was used before the sqlmap run. Pinned sqlmap confirmed the `id` query
parameter is injectable, then attempted a user-table dump. It exited zero but
produced no `users.csv`; the run metadata records `user_table_dump_confirmed: false`.
No administrator hash dump is claimed. This diverges from the planned order and
from the original SQLi-to-login chain.

The same administrator session uploaded a Weevely agent to DVWA's upload area,
and a single identity check confirmed execution. The upload is the root-cause
step because the SQLi occurred after login and did not supply the credentials.
The agent was defanged before evidence reached the host. The root-cause upload
is line 10,591; the SQLi phase's first candidate line is 10,354; administrator
login is line 10,351. Lines were selected from the isolated request labels and
the replay records, not from analysis output.

The 15,000 background rows use the same Organization X request shapes and NASA
client identity pairing. This capture has 15,247 total access rows, 10,384
background client identities, 903 User-Agents, a 93.475% visitor success share,
and 2,923 retained scanner rows. The named attack steps span 67.889%–69.463%
of the log. The collector defanged one PHP agent file.

DVWA is a deliberately vulnerable training application and this scenario makes
no separate CVE claim. Schema validation, byte-identical regeneration,
zero-parse-failure evidence validation, self-check, baseline-based defanging,
restoration of the complete manifest, isolation checks, and Defender scan
passed. Defender realtime protection was enabled and found zero detections.

## Round 7 analyst read

Read every row in the 1,804-row activity window (lines 6605-8408) using lossless per-second rows and complete request, User-Agent, referrer, status and response-size dictionaries. Verified the cached core-window hash against the final compressed log after approved User-Agent normalization, then read the final normalized User-Agents and all 50 raw background sample lines selected with seed 7002. Checked method/target plausibility, static reads versus accepting write routes, redirects and authentication, timestamps, client attribution, server-error responses, and native tool bursts versus hand pacing.

Read all 1804 rows (6605-8408), complete dictionaries (428 requests, 177 User-Agents), and all 249 actor requests in lossless row view over 417 seconds. Login and separate landing-page navigation precede security setting and native sqlmap probes; the later upload form, authenticated upload, and native agent command burst are coherent. Native tool probes cluster as expected and DVWA returns HTTP 200 error-page bodies for malformed database probes; no HTTP 5xx anomaly is present. Background visitors write only to login.php and static assets are reads. No recording defect found. No administrator hash dump or login derived from SQLi is claimed.

The final sample contains ordinary pages, forms, assets, uptime requests, and unchanged scanner probes; no additional recording defect was found. Source browser-version strings rewritten into IP-like numbers by the dataset anonymization are retained. The current measurements, exact write-candidate counts, full-log hash-bound analyst proof, restore proof, and ground-truth SHA-256 are in replay/self-check.txt and replay/analyst-review.json. Earlier numeric summaries above are historical round 6.

| Current labelled step | Access-log line |
|---|---:|
| `sqlmap_injection_check` | 7517 |
| `administrator_login` | 7080 |
| `security_level_low` | 7390 |
| `upload_form` | 8056 |
| `agent_upload` | 8311 |
