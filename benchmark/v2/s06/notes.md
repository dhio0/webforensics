# s06 held-out recording notes

The earlier numerical summary below records round 6. The Round 7 analyst read and `replay/self-check.txt` give the current recording measurements and access-log line numbers.

s06 adapts the intended local-file-inclusion scenario to a verified read-only
exercise in DVWA at pinned commit `a1978a2fed195acd093010af6395f86a281537ca`
(GPL-3.0-or-later). After using the lab's training account, the attacker
requests the DVWA file-inclusion page and confirms that it returns `/etc/passwd`
from the isolated container. The marked read is line 4,505; the preceding login
step is line 4,502. Both labels are derived from unique request headers.

The planned log/session poisoning path to code execution is not claimed. In this
container image, Apache access logs are collected through the container runtime,
and no repeatable writable log or session-file include path was verified. The
scenario therefore tests local-file inclusion and is an expected miss for RCE;
it creates no attacker file, has `root_cause_step: null`, and makes no CVE claim.

The log has 15,005 rows, including 15,000 background requests. The background
contains 10,384 client identities, 903 User-Agents, a 93.467% visitor success
share, and 2,923 scanner rows. Named steps are at 30.003%–30.023% of the log.
No file was defanged. Schema validation, byte-identical regeneration, evidence
parsing, self-check, isolation checks, full-manifest restoration, and Defender
scan passed; Defender realtime protection was enabled and found zero detections.

## Round 7 analyst read

Read every row in the 1,399-row activity window (lines 5254-6652) using lossless per-second rows and complete request, User-Agent, referrer, status and response-size dictionaries. Verified the cached core-window hash against the final compressed log after approved User-Agent normalization, then read the final normalized User-Agents and all 50 raw background sample lines selected with seed 7006. Checked method/target plausibility, static reads versus accepting write routes, redirects and authentication, timestamps, client attribution, server-error responses, and native tool bursts versus hand pacing.

Read all 1399 rows (5254-6652) and six raw actor rows over 262 seconds. Login redirects and authenticated pages are coherent; final local-file read returns HTTP 200. No write or code execution is inferred. Visitors write only to login.php; assets are reads. No server-error or recording defect found.

The final sample contains ordinary pages, forms, assets, uptime requests, and unchanged scanner probes; no additional recording defect was found. Source browser-version strings rewritten into IP-like numbers by the dataset anonymization are retained. The current measurements, exact write-candidate counts, full-log hash-bound analyst proof, restore proof, and ground-truth SHA-256 are in replay/self-check.txt and replay/analyst-review.json. Earlier numeric summaries above are historical round 6.

| Current labelled step | Access-log line |
|---|---:|
| `training_account_login` | 5578 |
| `lfi_file_read` | 6652 |
