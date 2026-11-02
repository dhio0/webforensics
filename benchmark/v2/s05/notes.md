# s05 recording notes

The earlier numerical summary below records round 6. The Round 7 analyst read and `replay/self-check.txt` will give the current recording's measurements.

s05 uses the deliberately vulnerable DVWA command-injection module from pinned
upstream commit `a1978a2fed195acd093010af6395f86a281537ca`. The relevant source
is `vulnerabilities/exec/source/low.php`, line 14, SHA-256
`399a0d5dd28436a952a5bb0d14390eb421e57ab2e7add68813b6ce283cc70f28`. DVWA is
the task's allowed training application for command injection; this module has
no separate CVE, so no CVE is claimed. Its GPL-3.0-or-later license and pinned
source archive are recorded in `SOURCES.md`.

The script checks the public site and login and module pages, authenticates to
the isolated application, and sets its security level to the local training
setting. Pinned Commix commit `625c0c46e4257c457774e39bd896307397eaab03`
confirmed that the module executes an operating-system command as the web
service account. A separately marked request then wrote a fixed plain-text
marker under the webroot, and the script read that file back. The captured file
is inert text; the scenario ran no shell or webshell file.

The nine named steps are labeled from `X-Lab-Step` headers, except
`commix_detection`, which is the first POST to the command module inside the
tool's recorded start/end time window. The access-log lines are:

| Step | Access-log line | Result |
|---|---:|---|
| `site_check` | 6,001 | HTTP 200; reconnaissance |
| `login_page_probe` | 6,002 | HTTP 200; reconnaissance |
| `command_module_probe` | 6,003 | HTTP 200; reconnaissance |
| `editor_login` | 6,004 | HTTP 200; valid account access |
| `security_page_open` | 6,005 | HTTP 200; valid account access |
| `security_level_set` | 6,006 | HTTP 200; valid account access |
| `commix_detection` | 6,007 | HTTP 200; initial Commix request |
| `command_injection_file_write` | 6,019 | HTTP 200; root cause |
| `marker_file_check` | 6,020 | HTTP 200; marker read back |

The nine named steps fall at 39.953%–40.080% of the 15,020-row access log. The
Commix run made 10 requests according to its summary; its number of probe
requests may vary by tool version. The 15,000 background rows comprise 12,077
visitors and 2,923 scanner rows. There are 10,384 client identities and 903
User-Agents; the largest client share is 0.973% and the largest User-Agent
share is 4.407%. Visitor 2xx/3xx success is 93.475%, and all scanner rows are
retained.

The replay sends source rows sequentially and drains each response before
starting the next. Nginx's completion log placed a few background rows in a
different order, so the self-check verifies the complete mapped-client count
multiset. The access-log and label-sidecar join uses request, status, client,
and timestamp, which handles occasional write-order differences between the
two logs.

The collector captured one new webroot file, the plain-text marker, and did
not need to defang anything. The scenario folder is 2,079,106 bytes. The ground
truth validates, regenerates byte-identically, and all evidence logs parse.
Restoring the pinned image reproduces all 252 manifest entries. Defender
realtime protection was enabled and the scan found zero detections.

## Round 7 analyst read

Read all 1,880 rows of the final retry-3 activity window (lines 5553-7432), all 21 actor requests raw, complete request/User-Agent/status-size dictionaries, and all 50 seeded background sample lines (seed 7005). Checked methods and accepting routes, redirects before authentication, successful authenticated pages, response sizes, scanner failures, static reads, timing, client diversity, and normalized User-Agents. Visitor writes use the login form; CSS and images are read requests. The protected module redirects anonymous access. The login POST and later unlabelled landing-page GET are separate actions. Native Commix requests cluster within two seconds; later marker creation and read-back remain human-spaced. No server-error or recording defect was found. IP-like browser version numbers come from source anonymization and are retained. The window has 1,265 HTTP 200, 465 redirects, and 150 HTTP 404 responses. Current measurements and ground-truth hash are in replay/self-check.txt; the earlier numerical section is historical round 6.
