# Ground truth: BTLO "Log Analysis - Compromised WordPress", pre-registered

Written BEFORE the evidence was downloaded and before running webforensics on it. Not
edited after the tool ran; its SHA-256 is recorded in the results file. Tool for run 1:
main at 226b4b0 (includes D94), unchanged until run 1 is scored.

## Sources
- S0: Blue Team Labs Online challenge "Log Analysis - Compromised WordPress" (free): one
  `access.log` of a WordPress site, in a password-protected zip. Its questions ask for the
  hidden admin login URI, the tools used, the exploited plugin and CVE, the webshell name
  and the status of its last request.
- S1: write-ups found by search (2026-11-03; several are on Medium and could not be opened,
  only their search summaries were read): redthreatcs, 0x00sec mirror, dev.to/mihika,
  azriq, yogasatriautama, dwyntech, cyberjunnkie, kaduprasad678, ERBATMAN, alexandertasse.
- Agreement across S1 is the basis below; where they differ, it is written down.

## Environment
WordPress with the plugins Contact Form 7 and Simple File List 4.2.2, and a hidden login
URL from a security plugin (`/wp-login.php?itsec-hb-token=adminlogin`). Only the access
log is given: no webroot, no error log, no baseline.

## Attackers (S1)
| IP | what S1 says |
|---|---|
| 119.241.22.121 | WPScan enumeration (one write-up instead credits it with the upload) |
| 168.22.54.119 | sqlmap |
| 103.69.55.212 | uploads the webshell through Simple File List and uses it (most write-ups) |
Any other client accused is a false accusation, except a client that the raw log shows
doing the same attack (to be listed as "unsure" before the run, see Line pinning).

## Entry point (root cause)
Unauthenticated file upload in Simple File List 4.2.2 (`ee-upload-engine.php`, with
`ee-file-engine.php` used to rename the upload to `.php`): a request from 103.69.55.212 to
`/wp-content/plugins/simple-file-list/...ee-upload-engine.php` or `...ee-file-engine.php`.
- Strict: root cause = one of those requests.
- Lenient: root cause = any request from 103.69.55.212 to the Simple File List plugin, or
  the first request to the webshell.
- Not correct: a WPScan or sqlmap request, Contact Form 7 (enumerated only; the BTLO
  question names CVE-2020-35489, which S1 treats as a scanned CVE, not the way in).

## Scripts and files
| path | role | expected |
|---|---|---|
| `/wp-content/uploads/simple-file-list/fr34k.php` | webshell, gone at the end (last request 404) | reported as a script seen only in the logs (no webroot is given) |
Any other script reported as attacker-used is a false accusation, unless the raw log shows
it was used the same way (to be listed before the run).

## Events
| id | what |
|---|---|
| E1 | WPScan enumeration from 119.241.22.121 |
| E2 | sqlmap requests from 168.22.54.119 |
| E3 | the Simple File List upload / rename requests from 103.69.55.212 |
| E4 | requests to fr34k.php, the last one answered 404 |

## Line pinning (allowed before the run)
After download and before the tool runs, plain `grep` on the log may fix the exact lines
for E1-E4, the exact webshell URL, and settle the upload IP where S1 disagrees. Those
lines are appended below under "Pinned lines", with the time they were added, and are part
of this key. Nothing else is changed.

## Metrics
- Event recall: E1-E4 cited somewhere in the report (E1/E2 may appear as unrelated
  attack activity; counted, but reported separately from the incident timeline).
- Webshell reported (log-only), and its disappearance (404) shown.
- Root cause strict / lenient.
- False IPs accused; false scripts.
- The report must say that no webroot was given (no claims about file contents).

## Run protocol
Run 1: tool at 226b4b0 unchanged, `--log access.log --log-format apache_combined` (or the
format the log is in), empty folder as the webroot. Fixes come after run 1 is scored and
are reported as post-hoc.

## Pinned lines (added 2026-11-03T07:29:28Z, after download, before any tool run)
Evidence: `access.log`, 2054 lines, SHA-256
`749c58b8af624d473cc018d3143887e4dd0f497edf4f0f506f79e4fd45fc7872`, times +0000. It also
holds a few error-log lines (`sh: 1: /usr/sbin/sendmail`, `[php7:notice] ... WP_Error`),
which the parser should count as unparsed lines, not drop silently.

**The upload IP, settled by the log (S1 disagreed):** the exploit requests came from
119.241.22.121 (`python-requests/2.24.0`), and the shell was then used from 103.69.55.212.
So the entry point is not tied to 103.69.55.212 as written above; the strict and lenient
rules below replace the IP part of "Entry point".

| id | lines | what |
|---|---|---|
| E1 | 1364 (first `WPScan v3.8.10` user agent) | WPScan from 119.241.22.121 |
| E2 | 1528 (`sqlmap/1.4.11`, POST /wp-login.php) | sqlmap from 168.22.54.119 |
| E3 | 1714 `POST /wp-content/plugins/simple-file-list/ee-upload-engine.php` 200; 1716 `POST .../ee-file-engine.php` 200 | upload of fr34k.png and rename to .php, from 119.241.22.121 |
| E4 | 1717 first `GET /wp-content/uploads/simple-file-list/fr34k.php` 200; POSTs 1719-1735 with varying sizes; 1736 GET 404 | shell use from 103.69.55.212, then gone |

- **Root cause, strict:** line 1714 or 1716. **Lenient:** any Simple File List request from
  119.241.22.121 or 103.69.55.212 at 06:19-06:27, or line 1717.
- **Attackers (accused = correct):** 119.241.22.121, 103.69.55.212, 168.22.54.119.
- **Unsure (accused = reported, neither hit nor false):** 110.29.54.120 (POSTs to the hidden
  login), 197.23.128.35 and 197.13.28.35 (probing the hidden login token), 103.212.94.19
  (plugin enumeration), 116.23.212.69 (phpMyAdmin pages right after the shell).
- **Not attackers (accused = false):** 172.21.0.1 (site setup, Docker gateway), 127.0.0.1,
  172.21.0.3 (wp-cron), 156.32.113.25, 132.52.56.77, and any other client.
- **Script:** `/wp-content/uploads/simple-file-list/fr34k.php` (log-only). Any other script
  reported as attacker-used is false.
