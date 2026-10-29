# Ground truth: Ali Hadi Linux Forensics "Case #1: Compromised Web Server", pre-registered

Written BEFORE the evidence was opened and before running webforensics on it. Not edited
after the tool ran; its SHA-256 is recorded in the session and in the results file.
The tool for run 1 is frozen at commit 3c05308 (main), which includes D84/D85 from the
first case. This case is held out: no rule may be changed before run 1 is scored.

## Sources
- S0: Ali Hadi, OSDFCon 2019 workshop manual for Case #1 (questions and hints only, no
  answers): VulnOSv2 host, web app under /var/www/html, "weird POST requests" using
  passthru / eval / base64_decode, SSH brute force from 192.168.210.131 that did not give
  access, users `php` and `mail`, a kernel exploit in /tmp. Image: archive.org/details/case1-webserver.
- S1: "A Linux Forensics Starter Case Study", Forensic Focus (full timeline in UTC).
- S2: hackmag.com "CyberDefenders: Hacked" (same VulnOSv2 image, same attacker IP, same
  `mail` SSH login at 13:23:34 local).
- S3: digitalinvestigator.blogspot.com, "Linux Web Server Forensics: Dr. Ali Hadi's Web
  Server Case" (2023).
- S4: forensicskween.com, CyberDefenders "Hacked" write-up.
Log excerpts in S1-S4 are screenshots; the facts below are the authors' statements.

## Environment
Ubuntu 14.04.4, hostname VulnOSv2 (192.168.210.135), Apache 2, Drupal 7.26 at /jabc/
(S1, S2). Time zone Europe/Brussels, CEST = UTC+02:00 in October 2019 (S1).
All times below are UTC.

## Attacker
- IP: 192.168.210.131 (S0-S4). Any other client accused counts as a false accusation.

## Events in scope (web logs and webroot), matched by IP, path, time +-120 s
| id | time (UTC) | what | match | source |
|---|---|---|---|---|
| W1 | 2019-10-05 11:01:27 | Drupalgeddon2 (CVE-2018-7600) exploit, POST to Drupal with a base64 PHP payload (eval/base64_decode/passthru), loads a Meterpreter stager to 192.168.210.131:4444. S3 counts three such POSTs. | POST, path under /jabc/ | S1, S3, S2, S0 |
| W2 | 2019-10-05 11:17:48 | webshell /var/www/html/jabc/scripts/update.php created (root, `vim scripts/update.php` in root's history: not an HTTP write) | file | S1, S3 |
| W3 | 2019-10-05 11:17:48 | webshell used: GET .../scripts/update.php?cmd=ls | GET, path /jabc/scripts/update.php | S1 |

Out of scope (not in web logs or webroot): SSH brute force from 10:39:26 (auth.log,
btmp), /tmp/37292.c kernel exploit CVE-2015-1328 (11:02:18, deleted), user `php` created
11:06:38 and added to sudo, `mail` added to sudo 11:09, `mail` SSH login 11:23:34,
lastlog tampering.

## Attacker files in the webroot (/var/www/html)
- jabc/scripts/update.php (created). No other attacker file in the webroot is named by
  the sources. Any other flagged file is a false accusation, listed for manual review
  (the sources may not be exhaustive).

## Root cause
- Strict: W1, a POST from 192.168.210.131 under /jabc/ within 120 s of 11:01:27.
- Lenient: any request from 192.168.210.131 under /jabc/ between 11:00:00 and 11:05:00
  (the exploit attempts).
- Expected weakness: Drupal 7.26 core, CVE-2018-7600 (render array injection), not SQL
  injection. The tool localizes only SQL injection, so code localization is n/a; any SQL
  injection finding is listed for manual review, not scored.

## Expected limits (stated before the run)
- update.php was written from a root shell, not by an HTTP request: a correct report
  says no HTTP write was found for it, and must not invent one.
- If the exploit payload is in the POST body, the access log cannot show it.

## Metrics
- Attacker file flagged (1). False file accusations (count, listed).
- IPs accused: only 192.168.210.131 expected.
- Event recall over W1, W3 (cited log lines); W2 from the file evidence.
- Root cause strict / lenient.
- No invented HTTP writer for update.php.
- Runtime, report size.

## Run protocol
Run 1: tool at 3c05308 unchanged, webroot /var/www/html, URL prefix /, Apache combined
access log, Apache error log at +0200 if present. Fixes, if any, come after run 1 is
scored and are reported as post-hoc.
