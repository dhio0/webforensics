# Ground truth: Ali Hadi "Web Server Case" (Challenge #1), pre-registered

Written BEFORE running webforensics on this evidence. Not edited after the tool ran;
its SHA-256 is recorded in the session and in the results file.

## Sources
- S1 (primary): Andrew Swartwood, "Ashemery.com: Challenge #1 - Web Server Case Write-up",
  Between Two DFIRns, 2017-03. https://betweentwodfirns.blogspot.com/2017/03/ashemerycom-challenge-1-web-server-case.html
- S2 (search summary only, full text not accessible): Syed Hasan, "Digital Forensics Write-up -
  Web Server Case by Ali Hadi" (Medium): attacker 192.168.56.102, sqlmap user agent.
- Evidence facts used only to locate items S1 names (file paths, hashes, which line of code):
  ntfs-listing.csv extracted from the verified image (media MD5 59c66fa4437123f020b91da5f15595b4).

All times UTC. The access log is -0700; S1's times match the log converted to UTC and the MFT.

## Attacker
- IP: 192.168.56.102 (S1, S2). Target 192.168.56.101.
- Other clients in the log (10.20.0.x, ::1) are not named as attackers by S1. Accusing them
  counts as a false accusation, flagged for manual review in the results (S1 does not
  explicitly clear them).

## Attack events (matched by: IP 192.168.56.102, path pattern, time within +-120 s)
| id | time (UTC) | what | path pattern | MITRE |
|---|---|---|---|---|
| G1 | 09-02 09:04:35 | command injection, POST (first exploitation per S1) | POST /dvwa/vulnerabilities/exec/ | T1190, T1059 |
| G2 | 09-02 09:31-09:42 | local file inclusion (hosts, data.txt, phpmyadmin config, abc.txt) | /dvwa/vulnerabilities/fi/?page=../ | T1190 |
| G3 | 09-02 10:49:53 | manual SQL injection | /dvwa/vulnerabilities/sqli/?id=a'+or+1=1 | T1190 |
| G4 | 09-02 11:15:40-11:25:53 | sqlmap SQL injection writing tmpukudk.php / tmpbiwuc.php, then GET /tmpbiwuc.php?cmd= | /dvwa/vulnerabilities/sqli/ , /tmp*.php | T1190, T1505.003 |
| G5 | 09-03 06:52:24 | sqlmap again, tmpudvfh.php / tmpbrjvl.php | /dvwa/vulnerabilities/sqli/ , /tmp*.php | T1190, T1505.003 |
| G6 | 09-03 07:10:15 | phpshell.php written to the DVWA upload folder (method not stated by S1) | /dvwa/hackable/uploads/phpshell.php | T1505.003 |
| G7 | 09-03 07:14:48-07:21:28 | webshells.zip, webshell.php, c99.php; phpshell used 07:16:03, c99 07:19:32, C99 commands 07:21:28 | /dvwa/c99.php, /dvwa/webshell*.php | T1505.003, T1059 |
| G8 | 09-03 07:31:30 | phpshell2.php | /dvwa/hackable/uploads/phpshell2.php | T1505.003 |

Out of scope (not observable in web logs or webroot): accounts user1/hacker (09:05),
RDP enabling, memory artifacts.

## Attacker files present in the webroot (htdocs) at acquisition
| path | sha256 |
|---|---|
| DVWA/hackable/uploads/phpshell.php | 08245eeb54a5d973b20a82e03d82556a693f5c63310e01a2f492b78dda132a99 |
| DVWA/hackable/uploads/phpshell2.php | 2e77d2db6ffba49be0ccf3850ee23de61b289d1e2dfee5b79e4d04563c42a1f7 |
| DVWA/webshells.zip | bdae3070d4d9a483a8f08db4d16c9100723dea6fba3a7e53cbf249851bad99ee |
| DVWA/webshell.php | 794f25b47b4773f6749b0f607f906e5181545eca7835a927c9a197c94c3fd74b |
| DVWA/c99.php | 4320d95cc2fe61e0b862756f8c4ffb251c7d1391e2f6841887c3dc765ba0369c |

Not on disk (deleted or outside htdocs): tmpukudk.php, tmpbiwuc.php, tmpudvfh.php, tmpbrjvl.php.
Every other file in htdocs (XAMPP dashboard, DVWA install) is not attacker-made.

## Root cause
- Strict: G1 (command injection POST to /dvwa/vulnerabilities/exec/, 09-02 09:04:35), the first
  exploitation per S1. S1 also blames DVWA's lack of input validation in general.
- Lenient: any request from 192.168.56.102 to one of the exploited entry points
  (exec, fi, sqli, upload) that S1 links to the compromise.

## Vulnerable code (SQL injection, the class the tool localizes)
The active DVWA security level is not in the logs, so any of these is accepted:
- DVWA/vulnerabilities/sqli/source/low.php line 9 (sha256 2ad9c6de...781af)
- DVWA/vulnerabilities/sqli/source/medium.php line 10 (b61da192...b3690)
- DVWA/vulnerabilities/sqli/source/high.php line 13 (a276db63...6eb1)
Note: index.php includes the source file through a variable path.

## Metrics
- Attacker files flagged: recall over the 5 files; false accusations = other flagged files.
- IPs accused: 192.168.56.102 expected; any other = false accusation (manual review).
- Event recall over G1-G8: an event counts when a timeline row cites a matching log line.
- Root cause: strict and lenient.
- Code: a finding at an accepted line.
- Runtime.

## Run protocol
Run 1 uses the tool exactly as committed (main dd2f83c), with no change for this case.
Any fix made afterwards is listed separately and its run is reported as post-hoc (run 2),
never as the main result.
