# Ground truth: BND Forensik-Challenge (2016), pre-registered

Written BEFORE the image was opened and before running webforensics on it. Not edited
after the tool ran; its SHA-256 is recorded in the results file. Tool for run 1: main
at 7bb44e3 (includes D84-D86), unchanged until run 1 is scored.

## Sources
- S0: BND scenario text (via github.com/xmatthias/bndchallange, Szenario.txt): a state
  insurance company's web server was hacked; root password changed; data of other hacks
  stored; the attackers first had no console access; a low-privilege user was created.
- S1: Niklas Bessler, "BND Forensic Challenge" write-up (nbessler.de, 2018).
- S2: xmatthias/bndchallange solution.md (GitHub, GPL-3.0).
- Image: ZIP_Challenge.zip, SHA-256 e13cefde0ee45f05dffa31644a18a10817b9b9801bbb9376ed841858a43c2573
  (matches S1), from the Wayback Machine copy of download.gsb.bund.de (2017-07-14).

## Environment
Debian, Apache 2, PHP pages index.php and originalIndex.php in /var/www/html. Server
192.168.1.10. Access log times are +0100. All times below are UTC.

## Attacker
- 192.168.1.11 (S1, S2). Any other client accused is a false accusation.

## Entry point (root cause)
OS command injection in /originalIndex.php: the `password` / `file` GET parameters reach
PHP system() (S1, S2), used to open a reverse shell as www-data. The exploit request is
dated differently by the sources, both recovered by carving deleted log data:
- S1: 2016-11-21 14:47:09 UTC; S2: 2016-11-22 08:48:56 UTC.
Both sources say the attacker cleaned the access log ("logs cut by hacker"): the exploit
line is NOT expected in the access.log on disk.
- Strict: root cause = a request from 192.168.1.11 to /originalIndex.php within 120 s of
  either time.
- Lenient: root cause = any request from 192.168.1.11 to /originalIndex.php or /index.php.
- Expected given the cleaned log: no correct root cause is possible from the on-disk log.
  A correct report then says the entry point is unknown or weak, and does not invent one.

## Webroot files
| path | role | expected |
|---|---|---|
| index.html | defaced (ransom page), last modified 2016-11-23 12:14:56 UTC (S1) | attacker change: a hit if flagged |
| originalIndex.php, index.php | the vulnerable application pages (input to system()) | not attacker files; flagging them as webshells is reported separately, not as a hit |
Any other flagged webroot file is a false accusation.

## Events still in the on-disk access log (S2 quotes them)
| id | time (UTC) | what |
|---|---|---|
| A1 | 2016-11-24 08:28:13 - 08:29:32 | 192.168.1.11 probes /index.php with varied `password` values (quote, XSS-like and long inputs) |

## Log tampering
Expected: the report states an evidence gap (log silence) covering the exploit window
(2016-11-21 14:47 to 2016-11-22 08:49 UTC).

## Out of scope (not in web logs or webroot)
Privilege escalation through a world-writable root cron script, the `hacker` account, the
root password change, /home/hackedData (steganography flag), /home/readFile, /etc/motd.

## Metrics
- A1 cited (event recall over what the on-disk log can show).
- index.html flagged (defacement). Vulnerable pages flagged as webshell (reported).
- False file accusations; false IPs.
- Root cause strict / lenient; or "unknown" when no correct one is possible (preferred to
  a wrong one).
- Gap over the exploit window reported.

## Run protocol
Run 1: tool at 7bb44e3 unchanged, webroot /var/www/html, Apache combined log at +0100,
error log if present. Fixes come after run 1 is scored and are reported as post-hoc.
