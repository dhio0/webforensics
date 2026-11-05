# Results

Every evaluation of webforensics, with first runs and post-hoc runs kept apart. The README has the summary table; the decisions log (`docs/decisions.md`) has the reasons for each fix.

## Lab benchmark

`webforensics eval benchmark/` runs the analyzer on every lab scenario and compares it with the scenario's ground truth ([docs/evaluation.md](evaluation.md)). Each scenario's evidence was recorded in one replay with Wazuh on, so it is scored twice against the same ground truth: through the FileAdapter (logs + manifest) and through the WazuhAdapter (`evidence/wazuh/recording.jsonl`):

| Scenario | Adapter | Split | Step recall | Root cause | False IPs | False files | IP precision | File precision | Expected rules | Code line |
|---|---|---|---|---|---|---|---|---|---|---|
| A: unauthenticated upload | file | dev | 3/3 | correct | 0 | 0 | 1.00 | 1.00 | - | n/a (upload) |
| | wazuh | dev | 3/3 | correct | 0 | 0 | 1.00 | 1.00 | - | n/a (upload) |
| B: POST SQLi login bypass, upload | file | dev | 5/5 | correct | 0 | 0 | 1.00 | 1.00 | - | correct |
| | wazuh | dev | 5/5 | correct | 0 | 0 | 1.00 | 1.00 | - | correct |
| D: busy site, no compromise | file | dev | - | correct (none) | 0 | 0 | - | - | 1/1 | - |
| | wazuh | dev | - | correct (none) | 0 | 0 | - | - | 1/1 | - |
| E: upload + forged mtime | file | held-out | 3/3 | correct | 0 | 0 | 1.00 | 1.00 | 1/1 | n/a (upload) |
| | wazuh | held-out | 3/3 | correct | 0 | 0 | 1.00 | 1.00 | 1/1 | n/a (upload) |
| F: GET SQLi login bypass, upload | file | dev | 4/4 | correct | 0 | 0 | 1.00 | 1.00 | - | correct |
| | wazuh | dev | 4/4 | correct | 0 | 0 | 1.00 | 1.00 | - | correct |

The WazuhAdapter cites lines of the recording; `eval` maps each to the log line with the same text before scoring. In E it catches the forged mtime from FIM (the file was `added` in realtime, then `modified` with a 2024 mtime) instead of from ctime.

Step recall in B and E includes the PHP error-log line written by the upload, so error-log correlation is measured too. In B the root-cause line is right, but the report does not claim SQL injection: the payload is in the POST body, which access logs don't record. It says the login method is not visible (low confidence) and names SQLi over POST as one possibility.

Read these numbers with care. The benchmark is small, synthetic, and made by the same person who wrote the rules. Scenario D failed on its first run: an admin's photo upload was blamed for a CMS cache file. That was fixed (D69), which counts as tuning on a dev scenario. E is held out and passed on its first run, before that fix. Reading D's report also showed that two bots' SQLi login bypass probably worked; the report now says so and recommends fixing the login, without accusing anyone (D71). Runtime is a few hundredths of a second per scenario (machine-dependent, so the table leaves it out). Large logs are measured in [docs/performance.md](performance.md).

## Benchmark v2: real applications, real attack tools

The five lab scenarios above are small and were written by the same person who wrote the rules. [Benchmark v2](../benchmark/v2/README.md) is harder and was built separately: twelve scenarios on pinned real applications (WordPress 5.5.3 with File Manager 6.0, phpMyFAQ 3.2.5, DVWA), attacked with real tools (sqlmap, Weevely, commix, Hydra) and mixed into 15,000 requests of public background traffic, replayed live at a few requests per second. The ground truth comes from the recording scripts, not from the tool. Eight scenarios are dev and four are held out.

The rules and the scorer's hash were written down before the first run ([PREREG.md](../benchmark/v2/results/PREREG.md)), and the analysis code stayed frozen at 93d205b for both runs. Run 2 is the frozen tool's official result, on the final benchmark (rounds 7 and 8):

| Split | Fully correct | Step recall | Root cause correct | False accusations |
|---|---|---|---|---|
| dev (8) | 2/8 | 0.12 | 2/8 | 0 |
| held-out (4) | 1/4 | 0.83 | 1/4 | 0 |

This is a poor result, and it stays in the README as recorded.
- **Passed:** s01 (unauthenticated plugin upload with an agent), s11 (a failed scan, correctly not called a compromise) and s12 (legitimate admin work, correctly not called an attack).
- **Why the rest fail, from the dev scenarios:** the tool does not read the query string, so `POST /wp-admin/update.php?action=upload-plugin` is not seen as an upload; it does not treat Apache multi-extension names (`.php..`) or a `.jpg` run by an `.htaccess` handler as scripts; new non-script files and an agent deleted before collection are missed; payloads sent in a POST body leave nothing in an access log. Details: [run2-analysis.md](../benchmark/v2/results/run2-analysis.md).
- **Run 1** (on an earlier recording replayed at about a hundred requests per second) gave dev 1/8 with four false accusations. The faster replay made background clients look like attackers; realistic pacing removed those accusations, and also an accidental "hit" in s07 and s10 ([run1-analysis.md](../benchmark/v2/results/run1-analysis.md)).
- **Held-out failures (s02, s06, s09) were listed but not examined**, so that the M9 fixes were not tuned on them.

**Run 3, after M9.** The fixes (D94) came from reading the eight dev scenarios only; each is a general rule with its own test, and the lab benchmark, the earlier DFIR cases and the real-scale case were rechecked first. The rules were again written down before the run.

| Split | Fully correct | Step recall | Root cause correct | False accusations |
|---|---|---|---|---|
| dev (8) | 6/8 | 0.91 | 6/8 | 0 |
| held-out (4) | 2/4 | 0.83 | 2/4 | 0 |

- **Held-out is the number to read:** 1/4 → 2/4. s02 is now correct and s09's root cause is an alternative instead of wrong; s06 is still missed. Those reports were not read.
- **The dev gain is post-hoc.** s03 (SQL injection in a POST body that writes no file) stays out of reach of a file-first tool. In s07 the tool names the brute-forced login as the way in and the upload as the alternative, while the ground truth names the upload (D94).
- **What the fixes added:** the query string of an upload; a clean login treated as valid-account abuse, not the way in; the attacker's session before the write; `.php..` and `.htaccess` handlers; an image answered like a script; command injection followed by a write on the same endpoint; non-code files written by the attacker; scripts driven through POST bodies and gone from the webroot; no review noise from files identical to the baseline. Details: [run3-analysis.md](../benchmark/v2/results/run3-analysis.md).

## Outside cases, scored against answer keys written first

### The first case

The lab is self-made, so the tool was also run on Ali Hadi's public DFIR challenge
"Web Server Case" (Windows, XAMPP, DVWA, attacked with a browser and sqlmap). The answer
key came from a public write-up and was fixed before the first run
([benchmark/external/ashemery-case1](../benchmark/external/ashemery-case1/README.md)).

The unchanged tool found all 5 attacker files and the attacker's IP among 15 clients.
It also accused 10 install files, missed the vulnerable SQL line, never saw the sqlmap
webshells the attacker had deleted, and wrote a 1.8 MB report. Each problem became a
general fix with its own test: Windows filesystems, install batches, scripts seen only in
the logs, following PHP includes, and grouped timelines (D84, D85). Run again, the tool
gives 0 false files, all 4 deleted scripts, the SQLi line, and a root cause that matches
the write-up's MFT times to the second, in a 60 KB report.

That second run was measured on the case that drove the fixes, so it is not proof that
they generalize. The first exploit, a command injection sent in a POST body, cannot be
seen in an access log at all.

### A second case, held out

The tool was then frozen and run on a second public case it had never seen (Ali Hadi's
Linux "Compromised Web Server": Drupal 7.26, Metasploit Drupalgeddon2), with the answer
key written first ([benchmark/external/ashemery-linux1](../benchmark/external/ashemery-linux1/README.md)).
It found the webshell and correctly found no HTTP request that wrote it, but missed the
exploit (no rule for code injection), named a 2016 phpMyAdmin request as the way in, and
accused the VM author's IP. After the fixes in D86 it gets every metric of that case right,
but that second run is post-hoc. The honest summary: each new real case has exposed new
gaps, so expect the next one to as well.

### A third case, held out

On the BND Forensik-Challenge (a defaced Debian server whose access log the attacker cut),
the frozen tool reported nothing suspicious and did not say that the log covered only one
minute ([benchmark/external/bnd-2016](../benchmark/external/bnd-2016/README.md)). It now flags
defaced start pages and says when the log starts after the webroot changed (D87). The entry
point stays unknown, because the exploit request was deleted from the log.

### A fourth case, at real scale

Real logs of two Indonesian public-sector servers, 7.6 million access-log lines in all,
with real bots and a brute-force campaign but no webroot
([benchmark/external/id-public-sector-2025](../benchmark/external/id-public-sector-2025/README.md)).
The frozen tool accused no one wrongly and found a webshell in one site's logs, but missed
the dataset's incident (an admin-panel takeover done through the panel's own API), could
not fit all 7.4M lines of one server in 16 GB of RAM, and wrote a 51 MB report for a
brute-forced WordPress site. Brute-force runs are now one event, sparse logs show only the
longest silences, and peak memory fell by 45% on large sites and 85% on the brute-forced
one, with byte-identical reports (D88). One run over all 7.4M lines now completes (3.7
min, 6.0 GB). Merging the sites first added one false file, since scripts were keyed by
path alone; they are now keyed by site (D89), and the single run matches the per-site runs.

### A fifth case, after M9

A free Blue Team Labs Online challenge: the access log of a WordPress site that was scanned
(WPScan, sqlmap), exploited through the Simple File List plugin, and used through a webshell
that was gone at the end; no webroot
([benchmark/external/btlo-compromised-wordpress](../benchmark/external/btlo-compromised-wordpress/README.md)).
The answer key was written before the download. Run 1, with the M9 tool, **crashed**: the log
is not strictly in time order. With that fixed it still found nothing, because the shell was
uploaded from one address and driven from another through POST bodies. After a general fix
(D95), the shell, its disappearance and the upload request (the root cause) are found, with
two of the three attacker addresses and no false accusation. That result is post-hoc.

## Vulnerable code localization

Give the webroot copy with `--webroot` and the report names the vulnerable line in the implicated PHP files (the root cause's endpoint and the endpoints that wrote files), for SQL injection:
```
- Lokasi: admin/login.php:13          (input enters the query)
- Query dijalankan di: admin/login.php:14 ($pdo->query)
$query = "SELECT id, username FROM users WHERE username = '$username' AND password = '$password'";
Contoh perbaikan: $stmt = $pdo->prepare("... WHERE username = ? AND password = ?"); $stmt->execute([$username, $password]);
```
It parses the code (tree-sitter) and tracks request input to the query within a file and function; code is never executed. On 13 real SQL injection fixes from GitHub advisories it detected 5, with no finding in any of the fixed files; the misses are flows through other functions and framework input APIs, which it does not follow ([docs/evaluation.md](evaluation.md)). Upload flaws are not localized yet.

## Robustness on damaged evidence

Real evidence is messy: logs out of time order, error lines mixed into access logs, cut lines, broken UTF-8, rotated `.gz` files copied halfway, manifests with broken rows. A seeded fuzzer damaged the lab and case evidence in those ways and ran the whole analysis: after two fixes, 10,000 damaged copies ran without an error (D96). The test suite keeps 40 such copies and checks that each gives the same bytes twice, that every cited line is the line it names, and that every line is either read or counted as unreadable. Shuffling a log or adding plain visits from new addresses changes no accusation. When most of a log cannot be read, the summary says so first, instead of "nothing found".

## Do the confidence labels mean anything?

A label is useful only if "high" is right more often than "low". Each claim with a label was scored against the answer keys: the files accused (right if the file is the attacker's), the requests named as writers, and the root cause (right only if exact).

**On the first runs of the outside cases** (Ali Hadi XAMPP and Linux, before any fix), the labels did not mean that. Of 12 files accused at **high**, 8 were application files: a file's label was the confidence of its *write time*, and those files had a clear birth time. 2 of 2 root causes, both at medium, were wrong. D100 made the label of an accusation the lower of the write-time confidence and the strength of the evidence that the file is the attacker's (see [how it works](how-it-works.md), step 8), and capped a root cause by the file it led to.

| First runs of the outside cases, files | right at high | wrong at high | right at medium | wrong at medium | right at low | wrong at low |
|---|---|---|---|---|---|---|
| Labels as reported then | 4 | **8** | 2 | 3 | 0 | 1 |
| The D100 rule applied to the same reports | 1 | **0** | 4 | **0** | 1 | 12 |

The second row is a replay of the rule on the saved reports, not a run of the tool: those runs cannot be repeated with the old fixes undone. It was also designed after seeing them. It is evidence that the rule does what it says, not a held-out measurement. The one right file at low is `c99.php`, a well-known webshell that the tool recognizes only by its obfuscation: there is no rule for known webshell signatures yet.

**On the development scenarios** (lab A, B, D, F and benchmark v2 development, which the tool was tuned on), every claim but one is right, so they cannot show calibration: 10 of 10 files at medium, 1 of 1 at low; 6 of 6 root causes at medium, 2 of 3 at low (the wrong one, s07, is the low one). No file is accused at high there: the lab markers are inert on purpose and the v2 agents are obfuscated, which is weak evidence alone.

**What "high" now means:** content that proves attacker code and an HTTP link to the attacker. It is rare by design. The honest test of the labels is the next pre-registered run on the held-out scenarios, which were not used here.
