# External case 4 (held out, real scale): Indonesian public-sector web logs

Real logs from two Indonesian public-sector organizations, published on Zenodo
("Web Server Log Dataset", DOI 10.5281/zenodo.20001206, MIT license, anonymized). The
first case at real-world scale: **7.4 million access-log lines** over about 22 virtual
hosts for Organization Y, with real bots, scanners and a brute-force campaign. Scored held
out: the answer key was written before the tool ran, and the tool was frozen at commit
2ad5d68 (after the fixes from cases 1-3). The logs are not stored here.

| File | What it is |
|---|---|
| `ground_truth.md` | Answer key, SHA-256 `1f78bf205b170f22c706b1f3ece86e7268f007b07d5b8813f589dec334220804`. |
| `score.py`, `score_sites.py` | Scoring for one run, and for the per-site runs of Organization Y. |
| `results/orgx-run1.txt` | Organization X, frozen tool. |
| `results/orgy-run1-scale.txt` | Organization Y, the pre-registered single run: did not fit in memory. |
| `results/orgy-run1b-sites.txt` | Organization Y, frozen tool, one run per site (a declared deviation). |
| `results/orgy-run2b-sites.txt`, `results/orgx-run2.txt` | After the fixes in D88 (post-hoc). |
| `results/orgy-run2-full.txt` | Organization Y, after D88, all 7.4M lines in one run (post-hoc). |
| `results/orgy-run3-full.txt` | The same after D89 (log-only scripts keyed by site): the false file is gone. |
| `results/orgy-memory-per-site.txt` | Runtime and peak memory per site, before and after. |

## What this case can and cannot test

**There is no webroot in this dataset**, so the tool's file-first method cannot run: no
file correlation, no timestomp check, no code localization. What it tests is the log
side at real scale: attack rules, actors, false accusations, gaps, memory, runtime, and
whether a report on millions of lines is still readable. The ground truth says so.

## Results

**Organization X** (Apache, 213,205 lines, scans and exploitation attempts, no compromise
per the dataset): correct "no compromise found", **no false accusation**, 676 attack-attempt
lines grouped as unrelated activity (one scanner), 6 s, 256 MB. Same before and after D88.

**Organization Y** (OpenLiteSpeed + CyberPanel, 7,426,129 lines). The dataset reports a
successful privilege escalation on 2025-04-29.

| | Run 1 / 1b (2ad5d68, held out) | Run 2b (after D88) |
|---|---|---|
| One run over all 7.4M lines | **did not fit**: ~12.5 GB projected, 5.4 GB free | completed (run 2c): 3.7 min, 6.0 GB peak; **one false file**, none after D89 (run 3) |
| Per-site runs (21) | all completed, 4.3 min, largest 3.0 GB | 3.5 min, largest 1.6 GB |
| The CyberPanel incident (actor 243.23.54.175) | **missed** (predicted in the ground truth) | missed |
| Other compromise found | a webshell, `/wp-admin/33.php`, used with `cmd=` on 2025-04-22 to 28 | same |
| True false accusations | 0 | 0 |
| Markdown reports, all sites | **52 MB** (one site 51 MB: 101,523 failed-login rows) | 268 KB |
| report.json, all sites | 114 MB | 3.9 MB |

**The missed incident.** The attacker logged in to the CyberPanel admin panel and created
gambling (judi online) virtual hosts with the panel's own API: authenticated requests with
no attack payload, on a server whose webroot is not in the evidence. Nothing in the tool
can tell that from an admin at work. The ground truth predicted this miss before the run.

**The webshell found.** `33.php` sits in `wp-admin/` but is not a WordPress core file; it
answered POSTs and `cmd=` requests with outputs of changing size, the days before the
dataset's incident date, and the dataset's own labels mark those lines `remote_code`. The
client, 71.34.77.255, is a shared address: it also carries the site's own WordPress
requests and a wp-login brute-force run (labelled `bruteforce_login_web`). So it counts as
an attack source per the labels, not a false accusation, but naming one person from it
would be wrong, and the report's shared-IP limitation applies. Whether this webshell led to
the 2025-04-29 incident is not shown by the evidence.

**One run over all sites (run 2c, after D88).** It fits now (6.0 GB peak) and finds the
same webshell and the same shared IP, but adds one false file, `/1514.php`. The same IP
probed that path on more than ten virtual hosts; one host's WordPress catch-all page
answered it (301, then 200 with the same size as dozens of other probes) and another host
answered 200 once. The tool keys a script by its path alone, since it assumes one site, so
answers from different hosts merged into what looked like one script in use. Per site this
does not happen. D89 keys such scripts by site (the folder of the log file) and counts
only 2xx answers as output; after it, one run over all sites (run 3, 221 s, 6.0 GB) finds
the same webshell, writer and IP as the per-site runs and no false file.

**Read with care.**
- The web-side incident actor (243.23.54.175) was located by searching the logs for the
  virtual-host names the dataset's labels give. That located the incident; it was not an
  independent answer from outside the evidence.
- Per-site runs lose correlation across sites (one actor across several sites is not
  linked). They are how a hosting server would be analyzed anyway (one site, one webroot).
- Run 2b is post-hoc on this case. The lab benchmark and cases 1 and 3 score the same after
  D88; case 2 was rechecked once its webshell copy was readable again (see the commit).
- The writer the report names for `33.php` is another non-core script,
  `wp-includes/interactivity-api/4360.php` (a POST 14 s earlier). The report treats it as
  an upload endpoint to fix in run 1b; after D88 the recommendation says it may be an upload
  flaw or another attacker script.

## Reproduce

1. Download `organization-x.zip` and `organization-y.zip` from
   <https://zenodo.org/records/20001206> (MD5 `b4bf79ef...` and `b1925ff7...`), unzip.
2. Use an empty folder as the webroot. Organization X, one run:
   ```
   webforensics analyze --log organization-x/log/apache2 --log-format apache_combined \
       --webroot EMPTY --out runX
   python -I benchmark/external/id-public-sector-2025/score.py runX
   ```
3. Organization Y, one run per directory that holds access logs (each `home/<site>/logs`,
   plus `usr/local/lsws/logs`, `usr/local/lscp/logs`, `usr/local/lscp/cyberpanel/logs`):
   ```
   webforensics analyze --log organization-y/log/home/sub20.domain1.com/logs \
       --log-format apache_combined --webroot EMPTY --out runY/home__sub20.domain1.com__logs
   python -I benchmark/external/id-public-sector-2025/score_sites.py runY 243.23.54.175
   ```
   Output directory names follow `relative/path` with `/` replaced by `__`.
