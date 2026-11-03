# External case: BTLO "Log Analysis - Compromised WordPress"

A free Blue Team Labs Online challenge: one Apache access log (2,054 lines) of a WordPress
site that was scanned (WPScan, sqlmap), exploited through the Simple File List 4.2.2
plugin, and used through a webshell that was gone at the end. Only the log is given: no
webroot, no error log, no baseline. This case was untouched before M9 part 1.

| File | What |
|---|---|
| `ground_truth.md` | Answer key, written **before** the evidence was downloaded, from public write-ups. Lines were pinned with plain `grep` after download and before any tool run (section "Pinned lines"). SHA-256 at run time: `2bc57df2e90b497d624e4a0c7c02b8ec5f57ded83644e56c8233861953baefbf`. |
| `score.py` | Scores a run folder against that key. |
| `results/` | Score output of each run. |

The log itself is not in the repository (BTLO terms). Evidence SHA-256:
`749c58b8af624d473cc018d3143887e4dd0f497edf4f0f506f79e4fd45fc7872`.

## Results

| | Run 1 (226b4b0, held out) | Run 2 (crash fix only) | Run 3 (after D95) |
|---|---|---|---|
| Report written | **no: crash** | yes | yes |
| Events E1-E4 in the timeline | - | 0/4 | 3/4 (sqlmap only as unrelated activity) |
| Webshell `fr34k.php` reported, and gone (404) | - | no (listed as unrelated activity) | yes, yes |
| Root cause | - | none | upload/rename request, line 1716: strict OK |
| Attackers accused | - | 0/3 | 2/3 (the sqlmap address is not linked) |
| False accusations | - | 0 | 0 |

**Run 1 is the honest held-out number, and it is the worst possible: the tool crashed.**
- The log is not strictly in time order: Apache writes a line when the request ends.
- Next to an unparsed line, that gave a gap whose end was before its start, which the data model refuses.

**Why run 2 still missed everything.**
- The attacker uploaded the shell with an exploit script from one address (119.241.22.121) and drove it from another (103.69.55.212), through POST bodies.
- M9's rule for such shells required the upload and the use to come from the same address.
- The shell's requests were flagged, but only as unrelated attack activity.

**Read with care.**
- Runs 2 and 3 are post-hoc: both fixes were made after seeing this case. Each is general and has a synthetic test (D95).
- Earlier cases and the lab benchmark were rechecked after the fixes.
- One public write-up credited the upload to the address that the log shows; the others named the shell user. The key was settled from the log before any run, as its rules allowed.

## Reproduce

1. Get the zip from the challenge page on blueteamlabs.online, and unzip it outside the repository.
2. Analyze and score:
   ```
   webforensics analyze --log CASE/access.log --log-format apache_combined \
       --webroot EMPTY_FOLDER --out CASE/run
   python -I benchmark/external/btlo-compromised-wordpress/score.py CASE/run
   ```
