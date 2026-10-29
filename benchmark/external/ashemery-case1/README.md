# External case: Ali Hadi "Web Server Case" (Challenge #1)

The first evaluation on an incident the tool's author did not build: a public DFIR
challenge by Dr. Ali Hadi (Windows Server 2008, XAMPP, DVWA, attacked from Kali with a
browser and sqlmap). The disk image is not stored here (no license is stated, and it holds
live webshells). This folder holds what is needed to reproduce and check the result:

| File | What it is |
|---|---|
| `ground_truth.md` | Answer key, written **before** the tool was run, from a public write-up. SHA-256 `97d108bfbe1f1f50936e6ded2d4c83037c7f7cbd6f7c0147bb19bb818b7f9bf8`, unchanged since. |
| `score.py` | The scoring rules of `ground_truth.md` as code. |
| `results/run1.txt` | Score of the committed tool before any change for this case (main result). |
| `results/run2.txt` | Score after the fixes in D84 and D85 (post-hoc, see below). |

## Results

| | Run 1 (dd2f83c, unchanged) | Run 2 (after D84, D85) |
|---|---|---|
| Attacker files flagged | 5/5 | 5/5 |
| Files falsely accused | **10** (install files of DVWA and XAMPP) | 0 |
| Attacker IP | correct, 0 of 14 other clients accused | same |
| Attack events cited (G1-G8) | 7/8 | 7/8 |
| Root cause, strict (first exploit per write-up) | wrong | wrong |
| Root cause, lenient (a documented way in) | correct: upload, 09-03 07:10 | correct: SQLi `INTO OUTFILE`, 09-02 11:25 |
| Deleted sqlmap shells reported | 0/4 | 4/4, with writer and `del` cleanup |
| Vulnerable SQLi line | not found (endpoint not analyzed) | `low.php:9`, `medium.php:10` (accepted lines) |
| Markdown report size | 1.8 MB, 3,701 timeline rows | 60 KB, 70 rows (JSON keeps all 3,698 events) |
| Runtime | 2.8 s | 2.7 s |

**Read with care.**
- One case is an anecdote, not a benchmark.
- Run 2 is post-hoc: the fixes were made after seeing this case's run 1, so run 2 shows the fixes work here, not that they generalize. Every fix is general (Windows filesystems, installs, includes, deleted scripts) and has its own synthetic test, and the lab benchmark still scores the same. A second, untouched case is still needed to check for overfitting.
- The strict root cause, a command injection at 09-02 09:04 in a POST body, cannot be seen in an access log, which never records POST bodies. In both runs the tool names a later exploit instead and caps its confidence at medium.
- The write-up's times are UTC and match the MFT and the log to the second. Its account of how `phpshell.php` was written is not stated; the tool attributes it to the DVWA upload form (POST at the same second).

## Reproduce

1. Download `Case1-Webserver.E01` from <https://archive.org/details/dfir-case1> (3.1 GB, no
   password). Check its MD5 against archive.org (`dd19d88de593ea88b5ba24518e19bac3`) and the
   media MD5 against `Case1-Webserver.E01.txt` (`59c66fa4437123f020b91da5f15595b4`).
2. In a separate virtual environment: `pip install pytsk3 libewf-python`. Extract into a
   folder outside the repository. Your antivirus will flag the webshells. Exclude only that
   folder, and remove the exclusion afterwards.
   ```
   python -I scripts/extract_e01.py Case1-Webserver.E01 CASE/extracted \
       xampp/apache/logs xampp/htdocs xampp/php/logs xampp/tmp
   python -I scripts/ntfs_listing_to_manifest.py CASE/extracted/ntfs-listing.csv \
       /xampp/htdocs CASE/extracted/manifest.tsv --hostname WIN-L0ZZQ76PMUF --utc-offset -0700
   ```
3. Analyze and score:
   ```
   webforensics analyze --log CASE/extracted/files/xampp/apache/logs/access.log \
       --log-format apache_combined --manifest CASE/extracted/manifest.tsv \
       --webroot CASE/extracted/files/xampp/htdocs \
       --error-log CASE/extracted/files/xampp/apache/logs/error.log \
       --error-log-format apache --error-log-utc-offset -0700 --out CASE/run
   python -I benchmark/external/ashemery-case1/score.py CASE/run
   ```
   The input hashes at the end of `results/run2.txt` let you check that you analyzed the
   same evidence. For run 1 the manifest lacked the `#filesystem=ntfs` line, which that
   version did not read. Every row is the same.
