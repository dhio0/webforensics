# External case 2 (held out): Ali Hadi Linux "Case #1: Compromised Web Server"

The second independent case, and the first that was **held out**: its answer key was
written before the evidence was opened, and the tool was frozen at commit 3c05308 (which
already held the fixes from case 1). Ubuntu 14.04 (VulnOSv2) with Apache, Drupal 7.26 and
OpenDocMan, attacked with Metasploit's Drupalgeddon2 module (CVE-2018-7600), a kernel
exploit, new accounts and a PHP webshell written from a root shell. The image is not
stored here (no license is stated, and it holds a live webshell).

| File | What it is |
|---|---|
| `ground_truth.md` | Answer key from the author's workshop manual and three public write-ups, written before the evidence was opened. SHA-256 `3e3284ba4dbf6e3a086d07a68af10131d25eac676e0e6b755699521183bdb6f8`. |
| `score.py` | The scoring rules of `ground_truth.md` as code. |
| `results/run1.txt` | The frozen tool (3c05308), unchanged: **the main result**. |
| `results/run2.txt` | After the fixes in D86 (post-hoc). |

## Results

| | Run 1 (3c05308, held out) | Run 2 (after D86) |
|---|---|---|
| Attacker file (`jabc/scripts/update.php`) | found | found |
| HTTP writer invented for it (it was written with vim) | none (correct) | none (correct) |
| Files falsely accused | **2** (OpenDocMan install files from 2016) | 0 |
| IPs falsely accused (3 other clients in the log) | **1** (the VM author's 2016 admin IP) | 0 |
| Exploit request in the timeline | **missed** | found (both Drupalgeddon2 POSTs) |
| Root cause, strict / lenient | **wrong / wrong** (a phpMyAdmin POST from 2016) | correct / correct |
| Markdown report | 27 KB | 17 KB |
| Runtime | 5.0 s | 3.5 s |

**Why run 1 failed** (each fixed in D86, with synthetic tests):
- **No rule for code injection.** The Drupalgeddon2 payload (`name[#post_render][]=passthru`, `eval(base64_decode(...))`) was in the URL, plainly visible, but the log rules covered only SQL injection, path traversal, uploads and webshell commands.
- **A shell written outside HTTP had no entry point.** The tool correctly found no request that wrote `update.php`, and so gave up instead of looking at what its user did before.
- **A form POST near an install batch counted as the writer.** D84 held the 457 OpenDocMan files to the weak-seed standard, but a single phpMyAdmin POST 40 s earlier passed it. That is how the VM author's IP was accused.

**Read with care.** Run 2 is post-hoc on this case. Run 1 is the honest held-out number,
and it was poor. The lab benchmark and case 1 score the same after D86.

## Reproduce

1. Download `Webserver.E01` from <https://archive.org/details/case1-webserver> (1.2 GB).
   File MD5 `94490ffee246f5401d067f77b9d7c345`, media MD5 `03e4a40ebaf6071b346fb2bf217a9f3b`.
2. Extract (the root file system is in the LVM volume `VulnOSv2-vg/root`, which the
   script finds). Exclude only the output folder from your antivirus.
   ```
   python -I scripts/extract_e01.py Webserver.E01 CASE/extracted var/www var/log/apache2 etc/apache2
   python -I scripts/ntfs_listing_to_manifest.py CASE/extracted/ntfs-listing.csv /var/www/html \
       CASE/extracted/manifest.tsv --hostname VulnOSv2 --utc-offset +0200 --filesystem ext2/ext3
   ```
3. Analyze and score:
   ```
   webforensics analyze --log CASE/extracted/files/var/log/apache2/access.log \
       --log-format apache_combined --manifest CASE/extracted/manifest.tsv \
       --webroot CASE/extracted/files/var/www/html \
       --error-log CASE/extracted/files/var/log/apache2/error.log \
       --error-log-format apache --error-log-utc-offset +0200 --out CASE/run
   python -I benchmark/external/ashemery-linux1/score.py CASE/run
   ```
