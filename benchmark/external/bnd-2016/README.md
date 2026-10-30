# External case 3 (held out): BND Forensik-Challenge (2016)

A recruiting challenge published by the German Federal Intelligence Service (BND): a
Debian web server of a state insurance company was hacked through a PHP page, the root
password was changed, the start page was defaced, and **the attacker cut the access log**.
Scored held out: the answer key was written before the image was opened, from the
scenario text and two public write-ups, and the tool was frozen at commit 7bb44e3 (after
the fixes from cases 1 and 2). The image is not stored here.

| File | What it is |
|---|---|
| `ground_truth.md` | Answer key, SHA-256 `5e1584fd990b6f14202c19f573ef6ee7031c731029c726f9bc893e71f9b29fb8`. |
| `score.py` | The scoring rules of `ground_truth.md` as code. |
| `results/run1.txt` | Frozen tool (7bb44e3): **the main result**. |
| `results/run2.txt` | After the fixes in D87 (post-hoc). |

## Results

| | Run 1 (7bb44e3, held out) | Run 2 (after D87) |
|---|---|---|
| Compromise reported | **no**: "no suspicious file found" | yes |
| Defaced `index.html` flagged | **missed** | found (Impact, T1491.002) |
| Gap over the exploit window (log starts after the attack) | **missed** | reported (21 to 24 Nov) |
| Root cause | none given (correct: the exploit line was deleted) | none given (same) |
| False files / false IPs | 0 / 0 | 0 / 0 |
| Attacker's remaining probes (24 Nov) | not shown | listed as unrelated attack activity (not linked to the defacement) |

Run 1 is the honest held-out number, and it was the worst failure so far: on a server
that was plainly hacked, the report said it found nothing suspicious, without saying the
log covered only one minute on the last day. What changed (D87):
- A defaced start page ("has been hacked", "hacked by ...") is a finding of its own.
- When webroot files changed in the 30 days before the first log line, the report says
  the log starts after them and that period is not in evidence.
- A summary with suspicious files but no linked request says no actor can be named.
- A simple rule for script injection probes.
- An extracted file the analyst's machine cannot read (an antivirus lock) no longer
  crashes the analysis: it is kept without content and counted.

**Not fixed, and not fixable from this evidence:** the exploit request is gone from the
log (the write-ups recovered it by carving deleted log data from the raw disk), so the
entry point stays unknown. The tool says so instead of guessing.

## Reproduce

1. Download `ZIP_Challenge.zip` from the Wayback Machine copy
   `https://web.archive.org/web/20170714192057id_/http://download.gsb.bund.de/BND/ZIP_Challenge.zip`
   (SHA-256 `e13cefde0ee45f05dffa31644a18a10817b9b9801bbb9376ed841858a43c2573`). It holds
   `challenge.ova` (SHA-256 `367daf77...`), a tar with `Debian-disk1.vmdk`.
2. `pip install pytsk3 libvmdk-python`, then:
   ```
   python -I scripts/extract_e01.py Debian-disk1.vmdk CASE/extracted var/www var/log/apache2 etc/apache2
   python -I scripts/ntfs_listing_to_manifest.py CASE/extracted/ntfs-listing.csv /var/www/html \
       CASE/extracted/manifest.tsv --hostname debian --utc-offset +0100 --filesystem ext2/ext3
   ```
3. Analyze and score:
   ```
   webforensics analyze --log CASE/extracted/files/var/log/apache2/access.log \
       --log-format apache_combined --manifest CASE/extracted/manifest.tsv \
       --webroot CASE/extracted/files/var/www/html \
       --error-log CASE/extracted/files/var/log/apache2/error.log \
       --error-log-format apache --error-log-utc-offset +0100 --out CASE/run
   python -I benchmark/external/bnd-2016/score.py CASE/run
   ```
