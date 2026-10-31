# Benchmark v2 status — resumable round 5

## Completed

- **s01** was re-recorded with Organization X visitor User-Agents and request shapes, paired with NASA KSC client identities because Organization X anonymizes almost all clients to one address. The transformation is documented in [s01/notes.md](s01/notes.md) and [SOURCES.md](SOURCES.md).
- s01 contains 15,000 background requests (12,077 visitors, 2,923 scanners) and 15,026 total access rows. It has 10,384 background client identities; largest client share 0.973%, largest User-Agent share 4.407%, and visitor 2xx/3xx share 96.274%.
- Attack labels are at lines 8110–8114, 8119, 8123, and 8126. The attack spans 53.973%–54.080% of the access log. There are two defanged files. Ground-truth SHA-256: `62a692cdbf2d15240c6e75bb912ae9ae54c1ada2e212695087b0d49dbb183858`.
- The scenario folder is 3,259,570 bytes. `replay/self-check.txt` reports schema and regeneration PASS, zero access parse failures, expected visitor/scanner mix, attack position, and size. Restore verification checked 2,845 manifest entries and refused a repository destination. Defender was enabled with real-time protection and reported 0 detections.
- Commit `10a8298` records s01 and its verification. Latest project checks before s03 setup: `pytest` 536 passed, 8 skipped; `ruff check .` passes; existing benchmark scenarios and goldens are unchanged. No files under `src/webforensics/` changed. No analysis or evaluation was run.

## In progress: s03 setup

- The upstream CVE-2024-27299 advisory and fix provenance are verified for phpMyFAQ 3.2.5, MPL-2.0. The advisory says the attacker must be authenticated and have news add/edit permission. Planned adaptation: authenticated Save News SQLi with database read proof only; no file write is claimed.
- The phpMyFAQ image built from source tag `3.2.5` and Composer dependencies. The internal PostgreSQL stack and benchmark admin setup ran; attacker isolation checks passed.
- **Blocker:** public and admin pages returned empty HTTP response bodies after setup. No s03 background replay, attack, evidence capture, labels, or ground truth has been recorded. See [s03/notes.md](s03/notes.md).

## Next exact step

Diagnose why phpMyFAQ 3.2.5 returns empty frontend/admin bodies after its setup (starting with Apache/PHP runtime errors and the release assets omitted from the GitHub source archive). Fix and verify the landing page and admin login/news form through the edge. Then implement the deterministic authenticated SQLi replay with sqlmap, check the `News.php` vulnerable-source hash/line, record background and attack, collect/defang evidence, run scenario self-check and Defender, and commit s03.

## Remaining plan

After s03, record dev scenarios s04, s05, s07, s08, s10, and s12, one commit each. Record held-out s02, s06, s09, and s11 last; add `HELDOUT.md` with each ground-truth hash and recording commit. Finish by updating README, SOURCES, and this status.

## Leftover files

- `lab/v2/.cache/zenodo-20001206-organization-x.zip` and `.cache/NASA_access_log_Jul95.gz` are ignored input datasets retained for subsequent scenario replays.
- `lab/v2/.cache/phpmyfaq-3.2.5-source.zip` is the verified codeload source archive (4.69 MB; SHA-256 in s03 notes). `phpmyfaq-3.2.5-src/` is its expanded ignored copy. An incomplete, slow official release tarball download may also remain in this cache; it was not used.
- `benchmark/v2/s03/replay/source-background.log.gz` and `source-preparation.json` are preparatory corpus files only. The current s03 app URL list is a failed-crawl draft and must be replaced after the app starts correctly. Its empty `evidence/access.log` is only a log mount placeholder; no evidence capture has begun.
- The s01 full restored tree remains at `C:\Windows\Temp\m8v2-restore-s01-51b317c261f04798a7d4ca714451702a`; a cleanup attempt was blocked by policy, so it was retained.
- The encrypted full s01 capture remains outside Git in the directory configured by `lab/v2/.env`.
