# Benchmark v2 status — resumable round 5

## Completed

- **s01** was re-recorded with Organization X visitor User-Agents and request shapes, paired with NASA KSC client identities because Organization X anonymizes almost all clients to one address. The transformation is documented in [s01/notes.md](s01/notes.md) and [SOURCES.md](SOURCES.md).
- s01 contains 15,000 background requests (12,077 visitors, 2,923 scanners) and 15,026 total access rows. It has 10,384 background client identities; largest client share 0.973%, largest User-Agent share 4.407%, and visitor 2xx/3xx share 96.274%.
- Attack labels are at lines 8110–8114, 8119, 8123, and 8126. The attack spans 53.973%–54.080% of the access log. There are two defanged files. Ground-truth SHA-256: `62a692cdbf2d15240c6e75bb912ae9ae54c1ada2e212695087b0d49dbb183858`.
- The scenario folder is 3,259,570 bytes. `replay/self-check.txt` reports schema and regeneration PASS, zero access parse failures, expected visitor/scanner mix, attack position, and size. Restore verification checked 2,845 manifest entries and refused a repository destination. Defender was enabled with real-time protection and reported 0 detections.
- Latest project checks: `pytest` 536 passed, 8 skipped; `ruff check .` passes; the existing benchmark scenarios and goldens are unchanged. No files under `src/webforensics/` changed. No analysis or evaluation was run.

## Next

Record **s03** using phpMyFAQ 3.2.5 (MPL-2.0, CVE-2024-27299), adapting the story to the verified vulnerability and documenting the adaptation. Then record dev scenarios s04, s05, s07, s08, s10, and s12, one commit each. Record held-out s02, s06, s09, and s11 last; add `HELDOUT.md` with each ground-truth hash and recording commit. Finish by updating README, SOURCES, and this status.

## Leftover files

- `lab/v2/.cache/zenodo-20001206-organization-x.zip` is an ignored source archive retained for subsequent scenario replays.
- `C:\Windows\Temp\m8v2-restore-s01-51b317c261f04798a7d4ca714451702a` is the verified full defanged restore tree. A cleanup attempt was blocked by policy; it is retained and should be removed manually when convenient.
- The encrypted full capture remains outside Git in the directory configured by `lab/v2/.env`.
