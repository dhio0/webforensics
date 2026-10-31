# Benchmark v2 status — complete

## Completed

All twelve scenarios are recorded on branch `m8-benchmark-v2`. Development split: s01, s03, s04, s05, s07, s08, s10, s12. Held-out split: s02, s06, s09, s11. Scenario counts, named access-log lines, split, app/CVE, adaptations, folder sizes, and ground-truth hashes are in [README.md](README.md); held-out ground-truth hashes and recording commits are in [HELDOUT.md](HELDOUT.md).

The recording commits are:

- s01 `10a8298`
- s03 `4c57176`
- s04 `c211f41`
- s05 `a5fda70`
- s07 `a769ddb`
- s08 `e9b2116`
- s10 `a540ea6`
- s12 `7362475`
- s11 `aff8cbf`
- s02 `ead8215`
- s06 `b983dee`
- s09 `cd8786e`

## Adaptations and limits

- s03 uses licensed phpMyFAQ instead of a small PHP app; the source lines and CVE fix provenance are recorded.
- s02 uses DVWA. Its SQLi page requires login; sqlmap confirmed injection but no user-table dump file was produced. The later agent upload is the ground-truth root cause, so this does not claim that SQLi supplied the login.
- s06 verifies a local-file read in DVWA only. A log/session poisoning path to RCE was not verified.
- s09 and s10 use the normal authenticated WordPress plugin installer and make no CVE claim for that installer. s07 likewise makes no CVE claim for plugin installation.
- s11 uses a failed sqlmap/search probe and scanner sweep. Some known WordPress paths returned normal 200/302/405 responses instead of only errors.
- s12 could not fetch a WordPress core update package on the internal-only network. It records opening the core-update page and uses a local benign cache-plugin update instead.

No scenario was skipped. No v2 analysis/evaluation was run. Existing goldens and `src/webforensics/` are unchanged.

## Final checks

- `pytest`: **536 passed, 8 skipped**.
- `ruff check .`: **All checks passed**.
- `git diff --stat main -- benchmark/scenarios tests/golden`: empty.
- All twelve per-scenario self-checks pass schema validation and byte-identical ground-truth regeneration. Evidence parsing reports zero access, manifest, and error-log parse failures in every scenario.
- All 12 scenario isolation checks reject a non-allowlisted service and cannot reach the external address. Every scenario restored its full manifest outside the repository.
- Defanged webroot scan found no script opener in any changed-file stub. `git grep` found no Weevely agent-template or Commix payload signatures.
- Defender full scan of `benchmark/v2/` found no threats; individual scenario scans report zero detections.
- `benchmark/v2/` totals 35,998,473 bytes, below the 150 MB limit; each scenario is below 5 MB.

## Next step

None. The benchmark v2 recording task is complete.

## Leftover files

Encrypted full captures are kept outside Git in the directory configured by `lab/v2/.env`. Source archives and replay inputs under `lab/v2/.cache/` are ignored build inputs. Restore-validation trees remain outside the repository:

- s01: `C:\Windows\Temp\m8v2-restore-s01-51b317c261f04798a7d4ca714451702a`
- s02: `%TEMP%\m8v2-restore-s02-benchv2-final-01`
- s03: `%TEMP%\m8v2-restore-s03-benchv2-final-11` plus earlier failed validation trees
- s04: `%TEMP%\m8v2-restore-s04-benchv2-final-01` through `-04`
- s05: `%TEMP%\m8v2-restore-s05-benchv2-final-01`
- s06: `%TEMP%\m8v2-restore-s06-benchv2-final-01`
- s07: `%TEMP%\m8v2-restore-s07-benchv2-final-01` and `-02`
- s08: `%TEMP%\m8v2-restore-s08-benchv2-final-01`
- s09: `%TEMP%\m8v2-restore-s09-benchv2-final-01`
- s10: `%TEMP%\m8v2-restore-s10-benchv2-final-01`
- s11: `%TEMP%\m8v2-restore-s11-benchv2-final-01`
- s12: `%TEMP%\m8v2-restore-s12-benchv2-final-01`

