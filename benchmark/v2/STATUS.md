# Benchmark v2 status — round 6 complete

## Round 6 changes

Claude reviewed all twelve scenarios before scoring. The review prompted these evidence and ground-truth fixes:

- Every evidence access log uses deterministic User-Agent mappings in `replay/ua_map.tsv`. SQLmap lines use the pinned tool's default identifier; scripted requests use a common browser or HTTP library identifier. The encrypted captures were left untouched for these rewrites.
- s01 excludes the six app-crawl requests from both the access log and label sidecar. The current first attack line is at 53.96% of the log.
- s03 and s04 were re-recorded after fixing crawler URL resolution, normalization, repeated-block rejection, and deduplication. The nested path share is 0.027% in both. Their phpMyFAQ tracking files are ordinary-traffic side effects and are not expected in reports.
- s06 records the successful local file read as its root cause and expected timeline step. The login step remains outside the incident timeline; no code execution or file write is claimed.
- s11 names the scanner address as the actor and remains a no-compromise scenario with no root cause.

## Round 6 commits

- UA normalization: `5ff2319` — `bench v2: neutral user agents in evidence`
- s01 crawl exclusion: `a519440` — `bench v2: s01 without crawl lines`
- s03/s04 crawler fix and re-recording: `23b518b` — `bench v2: s03/s04 fixed crawl and re-recorded`
- held-out ground-truth fixes: `0595d50` — `bench v2: held-out ground-truth fixes (s06, s11)`

The original recording commits remain listed below. Development split: s01, s03, s04, s05, s07, s08, s10, s12. Held-out split: s02, s06, s09, s11.

## Validation

- `pytest`: **536 passed, 8 skipped**.
- `ruff check .`: **All checks passed**.
- All twelve self-checks pass schema validation, byte-identical ground-truth regeneration, evidence-label joins, and the new User-Agent/path checks. Access, manifest, and error-log parse failures are zero in all scenarios.
- No access-log User-Agent contains `M8`, `m8v2`, or `crawler`. The remaining request-path counts are listed in [README.md](README.md); those are filenames and URLs.
- Repeated-segment paths account for **0.027%** of background requests in each scenario, below the 1% limit.
- Every compromise root-cause position is between 30% and 70%, including s01 and s06.
- The s03/s04 restore checks validated all 2,880 and 2,881 manifest entries. The other scenario restores passed in earlier rounds.
- Defender found zero detections in each scenario and in the full `benchmark/v2/` scan. The full-scan record is [defender-scan-round6.txt](defender-scan-round6.txt).
- `git diff --stat main -- benchmark/scenarios tests/golden` is empty; `src/webforensics/` is unchanged.
- No v2 analysis or evaluation was run. No Defender exclusion was added, and all attacks ran on the isolated lab network.
- `benchmark/v2/` is 35,903,281 bytes; every scenario is below 5 MB.

## Resume notes

The work is complete on branch `m8-benchmark-v2`. If resuming, start from the round 6 commits above. The held-out hashes and change notes are in [HELDOUT.md](HELDOUT.md). No scoring run has been performed on v2.

## Original recording commits

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

- s03 uses licensed phpMyFAQ instead of a small PHP app; vulnerable source and CVE fix provenance are recorded.
- s02 uses DVWA. Its SQLi page requires login; sqlmap confirmed injection but produced no user-table dump. The later agent upload is the ground-truth root cause, so this does not claim SQLi supplied the login.
- s06 verifies a local-file read in DVWA only. Log/session poisoning and RCE were not verified.
- s09 and s10 use the normal authenticated WordPress plugin installer and make no CVE claim for that installer. s07 likewise makes no CVE claim for plugin installation.
- s11 uses a failed sqlmap/search probe and scanner sweep. Some known WordPress paths returned normal 200/302/405 responses instead of only errors.
- s12 could not fetch a WordPress core update package on the internal-only network. It records opening the core-update page and uses a local benign cache-plugin update instead.

Encrypted full captures remain outside Git under the directory configured by `lab/v2/.env`. Source archives and replay inputs under `lab/v2/.cache/` are ignored build inputs. Restore validation trees are outside the repository.
