# Benchmark v2 status - round 7 in progress


## Round 7 progress (2026-11-01)

- Step 0 complete: all four password values in ignored `lab/v2/.env` were rotated locally. No values were printed or committed.
- Lab changes implemented: source-gap scaling (3.5 target requests/second), live rolling burst cap, detached background and attack workers, suspension/stall rejection, seeded human action spacing, and method-aware crawl/remapping.
- Portable restore implemented from registry-digest-pinned public WordPress files and SHA-256-pinned app/plugin/Composer archives. Generated install files use a small safe overlay; secret configuration and generated executables are stubs listed in `defanged.tsv`. Restore never reads `.env` or uses a local scenario image.
- Self-checks now report timing, background/overall peaks, hand spacing, native tool exemptions, POST targets, nearby writes, uninterrupted-run metadata, parser results, Defender, and clean-empty restore proof.
- Focused tests: 30 passed. Full suite: 559 passed, 8 skipped; `ruff check .` passed.
- The s01 pilot is currently recording; no round-7 scenario has been committed yet. Round-6 evidence and ground truth remain intact. No results directory, scorer, unit test, or golden was read or changed.
- **Exact next step:** poll the active s01 pilot to completion (expected 14:42 WIB), read its analyst sample/window, complete all pilot self-checks, and commit s01. Then follow the requested dev/held-out order, one scenario per commit, followed by the all-twelve restore proof and final docs.
- Step 1 implemented in `b1ff768` and startup fix `9864a5c`; the first pilot setup found a pre-existing WordPress startup race, fixed by waiting for the app listener before bootstrap and making bootstrap fail on early termination. No recording began. Round-6 source selection still uses GET/HEAD/POST; replay/remapping additionally support PUT/PATCH when the crawl discovers accepting endpoints. The active s01 run is listed below. The first live run must validate integration and may reveal recording defects; none of the new scenario metrics or clean-machine proofs is claimed yet.

The source includes one scanner POST to a semicolon-suffixed API probe ending in `.js`. It is retained unchanged as a scanner endpoint probe, not treated as a browser asset request, and reported separately as `scanner_disguised_api_static_suffix_probes`. Visitor POST/PUT/PATCH remapping rejects static assets. This interpretation preserves the unchanged scanner stream and makes the suffix exception visible.

### Concurrent recording support

Separate projects may set `COMPOSE_PROJECT_NAME`, `LAB_PREFIX` (a unique 172.31.x prefix), and `EDGE_PORT`. Internal-only networks and per-project volumes remain isolated. The proxy maps physical project addresses back to the accepted logical lab addresses; explicit background IP headers keep their existing mapping. See `parallel-isolation-round7.txt` for the live two-network test.

For a concurrent batch only, set `M8V2_DEFER_IMAGE_PROOF=1`: restore still uses public inputs and validates all files, but the image-removal proof is explicitly PENDING because other recordings still use those images. After every project is down, clear that variable, call `recording.validate_portable_restore()` for each scenario, and rerun `self_check.py`. Do not commit a scenario with PENDING proof or analyst review.

### Preserved encrypted round-6 captures

All twelve files were moved without overwriting or deleting them. They are outside Git beneath `C:\Users\Pongo\Documents\cases\benchmark-v2-full\old-round6\`:

- `s01/full-evidence.tar.gz.enc`
- `s02/full-evidence.tar.gz.enc`
- `s03/full-evidence.tar.gz.enc`
- `s04/full-evidence.tar.gz.enc`
- `s05/full-evidence.tar.gz.enc`
- `s06/full-evidence.tar.gz.enc`
- `s07/full-evidence.tar.gz.enc`
- `s08/full-evidence.tar.gz.enc`
- `s09/full-evidence.tar.gz.enc`
- `s10/full-evidence.tar.gz.enc`
- `s11/full-evidence.tar.gz.enc`
- `s12/full-evidence.tar.gz.enc`

Ignored build inputs remain in `lab/v2/.cache/`, including the newly pinned Composer archives in `.cache/portable/`. No raw attacker files were exported. The legacy round-6 status below is historical, not a round-7 completion claim.

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

Round 6 was complete on branch `m8-benchmark-v2`. For current work, use the round-7 progress and next step above. The held-out hashes and change notes are in [HELDOUT.md](HELDOUT.md). No scoring run has been performed on v2.

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

## Active round-7 run: s01

- Started: 2026-11-01T06:29:10.117605+00:00 (2026-11-01 13:29:10 WIB).
- Expected replay end: 2026-11-01T07:42:09.796410+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.
