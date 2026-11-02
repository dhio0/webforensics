# Benchmark v2 status - round 7 in progress

## Session continuation (2026-11-02, WIB)

- All seven replacement dev recordings are complete and uninterrupted; preserve their uncommitted evidence. The earlier active/failed run entries below are historical.
- s05 retry 3 analyst review is complete: all 1,880 final window rows, 21 raw actor rows, and 50 seed-7005 background rows were read; matching hash-bound proof and notes written. The old cached review was replaced.
- Docker is running, and no recording project/container remains active. Both batch flags are cleared for clean-image validation; local lab app images have been removed by the restore helper. Seven fresh external empty-destination restores are running sequentially.
- Full pytest: 564 passed, 8 skipped; Ruff passed.
- s03 committed as `368bd39`: clean-image restore verified all 2,880 exact manifest paths and hashes; self-check has no PENDING.
- Exact next step: finish remaining six restore proofs, rerun each self-check with no PENDING, commit each dev scenario separately, then record s02/s06/s09/s11 with unchanged stories. README/SOURCES edits inherited from the prior session remain uncommitted for final docs.

## Failed seven-scenario batch diagnosis (2026-11-02)

- The s03, s04, s05, s07, s08, s10 and s12 recordings begun on 2026-11-01 are invalid and must be re-recorded from clean volumes. Their `background-error.json` files show `RuntimeError`, `uninterrupted: false`, and termination near source line 11,950-12,100.
- Windows System events identify the cause: Kernel-Power event 42 says the machine entered sleep at 2026-11-01 09:12:18 UTC because of **Button or Lid**; Power-Troubleshooter event 1 reports sleep at 09:12:13 UTC and wake at 09:12:32 UTC. All seven replay errors were written at 09:12:32-33 UTC. The replay clock intentionally rejects such a suspension. The existing `SetThreadExecutionState` request did not prevent a manual button/lid sleep transition.
- Docker inspection of representative background and app containers reported `OOMKilled=false`; the later exit code 137 occurred when Docker was shut down at 11:09 UTC. The different HTTP error totals before suspension (4 to 5,182) are not the common stopping cause.
- The seven scenario folders were restored to their last committed state and their untracked partial files were removed. Only those seven stopped Compose projects and their disposable volumes were removed.
- For the new recordings, the active Balanced power plan's AC lid-close action was temporarily changed from Sleep (1) to Do nothing (0) and verified; the DC action remains Sleep (1). Restore the AC value to 1 after the recordings. Each host runner also requests continuous system execution. No partial log, file snapshot, label, or timestamp from the failed batch will be reused.
- Ignored `.cache/sXX-window-review-progress.json` files for the failed batch are stale and must not be used to claim review of the new recordings.
- The replacement recordings began from clean volumes in seven isolated projects. All seven scripted activity sequences finished without an attack error. The live windows have been parsed row by row for methods, statuses, clients, request targets, server errors, and writes to static suffixes; s10's six image-suffix POSTs are the intentional agent commands. The final 50-line samples, normalized User-Agents, and clean-image restore proofs remain pending until each background replay ends.
- Next: let the seven uninterrupted background replays finish, complete each analyst review and validation, then continue held-out scenarios, all-twelve restore, and final docs.

## s05 retry during replacement batch

- The first replacement s05 background replay finished uninterrupted, but ground-truth generation rejected two sidecar rows with the same `editor_login` label: the DVWA login POST and its immediate redirect GET. That recording is discarded, including its log and encrypted capture; no part will be stitched into the retry.
- Commit `75283d5` changes the labelled DVWA login in s05, s02, and s06 to keep the label on the POST and check the landing page with an unlabelled GET. Full pytest (564 passed, 8 skipped) and Ruff passed before the commit.
- s05 retry 3 was launched on 2026-11-02 at approximately 01:50 WIB. Its runner removes the earlier s05 project and volumes before recording; expected completion is approximately 03:03 WIB. The other six replacement dev recordings continue in isolated projects.
- The other six replacement dev recordings have now ended without replay errors. Their final analyst samples and activity windows were reviewed, and their self-checks pass with only the explicitly deferred image-removal proof. No six-scenario folder will be committed until s05 stops and the local images can be removed for clean restore validation.


## Round 7 progress (2026-11-01)

- Step 0 complete: all four password values in ignored `lab/v2/.env` were rotated locally. No values were printed or committed.
- Lab changes implemented: source-gap scaling (3.5 target requests/second), live rolling burst cap, detached background and attack workers, suspension/stall rejection, seeded human action spacing, and method-aware crawl/remapping.
- Portable restore implemented from registry-digest-pinned public WordPress files and SHA-256-pinned app/plugin/Composer archives. Generated install files use a small safe overlay; secret configuration and generated executables are stubs listed in `defanged.tsv`. Restore never reads `.env` or uses a local scenario image.
- Self-checks now report timing, background/overall peaks, hand spacing, native tool exemptions, POST targets, nearby writes, uninterrupted-run metadata, parser results, Defender, and clean-empty restore proof.
- Focused tests: 34 passed. Full suite: 563 passed, 8 skipped; `ruff check .` passed.
- Pilot s01 is complete and committed in `e9eec25`. Seven dev cases (s03, s04, s05, s07, s08, s10, s12) are recording in isolated projects; their scripted activity completed without errors. No results directory was read; scorer, unit tests, and goldens are unchanged.
- **Exact next step:** read the seven completed activity windows while their detached background replays finish at 16:36-16:37 WIB. After all projects stop, remove local app images, prove portable restore, read each seeded final sample, finalize self-checks/notes, and commit s03, s04, s05, s07, s08, s10, s12 separately. Then record the four held-out cases, prove all-twelve restore, and finalize docs.
- Step 1 implemented in `b1ff768` and startup fix `9864a5c`; the first pilot setup found a pre-existing WordPress startup race, fixed by waiting for the app listener before bootstrap and making bootstrap fail on early termination. No recording began. Round-6 source selection still uses GET/HEAD/POST; replay/remapping additionally support PUT/PATCH when the crawl discovers accepting endpoints. The discarded s01 run is listed below. The first live run must validate integration and may reveal recording defects; none of the new scenario metrics or clean-machine proofs is claimed yet.

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

- UA normalization: `5ff2319` â€” `bench v2: neutral user agents in evidence`
- s01 crawl exclusion: `a519440` â€” `bench v2: s01 without crawl lines`
- s03/s04 crawler fix and re-recording: `23b518b` â€” `bench v2: s03/s04 fixed crawl and re-recorded`
- held-out ground-truth fixes: `0595d50` â€” `bench v2: held-out ground-truth fixes (s06, s11)`

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

## Discarded round-7 run: s01 (attempt 1)

- Started: 2026-11-01T06:29:10.117605+00:00 (2026-11-01 13:29:10 WIB).
- Expected replay end: 2026-11-01T07:42:09.796410+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

- Discarded at 2026-11-01T06:46:47.777396+00:00 after identifying form-query routing defects. The host process and all lab volumes were stopped and removed. No part will be reused or stitched.
- phpMyFAQ preflight now discovers 31 URLs and 11 POST targets after rejecting static HTML fallbacks and removing per-visit tracking IDs. Its temporary project/volumes were removed.

## Completed round-7 run: s01 (attempt 2)

- Started: 2026-11-01T06:48:41.689427+00:00 (2026-11-01 13:48:41 WIB).
- Expected replay end: 2026-11-01T08:01:41.368232+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

- Additional pristine DVWA preflight found and corrected the old PHP truthiness authentication bypass; real anonymous denial and token-bearing login were verified. See `preflight-round7.txt`. Scenario step IDs and incident meanings are unchanged; s02 gains an ordinary login-form GET prerequisite.
- Ignored leftovers include `.cache/network-proof/`, `.cache/preflight-phpmyfaq/`, `.cache/preflight-dvwa/`, and `.cache/round7-s01-host.stdout.txt` / `.stderr.txt`, in addition to pinned source caches. No preflight containers or volumes remain.
- After the pilot completes, invoke the current `recording.validate_portable_restore()` once more before its commit: it now also removes surviving untagged historical app image IDs. The running host imported the earlier helper version.

- Analyst review is recorded only after reading: `replay/analyst-review.json` binds seed 7000 + scenario number, 50 exact background line numbers, the complete actor window, and the access-log SHA-256. `self_check.py` stays PENDING for analyst review until that matching record exists.

- s01 attempt 2 attack completed: eight hand-run actions, 17 actor HTTP requests, 365 seconds from first reconnaissance to final command. All 1,736 rows in lines 6153-7888 were read in a lossless table with complete request/User-Agent dictionaries; actor lines were also read raw. Review findings and raw/core hashes are in ignored `.cache/s01-window-review-progress.json`. The final 50-line random sample is not yet read and no completed analyst proof exists.
- Current pilot host PID: 6796. Continue polling; expected replay completion remains 15:01 WIB. No error flags were present at 14:17 WIB. Do not restart its containers or edit the live evidence log.
- For each concurrent batch, build the app/attacker/collector images once before startup, then set `M8V2_USE_PREBUILT_IMAGES=1` on its runners. This prevents concurrent tag/provenance changes. Use distinct projects/prefixes/ports and defer only the image-removal proof until all batch projects are down. Clear both batch flags before the final proof/check pass.

- s01 attempt 2 completed at 15:01 WIB; collection/restore/Defender finished afterward. It passed every recording check: 4,379-second log, 3.42955 overall requests/second, 20 maximum background/overall, 365-second attack, positions 40.97%-52.52%, zero static writes (one separately reported disguised scanner API probe). Analyst window and all 50 seeded final background lines have now been read and the proof written. Ground truth SHA-256: `1355a7e6ef9d4b41576a9b175625d664bef5f68a28d1369b139486febcbc4971`.
- Two empty external restore trees for s01 are preserved under `FULL_EVIDENCE_DIR/restore-round7/`: `s01-6ba1bb8034` and `s01-0f15bb83cb`. The current full capture is encrypted in external `s01/full-evidence.tar.gz.enc`; old round-6 captures remain untouched under `old-round6/`.

## Active round-7 run: s05

- Started: 2026-11-01T08:23:01.024555+00:00 (2026-11-01 15:23:01 WIB).
- Expected replay end: 2026-11-01T09:36:00.703360+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s03

- Started: 2026-11-01T08:23:41.262146+00:00 (2026-11-01 15:23:41 WIB).
- Expected replay end: 2026-11-01T09:36:40.940951+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s07

- Started: 2026-11-01T08:23:41.794952+00:00 (2026-11-01 15:23:41 WIB).
- Expected replay end: 2026-11-01T09:36:41.473757+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s10

- Started: 2026-11-01T08:23:42.910533+00:00 (2026-11-01 15:23:42 WIB).
- Expected replay end: 2026-11-01T09:36:42.589338+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s04

- Started: 2026-11-01T08:23:43.658655+00:00 (2026-11-01 15:23:43 WIB).
- Expected replay end: 2026-11-01T09:36:43.337460+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s08

- Started: 2026-11-01T08:23:44.906982+00:00 (2026-11-01 15:23:44 WIB).
- Expected replay end: 2026-11-01T09:36:44.585787+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s12

- Started: 2026-11-01T08:23:45.607780+00:00 (2026-11-01 15:23:45 WIB).
- Expected replay end: 2026-11-01T09:36:45.286585+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

- The benign s12 activity window is derived from clients of labelled steps, including unlabelled redirects from those clients. This validation-only correction preserves an empty attacker list and null root cause. Regression/full checks: 564 passed, 8 skipped; Ruff passed. No live evidence or timestamp was changed.
- Batch runner PIDs/projects are in ignored `.cache/round7-dev-batch.json`; per-case host stdout/stderr are `.cache/round7-sXX-host.*.txt`. All seven attacks completed without error markers by 15:51 WIB; background replay continues.

- Full activity windows have now been read for all seven active dev cases using complete lossless row/dictionary views plus raw actor lines: s03 5402-6830 (1,429 rows), s04 5703-7099 (1,397), s05 5553-7391 (1,839), s07 5853-8253 (2,401), s08 6605-8244 (1,640), s10 6452-8187 (1,736), s12 5254-7569 (2,316). Ignored `.cache/sXX-window-review-progress.json` files preserve hashes/findings. Final normalized-UA confirmation and the 50 seeded final background samples remain pending until collection. No completed analyst proof is claimed yet.

## Active round-7 run: s04

- Started: 2026-11-01T17:34:51.407493+00:00 (2026-11-02 00:34:51 WIB).
- Expected replay end: 2026-11-01T18:47:51.086298+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s03

- Started: 2026-11-01T17:34:51.478486+00:00 (2026-11-02 00:34:51 WIB).
- Expected replay end: 2026-11-01T18:47:51.157291+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s05

- Started: 2026-11-01T17:34:59.133923+00:00 (2026-11-02 00:34:59 WIB).
- Expected replay end: 2026-11-01T18:47:58.812728+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s07

- Started: 2026-11-01T17:41:41.651822+00:00 (2026-11-02 00:41:41 WIB).
- Expected replay end: 2026-11-01T18:54:41.330627+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s10

- Started: 2026-11-01T17:41:43.783079+00:00 (2026-11-02 00:41:43 WIB).
- Expected replay end: 2026-11-01T18:54:43.461884+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s12

- Started: 2026-11-01T17:41:44.524900+00:00 (2026-11-02 00:41:44 WIB).
- Expected replay end: 2026-11-01T18:54:44.203705+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s08

- Started: 2026-11-01T17:41:44.555875+00:00 (2026-11-02 00:41:44 WIB).
- Expected replay end: 2026-11-01T18:54:44.234680+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

## Active round-7 run: s05

- Started: 2026-11-01T18:51:31.495694+00:00 (2026-11-02 01:51:31 WIB).
- Expected replay end: 2026-11-01T20:04:31.174499+00:00.
- Background and attack are detached in their isolated containers.
- Windows sleep prevention requested. Any interruption invalidates the run.

- Session continuation: s04 final analyst proof and clean-image restore passed (2881 manifest files); self-check has no PENDING; full pytest and Ruff passed before its separate commit.

- Session continuation: s05 final analyst proof and clean-image restore passed (252 manifest files); self-check has no PENDING; full pytest and Ruff passed before its separate commit.
