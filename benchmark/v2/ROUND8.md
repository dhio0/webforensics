# Round 8 review fixes

Round eight is complete without a new recording. The branch is `m8-benchmark-v2`; nothing was pushed, pulled or merged. The evidence correction changes only mapped background client addresses. No Docker or restore run was needed. The encrypted full captures, webroot, manifests and restore inputs remain unchanged.

## Commits

- `76034f5`: s07 backup-index role, report exclusion and regression checks.
- `249452b`: production mapper change and verified address-only corrections for all twelve scenarios.
- `abac921`: current-only scenario notes and their numerical consistency script.
- The final documentation commit contains this report, known limits, current hashes and the final analyst records.

## Ground truth and self-check rule

Historical s07 ground-truth SHA-256 before the correction: `e9d8600bef80213e10e7473c88a9a54abb12b23325ff254976700150a446ef1f`.

Current s07 ground-truth SHA-256: `98eac551a0af55b4c1b75dbd888e3cb6d4dee4620f2f855c4dc94be3e58fa9df`.

The scenario source and recorded configuration now both declare the File Manager backup index as `side_effect` with `expected_in_report: false`. Only label.py generated ground truth, twice with identical bytes. Every non-attacker role must explicitly be excluded from the report or use a benign role. An unclassified change also needs a nonempty per-file `classification_justification` in the scenario configuration. The regression test rejects the old s07 representation. The other eleven scenarios had no new file-role defect.

## Address correction

Private counts below are distinct RFC1918 client addresses, not rows. Client count includes background, actor and application clients; every scenario retains 10,384 background clients. Each scenario remaps 9,749 distinct addresses across 13,190 access rows. Parse failures are zero and every self-check passes.

| ID | Private before / after | Rows rewritten | All clients | Historical access-log SHA-256 before | Current access-log SHA-256 after | Self-check |
|---|---:|---:|---:|---|---|---|
| s01 | 9749 / 0 | 13190 | 10386 | `ad6b6342b9d13d57c4f82b3027c1594ae5f6fa760d6b94fa02aa870fcde764cf` | `651e953a5e95cd5ab556f98e1409279e439aebee6444a63f48bba0ead8362d26` | PASS |
| s02 | 9749 / 0 | 13190 | 10385 | `fde6c98868469eca7e91da47730e4d73a3f6d473984d14de4123e8104813b16c` | `ebb9c26f22dbd9abb99b5bba1a5bf4ba624db6c7d060b93fbe4dd8938ae8599e` | PASS |
| s03 | 9749 / 0 | 13190 | 10385 | `4c4a1c4e7cf6df742bcb27ffb636c80267df43dd1bf06ae4d25f65181fa4a045` | `aef7541b0ec11c684e5f924e344ee3c05c412452713e67ba8b18f74ab666151e` | PASS |
| s04 | 9749 / 0 | 13190 | 10385 | `0accbb144f8c46671ce4cd75a906881230a236c25a3f58b5fc78d9dd0953fe2d` | `6237ecf2861109dd45ed3cfc813576b01160dd4b928b9fe7d137cdfafea3278d` | PASS |
| s05 | 9749 / 0 | 13190 | 10385 | `c42f73e71d2d0b60148b1a0986a54c63192921d79bdba5cedb5ff36ce49124be` | `a99a7536f13d11078b730650e60c3947b682d7c21e9a32f66662f4934b8e3530` | PASS |
| s06 | 9749 / 0 | 13190 | 10385 | `1c43bbf130af4a06c78ae5fd9be661c099518d2f4efd7e3da92c292d621cfd99` | `594a4ac89cb11af16eb35d9d27fc6a3d37927fb15599db573825c4d4f8bf95f4` | PASS |
| s07 | 9749 / 0 | 13190 | 10386 | `b5121f5f3314296323f874c350f48b79a2a5b465d62e5309aad06eda55f14504` | `ceeebe499c897cb20e017d0406f8218e2c46916cdcae97d9ec881523a0dbc228` | PASS |
| s08 | 9749 / 0 | 13190 | 10386 | `41dae3ac94acd54ded33886ad7e10b23285d7e0545185999693ed226bea7d422` | `b7693e3b6ab93992ebd8197c64037465ac30655fae5db5ef6fa7c29b52a0d6ae` | PASS |
| s09 | 9749 / 0 | 13190 | 10386 | `1e00261c82f31500caac35c0a8a478aeeda020bfd64af4d409f7873e06fc30c7` | `8731fcd3d044c47f00e6f3a1e8d6aaef54c0022a89a445a3d31f76b2ef02c956` | PASS |
| s10 | 9749 / 0 | 13190 | 10386 | `1f9c2b2b48df14b2ce7c53f122e74b2aec6e751523391b59b0e2c2d9588a42af` | `bbcc00be2d3947acc03e8f53bd4bd85f093569aba9075ad2577680fd0645c9d4` | PASS |
| s11 | 9749 / 0 | 13190 | 10386 | `b38b72849f67566a0846ab241e5059694ba6f5313db79d6eaecec0d31b012640` | `2b5d1a0e799d65b6f3a4b0aebbd477bd96b676b9955a02ce16bf3b20f24001be` | PASS |
| s12 | 9749 / 0 | 13190 | 10386 | `5cb56c159a934ba35f513b4fc2493f528e64b72f972a443fe6978963310aaa82` | `276c8355de25a0a68c66357cb38710ba9598e3566ce2ee30a660bb9ef5aaa3c2` | PASS |

The changed production IPMapper was run over every recorded seed and background input, without replay or network access. The output equals the rewritten ip_map.tsv byte for byte in all twelve scenarios. The map-order construction independently agrees with that input-order rerun; the mapper uses no random draw. The first 635 documentation-range mappings remain identical. Both mapping verification and the write operation can be reproduced with `python -m lab.v2.remap_background_ips --original-revision 76034f5` (add `--apply` only to apply the idempotent transformation).

Every old/new access row was compared field by field: only the mapped background client can differ. All timestamp, request, protocol, status, size, referrer and User-Agent bytes are unchanged. Actor rows and every labelled step row are fully byte-identical. Row counts, client counts, complete client-frequency distributions, and top shares match. The sidecar changes only its client_ip field. ip_map.tsv, labels and access logs agree; records.json contains no mapped background client needing correction. Every ground truth regenerates byte-identically after the remap, with unchanged attacker_ips. Reviews retain their prior selections and bind the new log hash with explicit historical hash and comparison provenance.

The recursive old-range search reads every scenario file, including gzip contents, excluding encrypted captures. No old-range client or scanner-path value remains. The only old-range literal is the historical range and its own leftover inventory inside each ip-remap.json; those are documented non-client metadata. The existing restore proofs remain valid because no restore input changed.

## Notes and known limits

All notes contain current measurements, current step lines and statuses, story, timing, file/write candidates, review provenance and limits. A short History section retains commits without old line numbers. `python -m lab.v2.scenario_notes` compares every note with a deterministic rendering from current ground truth, self-check values, log statuses and fixed provenance. It passes for all twelve.

README, ROUND7 and SOURCES now disclose the shared background, absent source referrer, anonymized scanner paths and browser versions, benchmark-only address pools, root-cause choices, out-of-time-order s02 array, lab names, short uniform logs and pacing cap, and intentional benign s12 actor address. HELDOUT records unchanged ground-truth meaning and new evidence hashes. A read-only literal search in src/webforensics found no m8v2- or benchadmin string; the tool was not run on v2.

One instruction needed a factual refinement: empty referrers apply to every background row, not every row of the complete evidence. There are fifteen WordPress cron self-requests with nonempty referrers across the suite. They remain untouched. The decompressed source-background SHA-256 is identical in all twelve scenarios: `785605cb97de075a2463570147b10a6039c6d5b6a595fd602114fd22b26f6549`.

## Final analyst pass

After the evidence fixes and final note/docs text, Codex performed a fresh read separate from the transformation checks: every ground-truth step line, twenty background lines per scenario selected with seeds 8001 through 8012, and each complete final note. The lossless view included all log fields and complete request and User-Agent dictionaries. Per-scenario round8-analyst-review.json binds the exact sample lines, step lines, reviewed raw-line hashes, current log and ground-truth hashes and final note hash. This is an additional analyst pass by the same agent, not an assertion of a second human reviewer.

| ID | Step lines read | Background sample seed | Background lines read | Finding |
|---|---:|---:|---:|---|
| s01 | 8 | 8001 | 20 | Upload and agent steps match the unauthenticated connector story; ordinary pages, assets, forms and missing scanner paths are coherent. |
| s02 | 5 | 8002 | 20 | Login precedes SQL injection in time despite array order. Later upload matches the root cause. Background redirects, assets and scanner failures are coherent; no dump is inferred. |
| s03 | 5 | 8003 | 20 | Authenticated editor and targeted save match the SQL injection story. Background form POSTs and fallback responses are coherent; no attacker file is inferred. |
| s04 | 6 | 8004 | 20 | Category upload and trailing-dot execution check match. Scanner paths can return the app fallback; ordinary assets are reads. |
| s05 | 9 | 8005 | 20 | Protected module redirects before login; security changes, Commix and marker write/read match. Background writes use login rather than assets. |
| s06 | 2 | 8006 | 20 | Training login and successful local-file read match. Notes correctly claim a read without code execution or a file write. |
| s07 | 11 | 8007 | 20 | Hydra success, separate login, upload, activation and marker match. The backup-index role is now correctly excluded. Background author paths retain disclosed lab naming. |
| s08 | 10 | 8008 | 20 | Upload, agent uses, deletion and final absence response match. Deleted ctime remains unavailable, explicitly stated in the note. |
| s09 | 4 | 8009 | 20 | Authenticated upload precedes the chosen timestomp root cause. The current note explains the ctime definition. Background forms, feeds, assets and scanner failures are coherent. |
| s10 | 9 | 8010 | 20 | Installer sequence and image-extension agent command match handler persistence. Background assets are read; forms receive writes. |
| s11 | 8 | 8011 | 20 | Scanner sweep includes normal and missing-route responses without a compromise. Note correctly keeps the scanner actor and null root cause. |
| s12 | 11 | 8012 | 20 | All labelled work is benign. Installer update, cache, media and catch-all response match the note; the shared actor address is intentional. |

No new recording defect was found. A stale SOURCES sentence about unverified tools was clarified to refer only to the original s01 pilot; later scenario tool checks remain recorded in their notes. The four review defects are closed: s07 has the correct expectation; RFC1918 background clients are gone; stale note measurements were removed; previously undisclosed limits are explicit. Shared traffic, anonymization, absent background referrers, lab names, short similar pacing, source-empty POST bodies, the s02/s06 adaptations, root-cause definitions and deleted s08 ctime remain documented limits rather than changed evidence.

## Validation and constraints

All twelve self-checks pass, with zero access, manifest and error parse failures. Full pytest: 571 passed, 8 skipped. Ruff check: all checks passed before each commit. Tests and checks use the repository virtual environment. Goldens and original benchmark scenarios remain byte-identical to main. src/webforensics and tests/unit were untouched. No v2 analysis/evaluation was run and benchmark/v2/results was never read. No Defender exclusion or live attacker-file export occurred. Historical encrypted captures were not edited. No change needed recording or a new restore proof.
