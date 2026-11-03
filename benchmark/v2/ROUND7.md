# Round 7 recording and portable restore report

Every scenario was recorded live in one uninterrupted run. The analysis code stayed frozen; no v2 analysis or evaluation was run during recording. All final self-checks pass with no PENDING. All times below are UTC; add seven hours for WIB.

Maximum rates show background / overall requests per second. Position covers the whole actor window, including unlabelled requests. Nearby writes count POST/PUT requests within five seconds of each file ctime; these are ambiguity measurements, not attribution claims.

| ID | Split | Log UTC interval; span | Avg req/s | Max background / overall | Activity span | Position | Background static writes | Nearby writes by file | Clean restore | Ground-truth SHA-256 |
|---|---|---|---:|---:|---:|---|---:|---|---|---|
| s01 | dev | 2026-11-01 06:48:42 to 08:01:41; 4379s | 3.42955 | 20 / 20 | 365s | 40.97-52.52% | 0 | `wp-content/plugins/wp-file-manager/lib/files/maintenance-agent.php`: 1; `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2 | PASS (2845 files) | `1355a7e6ef9d4b41576a9b175625d664bef5f68a28d1369b139486febcbc4971` |
| s02 | held-out | 2026-11-02 10:08:30 to 11:21:30; 4380s | 3.48151 | 20 / 142 | 417s | 43.31-55.14% | 0 | `hackable/uploads/m8v2-s02-agent.php`: 3 | PASS (252 files) | `ae3903050ffbd03e7f72fb3dc1b2a897f302b2d06b517b96b9e2f2215d257525` |
| s03 | dev | 2026-11-01 17:34:52 to 18:47:51; 4379s | 3.43069 | 20 / 20 | 260s | 35.96-45.47% | 0 | `data/tracking01112026`: 2 | PASS (2880 files) | `dd903488e8fc413836a42c621e12b708749da85fb686ce503ff29eef8e945005` |
| s04 | dev | 2026-11-01 17:34:51 to 18:47:51; 4380s | 3.42603 | 20 / 20 | 249s | 38.00-47.31% | 0 | `data/tracking01112026`: 2; `images/category-1-.php..`: 14 | PASS (2881 files) | `4461b705fdf37281ea2b268bea257776b3e68f65ac6b44be2a1422e6102e2c2f` |
| s05 | dev | 2026-11-01 18:51:32 to 20:04:31; 4379s | 3.43024 | 20 / 21 | 447s | 36.97-49.48% | 0 | `hackable/uploads/m8v2-s05-marker.txt`: 1 | PASS (252 files) | `d7498fa9f09b06d9616eef0e240ac0c6bb9445b19fa8b3f2cea3cecba9776002` |
| s06 | held-out | 2026-11-02 10:08:33 to 11:21:33; 4380s | 3.42603 | 20 / 20 | 262s | 35.01-44.33% | 0 | none | PASS (251 files) | `2985a2f356736b985aed1e7723eb365294c01c5ae374b03ea920f2a967e90121` |
| s07 | dev | 2026-11-01 17:41:42 to 18:54:41; 4379s | 3.43069 | 20 / 20 | 571s | 38.95-54.94% | 0 | `wp-content/plugins/m8v2-maintenance/m8v2-maintenance.php`: 3; `wp-content/uploads/m8v2-s07-marker.txt`: 1; `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2 | PASS (2846 files) | `98eac551a0af55b4c1b75dbd888e3cb6d4dee4620f2f855c4dc94be3e58fa9df` |
| s08 | dev | 2026-11-01 17:41:45 to 18:54:44; 4379s | 3.43046 | 20 / 20 | 466s | 43.96-54.88% | 0 | `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2; `wp-content/plugins/wp-file-manager/lib/files/m8v2-s08-agent.php`: N/A (deleted before collection; ctime unavailable) | PASS (2844 files) | `2b417bfe1a40e674004320c0812f4cbb28e1830a1adb620d5a5ea0bd8740378a` |
| s09 | held-out | 2026-11-02 10:09:00 to 11:21:59; 4379s | 3.42932 | 20 / 20 | 262s | 43.98-50.12% | 0 | `wp-content/plugins/m8v2-timestomp/m8v2-s09-agent.php`: 6; `wp-content/plugins/m8v2-timestomp/m8v2-timestomp.php`: 1; `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2 | PASS (2846 files) | `671cd2a275938df75344de4f54482c78ee51ada24814c417096dc23645cc9484` |
| s10 | dev | 2026-11-01 17:41:44 to 18:54:43; 4379s | 3.42932 | 20 / 20 | 443s | 42.96-54.52% | 0 | `wp-content/plugins/m8v2-persistence/.htaccess`: 4; `wp-content/plugins/m8v2-persistence/m8v2-persistence.php`: 4; `wp-content/plugins/m8v2-persistence/m8v2-photo.jpg`: 4; `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2 | PASS (2847 files) | `7d8775826f346bd2a18a20d2bf8afbcabbe51bf3fdc6c40ea40e8c68a35e1fbc` |
| s11 | held-out | 2026-11-02 10:08:58 to 11:21:58; 4380s | 3.44863 | 20 / 60 | 189s | 36.76-42.97% | 0 | `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2 | PASS (2844 files) | `f93c41e1eacdf7887f4b7199ed6a39e9f7a67534dadb53ec356caccb7ecd7971` |
| s12 | dev | 2026-11-01 17:41:45 to 18:54:44; 4379s | 3.42864 | 20 / 20 | 529s | 34.99-50.41% | 0 | `wp-content/cache/m8v2-s12-page.php`: 3; `wp-content/plugins/m8v2-cache-fixture/m8v2-cache-fixture.php`: 6; `wp-content/uploads/2026/11/m8v2-s12-admin-media.png`: 2; `wp-content/uploads/wp-file-manager-pro/fm_backup/index.php`: 2 | PASS (2847 files) | `3df574a0396581f17713fcf5ebc86d0c39b265ae64ab4c9c618b1c667d817afc` |

## Recording commits

- s01: `e9eec25 bench v2: re-record s01 with live round-7 pacing`
- s02: `cff2660 bench v2: re-record held-out s02 with portable round-7 proof`
- s03: `368bd39 bench v2: re-record s03 with portable round-7 proof`
- s04: `e60a707 bench v2: re-record s04 with portable round-7 proof`
- s05: `6ed94b6 bench v2: re-record s05 with portable round-7 proof`
- s06: `22c9a33 bench v2: re-record held-out s06 with portable round-7 proof`
- s07: `be1c149 bench v2: re-record s07 with portable round-7 proof`
- s08: `1d11e98 bench v2: re-record s08 with portable round-7 proof`
- s09: `4f190e1 bench v2: re-record held-out s09 with portable round-7 proof`
- s10: `0fd5bf5 bench v2: re-record s10 with portable round-7 proof`
- s11: `371d603 bench v2: re-record held-out s11 with portable round-7 proof`
- s12: `4dfb7ed bench v2: re-record s12 with portable round-7 proof`

## Portable reconstruction

`lab/v2/portable-inputs.json` pins public images by registry digest and public archives by SHA-256. `portable.py` verifies each archive and indexes file bytes by SHA-256. WordPress core comes from the pinned public image extracted through a temporary network-disabled container; plugin, DVWA, phpMyFAQ, and dependency files come from pinned public source archives. The restore selects exact bytes by each manifest hash rather than relying on locally built scenario images.

The committed overlay supplies generated installation artifacts such as Composer metadata. Secret-bearing configuration and generated executable files are inert stubs whose original hash, size, and reason are in `defanged.tsv`. Changed attacker files are also inert stubs. Restore accepts an empty directory outside the repository, verifies every written file, rechecks the completed tree, rejects extra/missing paths, and preserves trailing-dot names on Windows using extended paths. Each `replay/restore-validation.txt` records the empty external destination and proof that local app images were absent.

## Adaptations and limits

- Public request bodies are unavailable and replay empty. Visitor write methods map only to crawled accepting endpoints. Scanner requests stay unchanged; one semicolon-suffixed scanner API probe with a static-looking suffix is reported separately in each self-check.
- Native sqlmap, Hydra, Commix, Weevely, and scripted agent bursts are named in each scenario self-check; hand actions remain at least two seconds apart.
- s02 uses authenticated DVWA SQLi; it does not claim SQLi supplied the login or dumped the user table. s06 verifies local-file reading without claiming code execution. s07/s09/s10 use the normal authenticated plugin installer. s11 remains no-compromise with no attacker files and a null root cause; s12 remains benign.
- s12 uses a local benign cache-plugin update because the core-update package is unreachable on the isolated network.
- s08 deletes its agent before collection, so its ctime and a corresponding nearby-write count are unavailable. The report explicitly marks that file N/A; no timestamp or count is inferred.
- Earlier interrupted recordings were discarded and never resumed or stitched. Old round-6 encrypted captures remain under the external `old-round6/` directory listed in STATUS.
- Source browser-version strings rewritten into IP-like numbers by Organization X anonymization are retained.

## Final validation

The independent all-twelve restore batch passed on 2026-11-03 WIB. [`restore-all-round7.json`](restore-all-round7.json) contains the exact empty external destinations, verified manifest counts, completion times and app-image absence proofs. Every final self-check was rerun against its corresponding new proof. Full pytest: 564 passed, 8 skipped; Ruff: all checks passed. Goldens and original benchmark scenarios are byte-identical to `main`; scorer and unit tests are unchanged from the session checkpoint `fbdb09f`. AC and DC lid-close are Sleep (1), verified in [`power-restored-round7.txt`](power-restored-round7.txt).

## Other round-7 commits

- `b1ff768 bench v2: add live source pacing and portable restore inputs`
- `9864a5c bench v2: wait for app readiness before recording setup`
- `0510b97 bench v2: isolate concurrent recording projects`
- `8394349 bench v2: verify complete actor windows and safe restore overlays`
- `d001599 bench v2: keep form routing and reject static HTML fallbacks`
- `9cb0d8d bench v2: enforce real DVWA login and verify exact write routes`
- `cbdf23a bench v2: bind analyst reviews to complete recorded logs`
- `d26c628 bench v2: verify the completed Windows restore tree`
- `da83438 bench v2: stabilize batch image provenance and name agent bursts`
- `ca20899 bench v2: normalize metadata without changing recorded logs`
- `d50e370 bench v2: validate benign activity without inventing attackers`
- `75283d5 bench v2: keep DVWA login label on POST only`
- `c20c8f1 bench v2: record completed dev proofs and held-out batch start`
- `fbdb09f bench v2: checkpoint complete held-out activity-window reviews`
- `8bb71fc bench v2: fix held-out split and fail on Defender scan errors`
- `82b4418 bench v2: register completed held-out round-7 recordings`
- `41c60fe bench v2: prove all twelve portable restores without local app images`

Round-eight correction and final review: [ROUND8.md](ROUND8.md).

## Known limits

- **Shared background.** All twelve scenarios replay the same 15,000 Organization X request rows, remapped per application and paired with NASA client identities. Results remain valid for a tool whose analysis code is frozen, but held-out scenarios do not contain unseen background traffic. Never tune rules on the development background and claim held-out generalization for that background. A future v3 should draw a separate background slice per scenario.
- **Referrer.** The source dataset has no referrer, so it is empty in every replayed background row (100%). The complete evidence also includes application traffic: fifteen WordPress cron self-requests across the suite have nonempty referrers. Thus “empty in all rows” applies to background, not literally to every complete evidence log. No referrer was invented or removed.
- **Anonymized scanner paths.** Numeric file names such as `/1.php` and `/wp-admin/54.php` come from the dataset's anonymization and are kept as published. Source browser version strings that resemble IP addresses are also retained.
- **Client addresses.** The mapper uses `198.51.100.0/24`, `203.0.113.0/24`, and the available part of `192.0.2.0/24` first, then `198.18.0.0/15`, reserved for benchmarking. Round eight replaces the former private overflow addresses because they made public-site background look internal and left the actor unusually distinct. The first 635 mappings are unchanged. Only background client addresses changed; requests, timestamps, statuses, sizes, user agents, order and count are unchanged. No routable public client pool is used. Per-scenario `replay/ip-remap.json` records the rule, counts, old and new hashes and verification; encrypted full captures are unchanged and retain the original mapping.
- **Ground-truth design choices.** In s09 the root cause is the timestomp request because the collected agent ctime links to it; this does not mean timestamp manipulation first gained access. In s07 the root cause is the plugin upload, which introduces attacker-controlled code, rather than the earlier password guessing. These definitions are stated so readers can apply their own incident definition.
- **s02 step order.** The held-out steps are listed out of time order. The scorer does not depend on order, and the held-out ground truth is deliberately unchanged.
- **Lab names in evidence.** Attacker files, plugins and the s12 probe path retain `m8v2-...` names, and the WordPress author is `benchadmin`. Renaming them would require new recordings because the names occur in the webroot, manifests and hashes. A read-only literal search of `src/webforensics` found no `m8v2-` or `benchadmin` strings, so the tool under test does not use those literal names. This is a source inspection, not a v2 analysis run or a claim that names cannot indirectly affect any analysis.
- **Log length and pacing.** Each log covers about 73 minutes with almost the same length and rate, around 3.43 requests per second; s02 has additional native sqlmap traffic. The background cap produces a plateau at exactly 20 requests per second. Real incident logs usually cover days and include day/night variation; these recordings do not represent that range.
- **s12 actor address.** The benign administrator uses `192.0.2.131`, the same address as the attacker in other scenarios. This is intentional: the same address must not be convicted when its activity is benign. The scenario notes state this explicitly.
