# Benchmark v2 status — resumable round 5

## Completed

- **s01** was re-recorded with Organization X request shapes and User-Agents paired with NASA KSC client identities. It has 15,000 background requests and 15,026 total access rows. Its folder is 3,259,570 bytes, ground-truth SHA-256 is `62a692cdbf2d15240c6e75bb912ae9ae54c1ada2e212695087b0d49dbb183858`, and commit `10a8298` records the scenario.
- **s03** records authenticated phpMyFAQ 3.2.5 CVE-2024-27299 in Save News. The root cause is a 2xx attacker request; the source file is `News.php:289`, hash `b5bc9846390989799935252d07ba16ce480b0ca4a5ef7a1d9fc8de758421cd2a`. The targeted database-delay confirmation took 1.022 seconds; the generic sqlmap check did not detect the cross-field condition. No attacker file or operating-system command was used.
- s03 has 15,000 background requests (12,077 visitors, 2,923 scanners), 15,023 total rows, 10,384 clients, and 903 User-Agents. Largest client share is 0.973%, largest User-Agent share 4.407%, visitor success is 99.959%, and attacker steps span 33.955%–34.101% of the access log.
- s03 schema, byte-identical ground-truth regeneration, parse validation, restore of 2,880 manifest entries, and Defender scan pass. One large phpMyFAQ runtime tracking file is an inert public stub with original hash/size recorded; its full copy is encrypted outside Git. Folder size is 3,496,035 bytes. Ground-truth SHA-256 is `d96f2725dcfd534f9b992610946e43fa4a605895e2424cc7e9ef6cb269d52405`.
- s03 replay provenance and adaptation are documented in [s03/notes.md](s03/notes.md) and [SOURCES.md](SOURCES.md). The source/runtime fix keeps dynamic phpMyFAQ autoloading enabled; nginx resolves the selected app upstream on the internal network.
- **s04** records authenticated phpMyFAQ 3.2.5 CVE-2024-28105 category-image upload bypass. The 2xx root-cause request is line 6,455; the fixed marker is returned at line 6,456. The six attacker requests span 42.989%–43.023% of 15,006 rows. There are 15,000 background rows, 10,384 clients, and 903 User-Agents; visitor success is 99.959%, with 2,923 scanner rows retained. The collector defanged two files. Schema, byte-identical label regeneration, zero-parse-failure evidence validation, self-check, restore of all 2,881 manifest entries, and Defender scan pass. Folder size is 3,469,775 bytes, Defender detections are zero, and ground-truth SHA-256 is `6eb28af7c3cd7734fa2525e3b395c6483c8e6fb3ad2745112c7b530c0688b5d8`.
- s04 provenance and the isolated execution check are described in [s04/notes.md](s04/notes.md); CVE-2024-28105 and the scenario image digest are recorded in [SOURCES.md](SOURCES.md). `restore_webroot.py` now handles POSIX filenames ending in dots on Windows using extended paths.
- **s05** records command injection in pinned DVWA commit `a1978a2fed195acd093010af6395f86a281537ca` with pinned Commix. DVWA is the task-approved training app for this class and the module has no separate CVE. Commix confirmed command execution; the marked 2xx root-cause request is line 6,019 and its plain-text marker is read at line 6,020. The nine named steps span 39.953%–40.080% of 15,020 rows. The 15,000 background requests have 10,384 clients and 903 User-Agents; visitor success is 93.475%, with 2,923 scanners retained. No files required defanging. Schema, byte-identical label regeneration, zero-parse-failure evidence validation, self-check, restore of 252 manifest entries, and Defender scan pass. The scenario is 2,079,106 bytes with zero Defender detections; ground-truth SHA-256 is `3141713b0b8b62fe8a939115006cebb474938f01eb7da4b7563c41aea88b2e5c`.
- s05 source/license, Commix pin, source-line provenance, and the log-order adaptation are described in [s05/notes.md](s05/notes.md) and [SOURCES.md](SOURCES.md). The replay submits background requests sequentially; self-check compares exact client identity counts because a few completion rows can be reordered by the server logs.
- **s07** records the requested WordPress 5.5.3 login-guessing and plugin-upload chain with pinned Hydra. Hydra confirmed the local administrator account; the marked plugin ZIP upload is line 7,368 and the text marker check is line 7,371. The eleven named steps span 48.935%–49.068% of 15,022 rows. The 15,000 background requests have 10,384 clients and 903 User-Agents; visitor success is 96.274%, with 2,923 scanner rows retained. The plugin only writes a text marker rather than providing a shell. The collector defanged the plugin PHP and an empty File Manager backup side effect, which is marked `expected_in_report: false`; the plain-text marker remains unchanged. Schema, byte-identical label regeneration, zero-parse-failure evidence validation, self-check, restore of 2,846 manifest entries, and Defender scan pass. Folder size is 3,250,339 bytes with zero Defender detections; ground-truth SHA-256 is `8af2596a9823cef52d51561d745f464aed588cbfcf30317131fc6437d3decdbd`.
- s07 source pins, Hydra result, step selection, and the safe marker adaptation are documented in [s07/notes.md](s07/notes.md) and [SOURCES.md](SOURCES.md). No CVE is claimed for the normal authenticated WordPress plugin installer.
- **s08** records WordPress File Manager 6.0 CVE-2020-25213: an uploaded Weevely agent was used briefly and removed before collection. The 2xx root-cause upload is line 10,355, the removal request is line 10,368, and the absent-path check is line 10,371. Ten named steps span 68.910%–69.043% of 15,021 rows. The 15,000 background requests have 10,384 clients and 903 User-Agents; visitor success is 96.274%, with 2,923 scanner rows retained. The transient agent is recorded as deleted with its hash and size, but its content is absent; the collector defanged one empty File Manager side effect. Schema, byte-identical label regeneration with transient-file support, zero-parse-failure evidence validation, self-check, restore of 2,844 manifest entries, and Defender scan pass. Folder size is 3,250,508 bytes with zero Defender detections; ground-truth SHA-256 is `bd191ce98466319ccce0b7f3d321d8f1282d24f7db8a1fff8a9bd955ba20aabc`.
- s08 transient-file labeling, deletion evidence, and File Manager provenance are described in [s08/notes.md](s08/notes.md) and [SOURCES.md](SOURCES.md).
- Latest full project checks before s03 work: `pytest` 536 passed, 8 skipped; `ruff check .` passed. No files under `src/webforensics/` or existing goldens changed. No analysis or evaluation was run.

## Next exact step

Record dev scenario s10 from its pinned sources, run its scenario checks, and commit it with a clean status checkpoint. Continue with s12, then held-outs s02, s06, s09, and s11. Finish with `HELDOUT.md`, README, SOURCES, and final status updates.

## Remaining plan

1. Record remaining dev scenarios: s10, s12.
2. Record held-outs: s02, s06, s09, s11; add their ground-truth hashes and recording commits to `HELDOUT.md`.
3. Update README, SOURCES, and this status with the finished benchmark.

## Leftover files

- `lab/v2/.cache/zenodo-20001206-organization-x.zip` and `.cache/NASA_access_log_Jul95.gz` are ignored source datasets kept for upcoming replays.
- `lab/v2/.cache/phpmyfaq-3.2.5-source.zip` and its expanded copy are ignored build inputs. An incomplete official-release download may also remain; it was not used.
- Encrypted s01 and s03 full captures remain outside Git in the directory configured by `lab/v2/.env`.
- The encrypted s04 full capture remains outside Git in the directory configured by `lab/v2/.env`.
- The encrypted s05 full capture remains outside Git in the directory configured by `lab/v2/.env`.
- The encrypted s08 full capture remains outside Git in the directory configured by `lab/v2/.env`.
- s01's restored tree remains at `C:\Windows\Temp\m8v2-restore-s01-51b317c261f04798a7d4ca714451702a`. s03 restore-validation trees remain under `%TEMP%` from failed attempts; the successful verification tree is `%TEMP%\m8v2-restore-s03-benchv2-final-11`.
- s04 restore-validation scratch trees from failed and successful path-format checks remain under `%TEMP%`: `m8v2-restore-s04-benchv2-final-01` through `-04`.
- The s05 restore-validation tree remains at `%TEMP%\m8v2-restore-s05-benchv2-final-01`.
- The s07 restore-validation trees remain at `%TEMP%\m8v2-restore-s07-benchv2-final-01` and `-02`.
- The s08 restore-validation tree remains at `%TEMP%\m8v2-restore-s08-benchv2-final-01`.
