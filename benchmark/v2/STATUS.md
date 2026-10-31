# Benchmark v2 status — resumable round 5

## Completed

- **s01** was re-recorded with Organization X request shapes and User-Agents paired with NASA KSC client identities. It has 15,000 background requests and 15,026 total access rows. Its folder is 3,259,570 bytes, ground-truth SHA-256 is `62a692cdbf2d15240c6e75bb912ae9ae54c1ada2e212695087b0d49dbb183858`, and commit `10a8298` records the scenario.
- **s03** records authenticated phpMyFAQ 3.2.5 CVE-2024-27299 in Save News. The root cause is a 2xx attacker request; the source file is `News.php:289`, hash `b5bc9846390989799935252d07ba16ce480b0ca4a5ef7a1d9fc8de758421cd2a`. The targeted database-delay confirmation took 1.022 seconds; the generic sqlmap check did not detect the cross-field condition. No attacker file or operating-system command was used.
- s03 has 15,000 background requests (12,077 visitors, 2,923 scanners), 15,023 total rows, 10,384 clients, and 903 User-Agents. Largest client share is 0.973%, largest User-Agent share 4.407%, visitor success is 99.959%, and attacker steps span 33.955%–34.101% of the access log.
- s03 schema, byte-identical ground-truth regeneration, parse validation, restore of 2,880 manifest entries, and Defender scan pass. One large phpMyFAQ runtime tracking file is an inert public stub with original hash/size recorded; its full copy is encrypted outside Git. Folder size is 3,496,035 bytes. Ground-truth SHA-256 is `d96f2725dcfd534f9b992610946e43fa4a605895e2424cc7e9ef6cb269d52405`.
- s03 replay provenance and adaptation are documented in [s03/notes.md](s03/notes.md) and [SOURCES.md](SOURCES.md). The source/runtime fix keeps dynamic phpMyFAQ autoloading enabled; nginx resolves the selected app upstream on the internal network.
- Latest full project checks before s03 work: `pytest` 536 passed, 8 skipped; `ruff check .` passed. No files under `src/webforensics/` or existing goldens changed. No analysis or evaluation was run.

## Next exact step

Record dev scenario s04 from its pinned sources, run its scenario checks, and commit it with a clean status checkpoint. Continue with s05, s07, s08, s10, and s12, then held-outs s02, s06, s09, and s11. Finish with `HELDOUT.md`, README, SOURCES, and final status updates.

## Remaining plan

1. Record remaining dev scenarios: s04, s05, s07, s08, s10, s12.
2. Record held-outs: s02, s06, s09, s11; add their ground-truth hashes and recording commits to `HELDOUT.md`.
3. Update README, SOURCES, and this status with the finished benchmark.

## Leftover files

- `lab/v2/.cache/zenodo-20001206-organization-x.zip` and `.cache/NASA_access_log_Jul95.gz` are ignored source datasets kept for upcoming replays.
- `lab/v2/.cache/phpmyfaq-3.2.5-source.zip` and its expanded copy are ignored build inputs. An incomplete official-release download may also remain; it was not used.
- Encrypted s01 and s03 full captures remain outside Git in the directory configured by `lab/v2/.env`.
- s01's restored tree remains at `C:\Windows\Temp\m8v2-restore-s01-51b317c261f04798a7d4ca714451702a`. s03 restore-validation trees remain under `%TEMP%` from failed attempts; the successful verification tree is `%TEMP%\m8v2-restore-s03-benchv2-final-11`.
