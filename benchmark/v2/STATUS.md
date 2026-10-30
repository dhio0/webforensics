# Benchmark v2 status — round 5

## Completed

- **s01** was re-recorded from clean Docker volumes with all six round-5 fixes and
  committed as `1264c64` (`bench v2: s01 re-recorded (round 5)`). Its artifact and
  validation details are in [s01/notes.md](s01/notes.md).
- The s01 scenario directory is 1,998,293 bytes. Its 15,000 background requests split
  into 14,919 visitors and 81 scanners. Visitor responses were 13,383 HTTP 200, 984
  HTTP 301, 168 HTTP 302, and 384 HTTP 404; scanners retained 81 HTTP 404 responses.
- Seed 5031 selected the 54% attack start. Labeled attacker steps are at access-log
  lines 8110–8114 and 8120, 8123, and 8126. There are two defanged files. Defender
  reported zero detections. The ground-truth SHA-256 is
  `f0cf95566e789266c568260c18933f81500aa5e58ba1b624c19b500761d847c0`.
- Checks: restored all 2,845 manifest entries outside the repository and verified
  hashes/stubs; evidence adapters reported zero parse failures (the two stub hash
  differences are expected); schema and deterministic label regeneration passed;
  full suite `533 passed, 8 skipped`; Ruff passed; goldens remain unchanged.

## s03 not recorded

No candidate checked met all three requirements together: a small PHP application, an
explicit OSI-approved redistribution license, and a published SQL injection CVE whose
advisory or fix identifies the vulnerable source location.

- PHPGurukul Small CRM 3.0 has CVE-2024-44644 naming `manage-tickets.php`, but an
  explicit OSI-approved license and licensed source release were not verified.
- PHPGurukul Student Record System 3.20 has CVE-2024-44640 naming `add-course.php`,
  but its redistribution license remains unclear.
- phpMyFAQ 3.2.5 has an explicit MPL-2.0 license and verified CVE-2024-27299 source/fix
  provenance in `phpmyfaq/src/phpMyFAQ/News.php` lines 289 and 335. It is a full FAQ
  platform with an upstream repository about 52.8 MB, so it does not fit the small-app
  requirement.

No s03 source, image, attack, or ground truth was recorded. Per the task's stop condition,
work stops here; s02 and s04–s12 have not started. See [SOURCES.md](SOURCES.md) for
verification links and additional candidates.
