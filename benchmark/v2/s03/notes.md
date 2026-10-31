# s03: phpMyFAQ authenticated Save News SQL injection

## Scenario and provenance

This replay uses phpMyFAQ 3.2.5 (MPL-2.0) and CVE-2024-27299. The maintainer advisory says the affected news editor requires an authenticated user with add/edit rights. The upstream fix changes `authorEmail` escaping in `phpmyfaq/src/phpMyFAQ/News.php` at lines 289 and 335. The pinned 3.2.5 source tag is `ee05654763ef0f16137d3bd21ec50e2f21ffb8f8`; the downloaded source archive SHA-256 is `282b638d7ecda25d6a803d16d9865c6b8aa0516ec9ed6d24bfadabdc6800d05f`.

The replay authenticates the seeded benchmark administrator, opens Save News, runs pinned sqlmap with a generic single-field check, then uses one maintainer-documented short database-delay check to confirm the flaw. The generic sqlmap check did not identify the cross-field condition. The targeted confirmation returned HTTP 200 after a 1.022-second database delay. It wrote no server-side attack file and ran no operating-system command. The advisory and fix are linked below.

## Recorded evidence

- Access log: 15,023 rows, including 15,000 background rows; no access, manifest, or Apache error parse failures.
- Background diversity: 10,384 clients and 903 User-Agents. Largest client share is 0.973%; largest User-Agent share is 4.407%.
- Visitor 2xx/3xx share is 99.959%; all 2,923 source-classified scanner rows were retained.
- Five attacker steps are labelled between 33.955% and 34.101% of the access log. The root-cause request is an attacker HTTP 2xx response.
- Ground truth records `News.php`, line 289, with vulnerable-source SHA-256 `b5bc9846390989799935252d07ba16ce480b0ca4a5ef7a1d9fc8de758421cd2a`.
- One phpMyFAQ runtime tracking file changed during the run. Its path, original SHA-256, and size are in `evidence/manifest.tsv` and `evidence/defanged.tsv`; its public snapshot is an inert stub because the original is larger than the 1 MB public snapshot limit. The full webroot remains in the encrypted capture outside the repository.
- The s03 folder is 3,496,035 bytes. The schema, byte-identical ground-truth regeneration, background-diversity checks, evidence adapters, restore of 2,880 manifest entries, and Defender scan all pass. Defender realtime protection was enabled and detections were zero.
- Restore uses the pinned phpMyFAQ image plus five small setup-generated `index.html` files from `replay/restore-overlay/` and the locally configured database settings. The setup overlay contains no credentials.

The tracking file changes with ordinary traffic and is recorded as a side effect with `expected_in_report: false`.

## Sources

- [Maintainer security advisory GHSA-qgxx-4xv5-6hcw](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw)
- [Upstream fix commit 1b68a5f](https://github.com/thorsten/phpMyFAQ/commit/1b68a5f89fb65996c56285fa636b818de8608011)
- [phpMyFAQ 3.2.5 source tag](https://github.com/thorsten/phpMyFAQ/tree/3.2.5)
- [phpMyFAQ v3.2 installation guide](https://phpmyfaq.readthedocs.io/en/3.2/installation/)
