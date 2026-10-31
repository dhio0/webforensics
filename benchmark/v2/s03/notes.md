# s03: phpMyFAQ authenticated Save News SQL injection

## Scenario adaptation and verification status

This scenario uses phpMyFAQ 3.2.5 (MPL-2.0) and CVE-2024-27299. The upstream advisory says exploitation requires an authenticated account with permission to add or edit FAQ news. The upstream fix changes the `authorEmail` escaping in `phpmyfaq/src/phpMyFAQ/News.php` at lines 289 and 335. The 3.2.5 source tag was fetched and its SHA-256 verified as `282b638d7ecda25d6a803d16d9865c6b8aa0516ec9ed6d24bfadabdc6800d05f`.

The scenario adapts the originally proposed SQLi-to-file-write story to authenticated SQL injection in the Save News feature. The planned benignly bounded outcome is database read proof only, without writing a server file. This limitation follows the documented vulnerability path and does not claim an unauthenticated foothold. The attack has not yet been run or captured.

## Capture state

The phpMyFAQ image builds from the pinned 3.2.5 source archive using PHP 8.1 and Composer dependencies. The app stack starts on an internal Docker network with PostgreSQL. Setup created the database tables and benchmark administrator. The attacker network isolation checks passed. During initial runtime checks, the frontend and admin routes returned an empty response body after setup. This issue must be diagnosed and fixed before recording background traffic or an attack.

No s03 ground truth has been generated. No line numbers, vulnerable-code hash, file list, or attack outcome are claimed yet. The source code line numbers above are sourced from the upstream fix commit and still need to be connected to the replay's captured vulnerable source hash.

## Sources

- [Maintainer security advisory GHSA-qgxx-4xv5-6hcw](https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw)
- [Upstream fix commit 1b68a5f](https://github.com/thorsten/phpMyFAQ/commit/1b68a5f89fb65996c56285fa636b818de8608011)
- [phpMyFAQ 3.2.5 source tag](https://github.com/thorsten/phpMyFAQ/tree/3.2.5)
- [phpMyFAQ v3.2 installation guide](https://phpmyfaq.readthedocs.io/en/3.2/installation/)
