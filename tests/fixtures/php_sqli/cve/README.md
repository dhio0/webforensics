# Real SQL injection fixes (CVE) for the M7 localizer

Every reviewed GitHub advisory for a Composer package with CWE-89 and a fix commit (366
advisories, 190 with a commit, fetched 2026-10-29) was filtered by a rule fixed before the
analyzer was run on them:

1. the fix changes exactly one `.php` file outside test folders, and
2. the vulnerable file reads `$_GET`, `$_POST`, `$_REQUEST` or `$_COOKIE`
   (the scope of the brief).

13 cases passed. `cases.json` lists all of them with the lines the fix changed and the
outcome. Code is stored only for MIT-licensed projects (folders with a `NOTICE`); the others
(GPL, AGPL, LGPL or unclear licenses) are fetched into the ignored `.cache/` by
`python scripts/fetch_cve_fixtures.py`, and their test runs only when the cache exists.

- `detected`: a finding in the vulnerable file disappears in the fixed file, so the
  project's own fix confirms it.
- `exact`: in addition, the reported line is one the fix changed. Fixes often change the
  line that reads or cleans the input rather than the line that builds the query, so this
  is the stricter and lower number.
